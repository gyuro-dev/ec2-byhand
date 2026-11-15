from __future__ import annotations

import json
from contextlib import ExitStack

import pytest
from conftest import GOLDEN_DIR
from fs_golden import FIELDS, _decode, _sha256

from diskread import BytesDevice, DiskReadError, FileDevice
from diskread.fs import FileType
from diskread.fs.detect import detect_fs, open_fs
from diskread.fs.fat import Vfat
from diskread.system import Volume, assemble, parse_fstab, resolve_spec, scan, walk_system


def _open_system(stack: ExitStack):
    a, b = GOLDEN_DIR / "system-a.img", GOLDEN_DIR / "system-b.img"
    if not a.exists():
        pytest.skip("no golden images; run tools/golden/build_system.sh")
    disks = {
        "diskA": stack.enter_context(FileDevice(a)),
        "diskB": stack.enter_context(FileDevice(b)),
    }
    return assemble(scan(disks))


def test_mounted_tree_matches_kernel() -> None:
    expected = (
        {
            e["path"]: e
            for e in json.loads((GOLDEN_DIR / "system.json").read_text(encoding="utf-8"))["files"]
        }
        if (GOLDEN_DIR / "system.json").exists()
        else None
    )
    with ExitStack() as stack:
        system = _open_system(stack)
        assert expected is not None
        actual = {}
        for path, mount, ino, st in walk_system(system):
            fs = mount.fs
            e = {f: getattr(st, f) for f in FIELDS}
            e["type"] = str(st.type)
            e["sha256"] = _sha256(fs, ino) if st.type is FileType.REG else None
            if isinstance(fs, Vfat):  # Linux invents FAT inode numbers
                e.pop("ino")
            actual[_decode(path)] = e

    assert sorted(actual) == sorted(expected)
    diffs = [
        f"{p} {k}: {expected[p][k]!r} != {actual[p][k]!r}"
        for p in expected
        for k in actual[p]
        if expected[p][k] != actual[p][k]
    ]
    assert not diffs, "\n".join(diffs[:20])


def test_mounts_and_fstab_resolution() -> None:
    with ExitStack() as stack:
        system = _open_system(stack)
        assert system.root.name == "lvm:ec2dsys/root"
        assert [(m.mountpoint, m.volume.name) for m in system.mounts] == [
            (b"/", "lvm:ec2dsys/root"),
            (b"/boot", "diskAp1"),
            (b"/data", "diskB"),
            (b"/opt", "lvm:ec2dsys/opt"),
            (b"/var", "lvm:ec2dsys/var"),
            (b"/boot/efi", "diskAp3"),
        ]
        assert [(e.spec, reason) for e, reason in system.unresolved] == [
            ("/dev/xvdf1", "device not found among the scanned volumes")
        ]
        assert sorted(e.fstype for e in system.ignored) == ["swap", "tmpfs"]
        assert {v.name: v.fs_type for v in system.volumes} == {
            "diskAp1": "ext4",
            "diskAp3": "vfat",
            "diskB": "xfs",
            "lvm:ec2dsys/root": "xfs",
            "lvm:ec2dsys/var": "xfs",
            "lvm:ec2dsys/opt": "ext4",
        }


def test_parse_fstab_escapes_and_comments() -> None:
    entries = parse_fstab(
        b"# c\n\nUUID=ab /mnt/with\\040space ext4 defaults 0 2 # tail\nLABEL=x /a xfs\n"
    )
    assert [(e.spec, e.mountpoint, e.fstype, e.options) for e in entries] == [
        ("UUID=ab", "/mnt/with space", "ext4", "defaults"),
        ("LABEL=x", "/a", "xfs", "defaults"),
    ]


def test_resolve_spec_forms() -> None:
    dev = BytesDevice(bytes(512))
    vols = [
        Volume("p1", dev, uuid="AB-CD", label="boot", partuuid="1234-01", partlabel="EFI"),
        Volume("lv", dev, lvm=("my-vg", "root")),
    ]
    assert resolve_spec("UUID=ab-cd", vols) is vols[0]
    assert resolve_spec('LABEL="boot"', vols) is vols[0]
    assert resolve_spec("/dev/disk/by-partuuid/1234-01", vols) is vols[0]
    assert resolve_spec("PARTLABEL=EFI", vols) is vols[0]
    assert resolve_spec("/dev/mapper/my--vg-root", vols) is vols[1]
    assert resolve_spec("/dev/my-vg/root", vols) is vols[1]
    assert resolve_spec("/dev/nvme1n1p1", vols) is None


def test_ambiguous_root_is_an_error() -> None:
    with pytest.raises(DiskReadError, match="root filesystem"):
        assemble([])


def test_efi_mount_uses_fstab_options() -> None:
    with ExitStack() as stack:
        system = _open_system(stack)
        efi = next(m for m in system.mounts if m.mountpoint == b"/boot/efi")
        st = next(
            st for path, m, _, st in walk_system(system) if path == b"/boot/efi/EFI/amzn/grub.cfg"
        )
        assert "umask=0077" in efi.entry.options
        assert oct(st.mode) == "0o100700"  # from umask=0077, not the default 0755


def test_whole_disk_fat_is_not_an_mbr() -> None:
    path = GOLDEN_DIR / "vfat-fat12.img"
    if not path.exists():
        pytest.skip("no golden images; run tools/golden/build_vfat.sh")
    with FileDevice(path) as dev:
        from diskread.partition import read_partition_table

        assert read_partition_table(dev) is None
        assert [v.fs_type for v in scan({"disk": dev})] == ["vfat"]


def test_detect_fs() -> None:
    assert detect_fs(BytesDevice(bytes(4096))) is None
    for name, kind in (("ext4-default", "ext4"), ("xfs-al2023", "xfs"), ("vfat-fat32", "vfat")):
        path = GOLDEN_DIR / f"{name}.img"
        if not path.exists():
            pytest.skip("no golden images; run tools/golden/build_fs.sh")
        with FileDevice(path) as dev:
            assert detect_fs(dev) == kind
            assert type(open_fs(dev)).__name__.lower() == kind
