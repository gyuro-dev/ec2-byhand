"""One damaged thing on the disk costs a warning, not the run: a directory that cannot
be listed, a log that is not what it should be, a file whose blocks lie past the end of
the disk, container metadata in another shape. (Found by a review of the whole tool
before it was published, 2026-11-15; each of these used to end the run.)"""

from __future__ import annotations

import gzip
import io
import posixpath
import struct
import sys
import tarfile
import time
import zlib
from pathlib import Path

import pytest
from conftest import GOLDEN_DIR
from memfs import MemFs

from diskread import BytesDevice, DiskReadError, SliceDevice
from diskread.blockdev import will_read
from diskread.fs import Stat, lookup, valid_name, walk
from diskread.fs.ext4 import Ext4
from diskread.fs.ext4.blockmap import indirect_runs
from diskread.fs.ext4.inode import parse_inode
from diskread.fs.extents import MappedContent, Run
from diskread.fs.fat.dirent import parse_dir, volume_label
from diskread.fs.fat.fs import _codepage_option
from diskread.fs.xfs import Xfs
from diskread.fs.xfs import attr as xfs_attr
from diskread.fs.xfs.superblock import parse_superblock as parse_xfs_superblock
from diskread.lvm import find_volume_groups, read_label
from diskread.lvm.vg import _parse_segment
from diskread.partition import read_partition_table
from diskread.source import SystemSource, clean_path
from diskread.system import FstabEntry, Mount, System, Volume, parse_fstab, scan
from ec2_byhand import cli
from ec2_byhand.analyze import Snapshot, analyze
from ec2_byhand.archive import write_outputs
from ec2_byhand.bolt import Bolt
from ec2_byhand.packages import rpmheader
from ec2_byhand.packages.dpkg import read_dpkg
from ec2_byhand.secrets import SCAN_MAX_BYTES, find_secrets

DATA_DIR = Path(__file__).parent / "data"


def _snap(fs: MemFs) -> Snapshot:
    return Snapshot("test", SystemSource.from_fs(fs))


def _server() -> MemFs:
    fs = MemFs()
    fs.add_file("/etc/os-release", b"ID=test\n")
    fs.add_file("/home/app/notes.txt", b"hello\n")
    fs.add_file("/opt/app/app.conf", b"x=1\n")
    fs.add_file("/var/log/cloud-init.log", b"")
    fs.add_file("/var/lib/misc/state", b"")
    return fs


def _unlistable(fs: MemFs, path: str) -> None:
    """Make listing the directory at `path` fail, as damaged directory blocks do."""
    bad = fs.ino(path)
    listdir = fs.listdir

    def damaged(ino: int) -> list[tuple[bytes, int]]:
        if ino == bad:
            raise DiskReadError(f"directory {ino}: bad rec_len")
        return listdir(ino)

    fs.listdir = damaged  # type: ignore[method-assign]


@pytest.mark.parametrize("path", ["/home/app", "/home", "/var/log", "/var/lib", "/etc", "/var"])
def test_a_directory_that_cannot_be_listed_does_not_end_the_run(path: str) -> None:
    # The walk said so and went on; what looks things up by path afterwards (container
    # stores, npm caches, cloud-init's log, systemd's directories) must go on too.
    fs = _server()
    _unlistable(fs, path)
    m = analyze(_snap(fs))
    assert "/opt/app/app.conf" in {h["path"] for h in m["hand_placed"]}


def test_a_home_that_cannot_be_listed_is_said() -> None:
    fs = _server()
    _unlistable(fs, "/home/app")
    m = analyze(_snap(fs))
    by_code = {w["code"]: w for w in m["warnings"]}
    assert by_code["read-error"]["path"] == "/home/app"
    # A rootless Podman store may be there: it could not be looked at, and that is said.
    assert by_code["container-metadata-unreadable"]["entries"] == [
        "/home/app/.local/share/containers/storage"
    ]


def test_try_listdir_takes_what_cannot_be_read_as_absent() -> None:
    fs = _server()
    _unlistable(fs, "/home")
    src = SystemSource.from_fs(fs)
    with pytest.raises(DiskReadError):
        src.listdir("/home/app")
    assert src.try_listdir("/home/app") is None
    assert src.try_listdir("/home") is None
    assert src.try_listdir("/opt/app") == ["app.conf"]
    assert src.try_listdir("/nowhere") is None


def _cloud_init_server(log_name: str, log: bytes) -> MemFs:
    fs = MemFs()
    fs.add_dir("/var/lib/cloud/instance")
    fs.add_file("/opt/app/app.conf", b"x=1\n")
    fs.add_file(f"/var/log/{log_name}", log)
    return fs


def test_a_rotated_cloud_init_log_with_corrupt_data_is_passed_over() -> None:
    line = b"2026-11-15 01:33:51,123 - util.py[DEBUG]: Writing to /etc/x - wb: [644] 3 bytes\n"
    good = gzip.compress(line * 50)
    corrupt = good[:20] + bytes(b ^ 0xFF for b in good[20:40]) + good[40:]  # not truncated
    m = analyze(_snap(_cloud_init_server("cloud-init.log.1.gz", corrupt)))
    assert "cloud-init-log-missing" in {w["code"] for w in m["warnings"]}


def test_a_cloud_init_log_line_with_no_real_date_is_passed_over() -> None:
    log = (
        b"2026-13-45 01:33:51,123 - util.py[DEBUG]: Writing to /etc/x - wb: [644] 3 bytes\n"
        b"2026-11-15 01:33:52,000 - util.py[DEBUG]: Writing to /etc/y - wb: [644] 3 bytes\n"
    )
    m = analyze(_snap(_cloud_init_server("cloud-init.log", log)))
    assert "cloud-init-log-missing" not in {w["code"] for w in m["warnings"]}


class _PastTheDisk:
    """A file whose blocks lie past the end of the disk, as an EBS snapshot shows it:
    even being told of the read is refused."""

    size = 100_000

    def read_at(self, offset: int, length: int) -> bytes:
        raise DiskReadError("read out of range")

    def will_read(self, offset: int, length: int) -> None:
        raise DiskReadError("read out of range")


def test_telling_a_device_of_a_read_never_fails() -> None:
    will_read(_PastTheDisk())  # type: ignore[arg-type]
    will_read(_PastTheDisk(), 0, 10)  # type: ignore[arg-type]
    will_read(BytesDevice(b"x"))  # cannot fetch ahead: not told at all


def test_a_file_with_blocks_past_the_disk_is_skipped_not_fatal(tmp_path: Path) -> None:
    fs = _server()
    fs.add_file("/opt/app/broken.bin", b"x" * 100_000)
    bad = fs.ino("/opt/app/broken.bin")
    open_ = fs.open
    fs.open = lambda ino: _PastTheDisk() if ino == bad else open_(ino)  # type: ignore[method-assign,return-value]
    snap = _snap(fs)
    m = analyze(snap)
    items = {h["path"]: h for h in m["hand_placed"]}
    assert "error" in items["/opt/app/broken.bin"]
    archives = write_outputs(m, snap.source, None, tmp_path)
    skipped = {(s["archive"], s["path"]): s["reason"] for s in archives["skipped"]}
    assert skipped[("after", "/opt/app/broken.bin")] == "read-error"
    assert archives["after"]["entries"] > 0  # the rest is there


@pytest.mark.parametrize("names", ['{"a": 1}', "7", '"web"', "[7]", "null"])
def test_podman_container_names_in_another_shape(names: str) -> None:
    fs = _server()
    fs.add_file(
        "/var/lib/containers/storage/overlay-containers/containers.json",
        f'[{{"id": "abcdef0123456789", "names": {names}}}]'.encode(),
    )
    fs.add_file(
        "/var/lib/containers/storage/overlay-images/images.json",
        f'[{{"id": "0123", "names": {names}}}]'.encode(),
    )
    m = analyze(_snap(fs))
    (container,) = m["containers"]["containers"]
    assert container["name"] == "abcdef012345"  # no name to read: the id stands for it
    assert m["containers"]["images"] == []


def test_volumes_are_counted_each_by_what_lies_below_it() -> None:
    fs = _server()
    for volume, files in (("data", 3), ("data2", 1), ("empty", 0)):
        fs.add_dir(f"/var/lib/docker/volumes/{volume}/_data")
        for n in range(files):
            fs.add_file(f"/var/lib/docker/volumes/{volume}/_data/d/{n}", b"x" * 10)
    m = analyze(_snap(fs))
    found = {v["name"]: (v["files"], v["bytes"]) for v in m["containers"]["volumes"]}
    assert found == {"data": (3, 30), "data2": (1, 10), "empty": (0, 0)}


def test_a_removed_language_package_leaves_nothing_skipped(tmp_path: Path) -> None:
    # Its files that were not as installed are the baseline's: gone now, they are no
    # entry the "after" archive lacks.
    before, after = MemFs(), MemFs()
    before.add_file("/opt/app/venv/lib/site-packages/x/mod.py", b"edited\n")
    manifest = {
        "hand_placed": [],
        "modified_package_files": [],
        "deleted": [],
        "language_packages": [
            {
                "status": "removed",
                "modified": ["/opt/app/venv/lib/site-packages/x/mod.py"],
                "missing": [],
                "edited_after_install": [],
            }
        ],
    }
    archives = write_outputs(manifest, _snap(after).source, _snap(before).source, tmp_path)
    assert archives["skipped"] == []
    assert archives["before"]["entries"] == 1


@pytest.mark.parametrize(
    "content",
    [
        b"-----BEGIN PRIVATE KEY-----\n" * (SCAN_MAX_BYTES // 28),  # no END in sight
        b"a." * (SCAN_MAX_BYTES // 2),  # one endless "scheme"
        b"AKIAABCDEFGHIJKLMNOP " * (SCAN_MAX_BYTES // 21),  # nothing but findings
        b"password=hunter2secret\n" * (SCAN_MAX_BYTES // 23),
    ],
    ids=["begin-lines", "dotted-run", "access-keys", "passwords"],
)
def test_the_scan_for_secrets_stays_linear(content: bytes) -> None:
    # Each of these took minutes for one file before (quadratic in its size): a disk
    # with a few hundred of them would never have finished.
    started = time.perf_counter()
    find_secrets(content)
    assert time.perf_counter() - started < 20


def test_a_begin_line_without_an_end_does_not_hide_the_key_after_it() -> None:
    text = (
        b"-----BEGIN PRIVATE KEY-----\nnot closed\n"
        b"password = first-secret\n"
        b"-----BEGIN RSA PRIVATE KEY-----\nMIIB\nAAAA\n-----END RSA PRIVATE KEY-----\n"
        b"-----BEGIN PRIVATE KEY-----\nlast\n-----END PRIVATE KEY-----\n"
    )
    found = find_secrets(text)
    # As one pattern did: from the first BEGIN to the first END, then the next block.
    assert [(f.kind, f.line) for f in found] == [("private-key", 2), ("private-key", 9)]
    assert text[found[0].start : found[0].end].endswith(b"MIIB\nAAAA")
    assert text[found[1].start : found[1].end] == b"last"


def test_an_error_is_said_and_coded_even_with_no_stderr_left(monkeypatch, tmp_path: Path) -> None:
    # After SIGHUP (the SSH session lost) writing to stderr fails: the exit code must
    # still say what happened, not turn into a traceback.
    class Gone(io.TextIOBase):
        def write(self, text: str) -> int:
            raise OSError(5, "Input/output error")

    monkeypatch.setattr(sys, "stderr", Gone())
    args = ["--current-image", str(tmp_path / "missing.img"), "-o", str(tmp_path / "o")]
    assert cli.main(args) == 2


# --- diskread: what a damaged disk says must not be believed without a bound ----------


def test_a_hash_inside_an_fstab_field_is_part_of_it() -> None:
    # Cut at any "#", the line lost its fields and the entry with them: the volume was
    # left out of the analysis without a word.
    text = (
        b"# a comment\n"
        b"LABEL=data#1 /data xfs defaults 0 0\n"
        b"UUID=abc /mnt/a#b ext4 defaults,nofail 0 2 # the second disk\n"
        b"   # another comment\n"
        b"UUID=def /srv ext4 #only three fields before this\n"
    )
    found = [(e.line, e.spec, e.mountpoint, e.options) for e in parse_fstab(text)]
    assert found == [
        (2, "LABEL=data#1", "/data", "defaults"),
        (3, "UUID=abc", "/mnt/a#b", "defaults,nofail"),
        (5, "UUID=def", "/srv", "defaults"),
    ]


@pytest.mark.parametrize("depth", [600, 3000])
def test_a_path_many_hundreds_deep_is_resolved(depth: int) -> None:
    # The walk lists it; resolving it used to end in "too many levels of symbolic links"
    # (a recursion over its components), so it was never archived or compared.
    fs = MemFs()
    path = "/" + "/".join(["d"] * depth) + "/f"
    fs.add_file(path, b"x")
    fs.add_link("/top", "d/d/d")
    src = SystemSource.from_fs(fs)
    assert src.resolve(path) == (fs, fs.ino(path))
    assert src.resolve(path, follow_last=False) == (fs, fs.ino(path))
    assert src.read(path) == b"x"
    assert src.resolve(path + "/..") == (fs, fs.ino(posixpath.dirname(path)))
    assert src.realpath("/top/" + "/".join(["d"] * (depth - 3)) + "/f") == path
    assert src.resolve(path + "/nothing") is None


def test_an_xfs_symlink_larger_than_any_is_refused_before_it_is_read() -> None:
    image = GOLDEN_DIR / "xfs-al2023.img"
    if not image.exists():
        pytest.skip("no golden images; run tools/golden/build_fs.sh")
    data = bytearray(image.read_bytes())
    fs = Xfs(BytesDevice(data))
    ino = lookup(fs, "/link-very-long")
    assert len(fs.readlink(ino)) == 1002  # in remote blocks, and read
    at = fs.superblock.inode_offset(ino)
    struct.pack_into(">Q", data, at + 0x38, 5000)  # di_size: more than XFS ever stores

    reads: list[int] = []

    class Counting(BytesDevice):
        def read_at(self, offset: int, length: int) -> bytes:
            reads.append(offset)
            return super().read_at(offset, length)

    damaged = Xfs(Counting(data))
    reads.clear()
    with pytest.raises(DiskReadError, match="implausible symlink"):
        damaged.readlink(ino)
    assert reads == [at]  # the inode, none of its blocks


def test_a_remote_xattr_value_larger_than_any_is_refused_before_it_is_read() -> None:
    read: list[int] = []

    def block(number: int) -> bytes:
        read.append(number)
        return bytes(4096)

    for v5 in (True, False):
        with pytest.raises(DiskReadError, match="implausible remote attr value"):
            xfs_attr.read_remote_value(block, 0, 0xFFFFFFFF, 7, v5)
    assert read == []
    assert xfs_attr.read_remote_value(block, 3, 5000, 7, v5=False) == bytes(5000)


def test_a_gpt_entry_size_that_is_damage_is_refused_before_the_array_is_read() -> None:
    sector = 512
    disk = bytearray(sector * 64)
    disk[0x1BE + 4] = 0xEE  # protective MBR
    disk[0x1FE:0x200] = b"\x55\xaa"

    def header(lba: int, entry_size: int) -> None:
        raw = bytearray(sector)
        raw[:8] = b"EFI PART"
        struct.pack_into("<II", raw, 0x08, 0x00010000, 92)
        struct.pack_into("<QQQQ", raw, 0x18, lba, 63 if lba == 1 else 1, 34, 30)
        struct.pack_into("<QIII", raw, 0x48, 2, 128, entry_size, 0)
        struct.pack_into("<I", raw, 0x10, zlib.crc32(bytes(raw[:92])))
        disk[lba * sector : (lba + 1) * sector] = raw

    header(1, 0x10000000)  # 128 entries of 256 MiB each
    header(63, 0x10000000)
    with pytest.raises(DiskReadError, match="bad GPT entry size"):
        read_partition_table(BytesDevice(disk))


def test_a_short_name_the_code_page_cannot_read_costs_a_character_not_the_directory() -> None:
    def entry(name: bytes) -> bytes:
        return name.ljust(11) + bytes([0x20]) + bytes(20)

    data = entry(b"\x81 BAD   TXT") + entry(b"GOOD    TXT")  # 0x81 0x20 is no cp932 character
    names = [e.name for e in parse_dir(data, [(0, 0)], False, "cp932")]
    assert names[1] == b"GOOD.TXT"
    assert names[0].endswith(b"BAD.TXT")
    assert volume_label(b"\x81 LABEL    " + bytes([0x08]) + bytes(20), "cp932") is not None


def test_the_high_half_of_an_ext4_size_counts_as_linux_counts_it() -> None:
    def inode(mode: int) -> bytes:
        raw = bytearray(256)
        struct.pack_into("<H", raw, 0x00, mode)
        struct.pack_into("<I", raw, 0x04, 4096)  # i_size_lo
        struct.pack_into("<I", raw, 0x6C, 5)  # i_size_high, or the old i_dir_acl
        return bytes(raw)

    big = 4096 | 5 << 32
    assert parse_inode(12, inode(0o100644), False).size == big
    assert parse_inode(12, inode(0o040755), False).size == 4096  # ext4_isize ignores it
    assert parse_inode(12, inode(0o120777), False).size == 4096
    assert parse_inode(12, inode(0o040755), False, large_dir=True).size == big


def test_telling_a_directory_ahead_is_guarded_like_listing_it() -> None:
    # will_list parses the same metadata as listdir: whatever a parser makes of damaged
    # bytes must come out as DiskReadError there too (which will_list() passes over).
    for reader in (Ext4, Xfs):
        for name in ("stat", "listdir", "open", "readlink", "xattrs", "will_list"):
            assert hasattr(getattr(reader, name), "__wrapped__"), (reader.__name__, name)


def _pv(name: str) -> bytearray:
    path = GOLDEN_DIR / name
    if not path.exists():
        pytest.skip("no golden images; run tools/golden/build_lvm.sh")
    return bytearray(path.read_bytes())


def test_a_pv_that_cannot_be_read_costs_its_own_volume_group_only() -> None:
    healthy, damaged = _pv("lvm-whole.img"), _pv("lvm-2mda.img")
    label = read_label(BytesDevice(damaged))
    assert label is not None
    for mda in label.metadata_areas:
        damaged[mda.offset + 0x30] ^= 0xFF  # every copy of its metadata
    devices = [BytesDevice(healthy), BytesDevice(damaged)]
    with pytest.raises(DiskReadError, match="CRC"):
        find_volume_groups(devices)  # not asked to go on: as before
    unreadable: list[str] = []
    (vg,) = find_volume_groups(devices, unreadable)
    assert len(unreadable) == 2
    assert all("CRC" in message for message in unreadable)
    volumes = scan({"disk0": devices[0], "disk1": devices[1]})
    readable = sorted(v.name for v in volumes if v.error is None)
    assert readable == sorted(f"lvm:{vg.name}/{n}" for n, lv in vg.lvs.items() if lv.visible)
    assert [v.name for v in volumes if v.error is not None] == ["lvm", "lvm"]


def test_a_volume_that_cannot_be_opened_is_a_warning() -> None:
    root_fs = MemFs()
    dev = BytesDevice(bytes(512))
    root = Volume("/dev/xvda", dev, fs_type="xfs", fs=root_fs)
    lost = Volume("lvm", dev, error="PV abc: metadata area at 4096: CRC mismatch")
    asked = Volume("/dev/xvdf", dev, error="bad superblock")
    system = System(
        volumes=[root, lost, asked], root=root, mounts=[Mount(b"/", root, None, root_fs)]
    )
    entry = FstabEntry(3, "/dev/xvdf", "/data", "xfs", "defaults")
    system.unresolved.append((entry, "/dev/xvdf: bad superblock"))
    m = analyze(Snapshot("test", SystemSource.from_system(system), system))
    (warning,) = [w for w in m["warnings"] if w["code"] == "unreadable-volume"]
    assert warning["volume"] == "lvm"
    assert warning["message"].startswith("PV abc: metadata area at 4096: CRC mismatch")
    # The one an fstab line asked for is said there, once.
    assert [w["spec"] for w in m["warnings"] if w["code"] == "unresolved-mount"] == ["/dev/xvdf"]


# --- what an outside review found (2026-11-15): names and paths that lead elsewhere ----


def _entry_named(fs: MemFs, directory: str, name: bytes, target: str) -> None:
    """Give `directory` an entry of this (damaged) name for the inode at `target`."""
    fs._nodes[fs.ino(directory)]["children"][name] = fs.ino(target)


def test_names_that_are_none_and_paths_that_lead_elsewhere() -> None:
    assert all(valid_name(n) for n in (b"a", b"...", b" ", b"\xff"))
    assert not any(valid_name(n) for n in (b"", b".", b"..", b"a/b", b"/", b"a\0b"))
    assert all(clean_path(p) for p in ("/", "/etc", "/etc/a..b", "/a/...", "/a/ b"))
    bad = ("", "etc", "//etc", "/etc/", "/a/../b", "/a/./b", "/a//b", "/..", "/a/..")
    assert not any(clean_path(p) for p in bad)


def test_a_deleted_directory_is_archived_by_its_real_names_only(tmp_path: Path) -> None:
    # Followed, "/opt/gone/.." is /opt and "/opt/gone/../../etc/shadow" is /etc/shadow
    # under a name the list of sensitive paths does not know: the whole baseline would
    # be archived, its secrets with it, in members that climb out of where they unpack.
    before = MemFs()
    before.add_file("/opt/gone/kept.txt", b"kept\n")
    before.add_file("/opt/other.txt", b"other\n")
    before.add_file("/etc/shadow", b"root:$6$secret\n")
    _entry_named(before, "/opt/gone", b"..", "/opt")
    _entry_named(before, "/opt/gone", b"../../etc/shadow", "/etc/shadow")
    _entry_named(before, "/opt/gone", b"", "/etc/shadow")
    manifest = {
        "hand_placed": [],
        "modified_package_files": [],
        "deleted": [{"path": "/opt/gone", "type": "dir"}],
    }
    archives = write_outputs(manifest, _snap(MemFs()).source, _snap(before).source, tmp_path)
    with tarfile.open(tmp_path / "before.tar.gz") as tar:
        assert sorted(tar.getnames()) == ["opt/gone", "opt/gone/kept.txt"]
    reasons = {s["path"]: s["reason"] for s in archives["skipped"]}
    assert reasons == {
        "/opt/gone/": "invalid-path",
        "/opt/gone/..": "invalid-path",
        "/opt/gone/../../etc/shadow": "invalid-path",
    }


def test_a_path_that_is_another_under_a_false_name_is_not_archived(tmp_path: Path) -> None:
    fs = MemFs()
    fs.add_file("/etc/shadow", b"root:$6$secret\n")
    fs.add_file("/opt/pkg/tool", b"tool\n")
    false_name = "/opt/pkg/../../etc/shadow"
    manifest = {
        "hand_placed": [{"path": false_name, "status": "modified"}],
        "modified_package_files": [
            {"path": false_name, "problems": ["content"], "since_baseline": True}
        ],
        "deleted": [],
    }
    src = _snap(fs).source
    archives = write_outputs(manifest, src, src, tmp_path)
    assert archives["after"]["entries"] == 0
    assert archives["before"]["entries"] == 0
    assert archives["patches"]["files"] == 0
    assert {s["reason"] for s in archives["skipped"]} == {"invalid-path"}


def test_listing_a_directory_by_path_gives_names_only() -> None:
    fs = _server()
    _entry_named(fs, "/opt/app", b"..", "/etc")
    _entry_named(fs, "/opt/app", b"x/y", "/etc")
    assert SystemSource.from_fs(fs).listdir("/opt/app") == ["app.conf"]


def test_package_file_lists_take_plain_absolute_paths_only() -> None:
    status = b"Package: x\nStatus: install ok installed\nVersion: 1\nArchitecture: all\n\n"
    listing = b"/.\n/usr\n/usr/bin/x\n/opt/pkg/../../etc/shadow\n//etc/passwd\nusr/rel\n/a/./b\n"
    (pkg,) = read_dpkg(status, {"x.list": listing}.get, lambda _: None)
    assert [f.path for f in pkg.files] == ["/.", "/usr", "/usr/bin/x"]
    header = {
        rpmheader.BASENAMES: ["x", "shadow", "y"],
        rpmheader.DIRNAMES: ["/usr/bin/", "/opt/pkg/../../etc/", "/usr//lib/"],
        rpmheader.DIRINDEXES: [0, 1, 2],
    }
    assert [f.path for f in rpmheader._files(header)] == ["/usr/bin/x"]


def test_a_record_cannot_claim_what_lies_outside_its_prefix() -> None:
    # A RECORD is a file anyone can write: listed there, a path was a file of the
    # package and no longer one of the hand-placed.
    fs = _server()
    site = "/usr/lib/python3.9/site-packages"
    fs.add_file(f"{site}/evil-1.0.dist-info/METADATA", b"Name: evil\nVersion: 1.0\n")
    rows = (
        "evil/__init__.py",
        "../../../bin/evil",
        "../../../../root/backdoor.sh",
        "/etc/cron.d/x",
    )
    fs.add_file(f"{site}/evil-1.0.dist-info/RECORD", "".join(f"{r},,\n" for r in rows).encode())
    for row in rows:
        fs.add_file(posixpath.normpath(posixpath.join(site, row)), b"#!/bin/sh\n")
    m = analyze(_snap(fs))
    hand = {h["path"] for h in m["hand_placed"]}
    assert {"/root/backdoor.sh", "/etc/cron.d/x"} <= hand
    assert not {f"{site}/evil/__init__.py", "/usr/bin/evil"} & hand  # the package's own


def test_alternatives_take_only_links_out_of_the_hand_placed() -> None:
    fs = _server()
    fs.add_file("/var/lib/alternatives/editor", b"auto\n/usr/bin/editor\n\n/usr/bin/vim\n50\n")
    fs.add_file("/var/lib/alternatives/odd", b"auto\n/opt/app/app.conf\n\n/x\n50\n")
    fs.add_link("/usr/bin/editor", "/etc/alternatives/editor")
    fs.add_link("/etc/alternatives/editor", "/usr/bin/vim")
    m = analyze(_snap(fs))
    hand = {h["path"] for h in m["hand_placed"]}
    assert "/opt/app/app.conf" in hand  # a file: no alternatives link, whatever the state says
    assert not {"/usr/bin/editor", "/etc/alternatives/editor"} & hand


def test_bolt_reads_from_the_second_meta_page_when_the_first_is_damaged() -> None:
    data = bytearray(gzip.decompress((DATA_DIR / "containerd-meta.db.gz").read_bytes()))
    whole = Bolt(bytes(data))
    data[16 + 4] ^= 0xFF  # page 0's meta: its version, so its checksum fails too
    damaged = Bolt(bytes(data))
    assert damaged._page_size == whole._page_size
    assert sorted(damaged.bucket(b"v1") or {}) == sorted(whole.bucket(b"v1") or {})
    data[whole._page_size + 16 + 4] ^= 0xFF  # and page 1's
    with pytest.raises(DiskReadError, match="no valid meta page"):
        Bolt(bytes(data))


def test_an_indirect_block_reached_twice_ends_the_map() -> None:
    # Every pointer of the triple indirect block naming that same block: gone through
    # level by level, a thousand million steps for one file.
    bs = 4096
    reads: list[int] = []

    def read_block(block: int) -> bytes:
        reads.append(block)
        return struct.pack("<I", 100) * (bs // 4)

    i_block = struct.pack("<15I", *([0] * 14), 100)
    with pytest.raises(DiskReadError, match="reached twice"):
        indirect_runs(i_block, read_block, bs, 1 << 40, 12)
    assert reads == [100]


def test_the_blocks_of_a_directory_are_found_by_its_runs() -> None:
    bs = 4096
    far = 5_000_000_000  # a hole of 20 TiB before it: not stepped through
    runs = [Run(0, 10, 2), Run(1_000_000, 20, 3, unwritten=True), Run(far, 30, 2)]
    content = MappedContent(BytesDevice(b""), bs, runs, (far + 4) * bs)
    written = list(content.offsets(bs, written=True))
    assert written == [0, bs, far * bs, (far + 1) * bs]
    assert [o for o in written if not content.is_written(o)] == []
    mapped = list(content.offsets(4 * bs))
    assert mapped == [0, 1_000_000 * bs, far * bs]
    assert all(content.is_mapped(o) for o in mapped)
    short = MappedContent(BytesDevice(b""), bs, [Run(0, 10, 4)], 3 * bs + 5)
    assert list(short.offsets(bs)) == [0, bs, 2 * bs]  # whole blocks below the size


def test_an_xfs_superblock_with_sizes_no_filesystem_has_is_refused() -> None:
    image = GOLDEN_DIR / "xfs-al2023.img"
    if not image.exists():
        pytest.skip("no golden images; run tools/golden/build_fs.sh")
    with image.open("rb") as f:
        raw = bytearray(f.read(512))
    assert parse_xfs_superblock(bytes(raw)).dir_block_size == 4096
    damaged = bytearray(raw)
    damaged[0xC0] = 23  # sb_dirblklog: a directory block of 32 GiB, read whole
    with pytest.raises(DiskReadError, match="directory block size"):
        parse_xfs_superblock(bytes(damaged))


def test_a_volume_whose_root_cannot_be_read_is_said_and_passed_over() -> None:
    class NoRoot(MemFs):
        def stat(self, ino: int) -> Stat:
            if ino == self.root_ino:
                raise DiskReadError("inode 1: bad magic")
            return super().stat(ino)

    errors: list[tuple[bytes, str]] = []
    assert list(walk(NoRoot(), lambda path, err: errors.append((path, str(err))))) == []
    assert errors == [(b"/", "inode 1: bad magic")]
    with pytest.raises(DiskReadError):
        list(walk(NoRoot()))  # nobody to tell: as before


def test_small_things_a_damaged_disk_may_say() -> None:
    # codepage= that is no name at all
    assert _codepage_option({"codepage": "4\x0037"}) == "cp437"
    assert _codepage_option({"codepage": "\udc80"}) == "cp437"
    assert _codepage_option({"codepage": "932"}) == "cp932"
    # a slice is not told of what lies beside it on its parent
    part = SliceDevice(BytesDevice(bytes(4096)), 1024, 1024)
    with pytest.raises(DiskReadError):
        part.will_read(1024, 512)
    will_read(part, 1024, 512)  # the hint itself never fails
    # an LVM segment of no extents, or at a negative one
    for start, count in ((0, 0), (-1, 4), (0, -4)):
        segment = {"type": "striped", "start_extent": start, "extent_count": count}
        with pytest.raises(DiskReadError, match="bad segment extents"):
            _parse_segment("lv", segment, 4096)
