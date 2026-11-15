from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import GOLDEN_DIR, golden_cases, require_golden
from fs_golden import differences

from diskread import BytesDevice, DiskReadError, FileDevice
from diskread.fs import lookup
from diskread.fs.ext4 import Ext4

CASES = golden_cases(("ext4-",))


@pytest.mark.parametrize("verify", [False, True], ids=["plain", "checksums"])
@pytest.mark.parametrize("case", CASES or [None], ids=(lambda p: p.stem) if CASES else None)
def test_matches_kernel(case: Path | None, verify: bool) -> None:
    require_golden(CASES, "build_fs.sh")
    assert case is not None
    expected = json.loads(case.read_text(encoding="utf-8"))
    with FileDevice(GOLDEN_DIR / expected["image"]) as dev:
        fs = Ext4(dev, verify_checksums=verify)
        assert not fs.superblock.needs_recovery
        diffs = differences(fs, expected["files"])
    assert not diffs, f"{expected['mkfs']}\n" + "\n".join(diffs)


def test_lookup_and_partial_reads() -> None:
    path = GOLDEN_DIR / "ext4-default.img"
    if not path.exists():
        pytest.skip("no golden images; run tools/golden/build_fs.sh")
    with FileDevice(path) as dev:
        fs = Ext4(dev)
        ino = lookup(fs, "/etc/app/app.conf")
        assert fs.open(ino).read_at(0, 6) == b"listen"
        sparse = fs.open(lookup(fs, "/sparse.bin"))
        assert sparse.read_at(0, 16) == bytes(16)  # leading hole
        assert sparse.read_at((1 << 20) - 2, 4)[:2] == b"\0\0"
        assert sparse.read_at(sparse.size - 8, 8) == bytes(8)  # trailing hole
        with pytest.raises(FileNotFoundError):
            lookup(fs, "/etc/nope")


def test_rejects_non_ext4() -> None:
    with pytest.raises(DiskReadError, match="magic"):
        Ext4(BytesDevice(bytes(1 << 16)))


def _default_image() -> bytearray:
    path = GOLDEN_DIR / "ext4-default.img"
    if not path.exists():
        pytest.skip("no golden images; run tools/golden/build_fs.sh")
    return bytearray(path.read_bytes())


def _flip(img: bytearray, offset: int) -> Ext4:
    img[offset] ^= 0x01
    return Ext4(BytesDevice(bytes(img)), verify_checksums=True)


def test_checksums_catch_a_changed_inode() -> None:
    img = _default_image()
    fs = Ext4(BytesDevice(bytes(img)))
    ino = lookup(fs, "/etc/app/app.conf")
    sb = fs.superblock
    group, index = divmod(ino - 1, sb.inodes_per_group)
    at = fs._groups.inode_table(group) * sb.block_size + index * sb.inode_size
    bad = _flip(img, at + 0x10)  # i_mtime
    with pytest.raises(DiskReadError, match="checksum mismatch: ext4 inode"):
        bad.stat(ino)
    # Without verification the damage goes unnoticed.
    Ext4(BytesDevice(bytes(img))).stat(ino)


def test_checksums_catch_a_changed_directory_block() -> None:
    img = _default_image()
    fs = Ext4(BytesDevice(bytes(img)))
    app = fs._read_inode(lookup(fs, "/etc/app"))
    block = fs._content(app)._runs[0].physical
    bad = _flip(img, block * fs.superblock.block_size + 20)  # inside a name
    with pytest.raises(DiskReadError, match="checksum mismatch: ext4 directory block"):
        bad.listdir(app.ino)
    Ext4(BytesDevice(bytes(img))).listdir(app.ino)


def test_checksums_catch_a_changed_superblock() -> None:
    img = _default_image()
    with pytest.raises(DiskReadError, match="checksum mismatch: ext4 superblock"):
        _flip(img, 1024 + 0x108)  # s_mkfs_time: harmless to the parser
