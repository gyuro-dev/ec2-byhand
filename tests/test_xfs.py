from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from conftest import GOLDEN_DIR, golden_cases, require_golden
from fs_golden import differences
from sparse_image import open_image

from diskread import BytesDevice, DiskReadError, FileDevice
from diskread.fs import lookup, walk
from diskread.fs.xfs import Xfs, csum
from diskread.fs.xfs import dir as xdir

CASES = golden_cases(("xfs-",))


@pytest.mark.parametrize("verify", [False, True], ids=["plain", "checksums"])
@pytest.mark.parametrize("case", CASES or [None], ids=(lambda p: p.stem) if CASES else None)
def test_matches_kernel(case: Path | None, verify: bool) -> None:
    require_golden(CASES, "build_fs.sh")
    assert case is not None
    expected = json.loads(case.read_text(encoding="utf-8"))
    with open_image(GOLDEN_DIR / expected["image"]) as dev:
        fs = Xfs(dev, verify_checksums=verify)
        assert not fs.superblock.needs_repair
        assert fs.log_state == "clean"
        diffs = differences(fs, expected["files"])
    assert not diffs, f"{expected['mkfs']}\n" + "\n".join(diffs)


def test_lookup_and_partial_reads() -> None:
    path = GOLDEN_DIR / "xfs-al2023.img"
    if not path.exists():
        pytest.skip("no golden images; run tools/golden/build_fs.sh")
    with FileDevice(path) as dev:
        fs = Xfs(dev)
        ino = lookup(fs, "/etc/app/app.conf")
        assert fs.open(ino).read_at(0, 6) == b"listen"
        prealloc = fs.open(lookup(fs, "/prealloc.bin"))
        assert prealloc.read_at(0, 16) == bytes(16)  # unwritten, poisoned on disk
        assert prealloc.read_at(4096, 4) == b"xxxx"


@pytest.mark.parametrize("image", ["xfs-al2.img", "xfs-al2023.img"])
def test_a_large_directory_ends_at_its_data_blocks(image: str) -> None:
    # A directory of two blocks or more keeps its leaf blocks at 32 GiB. listdir
    # stepped through the whole 32 GiB below them, 1.3 s a directory (seen on AL2).
    path = GOLDEN_DIR / image
    if not path.exists():
        pytest.skip("no golden images; run tools/golden/build_fs.sh")
    with FileDevice(path) as dev:
        fs = Xfs(dev)
        large = [
            ino
            for _, ino, _ in walk(fs)
            if fs.inode(ino).data_fork.format != 1  # not shortform
            and fs.stat(ino).type.name == "DIR"
        ]
        assert large, "the image should have a directory of two blocks or more"
        for ino in large:
            content = fs._mapped_fork(fs.inode(ino).data_fork, ino, xdir.LEAF_OFFSET)
            assert content.size <= fs.stat(ino).size  # the data blocks, not 32 GiB


def test_real_64bit_inode_numbers() -> None:
    # xfs-ino64 (a packed 4 TiB image) is compared with the kernel by
    # test_matches_kernel; make sure it really exercises 8-byte numbers.
    path = GOLDEN_DIR / "xfs-ino64.img.sparse.gz"
    if not path.exists():
        pytest.skip("no golden image; run tools/golden/build_fs.sh tests/golden/out xfs-ino64")
    with open_image(path) as dev:
        fs = Xfs(dev)
        inos = [ino for _, ino, _ in walk(fs)]
        assert sum(ino >= 1 << 32 for ino in inos) > 1000
        i8 = [
            ino
            for ino in inos
            if fs.inode(ino).data_fork.format == 1 and fs.inode(ino).data_fork.data[1] > 0
        ]
        assert len(i8) >= 10  # shortform directories with i8count > 0


def test_shortform_dir_with_64bit_inode_numbers() -> None:
    # i8count > 0 switches every inode number to 8 bytes.
    big = (5 << 32) | 0x80
    data = bytes([2, 1]) + (128).to_bytes(8, "big")
    for name, ino in ((b"a", 129), (b"bee", big)):
        data += bytes([len(name)]) + b"\0\x60" + name + b"\x01" + ino.to_bytes(8, "big")
    assert xdir.parse_shortform(data, has_ftype=True, ino=1) == [(b"a", 129), (b"bee", big)]


def test_shortform_dir_overflow_is_rejected() -> None:
    data = bytes([1, 0]) + (128).to_bytes(4, "big") + bytes([200]) + b"\0\x60" + b"x"
    with pytest.raises(DiskReadError):
        xdir.parse_shortform(data, has_ftype=True, ino=1)


def test_rejects_non_xfs() -> None:
    with pytest.raises(DiskReadError, match="magic"):
        Xfs(BytesDevice(bytes(1 << 16)))


def _al2023_image() -> bytearray:
    path = GOLDEN_DIR / "xfs-al2023.img"
    if not path.exists():
        pytest.skip("no golden images; run tools/golden/build_fs.sh")
    return bytearray(path.read_bytes())


def test_checksums_cover_every_metadata_kind(monkeypatch: pytest.MonkeyPatch) -> None:
    # Guards against hooks that never run: the golden tree has block / leaf
    # / node directories, xattr leaves and remote values, remote symlinks
    # and B+tree-mapped files, so each kind of CRC must actually be checked.
    seen: set[str] = set()
    real = csum.check

    def spy(buf: bytes, offset: int, what: str) -> None:
        seen.add(re.sub(r" (of inode )?\d+$", "", what))
        real(buf, offset, what)

    monkeypatch.setattr(csum, "check", spy)
    fs = Xfs(BytesDevice(bytes(_al2023_image())), verify_checksums=True)
    for _path, ino, st in walk(fs):
        if st.type.name == "LNK":
            fs.readlink(ino)
        fs.xattrs(ino)
        if st.type.name == "REG":
            fs.open(ino)
    assert seen >= {
        "superblock",
        "inode",
        "directory block",
        "xattr block",
        "remote symlink block",
        "bmap btree block",
    }, seen


def _flip(img: bytearray, offset: int) -> Xfs:
    img[offset] ^= 0x01
    return Xfs(BytesDevice(bytes(img)), verify_checksums=True)


def test_checksums_catch_a_changed_inode() -> None:
    img = _al2023_image()
    fs = Xfs(BytesDevice(bytes(img)))
    ino = lookup(fs, "/etc/app/app.conf")
    bad = _flip(img, fs.superblock.inode_offset(ino) + 0x30)  # di_mtime
    with pytest.raises(DiskReadError, match="checksum mismatch: XFS inode"):
        bad.stat(ino)
    Xfs(BytesDevice(bytes(img))).stat(ino)  # unnoticed without verification


def test_checksums_catch_a_changed_directory_block() -> None:
    img = _al2023_image()
    fs = Xfs(BytesDevice(bytes(img)))
    big = next(
        ino
        for _, ino, st in walk(fs)
        if st.type.name == "DIR" and fs.inode(ino).data_fork.format != 1
    )
    run = fs._runs(fs.inode(big).data_fork, big)[0]
    bad = _flip(img, run.physical * fs.superblock.block_size + 0x50)  # inside an entry name
    with pytest.raises(DiskReadError, match="checksum mismatch: XFS directory block"):
        bad.listdir(big)


def test_checksums_catch_a_changed_superblock() -> None:
    img = _al2023_image()
    with pytest.raises(DiskReadError, match="checksum mismatch: XFS superblock"):
        _flip(img, 0x20 + 3)  # sb_uuid


def test_crc32c_check_value() -> None:
    from diskread.crc32c import crc32c, crc32c_raw

    assert crc32c(b"123456789") == 0xE3069283  # the standard CRC-32C check value
    assert crc32c_raw(0xFFFFFFFF, b"123456789") ^ 0xFFFFFFFF == 0xE3069283
