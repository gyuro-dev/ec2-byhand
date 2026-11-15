"""ext4 metadata_csum checks (crc32c, as fs/ext4 computes them).

All use the kernel's raw crc32c chaining (no inversion). The filesystem
seed is s_checksum_seed with the csum_seed feature, else crc32c(~0, uuid);
the superblock itself is summed from ~0. Per-inode seed:
crc32c(crc32c(fs_seed, le32 inode number), le32 i_generation).

  superblock        s_checksum @0x3FC over bytes 0..0x3FC
  group descriptor  bg_checksum @0x1E (u16): crc32c(fs_seed, le32 group,
                    descriptor with the field zeroed) & 0xFFFF
  inode             l_i_checksum_lo @0x7C (u16) and, if it fits,
                    i_checksum_hi @0x82 (u16): crc32c(inode seed, inode
                    with both fields zeroed)
  extent block      tail after eh_max entries: crc32c(inode seed, block up
                    to the tail)
  directory block   12-byte tail dirent (inode 0, rec_len 12, type 0xDE)
                    ending in the checksum: crc32c(inode seed, block up to
                    the tail). htree index blocks (the root, block 0 of an
                    indexed directory, may still end in a stale leaf tail)
                    use a dx_tail instead and are not checked.
  xattr block       h_checksum @0x10: crc32c(fs_seed, le64 block number,
                    block with the field zeroed)

ext4 metadata_csum の検証（fs/ext4 と同じ crc32c の計算）。シードは csum_seed 機能があれば
s_checksum_seed、なければ crc32c(~0, uuid)。対象ごとの場所と計算は上の表のとおり。
"""

from __future__ import annotations

import struct

from diskread.crc32c import crc32c_raw
from diskread.errors import DiskReadError

INODE_CSUM_LO = 0x7C
INODE_CSUM_HI = 0x82
GOOD_OLD_INODE_SIZE = 128
ZERO2, ZERO4 = b"\0\0", b"\0\0\0\0"


def _fail(what: str) -> None:
    """Raise DiskReadError for a mismatch at `what`."""
    raise DiskReadError(f"checksum mismatch: {what}")


def fs_seed(raw_sb: bytes, has_csum_seed: bool) -> int:
    """The filesystem checksum seed: s_checksum_seed, or crc32c(~0, uuid).

    ファイルシステムのチェックサムシード: s_checksum_seed、なければ crc32c(~0, uuid)。
    """
    if has_csum_seed:
        return int(struct.unpack_from("<I", raw_sb, 0x270)[0])
    return crc32c_raw(0xFFFFFFFF, raw_sb[0x68:0x78])


def check_superblock(raw_sb: bytes) -> None:
    """Verify the superblock's own checksum.

    スーパーブロック自身のチェックサムを検証する。
    """
    (stored,) = struct.unpack_from("<I", raw_sb, 0x3FC)
    if crc32c_raw(0xFFFFFFFF, raw_sb[:0x3FC]) != stored:
        _fail("ext4 superblock")


def check_group_desc(seed: int, group: int, desc: bytes) -> None:
    """Verify one group descriptor's checksum.

    グループディスクリプタ 1 つのチェックサムを検証する。
    """
    (stored,) = struct.unpack_from("<H", desc, 0x1E)
    c = crc32c_raw(seed, struct.pack("<I", group))
    c = crc32c_raw(c, desc[:0x1E] + ZERO2 + desc[0x20:])
    if c & 0xFFFF != stored:
        _fail(f"ext4 group descriptor {group}")


def inode_seed(seed: int, ino: int, raw: bytes) -> int:
    """The per-inode seed: the fs seed chained with the inode number and generation.

    inode ごとのシード: FS のシードに inode 番号と世代を連ねたもの。
    """
    (gen,) = struct.unpack_from("<I", raw, 0x64)
    return crc32c_raw(crc32c_raw(seed, struct.pack("<I", ino)), struct.pack("<I", gen))


def check_inode(seed: int, ino: int, raw: bytes, extra_isize: int) -> None:
    """Verify an inode's checksum (the high half only where i_extra_isize covers it).

    inode のチェックサムを検証する（上位半分は i_extra_isize が覆う場合だけ）。
    """
    has_hi = (
        len(raw) > GOOD_OLD_INODE_SIZE and GOOD_OLD_INODE_SIZE + extra_isize >= INODE_CSUM_HI + 2
    )
    data = bytearray(raw)
    data[INODE_CSUM_LO : INODE_CSUM_LO + 2] = ZERO2
    if has_hi:
        data[INODE_CSUM_HI : INODE_CSUM_HI + 2] = ZERO2
    c = crc32c_raw(inode_seed(seed, ino, raw), bytes(data))
    (lo,) = struct.unpack_from("<H", raw, INODE_CSUM_LO)
    if has_hi:
        (hi,) = struct.unpack_from("<H", raw, INODE_CSUM_HI)
        ok = c == (hi << 16 | lo)
    else:
        ok = c & 0xFFFF == lo
    if not ok:
        _fail(f"ext4 inode {ino}")


def check_extent_block(iseed: int, block: bytes, ino: int) -> None:
    """Verify the tail checksum of an extent tree block.

    エクステントツリーブロック末尾のチェックサムを検証する。
    """
    (max_entries,) = struct.unpack_from("<H", block, 4)
    tail = 12 + 12 * max_entries
    if tail + 4 > len(block):
        _fail(f"ext4 extent block of inode {ino} (no room for the tail)")
    (stored,) = struct.unpack_from("<I", block, tail)
    if crc32c_raw(iseed, block[:tail]) != stored:
        _fail(f"ext4 extent block of inode {ino}")


def check_dir_block(iseed: int, block: bytes, ino: int) -> None:
    """Checks blocks that end in a checksum dirent; others (htree index) pass.

    チェックサム dirent で終わるブロックを検証する。それ以外（htree インデックス）は素通し。
    """
    tail = len(block) - 12
    inode, rec_len, name_len, ftype = struct.unpack_from("<IHBB", block, tail)
    if (inode, rec_len, name_len, ftype) != (0, 12, 0, 0xDE):
        return
    (stored,) = struct.unpack_from("<I", block, tail + 8)
    if crc32c_raw(iseed, block[:tail]) != stored:
        _fail(f"ext4 directory block of inode {ino}")


def check_xattr_block(seed: int, block_nr: int, block: bytes) -> None:
    """Verify an xattr block's header checksum.

    xattr ブロックのヘッダのチェックサムを検証する。
    """
    (stored,) = struct.unpack_from("<I", block, 0x10)
    c = crc32c_raw(seed, struct.pack("<Q", block_nr))
    c = crc32c_raw(c, block[:0x10] + ZERO4 + block[0x14:])
    if c != stored:
        _fail(f"ext4 xattr block {block_nr}")
