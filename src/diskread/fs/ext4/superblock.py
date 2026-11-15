"""ext2/3/4 superblock and group descriptors.

Reference: "ext4 Data Structures and Algorithms" (kernel.org documentation,
Documentation/filesystems/ext4/). All fields are little-endian.

Superblock (1024 bytes at byte offset 1024), fields used here:
  0x00  s_inodes_count            0x04  s_blocks_count_lo
  0x14  s_first_data_block        0x18  s_log_block_size
  0x1C  s_log_cluster_size (bigalloc)
  0x20  s_blocks_per_group        0x28  s_inodes_per_group
  0x38  s_magic (0xEF53)          0x3A  s_state
  0x4C  s_rev_level               0x54  s_first_ino
  0x58  s_inode_size (u16)        0x5C  s_feature_compat
  0x60  s_feature_incompat        0x64  s_feature_ro_compat
  0x68  s_uuid[16]                0x78  s_volume_name[16]
  0xFE  s_desc_size (u16)         0x104 s_first_meta_bg
  0x150 s_blocks_count_hi         0x24C s_backup_bgs[2] (sparse_super2)

Group descriptor (32 bytes, or s_desc_size with 64bit):
  0x08  bg_inode_table_lo         0x28  bg_inode_table_hi

ext2/3/4 のスーパーブロックとグループディスクリプタ。フィールドは上の表のとおり（すべてリトル
エンディアン）。
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass
from functools import lru_cache

from diskread.blockdev import BlockDevice
from diskread.errors import DiskReadError, UnsupportedError

SUPERBLOCK_OFFSET = 1024
MAGIC = 0xEF53

# s_feature_compat
COMPAT_SPARSE_SUPER2 = 0x200
# s_feature_incompat
INCOMPAT_COMPRESSION = 0x1
INCOMPAT_FILETYPE = 0x2
INCOMPAT_RECOVER = 0x4
INCOMPAT_JOURNAL_DEV = 0x8
INCOMPAT_META_BG = 0x10
INCOMPAT_EXTENTS = 0x40
INCOMPAT_64BIT = 0x80
INCOMPAT_MMP = 0x100
INCOMPAT_FLEX_BG = 0x200
INCOMPAT_EA_INODE = 0x400
INCOMPAT_DIRDATA = 0x1000
INCOMPAT_CSUM_SEED = 0x2000
INCOMPAT_LARGEDIR = 0x4000
INCOMPAT_INLINE_DATA = 0x8000
INCOMPAT_ENCRYPT = 0x10000
INCOMPAT_CASEFOLD = 0x20000
# s_feature_ro_compat
RO_COMPAT_SPARSE_SUPER = 0x1
RO_COMPAT_HUGE_FILE = 0x8
RO_COMPAT_BIGALLOC = 0x200
RO_COMPAT_METADATA_CSUM = 0x400

# Features that change how data must be read and that we do not implement.
_UNSUPPORTED_INCOMPAT = {
    INCOMPAT_COMPRESSION: "compression",
    INCOMPAT_JOURNAL_DEV: "external journal device",
    INCOMPAT_DIRDATA: "dirdata",
}
_KNOWN_INCOMPAT = (
    INCOMPAT_FILETYPE
    | INCOMPAT_RECOVER
    | INCOMPAT_META_BG
    | INCOMPAT_EXTENTS
    | INCOMPAT_64BIT
    | INCOMPAT_MMP
    | INCOMPAT_FLEX_BG
    | INCOMPAT_EA_INODE
    | INCOMPAT_CSUM_SEED
    | INCOMPAT_LARGEDIR
    | INCOMPAT_INLINE_DATA
    | INCOMPAT_ENCRYPT
    | INCOMPAT_CASEFOLD
)


@dataclass(frozen=True)
class Superblock:
    """The superblock fields this reader uses.

    このリーダーが使うスーパーブロックのフィールド。
    """

    block_size: int
    cluster_size: int  # allocation unit; equals block_size without bigalloc
    blocks_count: int
    inodes_count: int
    first_data_block: int
    blocks_per_group: int
    inodes_per_group: int
    inode_size: int
    first_ino: int
    desc_size: int
    first_meta_bg: int
    backup_bgs: tuple[int, int]
    compat: int
    incompat: int
    ro_compat: int
    uuid: str
    volume_name: str
    state: int

    @property
    def group_count(self) -> int:
        """Number of block groups.

        ブロックグループ数。
        """
        n = self.blocks_count - self.first_data_block
        return (n + self.blocks_per_group - 1) // self.blocks_per_group

    @property
    def needs_recovery(self) -> bool:
        """The journal holds changes not yet written to their final place.

        True for a snapshot of a mounted filesystem. diskread does not replay
        the journal, so the most recent changes may be missing.

        ジャーナルに、最終位置へまだ書かれていない変更が残っている。マウント中に取ったスナップ
        ショットで True になる。diskread はジャーナルを再生しないので、直近の変更は欠けうる。
        """
        return bool(self.incompat & INCOMPAT_RECOVER)

    def has_incompat(self, flag: int) -> bool:
        """Whether s_feature_incompat has `flag` set.

        s_feature_incompat に `flag` が立っているか。
        """
        return bool(self.incompat & flag)


def parse_superblock(raw: bytes) -> Superblock:
    """Parse and sanity-check the 1024-byte superblock; unsupported features raise.

    1024 バイトのスーパーブロックを解析・検査する。非対応機能は例外にする。
    """
    (magic,) = struct.unpack_from("<H", raw, 0x38)
    if magic != MAGIC:
        raise DiskReadError("not an ext2/3/4 filesystem (bad superblock magic)")
    inodes_count, blocks_lo = struct.unpack_from("<II", raw, 0x00)
    first_data_block, log_block_size, log_cluster_size = struct.unpack_from("<III", raw, 0x14)
    (blocks_per_group,) = struct.unpack_from("<I", raw, 0x20)
    (inodes_per_group,) = struct.unpack_from("<I", raw, 0x28)
    (state,) = struct.unpack_from("<H", raw, 0x3A)
    (rev_level,) = struct.unpack_from("<I", raw, 0x4C)
    compat, incompat, ro_compat = struct.unpack_from("<III", raw, 0x5C)

    if log_block_size > 6:
        raise DiskReadError(f"implausible block size 2^{10 + log_block_size}")
    block_size = 1024 << log_block_size
    cluster_size = block_size
    if ro_compat & RO_COMPAT_BIGALLOC:
        if not log_block_size <= log_cluster_size <= log_block_size + 16:
            raise DiskReadError(f"bad bigalloc cluster size 2^{10 + log_cluster_size}")
        cluster_size = 1024 << log_cluster_size

    if rev_level == 0:
        first_ino, inode_size = 11, 128
    else:
        (first_ino,) = struct.unpack_from("<I", raw, 0x54)
        (inode_size,) = struct.unpack_from("<H", raw, 0x58)
    if inode_size < 128 or inode_size > block_size or inode_size & (inode_size - 1):
        raise DiskReadError(f"bad inode size {inode_size}")

    for flag, what in _UNSUPPORTED_INCOMPAT.items():
        if incompat & flag:
            raise UnsupportedError(f"ext4 feature not supported: {what}")
    unknown = incompat & ~(_KNOWN_INCOMPAT | sum(_UNSUPPORTED_INCOMPAT))
    if unknown:
        raise UnsupportedError(f"unknown ext4 incompat features {unknown:#x}")

    blocks_count = blocks_lo
    desc_size = 32
    if incompat & INCOMPAT_64BIT:
        (blocks_hi,) = struct.unpack_from("<I", raw, 0x150)
        blocks_count |= blocks_hi << 32
        (desc_size,) = struct.unpack_from("<H", raw, 0xFE)
        # The kernel's bounds (EXT4_MIN_DESC_SIZE_64BIT, EXT4_MAX_DESC_SIZE). A descriptor
        # larger than a block would also leave none per block to divide by.
        if not 64 <= desc_size <= 1024 or desc_size & (desc_size - 1):
            raise DiskReadError(f"bad group descriptor size {desc_size}")
    if blocks_per_group == 0 or inodes_per_group == 0:
        raise DiskReadError("zero blocks or inodes per group")

    (first_meta_bg,) = struct.unpack_from("<I", raw, 0x104)
    backup_bgs = struct.unpack_from("<II", raw, 0x24C)
    return Superblock(
        block_size=block_size,
        cluster_size=cluster_size,
        blocks_count=blocks_count,
        inodes_count=inodes_count,
        first_data_block=first_data_block,
        blocks_per_group=blocks_per_group,
        inodes_per_group=inodes_per_group,
        inode_size=inode_size,
        first_ino=first_ino,
        desc_size=desc_size,
        first_meta_bg=first_meta_bg,
        backup_bgs=backup_bgs,
        compat=compat,
        incompat=incompat,
        ro_compat=ro_compat,
        uuid=str(uuid.UUID(bytes=raw[0x68:0x78])),
        volume_name=raw[0x78:0x88].split(b"\0", 1)[0].decode("utf-8", "replace"),
        state=state,
    )


def _is_power_of(n: int, base: int) -> bool:
    """Whether n is b**k for some k >= 0."""
    while n > 1 and n % base == 0:
        n //= base
    return n == 1


class GroupDescriptors:
    """Locates each block group's inode table, reading descriptors lazily.

    各ブロックグループの inode テーブルの位置。ディスクリプタは遅延読み込み。
    """

    def __init__(self, dev: BlockDevice, sb: Superblock, csum_seed: int | None = None) -> None:
        self._dev = dev
        self._sb = sb
        self._per_block = sb.block_size // sb.desc_size
        self._block = lru_cache(maxsize=256)(self._read_block)
        self._csum_seed = csum_seed  # set: verify each descriptor used

    def _has_super(self, group: int) -> bool:
        """Whether a block group starts with a superblock backup."""
        sb = self._sb
        if group == 0:
            return True
        if sb.compat & COMPAT_SPARSE_SUPER2:
            return group in sb.backup_bgs
        if not sb.ro_compat & RO_COMPAT_SPARSE_SUPER:
            return True
        return group == 1 or any(_is_power_of(group, b) for b in (3, 5, 7))

    def _descriptor_block_location(self, index: int) -> int:
        """Block number of the index-th group descriptor block."""
        sb = self._sb
        if not sb.has_incompat(INCOMPAT_META_BG) or index < sb.first_meta_bg:
            return sb.first_data_block + 1 + index
        # meta_bg: each descriptor block lives in the first group it describes,
        # right after that group's superblock backup if it has one.
        group = index * self._per_block
        first_block = sb.first_data_block + group * sb.blocks_per_group
        return first_block + (1 if self._has_super(group) else 0)

    def _read_block(self, index: int) -> bytes:
        """One raw filesystem block."""
        bs = self._sb.block_size
        return self._dev.read_at(self._descriptor_block_location(index) * bs, bs)

    def inode_table(self, group: int) -> int:
        """First block of `group`'s inode table, reading its descriptor lazily (meta_bg aware).

        グループ `group` の inode テーブルの先頭ブロック（ディスクリプタは遅延読み込み）。
        """
        if not 0 <= group < self._sb.group_count:
            raise DiskReadError(f"block group {group} out of range")
        index, slot = divmod(group, self._per_block)
        raw = self._block(index)
        off = slot * self._sb.desc_size
        if self._csum_seed is not None:
            from diskread.fs.ext4.csum import check_group_desc

            check_group_desc(self._csum_seed, group, raw[off : off + self._sb.desc_size])
        (lo,) = struct.unpack_from("<I", raw, off + 0x08)
        hi = 0
        if self._sb.desc_size >= 64:
            (hi,) = struct.unpack_from("<I", raw, off + 0x28)
        return int(lo | (hi << 32))
