"""XFS superblock (v4 and v5) and address conversions.

Reference: "XFS Algorithms & Data Structures" (xfs-documentation). All
on-disk integers are big-endian.

Superblock (sector 0 of AG 0), fields used here:
  0x00 sb_magicnum "XFSB"   0x04 sb_blocksize    0x08 sb_dblocks (u64)
  0x20 sb_uuid[16]          0x30 sb_logstart (u64)  0x38 sb_rootino (u64)
  0x54 sb_agblocks          0x58 sb_agcount         0x60 sb_logblocks
  0x64 sb_versionnum (u16)  0x66 sb_sectsize (u16) 0x68 sb_inodesize (u16)
  0x6A sb_inopblock (u16)   0x6C sb_fname[12]
  0x78 sb_blocklog (u8)     0x7A sb_inodelog (u8)  0x7B sb_inopblog (u8)
  0x7C sb_agblklog (u8)     0xC0 sb_dirblklog (u8)     0xC8 sb_features2       0xCC sb_bad_features2
  0xD0 sb_features_compat   0xD4 sb_features_ro_compat
  0xD8 sb_features_incompat 0xDC sb_features_log_incompat

Inode numbers pack (AG, block in AG, slot in block):
  ino = agno << (agblklog + inopblog) | agbno << inopblog | slot
Filesystem block numbers in extent records pack (AG, block in AG):
  fsbno = agno << agblklog | agbno
Because AGs need not be a power of two blocks long, the linear block
number on the device is agno * agblocks + agbno.

XFS のスーパーブロック（v4 / v5）とアドレス変換。フィールドは上の表のとおり。inode 番号は (AG,
AG 内ブロック, ブロック内スロット) を、エクステント中の FS ブロック番号は (AG, AG 内ブロック)
を詰めたもの。AG のブロック数は 2 の冪とは限らないので、デバイス上の線形ブロックは agno *
agblocks + agbno。
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass

from diskread.errors import DiskReadError, UnsupportedError

MAGIC = b"XFSB"
VERSION_MASK = 0x000F
VERSION_4 = 4
VERSION_5 = 5
# v4 feature bits in sb_versionnum and sb_features2.
VERSION_DIRV2BIT = 0x2000
VERSION_MOREBITSBIT = 0x8000  # sb_features2 is valid
FEATURES2_FTYPE = 0x0200

INCOMPAT_FTYPE = 0x1
INCOMPAT_SPINODES = 0x2
INCOMPAT_META_UUID = 0x4
INCOMPAT_BIGTIME = 0x8
INCOMPAT_NEEDSREPAIR = 0x10
INCOMPAT_NREXT64 = 0x20
INCOMPAT_EXCHRANGE = 0x40
INCOMPAT_PARENT = 0x80
INCOMPAT_METADIR = 0x100
_KNOWN_INCOMPAT = (
    INCOMPAT_FTYPE
    | INCOMPAT_SPINODES
    | INCOMPAT_META_UUID
    | INCOMPAT_BIGTIME
    | INCOMPAT_NEEDSREPAIR
    | INCOMPAT_NREXT64
    | INCOMPAT_EXCHRANGE
    | INCOMPAT_PARENT
    | INCOMPAT_METADIR
)


@dataclass(frozen=True)
class Superblock:
    """The superblock fields this reader uses.

    このリーダーが使うスーパーブロックのフィールド。
    """

    block_size: int
    blocklog: int
    dblocks: int
    agblocks: int
    agcount: int
    agblklog: int
    inode_size: int
    inopblog: int
    dir_block_size: int
    root_ino: int
    log_start: int  # filesystem block number; 0 for an external log
    log_blocks: int
    incompat: int
    ro_compat: int
    uuid: str
    version: int  # 4 or 5
    features2: int  # v4 only (0 on v5)
    label: str

    @property
    def is_v5(self) -> bool:
        """Whether the version field says v5 (CRC-enabled).

        バージョンフィールドが v5（CRC あり）を示すか。
        """
        return self.version == VERSION_5

    @property
    def has_ftype(self) -> bool:
        """Directory entries carry a file type byte.

        ディレクトリエントリがファイルタイプのバイトを持つ。
        """
        if self.is_v5:
            return bool(self.incompat & INCOMPAT_FTYPE)
        return bool(self.features2 & FEATURES2_FTYPE)

    @property
    def needs_repair(self) -> bool:
        """xfs_repair was interrupted; metadata may be inconsistent.

        xfs_repair が中断された。メタデータは不整合かもしれない。
        """
        return bool(self.incompat & INCOMPAT_NEEDSREPAIR)

    def fsb_to_linear(self, fsbno: int) -> int:
        """A packed filesystem block number as a linear block number on the device.

        詰めた形式の FS ブロック番号を、デバイス上の線形ブロック番号に直す。
        """
        agno = fsbno >> self.agblklog
        agbno = fsbno & ((1 << self.agblklog) - 1)
        if agno >= self.agcount or agbno >= self.agblocks:
            raise DiskReadError(f"filesystem block {fsbno:#x} out of range")
        return agno * self.agblocks + agbno

    def inode_offset(self, ino: int) -> int:
        """Byte offset of an inode on the device.

        デバイス上での inode のバイトオフセット。
        """
        slot_bits = self.inopblog
        agno = ino >> (self.agblklog + slot_bits)
        agbno = (ino >> slot_bits) & ((1 << self.agblklog) - 1)
        slot = ino & ((1 << slot_bits) - 1)
        if agno >= self.agcount or agbno >= self.agblocks:
            raise DiskReadError(f"inode {ino} out of range")
        return (agno * self.agblocks + agbno) * self.block_size + slot * self.inode_size


def parse_superblock(raw: bytes) -> Superblock:
    """Parse and sanity-check the superblock; unsupported features raise.

    スーパーブロックを解析・検査する。非対応機能は例外にする。
    """
    if raw[:4] != MAGIC:
        raise DiskReadError("not an XFS filesystem (bad superblock magic)")
    (versionnum,) = struct.unpack_from(">H", raw, 0x64)
    version = versionnum & VERSION_MASK
    if version not in (VERSION_4, VERSION_5):
        raise UnsupportedError(f"XFS v{version} is not supported (v4 and v5 only)")
    features2 = 0
    if version == VERSION_4:
        if not versionnum & VERSION_DIRV2BIT:
            raise UnsupportedError("XFS v4 with version 1 directories is not supported")
        if versionnum & VERSION_MOREBITSBIT:
            # Old kernels wrote features2 at the wrong offset; Linux merges both.
            f2, bad_f2 = struct.unpack_from(">II", raw, 0xC8)
            features2 = f2 | bad_f2

    (block_size,) = struct.unpack_from(">I", raw, 0x04)
    (dblocks,) = struct.unpack_from(">Q", raw, 0x08)
    log_start, root_ino = struct.unpack_from(">QQ", raw, 0x30)
    agblocks, agcount = struct.unpack_from(">II", raw, 0x54)
    (log_blocks,) = struct.unpack_from(">I", raw, 0x60)
    (inode_size,) = struct.unpack_from(">H", raw, 0x68)
    blocklog, _sectlog, inodelog, inopblog, agblklog = struct.unpack_from(">BBBBB", raw, 0x78)
    dirblklog = raw[0xC0]
    _compat, ro_compat, incompat = struct.unpack_from(">III", raw, 0xD0)
    if version == VERSION_4:
        ro_compat = incompat = 0  # these fields only exist on v5

    if block_size != 1 << blocklog or not 512 <= block_size <= 65536:
        raise DiskReadError(f"bad XFS block size {block_size}")
    if (
        inode_size != 1 << inodelog
        or inopblog != blocklog - inodelog
        or not 256 <= inode_size <= 2048
    ):
        raise DiskReadError(f"bad XFS inode geometry (size {inode_size})")
    # As the kernel has it (XFS_MAX_BLOCKSIZE): a directory block is read whole, and a
    # damaged shift would make that gigabytes.
    if blocklog + dirblklog > 16:
        raise DiskReadError(f"bad XFS directory block size 2^{blocklog + dirblklog}")
    if agcount == 0 or agblocks == 0 or agblocks > 1 << agblklog:
        raise DiskReadError("bad XFS allocation group geometry")
    unknown = incompat & ~_KNOWN_INCOMPAT
    if unknown:
        raise UnsupportedError(f"unknown XFS incompat features {unknown:#x}")

    return Superblock(
        block_size=block_size,
        blocklog=blocklog,
        dblocks=dblocks,
        agblocks=agblocks,
        agcount=agcount,
        agblklog=agblklog,
        inode_size=inode_size,
        inopblog=inopblog,
        dir_block_size=block_size << dirblklog,
        root_ino=root_ino,
        log_start=log_start,
        log_blocks=log_blocks,
        incompat=incompat,
        ro_compat=ro_compat,
        uuid=str(uuid.UUID(bytes=raw[0x20:0x30])),
        label=raw[0x6C:0x78].split(b"\0", 1)[0].decode("utf-8", "replace"),
        version=version,
        features2=features2,
    )
