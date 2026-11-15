"""On-disk XFS inode: version 3 (v5 filesystems) and versions 1/2 (v4).

xfs_dinode, fields used here (big-endian):
  0x00 di_magic "IN"     0x02 di_mode (u16)   0x04 di_version (u8) = 3
  0x05 di_format (u8)    0x08 di_uid          0x0C di_gid
  0x10 di_nlink          0x18 di_big_nextents (u64, with NREXT64)
  0x20 di_atime          0x28 di_mtime        0x30 di_ctime
  0x38 di_size (u64)     0x40 di_nblocks (u64)
  0x4C di_nextents (u32) / di_big_anextents (u32, with NREXT64)
  0x50 di_anextents (u16)
  0x52 di_forkoff (u8, attr fork offset in 8-byte units)
  0x53 di_aformat (u8)   0x5A di_flags (u16)
  0x78 di_flags2 (u64)   0x90 di_crtime       0x98 di_ino (u64)
  0xB0 literal area: data fork, then the attr fork at forkoff * 8

Version 1/2 inodes (v4 filesystems) end their core at 0x64, where the
literal area starts; they have no flags2, creation time or di_ino.
Version 1 keeps the link count in the 16-bit di_onlink at 0x06.

Timestamps are {s32 seconds, u32 nanoseconds}, or with the BIGTIME inode
flag a u64 count of nanoseconds since 1901-12-13T20:45:52Z (-2^31 s).

ディスク上の XFS inode: version 3（v5 ファイルシステム）と version 1/2（v4）。フィールドは上の
表のとおり。タイムスタンプは {s32 秒, u32 ナノ秒}、BIGTIME フラグ付きなら 1901-12-13T20:45:52Z
からのナノ秒の u64。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from diskread.errors import DiskReadError, UnsupportedError

MAGIC = b"IN"
LITERAL_OFFSET = 0xB0
LITERAL_OFFSET_V2 = 0x64

FMT_DEV = 0
FMT_LOCAL = 1
FMT_EXTENTS = 2
FMT_BTREE = 3

DIFLAG_REALTIME = 0x1
DIFLAG2_BIGTIME = 0x8
DIFLAG2_NREXT64 = 0x10

BIGTIME_EPOCH_OFFSET_NS = (1 << 31) * 1_000_000_000


@dataclass(frozen=True, slots=True)
class Fork:
    """One fork (data or attr): its format and its bytes in the inode literal area.

    フォーク（data / attr）1 つ: 形式と、inode のリテラル領域内のバイト列。
    """

    format: int
    nextents: int
    data: bytes  # the fork's bytes inside the inode literal area


@dataclass(frozen=True, slots=True)
class Inode:
    """The parsed on-disk inode.

    解析済みのディスク上 inode。
    """

    ino: int
    mode: int
    uid: int
    gid: int
    nlink: int
    size: int
    nblocks: int
    flags: int
    flags2: int
    atime_ns: int
    mtime_ns: int
    ctime_ns: int
    crtime_ns: int | None  # None for version 1/2 inodes
    data_fork: Fork
    attr_fork: Fork | None


def _time(raw: bytes, offset: int, bigtime: bool) -> int:
    """An XFS timestamp as nanoseconds since the epoch."""
    if bigtime:
        (v,) = struct.unpack_from(">Q", raw, offset)
        return int(v - BIGTIME_EPOCH_OFFSET_NS)
    sec, nsec = struct.unpack_from(">iI", raw, offset)
    return int(sec * 1_000_000_000 + nsec)


def parse_inode(ino: int, raw: bytes) -> Inode:
    """Parse one raw inode (versions 1-3), normalising the differences between versions.

    生の inode 1 つを解析する（version 1〜3。版ごとの違いはここで吸収する）。
    """
    if raw[:2] != MAGIC:
        raise DiskReadError(f"inode {ino}: bad magic")
    mode, version, fmt = struct.unpack_from(">HBB", raw, 0x02)
    if version not in (1, 2, 3):
        raise UnsupportedError(f"inode {ino}: unknown inode version {version}")
    uid, gid, nlink = struct.unpack_from(">III", raw, 0x08)
    if version == 1:
        (nlink,) = struct.unpack_from(">H", raw, 0x06)
    (big_nextents,) = struct.unpack_from(">Q", raw, 0x18)
    size, nblocks = struct.unpack_from(">QQ", raw, 0x38)
    (nextents32,) = struct.unpack_from(">I", raw, 0x4C)
    (anextents16,) = struct.unpack_from(">H", raw, 0x50)
    forkoff, aformat = raw[0x52], raw[0x53]
    (flags,) = struct.unpack_from(">H", raw, 0x5A)
    flags2 = 0
    if version == 3:
        (flags2,) = struct.unpack_from(">Q", raw, 0x78)
        (di_ino,) = struct.unpack_from(">Q", raw, 0x98)
        if di_ino != ino:
            raise DiskReadError(f"inode {ino}: records itself as inode {di_ino}")
    if flags & DIFLAG_REALTIME:
        raise UnsupportedError(f"inode {ino}: realtime files are not supported")

    if flags2 & DIFLAG2_NREXT64:
        nextents, anextents = big_nextents, nextents32
    else:
        nextents, anextents = nextents32, anextents16

    literal = raw[LITERAL_OFFSET if version == 3 else LITERAL_OFFSET_V2 :]
    if forkoff:
        split = forkoff * 8
        if split >= len(literal):
            raise DiskReadError(f"inode {ino}: attr fork offset past the inode")
        data_fork = Fork(fmt, nextents, literal[:split])
        attr_fork: Fork | None = Fork(aformat, anextents, literal[split:])
    else:
        data_fork = Fork(fmt, nextents, literal)
        attr_fork = None

    bigtime = bool(flags2 & DIFLAG2_BIGTIME)
    return Inode(
        ino=ino,
        mode=mode,
        uid=uid,
        gid=gid,
        nlink=nlink,
        size=size,
        nblocks=nblocks,
        flags=flags,
        flags2=flags2,
        atime_ns=_time(raw, 0x20, bigtime),
        mtime_ns=_time(raw, 0x28, bigtime),
        ctime_ns=_time(raw, 0x30, bigtime),
        crtime_ns=_time(raw, 0x90, bigtime) if version == 3 else None,
        data_fork=data_fork,
        attr_fork=attr_fork,
    )
