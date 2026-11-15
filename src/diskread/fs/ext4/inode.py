"""On-disk ext4 inode.

Fields used (offsets within the inode, little-endian):
  0x00 i_mode (u16)        0x02 i_uid lo (u16)     0x04 i_size_lo
  0x08 i_atime             0x0C i_ctime            0x10 i_mtime
  0x18 i_gid lo (u16)      0x1A i_links_count (u16)
  0x1C i_blocks_lo         0x20 i_flags            0x28 i_block[15] (60 bytes)
  0x68 i_file_acl_lo       0x6C i_size_high
  0x74 l_i_blocks_high (u16)  0x76 l_i_file_acl_high (u16)
  0x78 l_i_uid_high (u16)     0x7A l_i_gid_high (u16)
  -- large inodes only (128 + i_extra_isize bytes are valid) --
  0x80 i_extra_isize (u16)
  0x84 i_ctime_extra  0x88 i_mtime_extra  0x8C i_atime_extra
  0x90 i_crtime       0x94 i_crtime_extra

Timestamps are a signed 32-bit seconds field plus, in large inodes, an
"extra" word: the low 2 bits extend the seconds (epoch bits << 32) and the
upper 30 bits are nanoseconds.

ディスク上の ext4 inode。使うフィールドのオフセットは上の表のとおり。タイムスタンプは符号付き
32 ビットの秒と、large inode では extra ワード（下位 2 ビットが秒の拡張、上位 30 ビットがナノ
秒）。
"""

from __future__ import annotations

import stat as _stat
import struct
from dataclasses import dataclass

from diskread.errors import DiskReadError

GOOD_OLD_INODE_SIZE = 128
I_BLOCK_OFFSET = 0x28
N_BLOCK_BYTES = 60

# i_flags
FLAG_ENCRYPT = 0x800
FLAG_INDEX = 0x1000
FLAG_HUGE_FILE = 0x40000
FLAG_EXTENTS = 0x80000
FLAG_EA_INODE = 0x200000
FLAG_INLINE_DATA = 0x10000000


def _decode_time(base: int, extra: int | None) -> int:
    """Seconds + extra word to nanoseconds: 2 low extra bits extend the seconds, the rest is ns."""
    sec = base - (1 << 32) if base & 0x80000000 else base
    nsec = 0
    if extra is not None:
        sec += (extra & 0x3) << 32
        nsec = extra >> 2
    return sec * 1_000_000_000 + nsec


@dataclass(frozen=True, slots=True)
class Inode:
    """The parsed on-disk inode, keeping the raw bytes for in-inode xattrs.

    解析済みのディスク上 inode。inode 内 xattr のために生のバイト列も持つ。
    """

    ino: int
    mode: int
    uid: int
    gid: int
    size: int
    links_count: int
    blocks_raw: int  # i_blocks as stored (512-byte or fs-block units)
    flags: int
    file_acl: int
    atime_ns: int
    mtime_ns: int
    ctime_ns: int
    crtime_ns: int | None
    raw: bytes  # the whole on-disk inode, for in-inode xattrs
    extra_isize: int

    @property
    def i_block(self) -> bytes:
        """The 60 bytes of i_block: an extent tree's root, block pointers, a short
        link's target or a device number (cut from `raw`, not kept a second time).

        i_block の 60 バイト: エクステント木の根・ブロックポインタ・短いリンクのリンク先・
        デバイス番号（`raw` から切り出す。二重には持たない）。
        """
        return self.raw[I_BLOCK_OFFSET : I_BLOCK_OFFSET + N_BLOCK_BYTES]

    def has_flag(self, flag: int) -> bool:
        """Whether i_flags has `flag` set.

        i_flags に `flag` が立っているか。
        """
        return bool(self.flags & flag)


def parse_inode(ino: int, raw: bytes, huge_file: bool, large_dir: bool = False) -> Inode:
    """Parse one raw inode; with `huge_file` the high half of i_blocks is valid. The
    high half of the size counts for regular files, and for the rest only with
    `large_dir` (as ext4_isize has it: without the feature those 4 bytes are the old
    i_dir_acl, which Linux ignores).

    生の inode 1 つを解析する。`huge_file` のときは i_blocks の上位が有効。サイズの上位は通常
    ファイルで有効で、それ以外では `large_dir` のときだけ（ext4_isize と同じ。その機能が無け
    ればその 4 バイトは昔の i_dir_acl で、Linux は無視する）。
    """
    mode, uid_lo, size_lo, atime, ctime, mtime = struct.unpack_from("<HHIIII", raw, 0x00)
    gid_lo, links = struct.unpack_from("<HH", raw, 0x18)
    blocks_lo, flags = struct.unpack_from("<II", raw, 0x1C)
    file_acl_lo, size_hi = struct.unpack_from("<II", raw, 0x68)
    blocks_hi, file_acl_hi, uid_hi, gid_hi = struct.unpack_from("<HHHH", raw, 0x74)

    extra_isize = 0
    if len(raw) > GOOD_OLD_INODE_SIZE:
        (extra_isize,) = struct.unpack_from("<H", raw, 0x80)
        if GOOD_OLD_INODE_SIZE + extra_isize > len(raw) or extra_isize & 3:
            raise DiskReadError(f"inode {ino}: bad i_extra_isize {extra_isize}")

    def extra(offset: int) -> int | None:
        # A field exists only if i_extra_isize covers it.
        if offset + 4 > GOOD_OLD_INODE_SIZE + extra_isize:
            return None
        return int(struct.unpack_from("<I", raw, offset)[0])

    crtime_base = extra(0x90)
    blocks = blocks_lo | ((blocks_hi << 32) if huge_file else 0)
    return Inode(
        ino=ino,
        mode=mode,
        uid=uid_lo | (uid_hi << 16),
        gid=gid_lo | (gid_hi << 16),
        size=size_lo | (size_hi << 32) if large_dir or _stat.S_ISREG(mode) else size_lo,
        links_count=links,
        blocks_raw=blocks,
        flags=flags,
        file_acl=file_acl_lo | (file_acl_hi << 32),
        atime_ns=_decode_time(atime, extra(0x8C)),
        mtime_ns=_decode_time(mtime, extra(0x88)),
        ctime_ns=_decode_time(ctime, extra(0x84)),
        crtime_ns=None if crtime_base is None else _decode_time(crtime_base, extra(0x94)),
        raw=raw,
        extra_isize=extra_isize,
    )
