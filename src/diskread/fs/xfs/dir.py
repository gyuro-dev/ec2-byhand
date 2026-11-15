"""XFS directories (v4 and v5): shortform (in the inode) and data blocks.

Shortform (data fork format LOCAL):
  header: count (u8), i8count (u8), parent (4 bytes, or 8 if i8count)
  entry:  namelen (u8), offset (u16), name, ftype (u8, with the ftype
          feature), inumber (4 or 8 bytes)

Block, leaf, node and btree directories all keep their entries in "data
blocks" of the directory block size below the 32 GiB leaf offset; the
leaf/free/hash index blocks above it are not needed to list a directory.
Data block (v5): 64-byte header with magic "XDB3" (single-block form,
which ends with leaf entries and an 8-byte tail) or "XDD3", then:
  used entry:   inumber (u64), namelen (u8), name, ftype (u8), padding,
                tag (u16); total length rounded up to 8
  unused entry: freetag 0xFFFF (u16), length (u16), ..., tag (u16)
On v4 the magics are "XD2B" / "XD2D" and the header is only 16 bytes
(magic + bestfree); entries lack the ftype byte unless the ftype feature
is on.

XFS のディレクトリ（v4 / v5）: shortform とデータブロック（レイアウトは上の表のとおり）。一覧
に必要なのは 32 GiB 境界より下のデータブロックだけで、その上の leaf / free / hash のインデック
スブロックは読まない。
"""

from __future__ import annotations

import struct

from diskread.errors import DiskReadError

DATA_BLOCK_MAGIC = b"XDB3"  # single-block directory
DATA_MAGIC = b"XDD3"
DATA_HEADER_SIZE = 64
V4_DATA_BLOCK_MAGIC = b"XD2B"
V4_DATA_MAGIC = b"XD2D"
V4_DATA_HEADER_SIZE = 16
BLOCK_TAIL_SIZE = 8
LEAF_OFFSET = 32 << 30  # XFS_DIR2_LEAF_OFFSET in bytes
FREE_TAG = 0xFFFF


def parse_shortform(data: bytes, has_ftype: bool, ino: int) -> list[tuple[bytes, int]]:
    """Entries of a shortform directory held in the inode.

    inode 内に持つ shortform ディレクトリのエントリ。
    """
    if len(data) < 6:
        raise DiskReadError(f"directory {ino}: truncated shortform header")
    count, i8count = data[0], data[1]
    inum_size = 8 if i8count else 4
    pos = 2 + inum_size
    out = []
    for _ in range(count):
        if pos + 3 > len(data):
            raise DiskReadError(f"directory {ino}: truncated shortform entry")
        namelen = data[pos]
        pos += 3  # namelen + 2-byte offset cookie
        name = bytes(data[pos : pos + namelen])
        pos += namelen + (1 if has_ftype else 0)
        if pos + inum_size > len(data) or len(name) != namelen or namelen == 0:
            raise DiskReadError(f"directory {ino}: shortform entry overflows")
        child = int.from_bytes(data[pos : pos + inum_size], "big")
        pos += inum_size
        if name not in (b".", b".."):  # never stored in this form; as the data blocks' are
            out.append((name, child))
    return out


def parse_data_block(
    block: bytes, has_ftype: bool, ino: int, v5: bool = True
) -> list[tuple[bytes, int]]:
    """Entries of one directory data block; unused entries are skipped by their free tag.

    ディレクトリのデータブロック 1 つ分のエントリ。未使用エントリは free タグで飛ばす。
    """
    magic = block[:4]
    if v5:
        block_magic, data_magic, header = DATA_BLOCK_MAGIC, DATA_MAGIC, DATA_HEADER_SIZE
    else:
        block_magic, data_magic, header = V4_DATA_BLOCK_MAGIC, V4_DATA_MAGIC, V4_DATA_HEADER_SIZE
    if magic == block_magic:
        (count,) = struct.unpack_from(">I", block, len(block) - BLOCK_TAIL_SIZE)
        end = len(block) - BLOCK_TAIL_SIZE - count * 8
        if end < header:
            raise DiskReadError(f"directory {ino}: block tail overflows")
    elif magic == data_magic:
        end = len(block)
    else:
        raise DiskReadError(f"directory {ino}: bad data block magic {magic!r}")

    out = []
    pos = header
    while pos < end:
        if pos + 4 > end:
            raise DiskReadError(f"directory {ino}: truncated entry at {pos}")
        (tag,) = struct.unpack_from(">H", block, pos)
        if tag == FREE_TAG:
            (length,) = struct.unpack_from(">H", block, pos + 2)
            if length < 8 or length % 8 or pos + length > end:
                raise DiskReadError(f"directory {ino}: bad free entry length {length} at {pos}")
            pos += length
            continue
        (child,) = struct.unpack_from(">Q", block, pos)
        namelen = block[pos + 8]
        entsize = (8 + 1 + namelen + (1 if has_ftype else 0) + 2 + 7) & ~7
        if namelen == 0 or pos + entsize > end:
            raise DiskReadError(f"directory {ino}: entry overflows at {pos}")
        name = bytes(block[pos + 9 : pos + 9 + namelen])
        if name not in (b".", b".."):
            out.append((name, child))
        pos += entsize
    return out
