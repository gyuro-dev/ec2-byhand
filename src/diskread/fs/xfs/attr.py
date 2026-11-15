"""XFS extended attributes (v4 and v5).

Shortform (attr fork format LOCAL):
  header: totsize (u16), count (u8), pad (u8)
  entry:  namelen (u8), valuelen (u8), flags (u8), name, value

Leaf block (attr fork EXTENTS/BTREE), v5 magic 0x3BEE at offset 8:
  0x38 count (u16) ... entries start at 0x50, 8 bytes each:
       hashval (u32), nameidx (u16), flags (u8), pad (u8)
  at nameidx, local:  valuelen (u16), namelen (u8), name, value
              remote: valueblk (u32), valuelen (u32), namelen (u8), name
Remote value blocks ("XARM", one header per filesystem block):
  0x04 offset (u32), 0x08 bytes (u32), data from 0x38.
Node blocks (magic 0x3EBE at offset 8) only index leaves and are skipped.
On v4: leaf magic 0xFBEE with a 32-byte header (count at 0x0C), node
magic 0xFEBE, and remote values are raw bytes with no per-block header.

Namespaces: no flag = "user.", ROOT = "trusted.", SECURE = "security.";
PARENT entries are parent pointers, which listxattr(2) does not show.
POSIX ACLs are stored as trusted.SGI_ACL_FILE / SGI_ACL_DEFAULT in XFS's
own format; the kernel lists those and also the converted
system.posix_acl_access / system.posix_acl_default.

XFS の拡張属性（v4 / v5）: shortform・leaf・リモート値（レイアウトは上の表のとおり）。名前空間
はフラグなしが「user.」、ROOT が「trusted.」、SECURE が「security.」。PARENT は親ポインタで
listxattr(2) には出ない。POSIX ACL は trusted.SGI_ACL_* に XFS 独自形式で入っており、カーネル
は変換した system.posix_acl_* も並べて見せる。
"""

from __future__ import annotations

import struct
from collections.abc import Callable

from diskread.errors import DiskReadError

ATTR_LOCAL = 0x01
ATTR_ROOT = 0x02
ATTR_SECURE = 0x04
ATTR_PARENT = 0x08
ATTR_INCOMPLETE = 0x80

LEAF_MAGIC = 0x3BEE
NODE_MAGIC = 0x3EBE
LEAF_HEADER_SIZE = 0x50
V4_LEAF_MAGIC = 0xFBEE
V4_NODE_MAGIC = 0xFEBE
V4_LEAF_HEADER_SIZE = 0x20
RMT_MAGIC = b"XARM"
RMT_HEADER_SIZE = 0x38
# The largest value the kernel stores (XFS_XATTR_SIZE_MAX): a length beyond it is damage,
# and must not have every block of the fork read to gather it.
MAX_VALUE_BYTES = 65536

ACL_NAMES = {
    "trusted.SGI_ACL_FILE": "system.posix_acl_access",
    "trusted.SGI_ACL_DEFAULT": "system.posix_acl_default",
}


def _full_name(flags: int, name: bytes) -> str | None:
    """The xattr's name with its namespace prefix, or None for entries the kernel hides."""
    if flags & (ATTR_PARENT | ATTR_INCOMPLETE):
        return None
    if flags & ATTR_ROOT:
        prefix = "trusted."
    elif flags & ATTR_SECURE:
        prefix = "security."
    else:
        prefix = "user."
    return prefix + name.decode("utf-8", "surrogateescape")


def parse_shortform(data: bytes, ino: int) -> dict[str, bytes]:
    """Shortform attributes from the attr fork's bytes.

    attr フォークのバイト列から shortform の属性を読む。
    """
    if len(data) < 4:
        raise DiskReadError(f"inode {ino}: truncated shortform attr header")
    totsize, count = struct.unpack_from(">HB", data, 0)
    if totsize > len(data):
        raise DiskReadError(f"inode {ino}: shortform attrs overflow the fork")
    out = {}
    pos = 4
    for _ in range(count):
        if pos + 3 > totsize:
            raise DiskReadError(f"inode {ino}: truncated shortform attr entry")
        namelen, valuelen, flags = data[pos], data[pos + 1], data[pos + 2]
        end = pos + 3 + namelen + valuelen
        if end > totsize:
            raise DiskReadError(f"inode {ino}: shortform attr entry overflows")
        name = _full_name(flags, data[pos + 3 : pos + 3 + namelen])
        if name is not None:
            out[name] = bytes(data[pos + 3 + namelen : end])
        pos = end
    return out


def parse_leaf(
    block: bytes, read_remote: Callable[[int, int], bytes], ino: int, v5: bool = True
) -> dict[str, bytes] | None:
    """Attributes in one attr fork block, or None if it is not a leaf.

    On v4, remote value blocks have no header, so the caller must not pass
    them in (see Xfs._raw_xattrs).

    attr フォークの 1 ブロック分の属性。leaf でなければ None。v4 のリモート値ブロックにはヘッ
    ダが無いので、呼び出し側が渡さないこと（Xfs._raw_xattrs 参照）。
    """
    if v5 and block[:4] == RMT_MAGIC:
        return None
    (magic,) = struct.unpack_from(">H", block, 8)
    if v5:
        leaf_magic, node_magic, header, count_at = LEAF_MAGIC, NODE_MAGIC, LEAF_HEADER_SIZE, 0x38
    else:
        leaf_magic, node_magic, header, count_at = (
            V4_LEAF_MAGIC,
            V4_NODE_MAGIC,
            V4_LEAF_HEADER_SIZE,
            0x0C,
        )
    if magic == node_magic:
        return None
    if magic != leaf_magic:
        raise DiskReadError(f"inode {ino}: bad attr block magic {magic:#x}")
    (count,) = struct.unpack_from(">H", block, count_at)
    if header + count * 8 > len(block):
        raise DiskReadError(f"inode {ino}: attr leaf entries overflow")
    out = {}
    for i in range(count):
        _hash, nameidx, flags = struct.unpack_from(">IHB", block, header + i * 8)
        if flags & ATTR_LOCAL:
            valuelen, namelen = struct.unpack_from(">HB", block, nameidx)
            name_at = nameidx + 3
            raw_name = block[name_at : name_at + namelen]
            value_at = name_at + namelen
            if value_at + valuelen > len(block):
                raise DiskReadError(f"inode {ino}: attr leaf value overflows")
            value: bytes | None = bytes(block[value_at : value_at + valuelen])
        else:
            valueblk, valuelen, namelen = struct.unpack_from(">IIB", block, nameidx)
            raw_name = block[nameidx + 9 : nameidx + 9 + namelen]
            value = None
        if len(raw_name) != namelen:
            raise DiskReadError(f"inode {ino}: attr leaf name overflows")
        name = _full_name(flags, raw_name)
        if name is None:
            continue
        out[name] = value if value is not None else read_remote(valueblk, valuelen)
    return out


def read_remote_value(
    read_fork_block: Callable[[int], bytes], valueblk: int, valuelen: int, ino: int, v5: bool = True
) -> bytes:
    """Gather a remote value from consecutive attr fork blocks.

    連続する attr フォークブロックからリモート値を集める。
    """
    if valuelen > MAX_VALUE_BYTES:
        raise DiskReadError(f"inode {ino}: implausible remote attr value of {valuelen} bytes")
    if not v5:  # v4: the value's bytes, back to back
        out = bytearray()
        blk = valueblk
        while len(out) < valuelen:
            out += read_fork_block(blk)
            blk += 1
        return bytes(out[:valuelen])
    out = bytearray()
    blk = valueblk
    while len(out) < valuelen:
        block = read_fork_block(blk)
        if block[:4] != RMT_MAGIC:
            raise DiskReadError(f"inode {ino}: bad remote attr block magic")
        offset, nbytes = struct.unpack_from(">II", block, 4)
        if offset != len(out) or RMT_HEADER_SIZE + nbytes > len(block) or nbytes == 0:
            raise DiskReadError(f"inode {ino}: inconsistent remote attr block")
        out += block[RMT_HEADER_SIZE : RMT_HEADER_SIZE + nbytes]
        blk += 1
    if len(out) != valuelen:
        raise DiskReadError(f"inode {ino}: remote attr value length mismatch")
    return bytes(out)


# xfs_da_intnode header: v5 (da3): 56-byte blkinfo, count, level, pad -> 64;
# v4: 12-byte blkinfo, count, level -> 16. Entries: hashval (u32), before (u32).
NODE_HEADER = {True: (0x38, 0x40), False: (0x0C, 0x10)}  # (count offset, entries offset)
MAX_DA_DEPTH = 5


def leaf_blocks(read_fork_block: Callable[[int], bytes], ino: int, v5: bool = True) -> list[int]:
    """Attr fork blocks holding leaves, found by walking the attr B+tree from
    block 0 as the kernel does. Scanning every block would not work on v4,
    where remote value blocks have no header to tell them apart.

    leaf を持つ attr フォークブロック。カーネルと同じくブロック 0 から attr B+tree を辿って見
    つける。v4 ではリモート値ブロックに見分けるためのヘッダが無いので、全ブロック走査では駄目
    。
    """
    leaf_magic, node_magic = (LEAF_MAGIC, NODE_MAGIC) if v5 else (V4_LEAF_MAGIC, V4_NODE_MAGIC)
    count_at, entries_at = NODE_HEADER[v5]
    out: list[int] = []
    seen: set[int] = set()

    def walk(blk: int, depth: int) -> None:
        if blk in seen or depth > MAX_DA_DEPTH:
            raise DiskReadError(f"inode {ino}: attr B+tree loops or is too deep")
        seen.add(blk)
        block = read_fork_block(blk)
        (magic,) = struct.unpack_from(">H", block, 8)
        if magic == leaf_magic:
            out.append(blk)
        elif magic == node_magic:
            (count,) = struct.unpack_from(">H", block, count_at)
            if entries_at + count * 8 > len(block):
                raise DiskReadError(f"inode {ino}: attr node overflows")
            for i in range(count):
                (before,) = struct.unpack_from(">I", block, entries_at + i * 8 + 4)
                walk(before, depth + 1)
        else:
            raise DiskReadError(f"inode {ino}: bad attr block magic {magic:#x} in block {blk}")

    walk(0, 0)
    return out


def acl_to_xattr(value: bytes, ino: int) -> bytes:
    """Convert an XFS on-disk ACL to the posix_acl_xattr format (version 2).

    XFS: acl_cnt (be32), then entries of tag (be32), id (be32), perm (be16), pad.

    XFS のディスク上 ACL を posix_acl_xattr 形式（version 2）に変換する。
    """
    if len(value) < 4:
        raise DiskReadError(f"inode {ino}: truncated ACL")
    (count,) = struct.unpack_from(">I", value, 0)
    if 4 + count * 12 != len(value):
        raise DiskReadError(f"inode {ino}: ACL length mismatch")
    out = bytearray(struct.pack("<I", 2))
    for i in range(count):
        tag, eid, perm = struct.unpack_from(">IIH", value, 4 + i * 12)
        if tag not in (0x02, 0x08):  # only ACL_USER and ACL_GROUP carry an id
            eid = 0xFFFFFFFF
        out += struct.pack("<HHI", tag, perm, eid)
    return bytes(out)
