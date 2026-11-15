"""ext4 extended attributes: in-inode, in an xattr block, and in EA inodes.

Entry (4-byte aligned, list ends with four zero bytes):
  0x00 e_name_len (u8)   0x01 e_name_index (u8)   0x02 e_value_offs (u16)
  0x04 e_value_inum (u32, nonzero = value lives in that EA inode)
  0x08 e_value_size (u32)   0x0C e_hash (u32)   0x10 e_name[e_name_len]

In-inode: after 128 + i_extra_isize comes a 4-byte magic 0xEA020000, then
entries; value offsets are relative to the first entry.
Block (i_file_acl): a 32-byte header starting with magic 0xEA020000 and
h_blocks == 1, then entries; value offsets are relative to the block start.

POSIX ACLs are stored in a compact ext4 format and converted here to the
format getxattr(2) returns.

ext4 の拡張属性: inode 内・xattr ブロック・EA inode（レイアウトは上の表のとおり）。POSIX ACL
は ext4 独自の形式から getxattr(2) が返す形式に変換する。
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass

from diskread.errors import DiskReadError

XATTR_MAGIC = 0xEA020000
BLOCK_HEADER_SIZE = 32

# e_name_index -> prefix. Index 2/3 carry the whole name with an empty suffix.
PREFIXES = {
    1: "user.",
    2: "system.posix_acl_access",
    3: "system.posix_acl_default",
    4: "trusted.",
    6: "security.",
    7: "system.",
    8: "system.richacl",
}
ACL_INDEXES = {2, 3}
SYSTEM_DATA = "system.data"  # inline-data overflow; hidden by the kernel


@dataclass(frozen=True)
class RawEntry:
    """One xattr entry before its value is fetched.

    値を読み出す前の xattr エントリ 1 つ。
    """

    name: str
    value_offs: int
    value_inum: int
    value_size: int


def parse_entries(buf: bytes, start: int, end: int, where: str) -> list[RawEntry]:
    """Entries of an xattr list with full names; stops at the four-zero-bytes terminator.

    xattr エントリの一覧（名前は接頭辞を解決済み）。4 バイトのゼロ終端で止まる。
    """
    out: list[RawEntry] = []
    pos = start
    while True:
        if pos + 4 > end:
            raise DiskReadError(f"{where}: unterminated xattr entry list")
        if buf[pos : pos + 4] == b"\0\0\0\0":
            return out
        if pos + 16 > end:
            raise DiskReadError(f"{where}: truncated xattr entry")
        name_len, index, value_offs, value_inum, value_size = struct.unpack_from("<BBHII", buf, pos)
        name_end = pos + 16 + name_len
        if name_end > end:
            raise DiskReadError(f"{where}: xattr name overflows")
        suffix = buf[pos + 16 : name_end].decode("utf-8", "surrogateescape")
        prefix = PREFIXES.get(index)
        if prefix is not None:
            out.append(RawEntry(prefix + suffix, value_offs, value_inum, value_size))
        pos = (name_end + 3) & ~3


def acl_to_xattr(value: bytes, where: str) -> bytes:
    """Convert ext4's on-disk ACL to the posix_acl_xattr format (version 2).

    ext4 のディスク上 ACL を posix_acl_xattr 形式（version 2）に変換する。
    """
    if len(value) < 4 or struct.unpack_from("<I", value, 0)[0] != 1:
        raise DiskReadError(f"{where}: bad ACL header")
    out = bytearray(struct.pack("<I", 2))
    pos = 4
    while pos < len(value):
        tag, perm = struct.unpack_from("<HH", value, pos)
        if tag in (0x02, 0x08):  # ACL_USER, ACL_GROUP carry an id
            (eid,) = struct.unpack_from("<I", value, pos + 4)
            pos += 8
        else:
            eid = 0xFFFFFFFF  # ACL_UNDEFINED_ID
            pos += 4
        out += struct.pack("<HHI", tag, perm, eid)
    if pos != len(value):
        raise DiskReadError(f"{where}: truncated ACL")
    return bytes(out)


def read_values(
    buf: bytes,
    entries: list[RawEntry],
    value_base: int,
    read_ea_inode: Callable[[int, int], bytes],
    where: str,
) -> dict[str, bytes]:
    """Fetch each entry's value, from the buffer or from its EA inode.

    各エントリの値を、バッファまたはその EA inode から読む。
    """
    out: dict[str, bytes] = {}
    for e in entries:
        if e.value_inum:
            value = read_ea_inode(e.value_inum, e.value_size)
        else:
            start = value_base + e.value_offs
            if start + e.value_size > len(buf):
                raise DiskReadError(f"{where}: xattr {e.name} value overflows")
            value = buf[start : start + e.value_size]
        out[e.name] = value
    return out
