"""XFS v5 metadata CRCs.

Each v5 metadata buffer carries a little-endian CRC-32C of the whole
buffer computed with the CRC field zeroed (xfs_verify_cksum):
  superblock        sb_crc @0xE0 over sb_sectsize bytes
  inode (v3)        di_crc @0x64 over the inode size
  directory block   @0x04 over the directory block (XDB3 / XDD3)
  bmap btree block  bb_crc @0x40 over the block (BMA3)
  attr leaf / node  @0x0C (da3_blkinfo) over the block
  remote attr value @0x0C over each filesystem block (XARM)
  remote symlink    @0x0C over each extent's buffer (XSLM)

XFS v5 のメタデータ CRC。各バッファは、CRC フィールドをゼロにして全体から計算した CRC-32C を持
つ（xfs_verify_cksum）。対象ごとの場所は上の表のとおり。
"""

from __future__ import annotations

import struct

from diskread.crc32c import crc32c
from diskread.errors import DiskReadError


def check(buf: bytes, offset: int, what: str) -> None:
    """Verify the CRC-32C at `offset`, computed over the buffer with the field zeroed.

    CRC フィールドをゼロにして全体から計算した CRC-32C を、`offset` の値と照合する。
    """
    (stored,) = struct.unpack_from("<I", buf, offset)
    if crc32c(buf[:offset] + b"\0\0\0\0" + buf[offset + 4 :]) != stored:
        raise DiskReadError(f"checksum mismatch: XFS {what}")
