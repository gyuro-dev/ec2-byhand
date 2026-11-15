"""CRC-32C (Castagnoli), as used by ext4 metadata_csum and XFS v5.

`crc32c_raw` is the bare register update with no pre/post inversion, like
the kernel's crc32c_le(): ext4 chains it and stores the raw value. XFS
starts from ~0 and stores the inverted result, which is the standard
CRC-32C that `crc32c` returns.

Pure Python, so the inner loop matters: this is slicing-by-8 (8 lookup
tables, one struct-decoded 8-byte step per iteration), several times
faster than the classic one-table byte loop.

ext4 metadata_csum と XFS v5 が使う CRC-32C（Castagnoli）。`crc32c_raw` は前後の反転なしの素の
更新（カーネルの crc32c_le() 相当）で、`crc32c` は標準の CRC-32C。純 Python なので内側のループ
が要で、slicing-by-8 により古典的な 1 テーブル方式の数倍速い。
"""

from __future__ import annotations

import struct

_POLY = 0x82F63B78  # reflected 0x1EDC6F41


def _tables() -> list[list[int]]:
    """Build the eight slicing-by-8 lookup tables."""
    t0 = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ _POLY if c & 1 else c >> 1
        t0.append(c)
    tables = [t0]
    for _ in range(7):
        prev = tables[-1]
        tables.append([t0[c & 0xFF] ^ (c >> 8) for c in prev])
    return tables


_T0, _T1, _T2, _T3, _T4, _T5, _T6, _T7 = _tables()


def crc32c_raw(crc: int, data: bytes) -> int:
    """Advance the bare CRC register over `data` (no pre/post inversion).

    前後の反転なしの素の CRC レジスタを `data` のぶん進める。
    """
    t0, t1, t2, t3 = _T0, _T1, _T2, _T3
    t4, t5, t6, t7 = _T4, _T5, _T6, _T7
    head = len(data) & ~7
    for lo, hi in struct.iter_unpack("<II", data[:head]):
        lo ^= crc
        crc = (
            t7[lo & 0xFF]
            ^ t6[(lo >> 8) & 0xFF]
            ^ t5[(lo >> 16) & 0xFF]
            ^ t4[lo >> 24]
            ^ t3[hi & 0xFF]
            ^ t2[(hi >> 8) & 0xFF]
            ^ t1[(hi >> 16) & 0xFF]
            ^ t0[hi >> 24]
        )
    for b in data[head:]:
        crc = t0[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc


def crc32c(data: bytes) -> int:
    """The standard CRC-32C of `data`.

    `data` の標準の CRC-32C。
    """
    return crc32c_raw(0xFFFFFFFF, data) ^ 0xFFFFFFFF
