"""XFS block mapping: extent lists and the bmap B+tree.

Extent record (xfs_bmbt_rec, 16 bytes, one big-endian 128-bit value):
  bit 127      extent flag (1 = unwritten, reads as zeros)
  bits 126-73  startoff   (logical block in the file, 54 bits)
  bits 72-21   startblock (filesystem block number, 52 bits)
  bits 20-0    blockcount (21 bits)

B+tree root in the inode fork (xfs_bmdr_block):
  bb_level (u16), bb_numrecs (u16), then maxrecs keys (u64) and maxrecs
  pointers (u64), where maxrecs = (fork size - 4) / 16.
Child blocks (long-format header: "BMA3", 72 bytes on v5; "BMAP", 24
bytes without the CRC/owner fields on v4):
  0x00 magic  0x04 bb_level (u16)  0x06 bb_numrecs (u16) ...
  leaves: records at 72; nodes: keys at 72, pointers at 72 + maxrecs * 8,
  with maxrecs = (block size - 72) / 16.

XFS のブロックマッピング: エクステントリストと bmap B+tree（レコードの詰め方は上の表のとおり）
。
"""

from __future__ import annotations

import itertools
import struct
from collections.abc import Callable

from diskread.errors import DiskReadError
from diskread.fs.extents import Run
from diskread.fs.xfs.inode import FMT_BTREE, FMT_EXTENTS, Fork
from diskread.fs.xfs.superblock import Superblock

REC_SIZE = 16
BMAP_CRC_MAGIC = b"BMA3"
LBLOCK_CRC_HEADER = 72
BMAP_MAGIC = b"BMAP"
LBLOCK_HEADER = 24
MAX_LEVELS = 9


def _decode_records(buf: bytes, offset: int, count: int, sb: Superblock) -> list[Run]:
    """Unpack `count` packed 128-bit extent records at `offset`."""
    runs = []
    for i in range(count):
        rec = int.from_bytes(buf[offset + i * REC_SIZE : offset + (i + 1) * REC_SIZE], "big")
        unwritten = bool(rec >> 127)
        startoff = (rec >> 73) & ((1 << 54) - 1)
        startblock = (rec >> 21) & ((1 << 52) - 1)
        count_ = rec & ((1 << 21) - 1)
        if count_:
            runs.append(Run(startoff, sb.fsb_to_linear(startblock), count_, unwritten))
    return runs


def fork_runs(
    fork: Fork, sb: Superblock, read_block: Callable[[int], bytes], ino: int
) -> list[Run]:
    """Runs for an EXTENTS or BTREE fork, sorted by logical block.

    EXTENTS / BTREE フォークの run を、論理ブロック順で返す。
    """
    if fork.format == FMT_EXTENTS:
        if fork.nextents * REC_SIZE > len(fork.data):
            raise DiskReadError(f"inode {ino}: {fork.nextents} extents overflow the fork")
        runs = _decode_records(fork.data, 0, fork.nextents, sb)
    elif fork.format == FMT_BTREE:
        runs = _btree_runs(fork, sb, read_block, ino)
    else:
        raise DiskReadError(f"inode {ino}: fork format {fork.format} has no block map")

    runs.sort(key=lambda r: r.logical)
    for a, b in itertools.pairwise(runs):
        if a.logical + a.length > b.logical:
            raise DiskReadError(f"inode {ino}: overlapping extents")
    return runs


def _btree_runs(
    fork: Fork, sb: Superblock, read_block: Callable[[int], bytes], ino: int
) -> list[Run]:
    """Runs of a B+tree fork: walk from the root in the inode down to the leaves."""
    level, numrecs = struct.unpack_from(">HH", fork.data, 0)
    if level == 0 or level > MAX_LEVELS:
        raise DiskReadError(f"inode {ino}: bad bmap btree root level {level}")
    maxrecs = (len(fork.data) - 4) // 16
    if numrecs > maxrecs:
        raise DiskReadError(f"inode {ino}: bmap btree root overflows")
    ptrs = struct.unpack_from(f">{numrecs}Q", fork.data, 4 + maxrecs * 8)

    runs: list[Run] = []
    magic, header = (BMAP_CRC_MAGIC, LBLOCK_CRC_HEADER) if sb.is_v5 else (BMAP_MAGIC, LBLOCK_HEADER)
    node_maxrecs = (sb.block_size - header) // 16
    # A tree has one way to each block. The level check alone stops a loop, but not
    # a node whose pointers all name the same child: every level would multiply the work.
    seen: set[int] = set()

    def walk(fsbno: int, expect_level: int) -> None:
        if fsbno in seen:
            raise DiskReadError(f"inode {ino}: bmap btree block {fsbno:#x} reached twice")
        seen.add(fsbno)
        block = read_block(sb.fsb_to_linear(fsbno))
        if block[:4] != magic:
            raise DiskReadError(f"inode {ino}: bad bmap btree block magic")
        lvl, n = struct.unpack_from(">HH", block, 4)
        if lvl != expect_level:
            raise DiskReadError(f"inode {ino}: bmap btree level mismatch")
        if lvl == 0:
            if header + n * REC_SIZE > len(block):
                raise DiskReadError(f"inode {ino}: bmap btree leaf overflows")
            runs.extend(_decode_records(block, header, n, sb))
            return
        if n > node_maxrecs:
            raise DiskReadError(f"inode {ino}: bmap btree node overflows")
        for child in struct.unpack_from(f">{n}Q", block, header + node_maxrecs * 8):
            walk(child, lvl - 1)

    for p in ptrs:
        walk(p, level - 1)
    return runs
