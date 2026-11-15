"""Mapping a file's logical blocks to disk blocks: extent trees and the
ext2/3 indirect block map.

Extent tree node (in i_block, or a whole block for deeper levels):
  header (12 bytes): magic 0xF30A (u16), entries (u16), max (u16),
                     depth (u16), generation (u32)
  depth > 0, index entries (12 bytes):
      ei_block (u32), ei_leaf_lo (u32), ei_leaf_hi (u16), unused (u16)
  depth == 0, leaf entries (12 bytes):
      ee_block (u32), ee_len (u16), ee_start_hi (u16), ee_start_lo (u32)
      ee_len > 32768 marks an unwritten (preallocated) extent of
      ee_len - 32768 blocks, which reads as zeros.

Indirect block map (i_block as 15 u32): 0-11 direct, 12 single indirect,
13 double indirect, 14 triple indirect. A zero pointer is a hole.

ファイルの論理ブロックからディスクブロックへの対応: エクステントツリーと ext2/3 の間接ブロック
マップ（レイアウトは上の表のとおり）。ee_len が 32768 を超えるエクステントは未書き込みでゼロと
して読める。間接マップはポインタ 0 が穴。
"""

from __future__ import annotations

import itertools
import struct
from collections.abc import Callable

from diskread.errors import DiskReadError
from diskread.fs.extents import MappedContent, Run

__all__ = ["MappedContent", "Run", "extent_runs", "indirect_runs"]

EXTENT_MAGIC = 0xF30A
EXTENT_INIT_MAX_LEN = 32768
MAX_EXTENT_DEPTH = 5


def extent_runs(i_block: bytes, read_block: Callable[[int], bytes], ino: int) -> list[Run]:
    """Runs of an extent-tree file, sorted by logical block and checked for overlap.

    エクステントツリー形式のファイルの run（論理ブロック順にソートし、重なりを検査）。
    """
    runs: list[Run] = []
    # A tree has one way to each block. The depth check alone stops a loop, but not
    # a node whose entries all name the same child: every level would multiply the work.
    seen: set[int] = set()

    def walk(node: bytes, expect_depth: int | None, level: int) -> None:
        magic, entries, max_entries, depth = struct.unpack_from("<HHHH", node, 0)
        if magic != EXTENT_MAGIC:
            raise DiskReadError(f"inode {ino}: bad extent header magic {magic:#x}")
        if expect_depth is not None and depth != expect_depth:
            raise DiskReadError(f"inode {ino}: extent tree depth mismatch")
        if depth > MAX_EXTENT_DEPTH or level > MAX_EXTENT_DEPTH:
            raise DiskReadError(f"inode {ino}: extent tree too deep")
        if entries > max_entries or 12 + 12 * entries > len(node):
            raise DiskReadError(f"inode {ino}: extent node overflows")
        for i in range(entries):
            off = 12 + 12 * i
            if depth == 0:
                lblk, length, start_hi, start_lo = struct.unpack_from("<IHHI", node, off)
                unwritten = length > EXTENT_INIT_MAX_LEN
                if unwritten:
                    length -= EXTENT_INIT_MAX_LEN
                if length:
                    runs.append(Run(lblk, start_lo | (start_hi << 32), length, unwritten))
            else:
                _, leaf_lo, leaf_hi = struct.unpack_from("<IIH", node, off)
                block = leaf_lo | (leaf_hi << 32)
                if block in seen:
                    raise DiskReadError(f"inode {ino}: extent tree block {block} reached twice")
                seen.add(block)
                walk(read_block(block), depth - 1, level + 1)

    walk(i_block, None, 0)
    runs.sort(key=lambda r: r.logical)
    for a, b in itertools.pairwise(runs):
        if a.logical + a.length > b.logical:
            raise DiskReadError(f"inode {ino}: overlapping extents")
    return runs


def indirect_runs(
    i_block: bytes, read_block: Callable[[int], bytes], block_size: int, nblocks: int, ino: int
) -> list[Run]:
    """Runs for a block-mapped file covering its first `nblocks` logical blocks.

    ブロックマップ形式のファイルの、先頭 `nblocks` 論理ブロック分の run。
    """
    ptrs_per_block = block_size // 4
    runs: list[Run] = []

    def add(logical: int, physical: int) -> None:
        if physical == 0:
            return
        last = runs[-1] if runs else None
        if (
            last
            and last.logical + last.length == logical
            and last.physical + last.length == physical
        ):
            runs[-1] = Run(last.logical, last.physical, last.length + 1)
        else:
            runs.append(Run(logical, physical, 1))

    # A map has one way to each indirect block. Without this, a triple indirect block
    # whose pointers all name one block would be gone through a thousand million times.
    seen: set[int] = set()

    def walk(block: int, level: int, logical: int) -> None:
        """Map the subtree under `block` (an indirect block at `level`) starting at `logical`."""
        if block == 0 or logical >= nblocks:
            return
        if block in seen:
            raise DiskReadError(f"inode {ino}: indirect block {block} reached twice")
        seen.add(block)
        ptrs = struct.unpack(f"<{ptrs_per_block}I", read_block(block))
        span = ptrs_per_block ** (level - 1)
        for i, p in enumerate(ptrs):
            start = logical + i * span
            if start >= nblocks:
                return
            if level == 1:
                add(start, p)
            else:
                walk(p, level - 1, start)

    direct = struct.unpack_from("<15I", i_block)
    for i in range(12):
        if i >= nblocks:
            return runs
        add(i, direct[i])
    logical = 12
    for level in (1, 2, 3):
        walk(direct[11 + level], level, logical)
        logical += ptrs_per_block**level
    return runs
