"""Extent runs and reading a file's bytes through them (shared by ext4 and XFS).

エクステントの run と、それ越しのファイル読み出し（ext4 と XFS で共用）。
"""

from __future__ import annotations

import bisect
from collections.abc import Iterator
from dataclasses import dataclass

from diskread.blockdev import BlockDevice, check_range, will_read


@dataclass(frozen=True)
class Run:
    """One contiguous mapping: `length` blocks from `logical` on to `physical` on disk.

    連続した 1 区間の対応: 論理 `logical` からディスク上の `physical` へ `length` ブロック。
    """

    logical: int  # first logical block
    physical: int  # first disk block, counted linearly from the start of the device
    length: int  # in blocks
    unwritten: bool = False


class MappedContent:
    """A file's bytes as a block device: runs of disk blocks, holes as zeros.

    ファイルのバイト列をブロックデバイスとして見せる: ディスクブロックの run の並びで、穴はゼ
    ロ。
    """

    def __init__(self, dev: BlockDevice, block_size: int, runs: list[Run], size: int) -> None:
        self._dev = dev
        self._bs = block_size
        self._runs = runs
        self._starts = [r.logical for r in runs]
        self._size = size

    @property
    def size(self) -> int:
        return self._size

    def is_mapped(self, offset: int) -> bool:
        """Whether the byte at `offset` is backed by a run (written or not).

        `offset` のバイトが run に載っているか（書き込み済みかは問わない）。
        """
        blk = offset // self._bs
        i = bisect.bisect_right(self._starts, blk) - 1
        return i >= 0 and blk < self._runs[i].logical + self._runs[i].length

    def is_written(self, offset: int) -> bool:
        """Whether the byte at `offset` is in a written (not hole, not unwritten) run.

        `offset` のバイトが書き込み済みの run にあるか（穴でも未書き込みでもない）。
        """
        blk = offset // self._bs
        i = bisect.bisect_right(self._starts, blk) - 1
        if i < 0:
            return False
        run = self._runs[i]
        return blk < run.logical + run.length and not run.unwritten

    def offsets(self, step: int, written: bool = False) -> Iterator[int]:
        """The multiples of `step` below the size that lie in a run (with `written`, in a
        written one), in order: the blocks of a directory that are there to read. Found
        by the runs, not by stepping through the size: what a damaged inode calls its
        size may be a hole of terabytes.

        サイズ未満の `step` の倍数のうち、run に載っているもの（`written` なら書き込み済みの
        run）を順に返す。ディレクトリの、読むべきブロックの位置。サイズを端から刻むのではなく
        run から求める: 壊れた inode の言うサイズは、テラバイトの穴かもしれない。
        """
        bs = self._bs
        end = self._size - self._size % step
        for run in self._runs:
            if written and run.unwritten:
                continue
            first = -(-run.logical * bs // step) * step
            yield from range(first, min((run.logical + run.length) * bs, end), step)

    def _pieces(self, offset: int, length: int) -> Iterator[tuple[int | None, int]]:
        """[offset, offset + length) as (disk offset, bytes) in order; None for zeros
        (a hole, or an unwritten run)."""
        bs = self._bs
        end = offset + length
        while offset < end:
            blk, within = divmod(offset, bs)
            i = bisect.bisect_right(self._starts, blk) - 1
            run = self._runs[i] if i >= 0 else None
            if run is not None and blk < run.logical + run.length:
                n = min(end - offset, (run.logical + run.length) * bs - offset)
                phys = None if run.unwritten else (run.physical + blk - run.logical) * bs + within
                yield phys, n
            else:
                # In a hole: zeros up to the next run (or the end).
                nxt = self._starts[i + 1] * bs if i + 1 < len(self._runs) else end
                n = min(end, nxt) - offset
                yield None, n
            offset += n

    def read_at(self, offset: int, length: int) -> bytes:
        check_range(self._size, offset, length)
        out = bytearray()
        for phys, n in self._pieces(offset, length):
            out += bytes(n) if phys is None else self._dev.read_at(phys, n)
        return bytes(out)

    def will_read(self, offset: int, length: int) -> None:
        check_range(self._size, offset, length)
        for phys, n in self._pieces(offset, length):
            if phys is not None:
                will_read(self._dev, phys, n)
