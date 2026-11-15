"""State of the XFS log: would mounting need log recovery to be accurate?

The internal log is a ring of 512-byte basic blocks. Each log record
starts with a header (big-endian):
  0x00 h_magicno 0xFEEDBABE   0x04 h_cycle      0x08 h_version
  0x0C h_len (data bytes)     0x10 h_lsn        0x18 h_tail_lsn
  0x28 h_num_logops           0x2C h_cycle_data[64]
  0x140 h_size (log buffer size, v2 logs)
LSNs are (cycle << 32 | basic block). The first word of every data sector
is overwritten on disk by the cycle number; the original words are kept
in h_cycle_data. So a 0xFEEDBABE at a sector start can only be a header,
and the newest header (highest LSN) is the log head.

Record data is h_num_logops operations (then padding): a 12-byte
big-endian op header (tid, len, clientid, flags) followed by `len` bytes. A transaction is a
"TRAN" header region, then for each logged item a format region (u16
type, u16 number of regions, ... in host byte order) and its data regions.

States:
  clean    the head record is a lone unmount record (xlog_check_unmount_rec)
  covered  everything from the tail to the head only re-logs the
           superblock: what fsfreeze and an idle filesystem leave behind.
           No file metadata is waiting in the log.
  dirty    anything else (e.g. a snapshot of a busy, mounted filesystem):
           the newest metadata may exist only in the log, which diskread
           does not replay.
Whenever parsing meets something unexpected, the answer is "dirty".

Finding the head without reading the whole log (it can be 2 GiB, i.e.
thousands of EBS Direct API reads): every sector carries the cycle number
it was last written in (word 0, or word 1 of a header), so the ring is
[cycle C ... C][C-1 ... C-1], like xlog_find_head assumes. A binary search
finds where the cycle changes; only the in-flight log buffers (at most 8
of 256 KiB, xfs_log.h) can blur that edge, so the newest header lies
within WINDOW_BB of it. The records from the tail are then read one by
one. If the cycles do not look like that, or the window holds no header,
the whole log is scanned instead (scan_all=True does that always and is
what the tests compare against).

XFS ログの状態: マウントしたらログ再生が要るか。clean はヘッドが unmount レコードだけ、covered
は tail から head までスーパーブロックの再ログだけ（fsfreeze 後やアイドル時の姿）、dirty はそ
れ以外で、解析が想定外に出会ったときも dirty。ヘッドはログ全体を読まずに探す: 各セクタに最後に
書かれたサイクル番号が入っているので二分探索で境界を見つけ、その近くの窓だけを調べる（詳細は上
の英語の段落）。
"""

from __future__ import annotations

import struct
from collections import OrderedDict
from collections.abc import Iterable
from typing import Literal

from diskread.blockdev import BlockDevice
from diskread.errors import DiskReadError, malformed_as_disk_read_error
from diskread.fs.xfs.superblock import Superblock

LogState = Literal["clean", "covered", "dirty"]

BBSIZE = 512
HEADER_MAGIC = 0xFEEDBABE
XLOG_VERSION_2 = 0x2
HEADER_CYCLE_SIZE = 32 * 1024
CYCLE_DATA_SLOTS = HEADER_CYCLE_SIZE // BBSIZE  # sectors covered by one header

OP_HEADER = struct.Struct(">IIBBH")  # tid, len, clientid, flags, pad
XLOG_COMMIT_TRANS = 0x02
XLOG_CONTINUE_TRANS = 0x04
XLOG_WAS_CONT_TRANS = 0x08
XLOG_UNMOUNT_TRANS = 0x20

TRANS_HEADER_MAGIC = 0x5452414E  # "TRAN", host byte order
XFS_LI_BUF = 0x123C
SUPERBLOCK_DADDR = 0


class _Dirty(Exception):
    """Internal: give up and report the log as dirty."""


# Max in-flight log buffers (XLOG_MAX_ICLOGS * XLOG_MAX_RECORD_BSIZE = 2 MiB)
# plus one record either side, in basic blocks.
WINDOW_BB = (8 * 256 * 1024 + 2 * 256 * 1024) // BBSIZE
CHUNK_BB = 128  # read and cache the log in 64 KiB pieces
# Pieces kept (16 MiB): more than the window around the head. A log that has to be
# scanned from end to end (2 GiB at most) must not stay in memory whole.
MAX_CHUNKS = 256


class _Ring:
    """The log as a ring of basic blocks, read on demand."""

    def __init__(self, dev: BlockDevice, start: int, nbb: int) -> None:
        if nbb <= 0:
            raise DiskReadError("XFS log of no blocks")
        self._dev, self._start, self.nbb = dev, start, nbb
        self._chunks: OrderedDict[int, bytes] = OrderedDict()

    def _chunk(self, i: int) -> bytes:
        """One cached chunk of the ring (the most recently used MAX_CHUNKS are kept)."""
        data = self._chunks.get(i)
        if data is None:
            first = i * CHUNK_BB
            n = min(CHUNK_BB, self.nbb - first)
            data = self._chunks[i] = self._dev.read_at(self._start + first * BBSIZE, n * BBSIZE)
            if len(self._chunks) > MAX_CHUNKS:
                self._chunks.popitem(last=False)
        else:
            self._chunks.move_to_end(i)
        return data

    def read(self, bb: int, count: int) -> bytes:
        """`count` basic blocks from `bb`, wrapping around the end."""
        out = bytearray()
        for i in range(count):
            b = (bb + i) % self.nbb
            off = (b % CHUNK_BB) * BBSIZE
            out += self._chunk(b // CHUNK_BB)[off : off + BBSIZE]
        return bytes(out)

    def cycle(self, bb: int) -> int:
        """The cycle number stamped on the basic block at `bb`."""
        word0, word1 = struct.unpack(">II", self.read(bb, 1)[:8])
        return int(word1 if word0 == HEADER_MAGIC else word0)

    def header_lsn(self, bb: int) -> int | None:
        """The LSN of a record header written at `bb`, else None."""
        head = self.read(bb, 1)
        magic, cycle = struct.unpack_from(">II", head, 0)
        if magic != HEADER_MAGIC:
            return None
        (lsn,) = struct.unpack_from(">Q", head, 0x10)
        # Ignore anything that is not a header written at this very block.
        return lsn if lsn >> 32 == cycle and lsn & 0xFFFFFFFF == bb else None


def _header_blocks(head: bytes) -> int:
    """How many basic blocks the record header at `head` occupies."""
    version = struct.unpack_from(">I", head, 0x08)[0]
    (h_size,) = struct.unpack_from(">I", head, 0x140)
    if version & XLOG_VERSION_2 and h_size > HEADER_CYCLE_SIZE:
        return int(-(-h_size // HEADER_CYCLE_SIZE))
    return 1


def _record_data(ring: _Ring, bb: int) -> bytes:
    """The data of the record at `bb`, with cycle-stamped words restored."""
    head = ring.read(bb, 1)
    (length,) = struct.unpack_from(">I", head, 0x0C)
    nsect = -(-length // BBSIZE)
    if nsect > CYCLE_DATA_SLOTS or _header_blocks(head) != 1:
        raise _Dirty  # large records need extended headers; never covering ones
    data = bytearray(ring.read(bb + 1, nsect))
    for i in range(nsect):
        data[i * BBSIZE : i * BBSIZE + 4] = head[0x2C + 4 * i : 0x30 + 4 * i]
    return bytes(data[:length])


def _only_superblock(data: bytes, num_ops: int) -> None:
    """Raise _Dirty unless every item in the first `num_ops` operations is
    the superblock buffer. (h_len is padded, so the op count, not the data
    length, says where the operations end.)"""
    pos = 0
    pending_data_regions = 0
    for _ in range(num_ops):
        if pos + OP_HEADER.size > len(data):
            raise _Dirty
        _tid, length, _client, flags, _ = OP_HEADER.unpack_from(data, pos)
        pos += OP_HEADER.size
        region = data[pos : pos + length]
        pos += length
        if len(region) != length or flags & (XLOG_CONTINUE_TRANS | XLOG_WAS_CONT_TRANS):
            raise _Dirty
        if length == 0 or flags & XLOG_COMMIT_TRANS:
            continue
        if pending_data_regions:
            pending_data_regions -= 1
            continue
        if length >= 4 and struct.unpack_from("<I", region, 0)[0] == TRANS_HEADER_MAGIC:
            continue
        if length < 16:
            raise _Dirty
        item_type, nregions = struct.unpack_from("<HH", region, 0)
        (blkno,) = struct.unpack_from("<q", region, 8)
        if item_type != XFS_LI_BUF or blkno != SUPERBLOCK_DADDR or nregions == 0:
            raise _Dirty
        pending_data_regions = nregions - 1


def _head_candidates(ring: _Ring) -> range | list[int] | None:
    """Basic blocks that may hold the newest header, or None to scan all."""
    nbb = ring.nbb
    first, last = ring.cycle(0), ring.cycle(nbb - 1)
    if first == last:
        edge = 0  # one cycle all round: the edge is at the wrap
    elif first == last + 1:
        lo, hi = 0, nbb - 1  # cycle(lo) != last, cycle(hi) == last
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if ring.cycle(mid) == last:
                hi = mid
            else:
                lo = mid
        edge = hi
    else:
        return None
    if nbb <= 2 * WINDOW_BB:
        return range(nbb)
    return [(edge + d) % nbb for d in range(-WINDOW_BB, WINDOW_BB)]


def _newest_header(ring: _Ring, candidates: Iterable[int]) -> tuple[int, int] | None:
    """The (basic block, LSN) of the newest record header among `candidates`, if any."""
    best: tuple[int, int] | None = None
    for bb in candidates:
        lsn = ring.header_lsn(bb)
        if lsn is not None and (best is None or lsn > best[1]):
            best = (bb, lsn)
    return best


@malformed_as_disk_read_error
def log_state(dev: BlockDevice, sb: Superblock, scan_all: bool = False) -> LogState | None:
    """The log's state, or None for an external log (not inspected).

    ログの状態。外部ログなら None（検査しない）。
    """
    if sb.log_start == 0:
        return None
    nbb = sb.log_blocks * sb.block_size // BBSIZE
    ring = _Ring(dev, sb.fsb_to_linear(sb.log_start) * sb.block_size, nbb)

    candidates = None if scan_all else _head_candidates(ring)
    newest = _newest_header(ring, candidates) if candidates is not None else None
    if newest is None:
        newest = _newest_header(ring, range(nbb))
    if newest is None:
        raise DiskReadError("XFS log has no valid record header")
    head_bb = newest[0]
    head = ring.read(head_bb, 1)

    # Clean: a lone unmount record at the head.
    (num_logops,) = struct.unpack_from(">I", head, 0x28)
    data_bb = head_bb + _header_blocks(head)
    if num_logops == 1 and ring.read(data_bb, 1)[9] & XLOG_UNMOUNT_TRANS:
        return "clean"

    # Covered: walk every record from the tail to the head.
    (tail_lsn,) = struct.unpack_from(">Q", head, 0x18)
    bb = (tail_lsn & 0xFFFFFFFF) % nbb
    try:
        for _ in range(nbb):
            if ring.header_lsn(bb) is None:
                raise _Dirty
            rec = ring.read(bb, 1)
            (ops,) = struct.unpack_from(">I", rec, 0x28)
            _only_superblock(_record_data(ring, bb), ops)
            if bb == head_bb:
                return "covered"
            (length,) = struct.unpack_from(">I", rec, 0x0C)
            bb = (bb + 1 + -(-length // BBSIZE)) % nbb
    except _Dirty:
        pass
    return "dirty"
