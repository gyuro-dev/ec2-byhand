"""An EBS snapshot read through the EBS direct APIs, as a diskread BlockDevice.

ListSnapshotBlocks names every block the snapshot holds (512 KiB each) with
a token to read it; blocks it does not list were never written and read
as zeros, like a fresh volume. GetSnapshotBlock returns one block and its
SHA-256, which is checked. Blocks are cached (least recently used), since
filesystem metadata is read again and again.

Each GetSnapshotBlock is a billed request, so `stats` counts them. Block
tokens expire (ListSnapshotBlocks' ExpiryTime); when a read is refused,
the blocks are listed again and the read retried once. A block whose data
arrives cut short or fails its SHA-256 is asked for again, a few times.

One request at a time spends most of its time waiting for the answer, so
the blocks a caller says it will read next (will_read) are fetched ahead by
a few threads; read_at itself stays synchronous. Fetching ahead asks for no
block the reads would not: only the blocks told, each once, and a block
fetched ahead stays out of the cache until it is read, so the cache cannot
drop it and have it fetched again; nor does a full cache drop a block told
to be read again. The one exception is what a read given up half way leaves
unread (at most READ_AHEAD_BLOCKS blocks).

EBS direct APIs 越しに読む EBS スナップショットを、diskread の BlockDevice として見せる。一覧
（ListSnapshotBlocks）に無いブロックは書かれたことがなく、ゼロとして読める。GetSnapshotBlock
は 1 回ごとに課金されるので stats で数え、ブロックは LRU でキャッシュし、SHA-256 を照合する。
ブロックトークンが切れて読みを拒まれたら、一覧を取り直して 1 回だけやり直す。データが途中で切
れたり SHA-256 が合わなかったりしたブロックは、数回まで取り直す。1 回ずつ順に呼ぶと時間のほと
んどが応答待ちになるので、呼び出し側が次に読むと告げたブロック（will_read）は数スレッドで先読
みする（read_at は同期のまま）。先読みは読み出しが頼まないブロックを取らない: 告げられたブロッ
クだけを 1 回ずつ取り、読まれるまではキャッシュの外に置くので、キャッシュから落ちて取り直すこ
ともない。例外は、途中で読むのをやめた分（最大 READ_AHEAD_BLOCKS 個）だけ。
"""

from __future__ import annotations

import base64
import hashlib
import threading
from collections import Counter, OrderedDict, deque
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import IncompleteReadError, ReadTimeoutError, ResponseStreamingError

from diskread.blockdev import check_range
from diskread.errors import DiskReadError
from ec2_byhand.aws import READ_AHEAD_THREADS

LIST_PAGE = 10000  # ListSnapshotBlocks MaxResults upper limit
FETCH_ATTEMPTS = 3  # how often one block is asked for before its read is given up
READ_AHEAD_PER_THREAD = 4  # blocks fetched ahead and not yet read, at most, a thread
READ_AHEAD_BLOCKS = READ_AHEAD_PER_THREAD * READ_AHEAD_THREADS  # 128 (64 MiB) by default
# A connection that drops while the block's data is streamed. botocore's own retries
# are over by then: they cover the request, not the reading of its body.
_BROKEN_STREAM = (IncompleteReadError, ReadTimeoutError, ResponseStreamingError)


@dataclass
class EbsStats:
    """How many EBS direct API calls this device made, and for how many bytes.

    このデバイスが呼んだ EBS direct API の回数とバイト数。
    """

    list_requests: int = 0
    block_requests: int = 0
    block_bytes: int = 0


@dataclass
class _Ahead:
    """A block fetched ahead, and how many of the reads told are still to come."""

    future: Future[bytes]
    reads: int = 0


class EbsSnapshotDevice:
    """One EBS snapshot as a BlockDevice (see the module docstring).

    EBS スナップショット 1 つを BlockDevice として見せる（モジュール docstring 参照）。
    """

    def __init__(
        self,
        client: Any,
        snapshot_id: str,
        cache_blocks: int = 512,
        on_fetch: Callable[[], None] | None = None,
        threads: int = READ_AHEAD_THREADS,
    ) -> None:
        """`client` is a boto3 "ebs" client (threads may share one). The cache holds
        `cache_blocks` blocks (512 KiB each; 512 blocks = 256 MiB). `on_fetch` is called
        after each GetSnapshotBlock, for progress reports, one call at a time. `threads`
        fetch ahead what will_read is told, at most READ_AHEAD_PER_THREAD blocks a thread
        ahead of the reads; 0 never fetches ahead."""
        self._on_fetch = on_fetch
        self._client = client
        self.snapshot_id = snapshot_id
        self.stats = EbsStats()
        self._cache: OrderedDict[int, bytes] = OrderedDict()
        self._cache_blocks = cache_blocks
        # What the fetching threads share with the reader, under the lock.
        self._lock = threading.Lock()
        self._tokens: dict[int, str] = {}
        self._listings = 0  # how often the blocks were listed: who renews an expired token
        # Fetching ahead, which only the reader drives. Blocks are told and read in the
        # same order, a block read again right after itself counting once (blocks
        # never written left out): _told holds those not yet fetched, _next those
        # fetched or being fetched, and _ahead each of these blocks once.
        self._threads = threads
        self._window = READ_AHEAD_PER_THREAD * threads
        self._pool: ThreadPoolExecutor | None = None
        self._told: deque[int] = deque()
        self._waiting: Counter[int] = Counter()  # how often each block is in _told
        self._last_told: int | None = None
        self._next: deque[int] = deque()
        self._ahead: dict[int, _Ahead] = {}
        self._last_read: int | None = None
        volume_gib, self.block_size = self._list_blocks()
        self._size = volume_gib << 30

    @property
    def size(self) -> int:
        return self._size

    def _list_blocks(self) -> tuple[int, int]:
        """List every block's token; returns (volume GiB, block size)."""
        tokens: dict[int, str] = {}
        kwargs = {"SnapshotId": self.snapshot_id, "MaxResults": LIST_PAGE}
        while True:  # the ebs client has no paginator for this operation
            page = self._client.list_snapshot_blocks(**kwargs)
            self.stats.list_requests += 1
            for b in page.get("Blocks", []):
                tokens[b["BlockIndex"]] = b["BlockToken"]
            if not page.get("NextToken"):
                break
            kwargs["NextToken"] = page["NextToken"]
        self._tokens = tokens
        self._listings += 1
        return page["VolumeSize"], page["BlockSize"]

    def _fetch(self, index: int) -> bytes:
        """One block: zeros if never written, else from the API. A block that arrives
        broken (the connection dropped, or the data does not match its SHA-256) is asked
        for again: one bad transfer must not end a run of thousands, or pass for damage
        on the disk."""
        if index not in self._tokens:
            return bytes(self.block_size)  # never written
        for _ in range(FETCH_ATTEMPTS - 1):
            try:
                return self._get(index)
            except (DiskReadError, *_BROKEN_STREAM):
                continue
        return self._get(index)  # the last attempt: what it raises is the caller's

    def _get(self, index: int) -> bytes:
        """Get one listed block from the API, SHA-256 checked; an expired token is renewed."""
        with self._lock:
            token, listing = self._tokens.get(index), self._listings
        if token is None:  # the snapshot no longer lists it
            return bytes(self.block_size)
        try:
            resp = self._client.get_snapshot_block(
                SnapshotId=self.snapshot_id, BlockIndex=index, BlockToken=token
            )
        except self._client.exceptions.ValidationException:
            with self._lock:  # the token may have expired: listed again, once for all threads
                if self._listings == listing:
                    self._list_blocks()
                token = self._tokens.get(index)
            if token is None:
                return bytes(self.block_size)
            resp = self._client.get_snapshot_block(
                SnapshotId=self.snapshot_id, BlockIndex=index, BlockToken=token
            )
        with self._lock:
            self.stats.block_requests += 1  # billed whether or not the data arrives whole
        data: bytes = resp["BlockData"].read()
        with self._lock:
            self.stats.block_bytes += len(data)
            if self._on_fetch is not None:
                self._on_fetch()
        if len(data) != self.block_size:
            raise DiskReadError(
                f"{self.snapshot_id}: block {index} is {len(data)} bytes, not {self.block_size}"
            )
        if resp.get("ChecksumAlgorithm") == "SHA256":
            digest = base64.b64encode(hashlib.sha256(data).digest()).decode()
            if digest != resp.get("Checksum"):
                raise DiskReadError(f"{self.snapshot_id}: block {index} does not match its SHA-256")
        return data

    def _remember(self, index: int, data: bytes) -> None:
        """Put a block in the LRU cache. What a full cache drops is the oldest block not
        told to be read again: a block read once and told again further on (a small file
        sharing it, or the walk's metadata a verification reads later) would otherwise
        fall out before the read-ahead reaches it, and be fetched twice (on Ubuntu 24.04,
        363 of 6,064 requests)."""
        self._cache[index] = data
        if len(self._cache) > self._cache_blocks:
            victim = next((i for i in self._cache if i not in self._waiting), None)
            if victim is None:
                self._cache.popitem(last=False)
            else:
                del self._cache[victim]

    def _block(self, index: int) -> bytes:
        """One block: fetched ahead, from the LRU cache, or fetched now."""
        again = index == self._last_read
        if index in self._tokens:  # blocks never written do not count, as in will_read
            self._last_read = index
        ahead = self._ahead.get(index)
        if ahead is not None:
            # A block read again right after itself was told once and is not a new read.
            return ahead.future.result() if again else self._take(index)
        data = self._cache.get(index)
        if data is not None:
            self._cache.move_to_end(index)
            return data
        data = self._fetch(index)
        self._remember(index, data)
        return data

    def _fill(self) -> None:
        """Start fetching what was told, up to the window (READ_AHEAD_PER_THREAD blocks a
        thread) ahead of the
        reads. A block is held until the last read told of it, out of the cache, so that
        the cache cannot drop it in between."""
        while self._told and len(self._ahead) < self._window:
            index = self._told.popleft()
            self._waiting[index] -= 1
            if not self._waiting[index]:
                del self._waiting[index]
            ahead = self._ahead.get(index)
            if ahead is None:
                cached = self._cache.pop(index, None)
                future: Future[bytes]
                if cached is not None:
                    future = Future()
                    future.set_result(cached)
                else:
                    if self._pool is None:
                        self._pool = ThreadPoolExecutor(self._threads, "ebs-read-ahead")
                    future = self._pool.submit(self._fetch, index)
                ahead = self._ahead[index] = _Ahead(future)
            ahead.reads += 1
            self._next.append(index)

    def _take(self, index: int) -> bytes:
        """The next read told of a block fetched ahead. Reads told before it and not made
        (a read given up half way, or a read of this block not told) are passed over:
        a block with no read left goes to the cache, where a later read can find it."""
        while True:
            told = self._next.popleft()
            ahead = self._ahead[told]
            ahead.reads -= 1
            if told == index:
                break
            if ahead.reads == 0:
                del self._ahead[told]
                if ahead.future.exception() is None:
                    self._remember(told, ahead.future.result())
        # Keep the threads busy while this block is waited for. It stays in _ahead until
        # it is in the cache, so that a later read told of it is not fetched again.
        self._fill()
        try:
            # Raises what the fetch raised, as if made now; the block's other reads told
            # meet the same error, and a read after them asks again.
            data = ahead.future.result()
        finally:
            if ahead.reads == 0:
                del self._ahead[index]
        if ahead.reads == 0:
            self._remember(index, data)
        return data

    def will_read(self, offset: int, length: int) -> None:
        check_range(self._size, offset, length)
        if self._threads <= 0 or length == 0:
            return
        bs = self.block_size
        for index in range(offset // bs, (offset + length - 1) // bs + 1):
            if index != self._last_told and index in self._tokens:  # the rest read as zeros
                self._told.append(index)
                self._waiting[index] += 1
                self._last_told = index
        self._fill()

    def close(self) -> None:
        """Stop fetching ahead: forget what was told, cancel the fetches not yet started
        and wait for the others. The device can still be read.

        先読みをやめる: 告げられた範囲を忘れ、まだ始まっていない取得を取り消して、始まった分
        の終わりを待つ。その後も読み出しはできる。
        """
        self._told.clear()
        self._waiting.clear()
        self._last_told = None
        self._next.clear()
        for ahead in self._ahead.values():
            ahead.future.cancel()
        self._ahead.clear()
        if self._pool is not None:
            self._pool.shutdown(wait=True, cancel_futures=True)
            self._pool = None

    def read_at(self, offset: int, length: int) -> bytes:
        check_range(self._size, offset, length)
        bs = self.block_size
        out = bytearray()
        end = offset + length
        while offset < end:
            index, within = divmod(offset, bs)
            n = min(end - offset, bs - within)
            out += self._block(index)[within : within + n]
            offset += n
        return bytes(out)
