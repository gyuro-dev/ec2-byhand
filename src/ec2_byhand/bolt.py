"""A read-only reader for bbolt (BoltDB) files, as containerd keeps its metadata in.

The file is fixed-size pages. Pages 0 and 1 are meta pages; the valid one (magic,
version, FNV-1a checksum) with the higher transaction id holds the root bucket.
A bucket is a B+tree: branch pages point to child pages by key, leaf pages hold
key/value pairs. A leaf value flagged as a bucket is a nested bucket: its 16-byte
header names the root page, or, when that is 0, the bucket's own page follows the
header inline. Pages are copy-on-write, so a snapshot taken while the database is
being written still shows a whole transaction through the newer valid meta page.

bbolt（BoltDB）ファイルを読むだけの読み手。containerd がメタデータを置く形式。ファイルは固定長
のページで、0 と 1 がメタページ。正しい（マジック・版・FNV-1a のチェックサム）ほうのうち
トランザクション番号の大きいものがルートのバケットを持つ。バケットは B+ 木で、ブランチは
キーで子ページを指し、リーフはキーと値の組を持つ。バケットの印のある値は入れ子のバケットで、
16 バイトのヘッダがルートのページを指すか、0 ならその後ろにバケット自身のページが続く。
ページは書き換えずに新しく書かれるので、書き込み中に撮ったスナップショットでも、新しいほうの
正しいメタページから 1 つのトランザクションの全体が見える。
"""

from __future__ import annotations

import struct
from collections.abc import Iterator

from diskread.errors import DiskReadError

MAGIC = 0xED0CDAED
VERSION = 2
PAGE_HEADER = 16  # id u64, flags u16, count u16, overflow u32
PAGE_SIZES = (4096, 8192, 16384, 65536)  # where page 1 may be, page 0 unreadable
ELEMENT = 16  # branch: pos, ksize, pgid u64; leaf: flags, pos, ksize, vsize
BRANCH, LEAF, META = 0x01, 0x02, 0x04
BUCKET_LEAF = 0x01  # a leaf value that is a nested bucket
MAX_DEPTH = 64  # deeper than any real tree: corrupt pages must not loop


def _fnv1a64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


class Bolt:
    """A bbolt database held in memory, read by bucket path.

    メモリに読み込んだ bbolt のデータベース。バケットのパスで読む。
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        # Two meta pages, written in turn: page 0, and page 1 one page after it. When
        # page 0 is the one caught half-written, its page size is not to be had, and
        # page 1 is looked for at the sizes a page can have (the OS page size).
        first = self._meta(0)
        metas = [first] if first is not None else []
        for size in (first[0],) if first is not None else PAGE_SIZES:
            second = self._meta(size)
            if second is not None and second[0] == size:
                metas.append(second)
                break
        if not metas:
            raise DiskReadError("bolt: no valid meta page")
        self._page_size = metas[0][0]
        self._root = max(metas, key=lambda meta: meta[2])[1]  # of the newer transaction

    def _meta(self, offset: int) -> tuple[int, int, int] | None:
        """(page size, root page, txid) of the meta page at `offset`, if valid."""
        start = offset + PAGE_HEADER
        raw = self._data[start : start + 64]
        if len(raw) < 64:
            return None
        magic, version, page_size, _flags, root, _seq, _free, _pgid, txid, checksum = struct.unpack(
            "<IIIIQQQQQQ", raw
        )
        if magic != MAGIC or version != VERSION or checksum != _fnv1a64(raw[:56]):
            return None
        if page_size < 512 or page_size > 1 << 20:
            return None
        return page_size, root, txid

    def _page(self, pgid: int) -> tuple[int, int, bytes]:
        """(flags, count, the page's bytes) of page `pgid`, overflow pages included."""
        start = pgid * self._page_size
        header = self._data[start : start + PAGE_HEADER]
        if len(header) < PAGE_HEADER:
            raise DiskReadError(f"bolt: page {pgid} is past the end of the file")
        _id, flags, count, overflow = struct.unpack("<QHHI", header)
        end = start + (overflow + 1) * self._page_size
        return flags, count, self._data[start:end]

    def _items(
        self, page: bytes, flags: int, count: int, depth: int
    ) -> Iterator[tuple[bytes, bytes, int]]:
        """(key, value, leaf flags) of every pair under a page, in key order."""
        if depth > MAX_DEPTH:
            raise DiskReadError("bolt: tree too deep (corrupt pages?)")
        for i in range(count):
            at = PAGE_HEADER + i * ELEMENT
            if at + ELEMENT > len(page):
                raise DiskReadError("bolt: element past the end of its page")
            if flags & BRANCH:
                _pos, _ksize, child = struct.unpack_from("<IIQ", page, at)
                cflags, ccount, cpage = self._page(child)
                yield from self._items(cpage, cflags, ccount, depth + 1)
            elif flags & LEAF:
                lflags, pos, ksize, vsize = struct.unpack_from("<IIII", page, at)
                k = at + pos
                if k + ksize + vsize > len(page):
                    raise DiskReadError("bolt: key or value past the end of its page")
                yield page[k : k + ksize], page[k + ksize : k + ksize + vsize], lflags
            else:
                raise DiskReadError(f"bolt: page of unknown kind {flags:#x}")

    def _bucket_items(self, header: bytes | None, depth: int) -> Iterator[tuple[bytes, bytes, int]]:
        """The pairs of a bucket given its 16-byte header (None: the root bucket)."""
        if header is None:
            flags, count, page = self._page(self._root)
        else:
            if len(header) < 16:
                raise DiskReadError("bolt: bucket header too short")
            (root,) = struct.unpack_from("<Q", header, 0)
            if root == 0:  # inline: the bucket's page follows its header
                page = header[16:]
                if len(page) < PAGE_HEADER:
                    raise DiskReadError("bolt: inline bucket too short")
                _id, flags, count, _overflow = struct.unpack_from("<QHHI", page, 0)
            else:
                flags, count, page = self._page(root)
        yield from self._items(page, flags, count, depth)

    def bucket(self, *path: bytes) -> dict[bytes, bytes | None] | None:
        """The bucket at `path` (names from the root) as key -> value, a nested bucket's
        value None; None if there is no such bucket.

        `path`（ルートからの名前）にあるバケットを、キー → 値（入れ子のバケットは None）で返す。
        無ければ None。
        """
        header: bytes | None = None
        for depth, name in enumerate(path):
            found = None
            for key, value, flags in self._bucket_items(header, depth):
                if key == name:
                    found = (value, flags)
                    break
            if found is None or not found[1] & BUCKET_LEAF:
                return None
            header = found[0]
        return {
            key: None if flags & BUCKET_LEAF else value
            for key, value, flags in self._bucket_items(header, len(path))
        }
