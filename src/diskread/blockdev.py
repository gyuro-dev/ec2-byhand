"""The "disk" abstraction every parser reads through.

A block device is just a fixed-size byte range with random access. Image
files, partitions, LVM logical volumes and EBS snapshots all implement it,
so parsers never care where the bytes come from.

全パーサーが読み取りに使う「ディスク」の抽象。ブロックデバイスはランダムアクセスできる固定長の
バイト列にすぎず、イメージファイル・パーティション・LVM の論理ボリューム・EBS スナップショット
のどれも同じ形で扱える。
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO, Protocol, runtime_checkable

from diskread.errors import DiskReadError


@runtime_checkable
class BlockDevice(Protocol):
    """The read-only, random-access byte range every parser consumes.

    全パーサーが読む、読み取り専用でランダムアクセスできるバイト範囲。
    """

    @property
    def size(self) -> int:
        """Total size in bytes.

        全体のサイズ（バイト）。
        """
        ...

    def read_at(self, offset: int, length: int) -> bytes:
        """Read exactly `length` bytes at `offset`.

        Raises DiskReadError if the range extends past the end of the device.

        `offset` から `length` バイトちょうどを読む。範囲がデバイスの端を越えると
        DiskReadError。
        """
        ...


@runtime_checkable
class ReadAhead(Protocol):
    """A block device that can start fetching what it is told will be read next.

    次に読まれると告げられた範囲を、先に取り寄せ始められるブロックデバイス。
    """

    def will_read(self, offset: int, length: int) -> None:
        """Note that [offset, offset + length) is to be read, after what was noted before.

        [offset, offset + length) を、これまでに告げた範囲の後に読む予定だと伝える。
        """
        ...


def will_read(dev: BlockDevice, offset: int = 0, length: int | None = None) -> None:
    """Tell `dev` that [offset, offset + length) (by default, to the end) is to be read
    next, after the ranges told before, so that a device that reads over a network can
    fetch it ahead. Only a hint: nothing is read here, devices that cannot fetch ahead
    ignore it, and it never fails: a range the device does not have (damaged metadata
    that points past its end) is left to the read, which meets the error and reports
    it. Tell only what will be read, since what a device fetches ahead and nobody reads
    is fetched for nothing.

    `dev` に [offset, offset + length)（既定は末尾まで）を、先に告げた範囲の次に読むと伝え、
    ネットワーク越しに読むデバイスが先読みできるようにする。ヒントにすぎず、ここでは何も読まな
    い。先読みできないデバイスは無視する。失敗もしない: デバイスに無い範囲（壊れたメタデータが
    末尾の先を指している）は読み出しに任せ、そこでエラーになって報告される。先読みして誰も読ま
    なければ無駄になるので、本当に読む範囲だけを告げる。
    """
    if isinstance(dev, ReadAhead):
        with contextlib.suppress(DiskReadError):
            dev.will_read(offset, dev.size - offset if length is None else length)


def check_range(dev_size: int, offset: int, length: int) -> None:
    """Raise DiskReadError unless [offset, offset + length) fits in dev_size.

    [offset, offset + length) が dev_size に収まらなければ DiskReadError。
    """
    if offset < 0 or length < 0 or offset + length > dev_size:
        raise DiskReadError(f"read out of range: offset={offset} length={length} size={dev_size}")


def read_chunks(dev: BlockDevice, chunk_size: int = 1 << 20) -> Iterator[bytes]:
    """The device's bytes in order, a chunk at a time, for files too large to hold in memory.

    デバイスのバイト列を先頭から少しずつ返す（メモリに載せきれない大きなファイルのため）。
    """
    for offset in range(0, dev.size, chunk_size):
        yield dev.read_at(offset, min(chunk_size, dev.size - offset))


class FileDevice:
    """A block device backed by a local image file.

    ローカルのイメージファイルを背にしたブロックデバイス。
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        # Stays open until close() (or __exit__), so no `with` here.
        self._f: BinaryIO = Path(path).open("rb")  # noqa: SIM115
        self._size = os.fstat(self._f.fileno()).st_size

    @property
    def size(self) -> int:
        return self._size

    def read_at(self, offset: int, length: int) -> bytes:
        check_range(self._size, offset, length)
        self._f.seek(offset)
        data = self._f.read(length)
        if len(data) != length:
            raise DiskReadError(f"short read at offset {offset}")
        return data

    def close(self) -> None:
        """Close the underlying image file.

        下のイメージファイルを閉じる。
        """
        self._f.close()

    def __enter__(self) -> FileDevice:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class BytesDevice:
    """A block device held in memory. Mostly useful for tests.

    メモリ上のブロックデバイス。主にテスト用。
    """

    def __init__(self, data: bytes | bytearray) -> None:
        self._data = bytes(data)

    @property
    def size(self) -> int:
        return len(self._data)

    def read_at(self, offset: int, length: int) -> bytes:
        check_range(len(self._data), offset, length)
        return self._data[offset : offset + length]


class SliceDevice:
    """A sub-range of another block device, e.g. a partition.

    別のブロックデバイスの部分範囲。パーティションなど。
    """

    def __init__(self, parent: BlockDevice, offset: int, size: int) -> None:
        check_range(parent.size, offset, size)
        self._parent = parent
        self._offset = offset
        self._size = size

    @property
    def size(self) -> int:
        return self._size

    @property
    def offset(self) -> int:
        """Start of this slice within the parent device, in bytes.

        親デバイス内でのこのスライスの開始位置（バイト）。
        """
        return self._offset

    def read_at(self, offset: int, length: int) -> bytes:
        check_range(self._size, offset, length)
        return self._parent.read_at(self._offset + offset, length)

    def will_read(self, offset: int, length: int) -> None:
        check_range(self._size, offset, length)  # not what lies beside it on the parent
        will_read(self._parent, self._offset + offset, length)
