"""Golden images packed by tools/golden/sparse_pack.py, as block devices."""

from __future__ import annotations

import bisect
import importlib.util
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from diskread import FileDevice
from diskread.blockdev import BlockDevice, check_range

_spec = importlib.util.spec_from_file_location(
    "sparse_pack", Path(__file__).parent.parent / "tools" / "golden" / "sparse_pack.py"
)
assert _spec is not None
assert _spec.loader is not None
sparse_pack = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sparse_pack)


class SparseDevice:
    """Stored chunks at their offsets; zeros everywhere else."""

    def __init__(self, path: Path) -> None:
        self._size, records = sparse_pack.load(str(path))
        self._starts = [off for off, _ in records]
        self._chunks = [data for _, data in records]

    @property
    def size(self) -> int:
        return self._size

    def read_at(self, offset: int, length: int) -> bytes:
        check_range(self._size, offset, length)
        out = bytearray(length)
        i = max(bisect.bisect_right(self._starts, offset) - 1, 0)
        end = offset + length
        while i < len(self._starts) and self._starts[i] < end:
            start, data = self._starts[i], self._chunks[i]
            lo, hi = max(start, offset), min(start + len(data), end)
            if lo < hi:
                out[lo - offset : hi - offset] = data[lo - start : hi - start]
            i += 1
        return bytes(out)


@contextmanager
def open_image(path: Path) -> Iterator[BlockDevice]:
    if path.name.endswith(".sparse.gz"):
        yield SparseDevice(path)
    else:
        with FileDevice(path) as dev:
            yield dev
