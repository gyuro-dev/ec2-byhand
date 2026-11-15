"""XFS log_state: the bounded head search must agree with a full scan of
the log, while reading only a few MiB of it (EBS Direct API reads cost a
request per 512 KiB)."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import GOLDEN_DIR
from sparse_image import open_image

from diskread.fs.xfs import Xfs
from diskread.fs.xfs import log as xlog

IMAGES = (
    sorted(
        p
        for p in GOLDEN_DIR.iterdir()
        if p.name.startswith(("xfs-", "dirty-xfs-", "frozen-xfs", "wrapped-xfs-"))
        and p.name.endswith((".img", ".img.sparse.gz"))
    )
    if GOLDEN_DIR.exists()
    else []
)


class _Counting:
    def __init__(self, dev) -> None:
        self._dev, self.size, self.bytes = dev, dev.size, 0

    def read_at(self, offset: int, length: int) -> bytes:
        self.bytes += length
        return self._dev.read_at(offset, length)


@pytest.mark.parametrize(
    "image", IMAGES or [None], ids=(lambda p: p.name.split(".")[0]) if IMAGES else None
)
def test_bounded_search_agrees_with_full_scan(image: Path | None) -> None:
    if image is None:
        pytest.skip("no golden images; run tools/golden/build_fs.sh and build_dirty.sh")
    with open_image(image) as dev:
        sb = Xfs(dev).superblock
        if sb.log_start == 0:
            pytest.skip("external log")
        counting = _Counting(dev)
        assert xlog.log_state(counting, sb) == xlog.log_state(dev, sb, scan_all=True)
        log_bytes = sb.log_blocks * sb.block_size
        if log_bytes > 4 * xlog.WINDOW_BB * xlog.BBSIZE:  # large enough for the search to matter
            assert counting.bytes < 8 << 20, (counting.bytes, log_bytes)


def _head_cycle(dev, sb) -> int:
    ring = xlog._Ring(
        dev,
        sb.fsb_to_linear(sb.log_start) * sb.block_size,
        sb.log_blocks * sb.block_size // xlog.BBSIZE,
    )
    _, lsn = xlog._newest_header(ring, range(ring.nbb))
    return lsn >> 32


@pytest.mark.parametrize(
    ("name", "states"),
    [
        ("wrapped-xfs-clean", {"clean"}),
        ("wrapped-xfs-frozen", {"clean", "covered"}),
        ("wrapped-xfs-0s", {"dirty"}),
    ],
)
def test_wrapped_log(name: str, states: set[str]) -> None:
    path = GOLDEN_DIR / f"{name}.img"
    if not path.exists():
        pytest.skip("no golden image; run tools/golden/build_dirty.sh")
    with open_image(path) as dev:
        fs = Xfs(dev)
        sb = fs.superblock
        assert _head_cycle(dev, sb) >= 3  # the ring went round at least twice
        counting = _Counting(dev)
        assert xlog.log_state(counting, sb) in states
        assert counting.bytes < sb.log_blocks * sb.block_size // 2
