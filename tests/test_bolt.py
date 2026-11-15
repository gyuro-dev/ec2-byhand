"""ec2_byhand.bolt against a real containerd meta.db, and against small databases built
here for what that one lacks (branch pages, a damaged meta page)."""

from __future__ import annotations

import gzip
import struct
from pathlib import Path

import pytest

from diskread.errors import DiskReadError
from ec2_byhand.bolt import BRANCH, BUCKET_LEAF, LEAF, MAGIC, META, Bolt, _fnv1a64

DATA = Path(__file__).parent / "data"
PAGE = 4096


def _meta(pgid: int, root: int, txid: int, *, damaged: bool = False) -> bytes:
    body = struct.pack("<IIIIQQQQQ", MAGIC, 2, PAGE, 0, root, 0, 0, 10, txid)
    checksum = _fnv1a64(body) ^ (1 if damaged else 0)
    page = struct.pack("<QHHI", pgid, META, 0, 0) + body + struct.pack("<Q", checksum)
    return page.ljust(PAGE, b"\0")


def _leaf(pgid: int, items: list[tuple[bytes, bytes, int]]) -> bytes:
    """A leaf page: (key, value, flags) pairs, the data after the elements."""
    head = struct.pack("<QHHI", pgid, LEAF, len(items), 0)
    elements, data = b"", b""
    for i, (key, value, flags) in enumerate(items):
        pos = (len(items) - i) * 16 + len(data)  # from this element to its key
        elements += struct.pack("<IIII", flags, pos, len(key), len(value))
        data += key + value
    return head + elements + data


def _branch(pgid: int, children: list[tuple[bytes, int]]) -> bytes:
    head = struct.pack("<QHHI", pgid, BRANCH, len(children), 0)
    elements, data = b"", b""
    for i, (key, child) in enumerate(children):
        pos = (len(children) - i) * 16 + len(data)
        elements += struct.pack("<IIQ", pos, len(key), child)
        data += key
    return head + elements + data


def _bucket(root: int) -> bytes:
    return struct.pack("<QQ", root, 0)


def _database(*, newer_meta_damaged: bool = False, branch_to: int = 4) -> bytes:
    inline = _bucket(0) + _leaf(0, [(b"x", b"1", 0)])
    pages = [
        _meta(0, root=2, txid=1),
        _meta(1, root=99 if newer_meta_damaged else 2, txid=2, damaged=newer_meta_damaged),
        _leaf(2, [(b"b", _bucket(3), BUCKET_LEAF)]),
        _branch(3, [(b"a", branch_to), (b"m", 5)]),
        _leaf(4, [(b"a", b"apple", 0), (b"inl", inline, BUCKET_LEAF)]),
        _leaf(5, [(b"m", b"melon", 0), (b"z", b"zucchini", 0)]),
    ]
    return b"".join(p.ljust(PAGE, b"\0") for p in pages)


def test_a_bucket_split_over_branch_pages_reads_whole() -> None:
    db = Bolt(_database())
    assert db.bucket() == {b"b": None}
    assert db.bucket(b"b") == {b"a": b"apple", b"inl": None, b"m": b"melon", b"z": b"zucchini"}
    assert db.bucket(b"b", b"inl") == {b"x": b"1"}  # an inline bucket
    assert db.bucket(b"b", b"a") is None  # a value, not a bucket
    assert db.bucket(b"nope") is None


def test_a_damaged_newer_meta_page_falls_back_to_the_other() -> None:
    # Torn while being written: its checksum fails, and the older one is used.
    assert Bolt(_database(newer_meta_damaged=True)).bucket(b"b", b"inl") == {b"x": b"1"}


def test_no_valid_meta_page_and_pages_past_the_end_are_errors() -> None:
    with pytest.raises(DiskReadError, match="no valid meta"):
        Bolt(b"\0" * PAGE * 2)
    db = Bolt(_database(branch_to=999))
    with pytest.raises(DiskReadError, match="past the end"):
        db.bucket(b"b")


def test_a_real_containerd_database() -> None:
    # Ubuntu 24.04's containerd after `ctr images pull docker.io/library/redis:7-alpine`,
    # `ctr run -d ... credis`, and in the k8s.io namespace `ctr images pull
    # docker.io/library/busybox:1.36` and `ctr containers create ... kbox` (2026-11-14).
    db = Bolt(gzip.decompress((DATA / "containerd-meta.db.gz").read_bytes()))
    assert set(db.bucket(b"v1") or {}) == {b"default", b"k8s.io", b"version"}
    assert set(db.bucket(b"v1", b"default", b"images") or {}) == {
        b"docker.io/library/redis:7-alpine"
    }
    credis = db.bucket(b"v1", b"default", b"containers", b"credis") or {}
    assert credis[b"image"] == b"docker.io/library/redis:7-alpine"
    assert len(db.bucket(b"v1", b"k8s.io", b"images") or {}) == 2  # a tag and CRI's id alias
