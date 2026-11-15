"""Snapshots of a mounted filesystem (built by tools/golden/build_dirty.sh).

The expected view is what the kernel shows after replaying the journal or
log. diskread does not replay, so recent changes may be missing or stale;
what must hold is: the snapshot is flagged as dirty, the walk completes,
and every file that was not touched recently is reported exactly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

import pytest
from conftest import GOLDEN_DIR, golden_cases, require_golden
from fs_golden import actual_entries, differences

from diskread import DiskReadError, FileDevice
from diskread.fs import Stat, walk
from diskread.fs.ext4 import Ext4
from diskread.fs.xfs import Xfs

CASES = golden_cases(("dirty-",))


@pytest.mark.parametrize("case", CASES or [None], ids=(lambda p: p.stem) if CASES else None)
def test_dirty_snapshot(case: Path | None) -> None:
    require_golden(CASES, "build_dirty.sh")
    assert case is not None
    expected = json.loads(case.read_text(encoding="utf-8"))
    touched = set(expected["touched"])
    exp = {e["path"]: e for e in expected["files"]}

    errors: list[tuple[bytes, DiskReadError]] = []
    with FileDevice(GOLDEN_DIR / expected["image"]) as dev:
        if case.stem.startswith("dirty-ext4"):
            fs = Ext4(dev)
            assert fs.superblock.needs_recovery
        else:
            fs = Xfs(dev)
            assert fs.log_state == "dirty"
        act = actual_entries(fs, on_error=lambda path, err: errors.append((path, err)))

    wrong = sorted(
        p
        for p in set(exp) | set(act)
        if (p not in exp or p not in act or exp[p] != {**exp[p], **act[p]}) and p not in touched
    )
    assert not wrong, f"untouched files misreported: {wrong[:10]}"
    # Read errors are tolerated only on recently touched paths.
    assert all(p.decode("utf-8", "surrogateescape") in touched for p, _ in errors), errors


class _BrokenFs:
    """Root with one good file, one inode that fails, and an unreadable dir."""

    root_ino = 1
    _STAT: ClassVar[dict[str, int | None]] = {
        "uid": 0,
        "gid": 0,
        "size": 0,
        "nlink": 1,
        "blocks": 0,
        "atime_ns": 0,
        "mtime_ns": 0,
        "ctime_ns": 0,
        "btime_ns": None,
        "rdev": None,
    }

    def stat(self, ino: int) -> Stat:
        if ino == 3:
            raise DiskReadError("inode 3: bad magic")
        mode = 0o040755 if ino in (1, 4) else 0o100644
        return Stat(ino=ino, mode=mode, **self._STAT)

    def listdir(self, ino: int) -> list[tuple[bytes, int]]:
        if ino == 4:
            raise DiskReadError("directory 4: bad block")
        return [(b"good", 2), (b"bad", 3), (b"dir", 4)]


def test_walk_reports_and_skips_errors() -> None:
    errors = []
    paths = [p for p, _, _ in walk(_BrokenFs(), lambda p, e: errors.append(p))]  # type: ignore[arg-type]
    assert paths == [b"/", b"/good", b"/dir"]
    assert errors == [b"/bad", b"/dir"]


def test_walk_raises_without_error_handler() -> None:
    with pytest.raises(DiskReadError, match="inode 3"):
        list(walk(_BrokenFs()))  # type: ignore[arg-type]


FROZEN = golden_cases(("frozen-",))


@pytest.mark.parametrize("case", FROZEN or [None], ids=(lambda p: p.stem) if FROZEN else None)
def test_frozen_snapshot_is_exact(case: Path | None) -> None:
    """fsfreeze before the snapshot: no warning, and an exact match."""
    require_golden(FROZEN, "build_dirty.sh")
    assert case is not None
    expected = json.loads(case.read_text(encoding="utf-8"))
    with FileDevice(GOLDEN_DIR / expected["image"]) as dev:
        if case.stem.startswith("frozen-ext4"):
            fs = Ext4(dev)
            assert not fs.superblock.needs_recovery
        else:
            fs = Xfs(dev)
            assert fs.log_state in ("clean", "covered")
        diffs = differences(fs, expected["files"])
    assert not diffs, "\n".join(diffs)


@pytest.mark.parametrize("prefix", ["dirty-ext4", "dirty-xfs"])
def test_manifest_warns_about_dirty_snapshot(prefix: str) -> None:
    from diskread.fs.detect import open_fs
    from diskread.source import SystemSource
    from ec2_byhand.analyze import Snapshot, analyze

    case = next((c for c in CASES if c.stem.startswith(prefix)), None)
    if case is None:
        pytest.skip("no golden data; run tools/golden/build_dirty.sh")
    with FileDevice(GOLDEN_DIR / f"{case.stem}.img") as dev:
        m = analyze(Snapshot(case.stem, SystemSource.from_fs(open_fs(dev))))
    dirty = [w for w in m["warnings"] if w["code"] == "dirty-snapshot"]
    assert dirty
    assert dirty[0]["mountpoint"] == "/"
    assert "freeze" in dirty[0]["message"]


def test_frozen_snapshot_has_no_dirty_warning() -> None:
    from diskread.fs.detect import open_fs
    from diskread.source import SystemSource
    from ec2_byhand.analyze import Snapshot, analyze

    for case in FROZEN:
        with FileDevice(GOLDEN_DIR / f"{case.stem}.img") as dev:
            m = analyze(Snapshot(case.stem, SystemSource.from_fs(open_fs(dev))))
        assert not [w for w in m["warnings"] if w["code"] == "dirty-snapshot"], case.stem
