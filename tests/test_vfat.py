from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import GOLDEN_DIR, golden_cases, require_golden
from fs_golden import actual_entries

from diskread import BytesDevice, DiskReadError, FileDevice
from diskread.fs import lookup
from diskread.fs.fat import Vfat
from diskread.fs.fat.dirent import fat_time_ns, lfn_checksum

CASES = golden_cases(("vfat-",))


@pytest.mark.parametrize("case", CASES or [None], ids=(lambda p: p.stem) if CASES else None)
def test_matches_kernel(case: Path | None) -> None:
    require_golden(CASES, "build_vfat.sh")
    assert case is not None
    expected = json.loads(case.read_text(encoding="utf-8"))
    exp = {e["path"]: e for e in expected["files"]}
    with FileDevice(GOLDEN_DIR / expected["image"]) as dev:
        act = actual_entries(Vfat(dev, expected["mount_options"]))

    assert sorted(act) == sorted(exp)
    # Linux invents inode numbers for FAT; only the root's is fixed.
    assert act["/"]["ino"] == exp["/"]["ino"] == 1
    assert len({a["ino"] for a in act.values()}) == len(act)
    diffs = [
        f"{p} {k}: expected {exp[p][k]!r}, got {act[p][k]!r}"
        for p in sorted(exp)
        for k in act[p]
        if k != "ino" and exp[p][k] != act[p][k]
    ]
    assert not diffs, expected["mount_options"] + "\n" + "\n".join(diffs[:30])


def test_identity_matches_blkid_style() -> None:
    path = GOLDEN_DIR / "vfat-fat32.img"
    if not path.exists():
        pytest.skip("no golden images; run tools/golden/build_vfat.sh")
    with FileDevice(path) as dev:
        fs = Vfat(dev)
        assert fs.label == "EFI"
        assert len(fs.uuid) == 9
        assert fs.uuid[4] == "-"
        assert fs.open(lookup(fs, "/EFI/amzn/grub.cfg")).read_at(0, 6) == b"search"


def test_kernel_time_rules() -> None:
    assert fat_time_ns(0, (0 << 9) | (1 << 5) | 1, 0, 0) == 315532800 * 10**9  # 1980-01-01
    assert fat_time_ns(0, 0, 0, 0) == 315532800 * 10**9  # month/day 0 clamp to 1
    assert (
        fat_time_ns(1, (0 << 9) | (1 << 5) | 1, 150, 0) == (315532800 + 2 + 1) * 10**9 + 500_000_000
    )
    assert fat_time_ns(0, (0 << 9) | (1 << 5) | 1, 0, 9 * 3600) == (315532800 - 9 * 3600) * 10**9


def test_lfn_checksum() -> None:
    assert lfn_checksum(b"LONGFI~1TXT") == lfn_checksum(b"LONGFI~1TXT")
    assert lfn_checksum(b"README  TXT") != lfn_checksum(b"README  TX ")


def test_rejects_non_fat() -> None:
    with pytest.raises(DiskReadError, match="not a FAT"):
        Vfat(BytesDevice(bytes(4096)))
