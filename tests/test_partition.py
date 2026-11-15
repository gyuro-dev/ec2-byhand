from __future__ import annotations

import json
import re
import struct
from pathlib import Path

import pytest
from conftest import golden_cases, require_golden

from diskread import BytesDevice, DiskReadError, FileDevice
from diskread.partition import read_partition_table

CASES = golden_cases(("gpt-", "mbr-"))


def _case_id(p: Path) -> str:
    return p.stem


@pytest.mark.parametrize("case", CASES or [None], ids=_case_id if CASES else None)
def test_matches_sfdisk(case: Path | None) -> None:
    require_golden(CASES, "build_partition.sh")
    assert case is not None
    expected = json.loads(case.read_text(encoding="utf-8"))["partitiontable"]

    with FileDevice(case.with_suffix(".img")) as dev:
        table = read_partition_table(dev)

    assert table is not None
    assert table.scheme == {"gpt": "gpt", "dos": "mbr"}[expected["label"]]
    assert table.disk_id.lower() == expected["id"].lower()
    assert table.sector_size == expected["sectorsize"]
    if table.scheme == "gpt":
        assert table.first_usable_lba == expected["firstlba"]
        assert table.last_usable_lba == expected["lastlba"]
        assert not table.used_backup_header

    assert len(table.partitions) == len(expected["partitions"])
    for exp in expected["partitions"]:
        number = int(re.search(r"(\d+)$", exp["node"]).group(1))
        got = table.get(number)
        assert got is not None, f"partition {number} missing"
        assert got.start_lba == exp["start"]
        assert got.size_lba == exp["size"]
        if table.scheme == "gpt":
            assert got.type == exp["type"]
            assert got.uuid == exp["uuid"]
            assert got.name == exp.get("name", "")
        else:
            assert int(got.type, 16) == int(exp["type"], 16)
            assert got.bootable == exp.get("bootable", False)


def _load(name: str) -> bytearray:
    path = Path(__file__).parent / "golden" / "out" / f"{name}.img"
    if not path.exists():
        pytest.skip("no golden images; run tools/golden/build_partition.sh")
    return bytearray(path.read_bytes())


def test_gpt_falls_back_to_backup_header() -> None:
    data = _load("gpt-al2023")
    data[512 : 512 + 8] = b"XXXXXXXX"  # break the primary header signature

    table = read_partition_table(BytesDevice(data))

    assert table is not None
    assert table.used_backup_header
    assert sorted(p.number for p in table.partitions) == [1, 127, 128]


def test_gpt_rejects_when_both_headers_are_broken() -> None:
    data = _load("gpt-al2023")
    data[512 : 512 + 8] = b"XXXXXXXX"
    data[-512 : -512 + 8] = b"XXXXXXXX"

    with pytest.raises(DiskReadError, match="all GPT headers"):
        read_partition_table(BytesDevice(data))


def test_gpt_detects_entry_array_corruption() -> None:
    data = _load("gpt-lvm")
    # Flip a byte in the primary entry array (LBA 2); the backup is intact.
    data[2 * 512 + 0x38] ^= 0xFF

    table = read_partition_table(BytesDevice(data))

    assert table is not None
    assert table.used_backup_header
    assert table.get(2).name == "データ"


def test_grown_disk_uses_backup_at_alternate_lba() -> None:
    data = _load("gpt-grown")
    data[2 * 512 + 0x38] ^= 0xFF  # damage the primary entry array only

    table = read_partition_table(BytesDevice(data))

    assert table is not None
    assert table.used_backup_header
    assert table.get(1).name == "root"
    # The last LBA of the grown disk holds no header at all.
    assert data[-512:-504] != b"EFI PART"


def test_no_boot_signature_means_unpartitioned() -> None:
    assert read_partition_table(BytesDevice(bytes(4096))) is None


def test_mbr_ebr_loop_is_rejected() -> None:
    sector = bytearray(512)
    sector[0x1FE:0x200] = b"\x55\xaa"
    # Slot 1: extended partition at LBA 1.
    sector[0x1BE + 4] = 0x05
    struct.pack_into("<II", sector, 0x1BE + 8, 1, 7)
    ebr = bytearray(512)
    ebr[0x1FE:0x200] = b"\x55\xaa"
    # Next-EBR entry points back at the extended start (relative offset 0).
    ebr[0x1BE + 16 + 4] = 0x05
    struct.pack_into("<II", ebr, 0x1BE + 16 + 8, 0, 1)
    disk = bytes(sector) + bytes(ebr) + bytes(512 * 6)

    with pytest.raises(DiskReadError, match="loops"):
        read_partition_table(BytesDevice(disk))
