from __future__ import annotations

import hashlib
import json
from contextlib import ExitStack
from pathlib import Path

import pytest
from conftest import GOLDEN_DIR, golden_cases, require_golden

from diskread import BlockDevice, BytesDevice, DiskReadError, FileDevice, UnsupportedError
from diskread.lvm import config, find_volume_groups, read_label
from diskread.lvm.label import MDA_HEADER_SIZE, lvm_crc, read_ring
from diskread.partition import read_partition_table

CASES = golden_cases(("lvm-",))
# Layouts our reader handles; everything else must raise UnsupportedError.
SUPPORTED_LAYOUTS = {"linear", "striped"}


def _sha256(dev: BlockDevice) -> str:
    h = hashlib.sha256()
    chunk = 1 << 20
    for off in range(0, dev.size, chunk):
        h.update(dev.read_at(off, min(chunk, dev.size - off)))
    return h.hexdigest()


def _open_pv_devices(stack: ExitStack, expected: dict) -> list[BlockDevice]:
    devs: list[BlockDevice] = []
    for image in expected["images"]:
        dev: BlockDevice = stack.enter_context(FileDevice(GOLDEN_DIR / image))
        if expected["partition"] is not None:
            table = read_partition_table(dev)
            assert table is not None
            dev = table.get(expected["partition"]).open(dev)
        devs.append(dev)
    return devs


@pytest.mark.parametrize("case", CASES or [None], ids=(lambda p: p.stem) if CASES else None)
def test_matches_lvm_tools(case: Path | None) -> None:
    require_golden(CASES, "build_lvm.sh")
    assert case is not None
    expected = json.loads(case.read_text(encoding="utf-8"))

    with ExitStack() as stack:
        devs = _open_pv_devices(stack, expected)
        vgs = find_volume_groups(devs)

        assert len(vgs) == 1
        vg = vgs[0]
        assert vg.name == expected["vg"]["name"]
        assert vg.uuid == expected["vg"]["uuid"]
        assert vg.extent_size == expected["vg"]["extent_size"]
        assert vg.seqno == expected["vg"]["seqno"]
        assert sorted(pv.uuid for pv in vg.pvs.values()) == sorted(
            p["uuid"] for p in expected["pvs"]
        )
        assert vg.missing_pvs == []

        assert sorted(vg.lvs) == sorted(lv["name"] for lv in expected["lvs"])
        for exp in expected["lvs"]:
            lv = vg.lvs[exp["name"]]
            assert lv.uuid == exp["uuid"]
            assert lv.size == exp["size"]
            assert len(lv.segments) == exp["segments"]
            assert lv.visible == (not exp["hidden"])
            if exp["layout"] in SUPPORTED_LAYOUTS:
                assert _sha256(vg.open_lv(exp["name"])) == exp["sha256"], exp["name"]
            else:
                with pytest.raises(UnsupportedError):
                    vg.open_lv(exp["name"])


def test_missing_pv_is_reported() -> None:
    case = GOLDEN_DIR / "lvm-multi.json"
    if not case.exists():
        pytest.skip("no golden images; run tools/golden/build_lvm.sh")
    with FileDevice(GOLDEN_DIR / "lvm-multi-a.img") as dev:
        (vg,) = find_volume_groups([dev])
        assert len(vg.missing_pvs) == 1
        with pytest.raises(DiskReadError, match="missing PV"):
            vg.open_lv("span")


def test_label_crc_mismatch_is_detected() -> None:
    path = GOLDEN_DIR / "lvm-whole.img"
    if not path.exists():
        pytest.skip("no golden images; run tools/golden/build_lvm.sh")
    data = bytearray(path.read_bytes()[: 1 << 20])
    data[512 + 0x30] ^= 0xFF  # inside the PV UUID, covered by the label CRC
    with pytest.raises(DiskReadError, match="label CRC"):
        read_label(BytesDevice(data))


def test_non_pv_returns_none() -> None:
    assert read_label(BytesDevice(bytes(8192))) is None
    assert find_volume_groups([BytesDevice(bytes(8192))]) == []


def test_lvm_crc_known_value() -> None:
    # Taken from the lvm-whole golden image: the label CRC of sector 1.
    path = GOLDEN_DIR / "lvm-whole.img"
    if not path.exists():
        pytest.skip("no golden images; run tools/golden/build_lvm.sh")
    sector = path.read_bytes()[512:1024]
    assert lvm_crc(sector[0x14:]) == int.from_bytes(sector[0x10:0x14], "little")


def test_ring_buffer_wraps_after_header() -> None:
    size = 2048
    area = bytearray(size)
    area[size - 4 :] = b"ABCD"
    area[MDA_HEADER_SIZE : MDA_HEADER_SIZE + 3] = b"EFG"
    dev = BytesDevice(bytes(100) + bytes(area))
    assert read_ring(dev, 100, size, size - 4, 7) == b"ABCDEFG"


def test_ring_rejects_offset_outside_area() -> None:
    dev = BytesDevice(bytes(4096))
    with pytest.raises(DiskReadError):
        read_ring(dev, 0, 2048, 4000, 10)


class TestConfigParser:
    def test_sections_values_and_comments(self) -> None:
        text = """
        vg {  # trailing comment
            id = "a-b"
            n = -3
            f = 1.5
            empty = []
            mixed = ["pv0", 0, "pv1", 10]
            app.v2+x_y { status = ["READ", "VISIBLE"] }
            1data { x = 1 }
        }
        contents = "Text Format # not a comment"
        """
        md = config.parse(text)
        vg = md["vg"]
        assert vg["id"] == "a-b"
        assert vg["n"] == -3
        assert vg["f"] == 1.5
        assert vg["empty"] == []
        assert vg["mixed"] == ["pv0", 0, "pv1", 10]
        assert vg["app.v2+x_y"] == {"status": ["READ", "VISIBLE"]}
        assert vg["1data"] == {"x": 1}
        assert md["contents"] == "Text Format # not a comment"

    def test_string_escapes(self) -> None:
        md = config.parse(r'description = "say \"hi\" \\ ok"')
        assert md["description"] == 'say "hi" \\ ok'

    @pytest.mark.parametrize(
        "text",
        ['a = "unterminated', "a {", "}", "a = [1 2]", "a = word", "a b"],
    )
    def test_malformed(self, text: str) -> None:
        with pytest.raises(DiskReadError):
            config.parse(text)


def _two_copy_image() -> tuple[bytearray, list[int]]:
    path = GOLDEN_DIR / "lvm-2mda.img"
    if not path.exists():
        pytest.skip("no golden images; run tools/golden/build_lvm.sh")
    data = bytearray(path.read_bytes())
    label = read_label(BytesDevice(data))
    assert label is not None
    assert len(label.metadata_areas) == 2
    return data, [m.offset for m in label.metadata_areas]


def test_damaged_metadata_copy_is_skipped_with_warning() -> None:
    data, (first, _second) = _two_copy_image()
    data[first + 0x30] ^= 0xFF  # break the first copy's header CRC

    (vg,) = find_volume_groups([BytesDevice(data)])

    assert vg.name == "gvg4"
    assert "root" in vg.lvs
    assert len(vg.warnings) == 1
    assert "CRC" in vg.warnings[0]


def test_all_metadata_copies_damaged_is_an_error() -> None:
    data, offsets = _two_copy_image()
    for off in offsets:
        data[off + 0x30] ^= 0xFF
    with pytest.raises(DiskReadError, match="CRC"):
        find_volume_groups([BytesDevice(data)])
