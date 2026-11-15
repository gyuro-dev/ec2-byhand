"""LVM2 physical volume label and metadata area (on-disk binary parts).

Label (in one of the first 4 sectors, normally sector 1), little-endian:
  0x00  "LABELONE"
  0x08  sector number of this label (u64)
  0x10  CRC of bytes 0x14..end of sector (u32)
  0x14  offset of the PV header from the label start (u32), normally 0x20
  0x18  "LVM2 001"

PV header:
  uuid (32 ASCII chars, no dashes)
  device size in bytes (u64)
  data area list:     (offset u64, size u64)... terminated by (0, 0)
  metadata area list: (offset u64, size u64)... terminated by (0, 0)

Metadata area header (at the metadata area offset, 512 bytes):
  0x00  CRC of bytes 0x04..0x200 (u32)
  0x04  magic " LVM2 x[5A%r0N*>"
  0x14  version (u32) = 1
  0x18  start of this area in bytes (u64)
  0x20  size of this area in bytes (u64)
  0x28  raw locations: (offset u64, size u64, CRC u32, flags u32)... terminated by zeros

The text after the header is a ring buffer: older metadata versions stay
in it, and only raw location 0 points at the current one. A location may
wrap around the end of the area back to just after the header.

LVM2 の PV ラベルとメタデータ領域（ディスク上のバイナリ部分。レイアウトは上の表のとおり）。ヘ
ッダの後ろのテキストはリングバッファで、古い版も残っており、現行版は raw location 0 だけが指す
。位置は領域の端を越えてヘッダ直後へ折り返すことがある。
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

from diskread.blockdev import BlockDevice
from diskread.errors import DiskReadError, UnsupportedError, malformed_as_disk_read_error

SECTOR = 512
LABEL_SCAN_SECTORS = 4
LABEL_ID = b"LABELONE"
LABEL_TYPE = b"LVM2 001"
MDA_MAGIC = b" LVM2 x[5A%r0N*>"
MDA_HEADER_SIZE = 512
INITIAL_CRC = 0xF597A6CF
RAW_LOCN_IGNORED = 0x1
# Metadata text is a few KiB in practice; cap reads on corrupt sizes.
MAX_METADATA_TEXT = 64 << 20


def lvm_crc(data: bytes, initial: int = INITIAL_CRC) -> int:
    """LVM's CRC-32: the standard polynomial, but no pre/post inversion.

    zlib.crc32(data, c) computes ~update(~c, data), so feeding it the
    inverted seed and inverting the result gives the raw update.

    LVM の CRC-32: 多項式は標準だが前後の反転が無い。zlib.crc32(data, c) は ~update(~c, data)
    を計算するので、反転したシードを渡して結果を反転すると素の更新になる。
    """
    return ~zlib.crc32(data, ~initial & 0xFFFFFFFF) & 0xFFFFFFFF


def format_uuid(raw: str) -> str:
    """Insert dashes the way LVM prints UUIDs: 6-4-4-4-4-4-6.

    LVM の表示と同じ 6-4-4-4-4-4-6 の位置に UUID のダッシュを入れる。
    """
    if len(raw) != 32:
        raise DiskReadError(f"bad LVM UUID length: {raw!r}")
    parts, i = [], 0
    for n in (6, 4, 4, 4, 4, 4, 6):
        parts.append(raw[i : i + n])
        i += n
    return "-".join(parts)


@dataclass(frozen=True)
class DiskArea:
    """An (offset, size) byte range on the PV device.

    PV デバイス上の（オフセット, サイズ）のバイト範囲。
    """

    offset: int
    size: int


@dataclass(frozen=True)
class PVLabel:
    """The parsed PV label: uuid, device size, data and metadata areas.

    解析済みの PV ラベル: UUID・デバイスサイズ・データ / メタデータ領域。
    """

    label_sector: int
    uuid: str
    device_size: int
    data_areas: list[DiskArea]
    metadata_areas: list[DiskArea]


@dataclass(frozen=True)
class MetadataText:
    """The current metadata text and the metadata area it came from.

    現行のメタデータテキストと、その出どころのメタデータ領域。
    """

    text: str
    mda: DiskArea


def _read_areas(buf: bytes, pos: int) -> tuple[list[DiskArea], int]:
    """Read an (offset, size) list terminated by (0, 0); returns (areas, position after it)."""
    areas: list[DiskArea] = []
    while True:
        if pos + 16 > len(buf):
            raise DiskReadError("unterminated PV header area list")
        offset, size = struct.unpack_from("<QQ", buf, pos)
        pos += 16
        if offset == 0:
            return areas, pos
        areas.append(DiskArea(offset, size))


@malformed_as_disk_read_error
def read_label(dev: BlockDevice) -> PVLabel | None:
    """Return the PV label, or None if the device is not an LVM2 PV.

    PV ラベルを返す。LVM2 の PV でなければ None。
    """
    if dev.size < LABEL_SCAN_SECTORS * SECTOR:
        return None
    head = dev.read_at(0, LABEL_SCAN_SECTORS * SECTOR)
    for sector in range(LABEL_SCAN_SECTORS):
        buf = head[sector * SECTOR : (sector + 1) * SECTOR]
        if buf[:8] != LABEL_ID:
            continue
        sector_xl, crc_xl, offset_xl = struct.unpack_from("<QII", buf, 8)
        if sector_xl != sector:
            continue
        if lvm_crc(buf[0x14:]) != crc_xl:
            raise DiskReadError(f"LVM label CRC mismatch in sector {sector}")
        if buf[0x18:0x20] != LABEL_TYPE:
            raise UnsupportedError(f"unsupported LVM label type {buf[0x18:0x20]!r}")
        if not 0x20 <= offset_xl < SECTOR - 40:
            raise DiskReadError(f"bad PV header offset {offset_xl}")

        pos = offset_xl
        uuid = format_uuid(buf[pos : pos + 32].decode("ascii"))
        (device_size,) = struct.unpack_from("<Q", buf, pos + 32)
        data_areas, pos = _read_areas(buf, pos + 40)
        metadata_areas, _ = _read_areas(buf, pos)
        return PVLabel(sector, uuid, device_size, data_areas, metadata_areas)
    return None


@malformed_as_disk_read_error
def read_metadata_text(dev: BlockDevice, mda: DiskArea) -> MetadataText | None:
    """Read the current metadata text from one metadata area.

    Returns None if the area holds no metadata or is marked ignored.

    1 つのメタデータ領域から現行のメタデータテキストを読む。メタデータが無い、または ignored
    の印が付いていれば None。
    """
    header = dev.read_at(mda.offset, MDA_HEADER_SIZE)
    (crc,) = struct.unpack_from("<I", header, 0)
    if lvm_crc(header[4:]) != crc:
        raise DiskReadError(f"LVM metadata area header CRC mismatch at {mda.offset}")
    if header[4:20] != MDA_MAGIC:
        raise DiskReadError(f"bad LVM metadata area magic at {mda.offset}")
    version, start, size = struct.unpack_from("<IQQ", header, 0x14)
    if version != 1:
        raise UnsupportedError(f"unsupported LVM metadata area version {version}")
    if start != mda.offset:
        raise DiskReadError(f"metadata area at {mda.offset} claims to start at {start}")

    offset, length, text_crc, flags = struct.unpack_from("<QQII", header, 0x28)
    if offset == 0 or length == 0 or flags & RAW_LOCN_IGNORED:
        return None
    raw = read_ring(dev, start, size, offset, length)
    if lvm_crc(raw) != text_crc:
        raise DiskReadError(f"LVM metadata text CRC mismatch at {mda.offset}")
    # The stored text is NUL-terminated and the NUL is counted in length.
    return MetadataText(raw.split(b"\0", 1)[0].decode("utf-8"), mda)


def read_ring(dev: BlockDevice, start: int, size: int, offset: int, length: int) -> bytes:
    """Read `length` bytes at `offset` within a metadata ring buffer.

    The usable ring is [MDA_HEADER_SIZE, size) relative to `start`.

    メタデータのリングバッファ内の `offset` から `length` バイトを読む。使える範囲は `start`
    基準で [MDA_HEADER_SIZE, size)。
    """
    if length > MAX_METADATA_TEXT or length > size - MDA_HEADER_SIZE:
        raise DiskReadError(f"implausible LVM metadata size {length}")
    if not MDA_HEADER_SIZE <= offset < size:
        raise DiskReadError(f"LVM metadata offset {offset} outside its area")
    first = min(length, size - offset)
    data = dev.read_at(start + offset, first)
    if first < length:
        data += dev.read_at(start + MDA_HEADER_SIZE, length - first)
    return data
