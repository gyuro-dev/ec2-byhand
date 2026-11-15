"""GUID Partition Table (UEFI spec, chapter 5.3).

Header (LBA 1, backup at the last LBA), little-endian:
  0x00  signature "EFI PART"
  0x08  revision (u32)
  0x0C  header size (u32)
  0x10  header CRC32 (u32), computed with this field zeroed
  0x18  this header's LBA (u64)
  0x20  the other header's LBA (u64)
  0x28  first usable LBA (u64)
  0x30  last usable LBA (u64)
  0x38  disk GUID (16)
  0x48  partition entry array LBA (u64)
  0x50  number of entries (u32)
  0x54  size of one entry (u32)
  0x58  entry array CRC32 (u32)

Partition entry:
  0x00  type GUID (16), all zero = unused
  0x10  unique GUID (16)
  0x20  first LBA (u64)
  0x28  last LBA, inclusive (u64)
  0x30  attributes (u64)
  0x38  name, UTF-16LE, 72 bytes

GUID パーティションテーブル（UEFI 仕様 5.3 章。レイアウトは上の表のとおり）。
"""

from __future__ import annotations

import struct
import uuid
import zlib
from dataclasses import dataclass

from diskread.blockdev import BlockDevice
from diskread.errors import DiskReadError
from diskread.partition import Partition, PartitionTable

SIGNATURE = b"EFI PART"
MIN_HEADER_SIZE = 92
MIN_ENTRY_SIZE = 128
# 128 on every real disk. The array is read whole (entries * size): a size that is
# damage must not have that read gigabytes.
MAX_ENTRY_SIZE = 4096
# Real tables have 128 entries; anything far above that is corruption.
MAX_ENTRIES = 4096


@dataclass(frozen=True)
class _Header:
    """The fields of one GPT header this reader uses."""

    my_lba: int
    alternate_lba: int
    first_usable_lba: int
    last_usable_lba: int
    disk_guid: str
    entries_lba: int
    num_entries: int
    entry_size: int
    entries_crc: int


def _guid(raw: bytes) -> str:
    # GUIDs on disk store their first three fields little-endian.
    """A GUID as canonical upper-case text (the first three fields are little-endian on disk)."""
    return str(uuid.UUID(bytes_le=raw)).upper()


def _read_header(dev: BlockDevice, lba: int, sector_size: int) -> _Header:
    """Read and CRC-check the GPT header at `lba`."""
    raw = dev.read_at(lba * sector_size, sector_size)
    if raw[:8] != SIGNATURE:
        raise DiskReadError(f"no GPT signature at LBA {lba}")
    (header_size,) = struct.unpack_from("<I", raw, 0x0C)
    if not MIN_HEADER_SIZE <= header_size <= sector_size:
        raise DiskReadError(f"bad GPT header size {header_size} at LBA {lba}")
    (stored_crc,) = struct.unpack_from("<I", raw, 0x10)
    zeroed = raw[:0x10] + b"\0\0\0\0" + raw[0x14:header_size]
    if zlib.crc32(zeroed) != stored_crc:
        raise DiskReadError(f"GPT header CRC mismatch at LBA {lba}")

    my_lba, alternate_lba, first_usable, last_usable = struct.unpack_from("<QQQQ", raw, 0x18)
    if my_lba != lba:
        raise DiskReadError(f"GPT header at LBA {lba} claims to be at LBA {my_lba}")
    disk_guid = _guid(raw[0x38:0x48])
    entries_lba, num_entries, entry_size, entries_crc = struct.unpack_from("<QIII", raw, 0x48)
    if not MIN_ENTRY_SIZE <= entry_size <= MAX_ENTRY_SIZE or entry_size % 8 != 0:
        raise DiskReadError(f"bad GPT entry size {entry_size}")
    if num_entries > MAX_ENTRIES:
        raise DiskReadError(f"implausible GPT entry count {num_entries}")
    return _Header(
        my_lba=my_lba,
        alternate_lba=alternate_lba,
        first_usable_lba=first_usable,
        last_usable_lba=last_usable,
        disk_guid=disk_guid,
        entries_lba=entries_lba,
        num_entries=num_entries,
        entry_size=entry_size,
        entries_crc=entries_crc,
    )


def _read_entries(dev: BlockDevice, h: _Header, sector_size: int) -> list[Partition]:
    """Read and CRC-check the partition entry array, skipping unused slots."""
    array = dev.read_at(h.entries_lba * sector_size, h.num_entries * h.entry_size)
    if zlib.crc32(array) != h.entries_crc:
        raise DiskReadError(f"GPT entry array CRC mismatch at LBA {h.entries_lba}")

    out: list[Partition] = []
    for i in range(h.num_entries):
        e = array[i * h.entry_size : (i + 1) * h.entry_size]
        type_raw = e[0x00:0x10]
        if type_raw == b"\0" * 16:
            continue
        first_lba, last_lba, attributes = struct.unpack_from("<QQQ", e, 0x20)
        if last_lba < first_lba:
            raise DiskReadError(f"GPT entry {i + 1} ends before it starts")
        name = e[0x38:0x80].decode("utf-16-le", errors="replace").split("\0", 1)[0]
        out.append(
            Partition(
                number=i + 1,
                start_lba=first_lba,
                size_lba=last_lba - first_lba + 1,
                sector_size=sector_size,
                type=_guid(type_raw),
                uuid=_guid(e[0x10:0x20]),
                name=name,
                attributes=attributes,
            )
        )
    return out


def read(dev: BlockDevice, sector_size: int = 512) -> PartitionTable:
    """Parse the primary GPT, falling back to the backup if the primary is damaged.

    The backup is looked for where the primary header says it is
    (alternate_lba) and at the last LBA. They differ when a disk was grown
    without moving the backup (an EBS volume resized without growpart).

    プライマリ GPT を読み、壊れていればバックアップへフォールバックする。バックアップはプライ
    マリヘッダの alternate_lba の位置と最終 LBA の両方で探す（growpart せずに拡張した EBS ボリ
    ュームでは両者がずれる）。
    """
    last_lba = dev.size // sector_size - 1
    used_backup = False
    primary: _Header | None = None
    try:
        primary = _read_header(dev, 1, sector_size)
        header = primary
        partitions = _read_entries(dev, header, sector_size)
    except DiskReadError as primary_err:
        candidates = [last_lba]
        if primary is not None and 1 < primary.alternate_lba < last_lba:
            candidates.insert(0, primary.alternate_lba)
        errors = [f"primary: {primary_err}"]
        for lba in candidates:
            try:
                header = _read_header(dev, lba, sector_size)
                partitions = _read_entries(dev, header, sector_size)
                break
            except DiskReadError as err:
                errors.append(f"backup at LBA {lba}: {err}")
        else:
            raise DiskReadError("all GPT headers are unusable: " + "; ".join(errors))
        used_backup = True

    return PartitionTable(
        scheme="gpt",
        disk_id=header.disk_guid,
        sector_size=sector_size,
        partitions=partitions,
        first_usable_lba=header.first_usable_lba,
        last_usable_lba=header.last_usable_lba,
        used_backup_header=used_backup,
    )
