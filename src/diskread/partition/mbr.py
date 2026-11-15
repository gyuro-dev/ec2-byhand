"""MBR partition table, including the EBR chain of an extended partition.

Layout of LBA 0:
  0x1B8  disk signature (u32)
  0x1BE  four 16-byte partition entries
  0x1FE  boot signature 0x55 0xAA

Partition entry:
  0x00  status (0x80 = bootable)
  0x04  type
  0x08  first LBA (u32)
  0x0C  number of sectors (u32)

MBR パーティションテーブル。拡張パーティションの EBR チェーンも辿る（レイアウトは上の表のとお
り）。
"""

from __future__ import annotations

import struct

from diskread.blockdev import BlockDevice
from diskread.errors import DiskReadError
from diskread.partition import Partition, PartitionTable

TYPE_EMPTY = 0x00
TYPE_GPT_PROTECTIVE = 0xEE
EXTENDED_TYPES = frozenset({0x05, 0x0F, 0x85})

# How many EBRs of a chain are followed: a real disk has a handful of logical
# partitions, and a damaged chain must end somewhere.
MAX_LOGICAL = 128


def has_boot_signature(sector: bytes) -> bool:
    """Whether the sector ends with the 55 AA boot signature.

    セクタ末尾が 55 AA のブートシグネチャか。
    """
    return sector[0x1FE:0x200] == b"\x55\xaa"


def _entries(sector: bytes) -> list[tuple[int, int, int, int]]:
    """Return (status, type, first_lba, num_sectors) for the four slots."""
    out = []
    for i in range(4):
        e = sector[0x1BE + 16 * i : 0x1BE + 16 * (i + 1)]
        status, ptype = e[0], e[4]
        first_lba, num_sectors = struct.unpack_from("<II", e, 8)
        out.append((status, ptype, first_lba, num_sectors))
    return out


def is_protective(sector: bytes) -> bool:
    """Whether any slot has the GPT protective type (0xEE).

    GPT の保護用タイプ（0xEE）のスロットがあるか。
    """
    return any(ptype == TYPE_GPT_PROTECTIVE for _, ptype, _, _ in _entries(sector))


def read(dev: BlockDevice, sector_size: int = 512) -> PartitionTable:
    """Parse the MBR at LBA 0, following the EBR chain of an extended partition.

    LBA 0 の MBR を解析する。拡張パーティションの EBR チェーンも辿る。
    """
    lba0 = dev.read_at(0, sector_size)
    if not has_boot_signature(lba0):
        raise DiskReadError("MBR boot signature missing")
    (disk_sig,) = struct.unpack_from("<I", lba0, 0x1B8)

    partitions: list[Partition] = []
    extended_start: int | None = None
    for slot, (status, ptype, first_lba, num_sectors) in enumerate(_entries(lba0)):
        if ptype == TYPE_EMPTY or num_sectors == 0:
            continue
        partitions.append(
            Partition(
                number=slot + 1,
                start_lba=first_lba,
                size_lba=num_sectors,
                sector_size=sector_size,
                type=f"{ptype:02x}",
                bootable=status == 0x80,
            )
        )
        if ptype in EXTENDED_TYPES:
            if extended_start is not None:
                raise DiskReadError("MBR has more than one extended partition")
            extended_start = first_lba

    if extended_start is not None:
        partitions.extend(_read_logical(dev, sector_size, extended_start))

    return PartitionTable(
        scheme="mbr",
        disk_id=f"0x{disk_sig:08x}",
        sector_size=sector_size,
        partitions=partitions,
    )


def _read_logical(dev: BlockDevice, sector_size: int, extended_start: int) -> list[Partition]:
    """Walk the EBR linked list inside an extended partition.

    In each EBR, entry 0 is the logical partition (start relative to this
    EBR) and entry 1 points to the next EBR (start relative to the start of
    the extended partition).
    """
    out: list[Partition] = []
    ebr_lba = extended_start
    seen: set[int] = set()
    # Counted in EBRs read, not partitions found: a chain of EBRs with an empty
    # first entry finds none, and could go on across the whole disk.
    while len(seen) < MAX_LOGICAL:
        if ebr_lba in seen:
            raise DiskReadError(f"EBR chain loops at LBA {ebr_lba}")
        seen.add(ebr_lba)

        ebr = dev.read_at(ebr_lba * sector_size, sector_size)
        if not has_boot_signature(ebr):
            raise DiskReadError(f"EBR at LBA {ebr_lba} has no boot signature")
        entries = _entries(ebr)

        status, ptype, rel_start, num_sectors = entries[0]
        if ptype != TYPE_EMPTY and num_sectors != 0:
            out.append(
                Partition(
                    number=5 + len(out),
                    start_lba=ebr_lba + rel_start,
                    size_lba=num_sectors,
                    sector_size=sector_size,
                    type=f"{ptype:02x}",
                    bootable=status == 0x80,
                )
            )

        _, next_type, next_rel, next_sectors = entries[1]
        if next_type == TYPE_EMPTY or next_sectors == 0:
            return out
        ebr_lba = extended_start + next_rel
    raise DiskReadError(f"EBR chain of more than {MAX_LOGICAL} links")
