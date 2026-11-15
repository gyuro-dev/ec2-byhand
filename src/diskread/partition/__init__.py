"""Partition tables: MBR (including extended/logical partitions) and GPT.

パーティションテーブル: MBR（拡張・論理パーティション含む）と GPT。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from diskread.blockdev import BlockDevice, SliceDevice
from diskread.errors import malformed_as_disk_read_error


@dataclass(frozen=True)
class Partition:
    # Numbered the way Linux names device nodes: MBR primaries are 1-4 by
    # slot, logical partitions start at 5, GPT uses the entry index + 1.
    """One partition, numbered the way Linux names device nodes.

    パーティション 1 つ。番号の付け方は Linux のデバイス名と同じ。
    """

    number: int
    start_lba: int
    size_lba: int
    sector_size: int
    # MBR: two hex digits ("83"). GPT: upper-case type GUID.
    type: str
    # GPT only.
    uuid: str | None = None
    name: str | None = None
    attributes: int = 0
    # MBR only.
    bootable: bool = False

    @property
    def offset(self) -> int:
        """Start of the partition on the device, in bytes.

        デバイス上での開始位置（バイト）。
        """
        return self.start_lba * self.sector_size

    @property
    def size(self) -> int:
        """Size in bytes.

        サイズ（バイト）。
        """
        return self.size_lba * self.sector_size

    def open(self, dev: BlockDevice) -> SliceDevice:
        """The partition's byte range as a device of its own.

        このパーティションの範囲を独立したデバイスとして開く。
        """
        return SliceDevice(dev, self.offset, self.size)


@dataclass(frozen=True)
class PartitionTable:
    """A parsed MBR or GPT and its partitions.

    解析済みの MBR / GPT とそのパーティション。
    """

    scheme: Literal["mbr", "gpt"]
    # MBR: "0x" + 8 hex digits. GPT: upper-case disk GUID.
    disk_id: str
    sector_size: int
    partitions: list[Partition]
    # GPT only: usable LBA range, and whether the backup header had to be used.
    first_usable_lba: int | None = None
    last_usable_lba: int | None = None
    used_backup_header: bool = False

    def get(self, number: int) -> Partition | None:
        """The partition with this number, or None.

        この番号のパーティション。無ければ None。
        """
        for p in self.partitions:
            if p.number == number:
                return p
        return None


@malformed_as_disk_read_error
def read_partition_table(dev: BlockDevice, sector_size: int = 512) -> PartitionTable | None:
    """Detect and parse the partition table, or return None if there is none.

    A device with no boot signature is treated as unpartitioned (for example
    a filesystem written straight onto the whole volume).

    パーティションテーブルを検出して読む。無ければ None。ブートシグネチャの無いデバイスは非パ
    ーティション扱い（ボリューム全体に直接ファイルシステムを書いた場合など）。
    """
    from diskread.fs.fat.bpb import looks_like_fat
    from diskread.partition import gpt, mbr

    lba0 = dev.read_at(0, sector_size)
    if not mbr.has_boot_signature(lba0):
        return None
    # A FAT volume written to the whole disk also ends its first sector with
    # 55 AA; its boot sector is not an MBR.
    if looks_like_fat(lba0) and not mbr.is_protective(lba0):
        return None
    if mbr.is_protective(lba0):
        return gpt.read(dev, sector_size)
    return mbr.read(dev, sector_size)


__all__ = ["Partition", "PartitionTable", "read_partition_table"]
