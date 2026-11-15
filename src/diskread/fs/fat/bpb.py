"""FAT boot sector (BPB) and the file allocation table.

Boot sector, little-endian, fields used here:
  0x00 jump (EB xx 90 or E9 xx xx)   0x03 OEM name[8]
  0x0B bytes per sector (u16)        0x0D sectors per cluster (u8)
  0x0E reserved sectors (u16)        0x10 number of FATs (u8)
  0x11 root entries (u16, 0 on FAT32) 0x13 total sectors (u16)
  0x15 media                          0x16 sectors per FAT (u16, 0 on FAT32)
  0x20 total sectors (u32)
  FAT12/16: 0x27 volume id, 0x2B volume label[11]
  FAT32:    0x24 sectors per FAT (u32), 0x28 ext flags, 0x2C root cluster,
            0x43 volume id, 0x47 volume label[11]
  0x1FE signature 55 AA

The FAT type follows from the number of data clusters (Microsoft's rule,
which Linux also uses): < 4085 is FAT12, < 65525 FAT16, otherwise FAT32.

FAT のブートセクタ（BPB）とファイルアロケーションテーブル（レイアウトは上の表のとおり）。FAT
の種類はデータクラスタ数で決まる（Microsoft の規則で Linux も同じ。4085 未満は FAT12、65525 未
満は FAT16、それ以外は FAT32）。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Literal

from diskread.blockdev import BlockDevice
from diskread.errors import DiskReadError

FatType = Literal[12, 16, 32]
# A FAT32 entry holds 28 bits, and the values from 0x0FFFFFF7 up mark bad clusters and
# the end of a chain: clusters 2 to 0x0FFFFFF6 are all a table can name.
MAX_FAT32_CLUSTERS = 0x0FFFFFF5


@dataclass(frozen=True)
class BootSector:
    """The BPB fields this reader uses, converted to byte offsets and sizes.

    このリーダーが使う BPB のフィールド（バイトのオフセット・サイズに換算済み）。
    """

    fat_type: FatType
    bytes_per_sector: int
    cluster_size: int
    fat_offset: int  # byte offset of the FAT in use
    fat_bytes: int
    root_dir_offset: int  # FAT12/16 fixed root directory
    root_dir_bytes: int
    data_offset: int  # byte offset of cluster 2
    cluster_count: int
    root_cluster: int  # FAT32 only
    volume_id: int
    label: str  # from the boot sector; the root directory may hold another


def looks_like_fat(sector: bytes) -> bool:
    """Whether the sector looks like a FAT boot sector (jump, 55 AA, not NTFS / exFAT).

    FAT のブートセクタらしいか（ジャンプ命令と 55 AA があり、NTFS / exFAT でない）。
    """
    if len(sector) < 512 or sector[0x1FE:0x200] != b"\x55\xaa":
        return False
    if not ((sector[0] == 0xEB and sector[2] == 0x90) or sector[0] == 0xE9):
        return False
    if sector[3:11] in (b"NTFS    ", b"EXFAT   "):
        return False
    bps, spc, reserved, nfats = struct.unpack_from("<HBHB", sector, 0x0B)
    return (
        bps in (512, 1024, 2048, 4096)
        and spc in (1, 2, 4, 8, 16, 32, 64, 128)
        and reserved > 0
        and nfats in (1, 2)
        and sector[0x15] >= 0xF0
    )


def parse_boot_sector(sector: bytes) -> BootSector:
    """Parse and sanity-check the boot sector; the FAT type follows from the cluster count.

    ブートセクタを解析・検査する。FAT の種類はデータクラスタ数から決まる。
    """
    if not looks_like_fat(sector):
        raise DiskReadError("not a FAT filesystem (bad boot sector)")
    bps, spc, reserved, nfats, root_entries, total16 = struct.unpack_from("<HBHBHH", sector, 0x0B)
    (fat16_size,) = struct.unpack_from("<H", sector, 0x16)
    (total32,) = struct.unpack_from("<I", sector, 0x20)
    total = total16 or total32
    fat_sectors = fat16_size
    if fat_sectors == 0:
        (fat_sectors,) = struct.unpack_from("<I", sector, 0x24)
    root_sectors = (root_entries * 32 + bps - 1) // bps
    data_sector = reserved + nfats * fat_sectors + root_sectors
    if fat_sectors == 0 or total <= data_sector:
        raise DiskReadError("bad FAT geometry")
    cluster_count = (total - data_sector) // spc
    if cluster_count > MAX_FAT32_CLUSTERS:
        raise DiskReadError(f"bad FAT geometry: {cluster_count} clusters")
    fat_type: FatType = 12 if cluster_count < 4085 else 16 if cluster_count < 65525 else 32

    active_fat = 0
    root_cluster = 0
    if fat_type == 32:
        (ext_flags,) = struct.unpack_from("<H", sector, 0x28)
        if ext_flags & 0x80:  # mirroring off: only this FAT is valid
            active_fat = ext_flags & 0xF
        (root_cluster,) = struct.unpack_from("<I", sector, 0x2C)
        id_off, label_off = 0x43, 0x47
    else:
        id_off, label_off = 0x27, 0x2B
    if active_fat >= nfats:
        raise DiskReadError("active FAT out of range")
    (volume_id,) = struct.unpack_from("<I", sector, id_off)
    return BootSector(
        fat_type=fat_type,
        bytes_per_sector=bps,
        cluster_size=bps * spc,
        fat_offset=(reserved + active_fat * fat_sectors) * bps,
        fat_bytes=fat_sectors * bps,
        root_dir_offset=(reserved + nfats * fat_sectors) * bps,
        root_dir_bytes=root_entries * 32,
        data_offset=data_sector * bps,
        cluster_count=cluster_count,
        root_cluster=root_cluster,
        volume_id=volume_id,
        label=sector[label_off : label_off + 11].decode("cp437").rstrip(" "),
    )


class Fat:
    """The allocation table: follows cluster chains.

    アロケーションテーブル。クラスタチェーンを辿る。
    """

    def __init__(self, dev: BlockDevice, bs: BootSector) -> None:
        self._bs = bs
        # Only the entries in use: one per data cluster after two reserved ones, of 12,
        # 16 or 32 bits. The table's size as the boot sector gives it is checked against
        # nothing, and a damaged one would have this hold gigabytes in memory.
        in_use = ((bs.cluster_count + 2) * bs.fat_type + 7) // 8
        self._table = dev.read_at(bs.fat_offset, min(bs.fat_bytes, in_use))
        self._eoc = {12: 0xFF8, 16: 0xFFF8, 32: 0x0FFFFFF8}[bs.fat_type]

    def next(self, cluster: int) -> int:
        """The FAT entry for `cluster`: the next cluster, or an end-of-chain / free marker.

        `cluster` の FAT エントリ: 次のクラスタ、または終端 / 空きの印。
        """
        t = self._bs.fat_type
        if t == 32:
            return int(struct.unpack_from("<I", self._table, cluster * 4)[0]) & 0x0FFFFFFF
        if t == 16:
            return int(struct.unpack_from("<H", self._table, cluster * 2)[0])
        off = cluster + cluster // 2
        (v,) = struct.unpack_from("<H", self._table, off)
        return int(v >> 4 if cluster & 1 else v & 0xFFF)

    def chain(self, first: int) -> list[int]:
        """Clusters of a chain starting at `first` (0 means no clusters).

        `first` から始まるチェーンのクラスタ列（0 はクラスタなし）。
        """
        out: list[int] = []
        c = first
        last_valid = self._bs.cluster_count + 1
        while c != 0 and c < self._eoc:
            if not 2 <= c <= last_valid:
                raise DiskReadError(f"FAT chain points to invalid cluster {c:#x}")
            out.append(c)
            if len(out) > self._bs.cluster_count:
                raise DiskReadError(f"FAT chain starting at cluster {first} loops")
            c = self.next(c)
        return out
