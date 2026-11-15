"""Read-only FAT12/16/32 (vfat) reader, for EFI system partitions.

EFI システムパーティション向けの、読み取り専用 FAT12/16/32（vfat）リーダー。
"""

from __future__ import annotations

from diskread.fs.fat.fs import Vfat

__all__ = ["Vfat"]
