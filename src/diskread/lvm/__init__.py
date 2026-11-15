"""LVM2: read physical volume labels and metadata, and expose logical volumes.

LVM2: 物理ボリュームのラベルとメタデータを読み、論理ボリュームを見せる。
"""

from __future__ import annotations

from diskread.lvm.label import PVLabel, read_label
from diskread.lvm.vg import (
    LogicalVolume,
    LogicalVolumeDevice,
    PhysicalVolume,
    Segment,
    VolumeGroup,
    find_volume_groups,
)

__all__ = [
    "LogicalVolume",
    "LogicalVolumeDevice",
    "PVLabel",
    "PhysicalVolume",
    "Segment",
    "VolumeGroup",
    "find_volume_groups",
    "read_label",
]
