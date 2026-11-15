"""Recognise and open the filesystem on a block device.

ブロックデバイス上のファイルシステムの認識と open。
"""

from __future__ import annotations

import struct
from typing import Literal

from diskread.blockdev import BlockDevice
from diskread.errors import UnsupportedError, malformed_as_disk_read_error
from diskread.fs.ext4 import Ext4
from diskread.fs.fat import Vfat
from diskread.fs.fat.bpb import looks_like_fat
from diskread.fs.xfs import Xfs

FsType = Literal["ext4", "xfs", "vfat"]


def detect_fs(dev: BlockDevice) -> FsType | None:
    """Identify the filesystem by its superblock / boot sector; None if unrecognised.

    "ext4" covers ext2 and ext3 too: they share the superblock. "vfat" is
    FAT12/16/32.

    スーパーブロック／ブートセクタからファイルシステムを判定する。不明なら None。「ext4」は
    ext2 / ext3 も含み、「vfat」は FAT12/16/32。
    """
    if dev.size >= 512 and dev.read_at(0, 4) == b"XFSB":
        return "xfs"
    if dev.size >= 2048 and struct.unpack("<H", dev.read_at(1024 + 0x38, 2))[0] == 0xEF53:
        return "ext4"
    if dev.size >= 512 and looks_like_fat(dev.read_at(0, 512)):
        return "vfat"
    return None


@malformed_as_disk_read_error
def open_fs(
    dev: BlockDevice, options: str = "", verify_checksums: bool = False
) -> Ext4 | Xfs | Vfat:
    """Open the filesystem on `dev`.

    `options` are mount options (as in fstab). Only vfat uses them: FAT has
    no owners or permissions, so Linux takes them from uid=, umask= etc.
    `verify_checksums` checks ext4 metadata_csum / XFS v5 CRCs of the
    metadata read (FAT has none).

    `dev` 上のファイルシステムを開く。`options` は fstab のマウントオプションで、使うのは vfat
    だけ（FAT には所有者や権限が無いため）。`verify_checksums` で ext4 metadata_csum / XFS v5
    の CRC を検証する（FAT には無い）。
    """
    kind = detect_fs(dev)
    if kind == "xfs":
        return Xfs(dev, verify_checksums)
    if kind == "ext4":
        return Ext4(dev, verify_checksums)
    if kind == "vfat":
        return Vfat(dev, options)
    raise UnsupportedError("no supported filesystem (ext2/3/4, XFS or FAT) found")


@malformed_as_disk_read_error
def fs_identity(fs: Ext4 | Xfs | Vfat) -> tuple[str, str]:
    """(UUID, label) as blkid would report them.

    blkid が報告する形の (UUID, ラベル)。
    """
    if isinstance(fs, Vfat):
        return fs.uuid, fs.label
    sb = fs.superblock
    if isinstance(fs, Xfs):
        return sb.uuid, sb.label  # type: ignore[union-attr]
    return sb.uuid, sb.volume_name  # type: ignore[union-attr]
