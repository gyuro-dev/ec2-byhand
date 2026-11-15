"""diskread: pure-Python, read-only parsers for disks, partitions, LVM and filesystems.

This package must not depend on AWS or on ec2_byhand, so it can be tested
against local image files and split out later.

diskread: ディスク・パーティション・LVM・ファイルシステムを読み取り専用で解析する純 Python の
パーサー群。AWS にも ec2_byhand にも依存しない（ローカルのイメージファイルでテストでき、将来切り
出せるように）。
"""

from __future__ import annotations

from diskread.blockdev import BlockDevice, BytesDevice, FileDevice, SliceDevice
from diskread.errors import DiskReadError, UnsupportedError

__all__ = [
    "BlockDevice",
    "BytesDevice",
    "DiskReadError",
    "FileDevice",
    "SliceDevice",
    "UnsupportedError",
]
