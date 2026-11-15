"""Read-only ext2/3/4 reader.

読み取り専用の ext2/3/4 リーダー。
"""

from __future__ import annotations

from diskread.fs.ext4.fs import Ext4
from diskread.fs.ext4.superblock import Superblock

__all__ = ["Ext4", "Superblock"]
