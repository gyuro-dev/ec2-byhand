"""Read-only XFS reader (v5, and the older v4).

読み取り専用の XFS リーダー（v5 と、古い v4）。
"""

from __future__ import annotations

from diskread.fs.xfs.fs import Xfs
from diskread.fs.xfs.superblock import Superblock

__all__ = ["Superblock", "Xfs"]
