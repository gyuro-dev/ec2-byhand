"""ec2-byhand: extract hand-placed and hand-modified files from EBS snapshots.

ec2-byhand: EBS スナップショットから、手で置いた・手で変えたファイルを抽出する。
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ec2-byhand")  # pyproject.toml is the one place the version is written
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "unknown"
