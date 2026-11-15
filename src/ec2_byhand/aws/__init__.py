"""Reading EC2 disks from EBS snapshots (EBS direct APIs) instead of image files.

イメージファイルの代わりに、EBS スナップショット（EBS direct APIs）から EC2 のディスクを読む。
"""

from __future__ import annotations

# GetSnapshotBlock requests in flight at once, at most (--parallel). Here, not in ebs,
# so that the command line can show them without importing botocore. Measured from a PC
# in Japan to ap-northeast-1 on 2026-11-14, fetching alone: 16 gave 60-77 MiB/s, 32 gave
# 87, 64 gave 80 (each request then waited longer: a limit of the line or of AWS).
READ_AHEAD_THREADS = 32
MAX_THREADS = 128  # what --parallel accepts
