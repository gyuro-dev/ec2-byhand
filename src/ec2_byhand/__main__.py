"""python -m ec2_byhand

`python -m ec2_byhand` の入口。
"""

from __future__ import annotations

import sys

from ec2_byhand.cli import main

sys.exit(main())
