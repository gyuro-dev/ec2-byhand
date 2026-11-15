from __future__ import annotations

import os
from pathlib import Path

import pytest

# The tests read the command's English: without this it would follow the locale of the
# machine they run on (ec2_byhand.messages). The casebook cases run the command as a
# process of its own, so the environment says it; test_messages.py asks for Japanese.
os.environ["EC2_BYHAND_LANG"] = "en"

GOLDEN_DIR = Path(__file__).parent / "golden" / "out"


def golden_cases(prefixes: tuple[str, ...]) -> list[Path]:
    """Golden JSON files for the given case-name prefixes.

    The images are built by tools/golden/*.sh in WSL and are not committed.
    """
    return sorted(p for p in GOLDEN_DIR.glob("*.json") if p.stem.startswith(prefixes))


def require_golden(cases: list[Path], builder: str) -> None:
    if not cases:
        pytest.skip(
            f"no golden images; run: wsl -u root -- bash tools/golden/{builder} tests/golden/out"
        )


def pytest_collection_modifyitems(config, items) -> None:
    """Skip the casebook end-to-end cases when the verify images are missing,
    the same way require_golden skips the Python golden tests."""
    if (GOLDEN_DIR / "verify-al2023-before.img").exists():
        return
    skip = pytest.mark.skip(
        reason="no golden images; "
        "run: wsl -u root -- bash tools/golden/build_verify.sh tests/golden/out"
    )
    for item in items:
        if item.path is not None and item.path.name == "casebook_verify.yaml":
            item.add_marker(skip)
