"""Print the release notes of one version from CHANGELOG.md.

    python scripts/release_notes.py 0.1.0 > notes.md

The notes are the version's section (without its heading), a link to the version on
PyPI and the "compare" link at the bottom of the changelog. Exits with 1 when the
version has no section, so that a release is not made without notes.

CHANGELOG.md から、1 つの版のリリースノートを出力する。版の節（見出しを除く）に、PyPI の版の
ページと、CHANGELOG の下にある比較のリンクを足す。版の節がなければ 1 で終わる（ノートなしで
リリースを作らないため）。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
PYPI_URL = "https://pypi.org/project/ec2-byhand/{version}/"


def release_notes(changelog: str, version: str) -> str | None:
    """The notes of `version`, or None when it has no section.

    `version` の版のノート。節がなければ None。
    """
    heading = re.compile(rf"^## \[{re.escape(version)}\]", re.MULTILINE)
    found = heading.search(changelog)
    if found is None:
        return None
    body_start = changelog.index("\n", found.end()) + 1
    # The section ends at the next "## [" heading or at the link definitions.
    end = re.compile(r"^(## \[|\[[^\]]+\]: )", re.MULTILINE).search(changelog, body_start)
    body = changelog[body_start : end.start() if end else len(changelog)].strip()
    lines = [body, "", f"**PyPI**: {PYPI_URL.format(version=version)}"]
    link = re.search(rf"^\[{re.escape(version)}\]: (\S+)$", changelog, re.MULTILINE)
    if link is not None and "/compare/" in link.group(1):
        lines += ["", f"**Full changelog**: {link.group(1)}"]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    """Print the notes of the version given (with or without its "v"); the exit code.

    渡された版（「v」は付いていてもよい）のノートを出力する。終了コードを返す。
    """
    if len(argv) != 1:
        print("usage: release_notes.py VERSION", file=sys.stderr)
        return 2
    version = argv[0].removeprefix("v")
    notes = release_notes(CHANGELOG.read_text(encoding="utf-8"), version)
    if notes is None:
        print(f"CHANGELOG.md has no section for {version}", file=sys.stderr)
        return 1
    sys.stdout.write(notes)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
