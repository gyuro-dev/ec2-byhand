"""scripts/release_notes.py: the GitHub release notes, made from CHANGELOG.md. And the
changelog itself keeps the form the script and the publish workflow rely on."""

from __future__ import annotations

import importlib.util
import re
import tomllib
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "release_notes", ROOT / "scripts" / "release_notes.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHANGELOG = """\
# Changelog

## [Unreleased]

## [0.2.0] - 2026-10-22

### Changed

- Two.

## [0.1.0] - 2026-10-21

The first release.

[Unreleased]: https://example.com/compare/v0.2.0...HEAD
[0.2.0]: https://example.com/compare/v0.1.0...v0.2.0
[0.1.0]: https://example.com/releases/tag/v0.1.0
"""


def test_notes_are_the_section_with_links() -> None:
    notes = _script().release_notes(CHANGELOG, "0.2.0")
    assert notes == (
        "### Changed\n\n- Two.\n\n"
        "**PyPI**: https://pypi.org/project/ec2-byhand/0.2.0/\n\n"
        "**Full changelog**: https://example.com/compare/v0.1.0...v0.2.0\n"
    )


def test_last_section_stops_at_the_link_definitions() -> None:
    # No "compare" link for the first release: none is added.
    notes = _script().release_notes(CHANGELOG, "0.1.0")
    assert notes == "The first release.\n\n**PyPI**: https://pypi.org/project/ec2-byhand/0.1.0/\n"


def test_a_version_without_a_section_has_no_notes() -> None:
    script = _script()
    assert script.release_notes(CHANGELOG, "0.2") is None
    assert script.release_notes(CHANGELOG, "0.3.0") is None
    assert script.main(["0.3.0"]) == 1  # the real changelog has no such version either
    assert script.main([]) == 2


def test_the_real_changelog_keeps_its_form(capsys) -> None:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(r"^## \[([^\]]+)\]", text, re.MULTILINE)
    assert headings[0] == "Unreleased"  # always there, on top
    versions = headings[1:]
    assert versions == sorted(versions, key=lambda v: [int(x) for x in v.split(".")], reverse=True)
    for version in versions:  # every released version has notes the script can print
        assert _script().main([f"v{version}"]) == 0
        assert capsys.readouterr().out.strip()
    # Once a version is released, it is the one pyproject.toml names or an older one.
    current = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    if versions:
        assert [int(x) for x in versions[0].split(".")] <= [
            int(x) for x in current["version"].split(".")
        ]
