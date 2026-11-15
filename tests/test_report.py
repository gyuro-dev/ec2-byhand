"""report.txt: the paths behind the summary's numbers, for a person to read."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import GOLDEN_DIR
from memfs import MemFs

from diskread.source import SystemSource
from ec2_byhand import cli, report
from ec2_byhand.analyze import Snapshot, analyze
from ec2_byhand.archive import write_outputs
from ec2_byhand.messages import language

CURRENT = GOLDEN_DIR / "verify-al2023.img"
BASELINE = GOLDEN_DIR / "verify-al2023-before.img"


def _need_images() -> None:
    if not BASELINE.exists():
        pytest.skip(
            "no golden data; run: wsl -u root -- bash tools/golden/build_verify.sh tests/golden/out"
        )


def _snap(fs: MemFs) -> Snapshot:
    return Snapshot("test", SystemSource.from_fs(fs))


def _sections(lines: list[str]) -> dict[str, list[str]]:
    """Heading (without its count) -> the lines under it."""
    out: dict[str, list[str]] = {}
    name = None
    for line in lines:
        if not line:
            name = None
        elif name is not None:
            out[name].append(line)
        elif not line.startswith(" ") and line.endswith(")") and " (" in line:
            name = line.rsplit(" (", 1)[0]
            out[name] = []
    return out


def _manifest(tmp_path: Path) -> dict:
    """A server compared with its AMI: files added, changed and deleted, a secret, a link."""
    before, after = MemFs(), MemFs()
    for fs in (before, after):
        fs.add_file("/etc/os-release", b"ID=test\n")
    before.add_file("/opt/old/keep.txt", b"one\n")
    before.add_file("/opt/gone/a", b"a")
    before.add_file("/opt/gone/b/c", b"c")
    after.add_file("/opt/old/keep.txt", b"two\n")
    after.add_file("/opt/app/app.ini", b"[db]\npassword = hunter2-for-real\n")
    after.add_file("/opt/app/id_rsa", b"key")
    after.add_link("/opt/app/current", "releases/3")
    after.add_file("/opt/app/evil\nhand-placed (0)\x1b[2J", b"x")
    current, baseline = _snap(after), _snap(before)
    m = analyze(current, baseline)
    m["archives"] = write_outputs(m, current.source, baseline.source, tmp_path)
    return m


def test_every_item_of_the_manifest_has_its_line(tmp_path: Path) -> None:
    m = _manifest(tmp_path)
    lines = report.report_lines(m, ["hand-placed:           7"])
    assert lines[0].startswith("ec2-byhand ")
    assert lines[2] == "current:               test"
    assert lines[3] == "hand-placed:           7"  # the summary, as the run printed it
    sections = _sections(lines)
    hand = sections["hand-placed"]
    assert len(hand) == len(m["hand_placed"]) == m["summary"]["hand_placed"]
    assert f"hand-placed ({len(hand)})" in lines
    by_path = {line.rsplit("  ", 1)[1]: line for line in (x.strip() for x in hand)}
    assert by_path["/opt/app/"].startswith("added")
    assert by_path["/opt/app/current -> releases/3"].startswith("added")
    assert by_path["/opt/app/app.ini [secrets: password (2)]"].startswith("added")
    assert by_path["/opt/app/id_rsa [sensitive]"].startswith("added")
    assert by_path["/opt/old/keep.txt [changed: sha256]"].startswith("modified")
    # A gone directory is one line that says how much went with it.
    assert sections["deleted"] == ["  /opt/gone/ (and 3 below it)"]
    assert "  after   /opt/app/id_rsa [sensitive]" in sections["skipped"]
    assert sections["masked"] == ["  after   /opt/app/app.ini [password]"]


def test_a_file_name_cannot_forge_a_line_or_act_on_the_terminal(tmp_path: Path) -> None:
    lines = report.report_lines(_manifest(tmp_path), [])
    text = "\n".join(lines)
    assert "\x1b" not in text
    assert lines.count("hand-placed (0)") == 0
    assert "/opt/app/evil\\nhand-placed (0)\\x1b[2J" in text


def test_nothing_found_is_a_report_of_the_summary_alone() -> None:
    fs = MemFs()
    m = analyze(_snap(fs), _snap(fs))
    assert m["summary"]["hand_placed"] == 0
    lines = report.report_lines(m, ["hand-placed:           0"])
    assert lines[2:] == ["current:               test", "hand-placed:           0"]


def test_headings_and_notes_follow_the_language_the_items_do_not(tmp_path: Path) -> None:
    m = _manifest(tmp_path)
    with language("ja"):
        lines = report.report_lines(m, [])
    sections = _sections(lines)
    assert "のレポート（" in lines[0]
    assert sections["削除されたファイル"] == ["  /opt/gone/（配下に 3）"]
    assert any(
        line.lstrip().startswith("modified") for line in sections["手動で配置されたファイル"]
    )
    assert "[changed: sha256]" in "\n".join(lines)  # the manifest's words, to find it there


def test_the_command_writes_the_report_beside_the_manifest(tmp_path: Path, capsys) -> None:
    _need_images()
    out = tmp_path / "out"
    args = ["--current-image", str(CURRENT), "--baseline-image", str(BASELINE), "-o", str(out)]
    assert cli.main(args) == 0
    printed = capsys.readouterr().out.splitlines()
    written = (out / "report.txt").read_text(encoding="utf-8").splitlines()
    assert f"report:                {out / 'report.txt'}" in printed
    assert written[3 : 3 + len(printed)] == printed  # the same summary, then the lists
    m = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    sections = _sections(written)
    assert len(sections["hand-placed"]) == m["summary"]["hand_placed"]
    assert len(sections["modified package files"]) == m["summary"]["modified_package_files"]
    for item in m["hand_placed"] + m["modified_package_files"] + m["deleted"]:
        assert any(f"  {item['path']}" in line for line in written), item["path"]
    assert any("requests/__version__.py" in line for line in sections["language packages"])

    # --no-archives still writes it; --force replaces the one of the run before.
    (out / "report.txt").write_text("stale", encoding="utf-8")
    assert cli.main([*args, "--no-archives", "--force", "-q"]) == 0
    assert (out / "report.txt").read_text(encoding="utf-8").startswith("ec2-byhand ")
    assert not (out / "after.tar.gz").exists()
