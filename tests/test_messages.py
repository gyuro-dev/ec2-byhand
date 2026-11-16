"""The messages in English and Japanese (ec2_byhand.messages): the two tables agree, the
code and the tables agree, and the command speaks the language the environment asks for.

The other tests read the command's English (conftest.py sets EC2_BYHAND_LANG=en); the
Japanese is read here.
"""

from __future__ import annotations

import ast
import json
import re
import string
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from conftest import GOLDEN_DIR

from ec2_byhand import messages
from ec2_byhand.cli import main
from ec2_byhand.messages import LABELS, LANGS, TEXTS, language, msg, row, width, wrap

SRC = Path(__file__).parent.parent / "src"
JAPANESE = re.compile("[぀-ヿ一-鿿]")
CURRENT = GOLDEN_DIR / "verify-al2023.img"
LOCALE_VARIABLES = ("EC2_BYHAND_LANG", "LC_ALL", "LC_MESSAGES", "LANG")


def _placeholders(texts: dict[str, str]) -> dict[str, list[str]]:
    """The {...} names of each message: the same in every language."""
    return {
        key: sorted({name for _, name, _, _ in string.Formatter().parse(text) if name})
        for key, text in texts.items()
    }


@pytest.mark.parametrize("table", [TEXTS, LABELS], ids=["TEXTS", "LABELS"])
def test_languages_have_same_keys_and_placeholders(table: dict[str, dict[str, str]]) -> None:
    assert tuple(table) == LANGS == ("en", "ja")
    assert _placeholders(table["en"]) == _placeholders(table["ja"])
    # The same order too, so that the two can be read side by side.
    assert list(table["en"]) == list(table["ja"])


@pytest.mark.parametrize("table", [TEXTS, LABELS], ids=["TEXTS", "LABELS"])
def test_english_has_no_japanese(table: dict[str, dict[str, str]]) -> None:
    assert [key for key, text in table["en"].items() if JAPANESE.search(text)] == []


def _keys_in_code(function: str) -> set[str]:
    """Every key the code passes to msg() or row(): the strings of the first argument
    (there may be two: msg("a" if x else "b"))."""
    keys = set()
    for path in SRC.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == function
                and node.args
            ):
                first = [n.value for n in ast.walk(node.args[0]) if isinstance(n, ast.Constant)]
                assert first, f"{path.name}:{node.lineno}: a key this test cannot see"
                keys.update(first)
    return keys


def test_the_code_and_the_tables_name_the_same_keys() -> None:
    assert _keys_in_code("msg") == set(TEXTS["en"])
    # A label stands in a row of the summary, or heads a section of report.txt.
    assert _keys_in_code("row") | _keys_in_code("label") == set(LABELS["en"])


def test_english_unless_asked_and_as_before_afterwards() -> None:
    assert msg("interrupted") == "interrupted"
    with language("ja"):
        assert msg("interrupted") == "中断しました"
        with language("en"):
            assert msg("interrupted") == "interrupted"
        assert msg("interrupted") == "中断しました"
    assert msg("interrupted") == "interrupted"
    with pytest.raises(ValueError, match="'fr'"), language("fr"):
        pass


def test_a_thread_speaks_the_same_language() -> None:
    # Progress is reported from the threads that fetch blocks ahead.
    with language("ja"), ThreadPoolExecutor(1) as pool:
        assert pool.submit(msg, "interrupted").result() == "中断しました"


@pytest.mark.parametrize(
    ("environment", "os_locale", "expected"),
    [
        ({}, None, "en"),
        ({}, "Japanese_Japan", "ja"),  # Windows names its locales so
        ({}, "ja_JP", "ja"),
        ({}, "English_United States", "en"),
        ({"LANG": "ja_JP.UTF-8"}, None, "ja"),
        ({"LANG": "C.UTF-8"}, "Japanese_Japan", "en"),
        ({"LANG": "en_US.UTF-8", "LC_MESSAGES": "ja_JP.UTF-8"}, None, "ja"),
        ({"LC_MESSAGES": "ja_JP.UTF-8", "LC_ALL": "C"}, None, "en"),
        ({"EC2_BYHAND_LANG": "ja", "LC_ALL": "C", "LANG": "en_US.UTF-8"}, None, "ja"),
        ({"EC2_BYHAND_LANG": "en", "LANG": "ja_JP.UTF-8"}, "Japanese_Japan", "en"),
        ({"EC2_BYHAND_LANG": "JA"}, None, "ja"),
        ({"EC2_BYHAND_LANG": "fr", "LANG": "ja_JP.UTF-8"}, None, "en"),  # no French: English
        ({"EC2_BYHAND_LANG": "", "LANG": "ja_JP.UTF-8"}, None, "ja"),  # empty is not set
    ],
)
def test_language_from_environment(
    environment: dict[str, str], os_locale: str | None, expected: str, monkeypatch
) -> None:
    for name in LOCALE_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(messages.locale, "getlocale", lambda: (os_locale, "UTF-8"))
    assert messages.language_from_environment() == expected


def test_width_counts_full_width_characters_twice() -> None:
    assert width("noise") == 5
    assert width("ノイズ") == 6
    assert width("EBS ボリューム") == 14


def test_rows_start_their_values_in_one_column() -> None:
    for lang in LANGS:
        with language(lang):
            starts = {width(row(key, "x")) - 1 for key in LABELS[lang]}
            assert len(starts) == 1, lang
    # English: the longest label, its colon and a space (until 0.1.1 the longest row
    # padded its own value, and its number stood three columns off the others).
    assert row("noise", "628") == "noise:                  628"
    assert row("modified_package_files", "10") == "modified package files: 10"
    assert row("baseline", "none\n(more)") == "baseline:               none\n" + " " * 24 + "(more)"


def test_wrap_breaks_japanese_by_what_a_terminal_shows() -> None:
    text = "機密情報を含むファイルの中身もアーカイブに入れる（--include-sensitive を付けたとき）。"
    lines = wrap(text, 30)
    assert "".join(lines).replace(" ", "") == text.replace(" ", "")
    assert all(width(line) <= 30 for line in lines)
    assert not [line for line in lines if line[0] in "、。）」" or line[-1] in "（「"]
    assert "--include-sensitive" in "\n".join(lines)  # a word of ASCII stays whole
    # 20 columns hold the opening bracket, but a line does not end with one.
    assert wrap("例: '/opt/app/**'（読みもしない）", 20) == [
        "例: '/opt/app/**'",
        "（読みもしない）",
    ]
    assert wrap("", 20) == []


def test_help_in_japanese_fits_the_terminal(monkeypatch, capsys) -> None:
    monkeypatch.setenv("EC2_BYHAND_LANG", "ja")
    monkeypatch.setenv("COLUMNS", "80")
    with pytest.raises(SystemExit) as exit_:
        main(["--help"])
    assert exit_.value.code == 0
    out = capsys.readouterr().out
    assert "現在のサーバー（いずれか 1 つ）:" in out
    assert "このヘルプを表示して終了する" in out
    described = out.split("オプション:")[1].splitlines()
    assert max(width(line) for line in described) <= 78  # as argparse wraps: 2 short of 80


def test_help_in_english_has_no_japanese(monkeypatch, capsys) -> None:
    monkeypatch.setenv("COLUMNS", "80")
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert not JAPANESE.search(out)
    assert "options:\n  -h, --help            show this help message and exit" in out
    assert "EC2_BYHAND_LANG=ja" in out


def test_errors_in_japanese_and_english_again_afterwards(tmp_path, monkeypatch, capsys) -> None:
    out = tmp_path / "out"
    args = ["--current-image", str(tmp_path / "nope.img"), "-o", str(out)]
    monkeypatch.setenv("EC2_BYHAND_LANG", "ja")
    assert main(args) == 2
    assert "ec2-byhand: エラー: current: イメージファイルがありません:" in capsys.readouterr().err
    assert msg("interrupted") == "interrupted"  # main leaves the language as it found it
    monkeypatch.setenv("EC2_BYHAND_LANG", "en")
    assert main(args) == 2
    assert "ec2-byhand: error: current: no such image file:" in capsys.readouterr().err


def test_argument_errors_in_japanese(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("EC2_BYHAND_LANG", "ja")
    for args, expected in [
        (["--max-file-size", "huge"], "サイズではありません: 'huge'"),
        (["--exclude", "*.bak"], "パスのパターンではありません: '*.bak'"),
        (["--parallel", "0"], "1 から 128 までの整数を指定してください: '0'"),
        (["--upload", "bucket/prefix"], "s3:// の URL ではありません: 'bucket/prefix'"),
    ]:
        with pytest.raises(SystemExit) as exit_:
            main(["--current-image", "x.img", "-o", str(tmp_path / "out"), *args])
        assert exit_.value.code == 2
        assert expected in capsys.readouterr().err


def test_summary_in_japanese_and_manifest_in_english(tmp_path, monkeypatch, capsys) -> None:
    if not CURRENT.exists():
        pytest.skip(
            "no golden data; run: wsl -u root -- bash tools/golden/build_verify.sh tests/golden/out"
        )
    monkeypatch.setenv("EC2_BYHAND_LANG", "ja")
    out = tmp_path / "out"
    assert main(["--current-image", str(CURRENT), "--no-archives", "-o", str(out)]) == 0
    captured = capsys.readouterr()
    assert "ec2-byhand: どのパッケージにも属さない" in captured.err
    summary = captured.out.splitlines()
    rows = [line for line in summary if not line.startswith("警告: ")]
    column = width("変更されたパッケージファイル: ")
    for line in rows:
        head = line[: line.index(":") + 1] if not line.startswith(" ") else ""
        assert width(head) <= column, line
        assert line[len(head) :].startswith(" " * (column - width(head))), line
    assert "手動で配置されたファイル:" in captured.out
    assert "baseline:                     なし: AMI に元からあるファイルも" in captured.out
    assert (
        " " * column + "（古いバックアップを指定する: --baseline-snapshot, --baseline-ami）" in rows
    )
    # The warning's own text is the manifest's, and the manifest is data: English.
    assert "警告: no-baseline: no baseline snapshot: results include files" in captured.out
    text = (out / "manifest.json").read_text(encoding="utf-8")
    assert not JAPANESE.search(text)
    assert json.loads(text)["warnings"][0]["code"] == "no-baseline"
