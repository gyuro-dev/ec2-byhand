"""Public docstrings are English first, then Japanese.

公開 docstring（モジュールの先頭、公開クラス・関数・メソッド）が
「英語の段落のあとに日本語の段落」の形になっていることと、モジュール
レベルの公開クラス・関数に docstring があることを機械的に確かめる。
内部（`_` 付き）は英語のみでよく、有無も問わない。
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).parent.parent / "src"
FILES = sorted(SRC.rglob("*.py"))


def _has_japanese(text: str) -> bool:
    # ひらがな・カタカナ・CJK 統合漢字のどれかがあれば日本語とみなす。
    return any(0x3040 <= ord(c) <= 0x30FF or 0x4E00 <= ord(c) <= 0x9FFF for c in text)


def _docstring(node: ast.AST) -> str | None:
    body = getattr(node, "body", None)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[0].value.value
    return None


def _public_docstrings(tree: ast.Module) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = [("module", _docstring(tree))]
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith("_"):
            out.append((node.name, _docstring(node)))
            if isinstance(node, ast.ClassDef):
                out.extend(
                    (f"{node.name}.{sub.name}", _docstring(sub))
                    for sub in node.body
                    if isinstance(sub, ast.FunctionDef) and not sub.name.startswith("_")
                )
    return out


@pytest.mark.parametrize("path", FILES, ids=lambda p: str(p.relative_to(SRC)))
def test_public_docstrings_are_english_then_japanese(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    problems = []
    for name, doc in _public_docstrings(tree):
        if doc is None:
            # モジュールと、モジュールレベルの公開クラス・関数には必須。
            # 公開クラスのメソッドは、Protocol 実装の重複を避けるため有無を問わない。
            if "." not in name:
                problems.append(f"{name}: docstring が無い")
            continue
        first = doc.strip().split("\n\n")[0]
        if not first.isascii():
            problems.append(f"{name}: 最初の段落が英語（ASCII）でない")
        before_params = doc.split(":param")[0]
        if not _has_japanese(before_params):
            problems.append(f"{name}: 日本語の段落が無い")
    assert not problems, "\n".join(problems)
