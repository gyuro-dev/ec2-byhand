"""Parser for the LVM2 text metadata format (the lvm.conf-style syntax).

    vgname {
        id = "..."
        extent_size = 8192        # comment
        status = ["READ", "WRITE"]
        physical_volumes {
            pv0 { ... }
        }
    }
    contents = "Text Format Volume Group"

Sections become dicts, `key = value` pairs become entries. Values are
str, int, float or lists of those. Section and key names may be any run of
non-delimiter characters (LV names like "app.v2+x_y" or "1data" are legal).

LVM2 テキストメタデータ形式（lvm.conf 風の文法）のパーサー。セクションは dict に、key = value
の対はエントリになる。値は str / int / float かそのリスト。セクション名とキー名は区切り文字以
外なら何でもよい。
"""

from __future__ import annotations

import re

from diskread.errors import DiskReadError, malformed_as_disk_read_error

type Value = str | int | float | list[Value]
type Section = dict[str, Value | Section]

_INT = re.compile(r"-?\d+\Z")
_FLOAT = re.compile(r"-?\d+\.\d*\Z")
_PUNCT = "{}[]=,"


def _tokenize(text: str) -> list[tuple[str, str]]:
    """Split into (kind, value) tokens; kind is 'str', 'word' or a punctuation char."""
    tokens: list[tuple[str, str]] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "#":
            nl = text.find("\n", i)
            i = n if nl < 0 else nl + 1
        elif c in _PUNCT:
            tokens.append((c, c))
            i += 1
        elif c == '"':
            i += 1
            out = []
            while True:
                if i >= n:
                    raise DiskReadError("unterminated string in LVM metadata")
                c = text[i]
                if c == "\\" and i + 1 < n:
                    out.append(text[i + 1])
                    i += 2
                elif c == '"':
                    i += 1
                    break
                else:
                    out.append(c)
                    i += 1
            tokens.append(("str", "".join(out)))
        else:
            start = i
            while i < n and not text[i].isspace() and text[i] not in _PUNCT + '"#':
                i += 1
            tokens.append(("word", text[start:i]))
    return tokens


class _Parser:
    """Recursive-descent parser over the token list."""

    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> tuple[str, str] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> tuple[str, str]:
        tok = self._peek()
        if tok is None:
            raise DiskReadError("unexpected end of LVM metadata")
        self.pos += 1
        return tok

    def _expect(self, kind: str) -> str:
        k, v = self._next()
        if k != kind:
            raise DiskReadError(f"LVM metadata: expected {kind!r}, got {v!r}")
        return v

    def section_body(self, top_level: bool) -> Section:
        """Entries and subsections until the matching '}' (or, at the top level, the end)."""
        out: Section = {}
        while True:
            tok = self._peek()
            if tok is None:
                if top_level:
                    return out
                raise DiskReadError("unterminated section in LVM metadata")
            if tok[0] == "}":
                if top_level:
                    raise DiskReadError("unbalanced '}' in LVM metadata")
                self.pos += 1
                return out
            name = self._expect("word")
            k, v = self._next()
            if k == "{":
                out[name] = self.section_body(top_level=False)
            elif k == "=":
                out[name] = self.value()
            else:
                raise DiskReadError(f"LVM metadata: unexpected {v!r} after {name!r}")

    def value(self) -> Value:
        """One value: a string, a number, or a list of values."""
        k, v = self._next()
        if k == "str":
            return v
        if k == "word":
            return _number(v)
        if k == "[":
            items: list[Value] = []
            if self._peek() == ("]", "]"):
                self.pos += 1
                return items
            while True:
                items.append(self.value())
                k, v = self._next()
                if k == "]":
                    return items
                if k != ",":
                    raise DiskReadError(f"LVM metadata: expected ',' or ']', got {v!r}")
        raise DiskReadError(f"LVM metadata: unexpected {v!r} as a value")


def _number(word: str) -> int | float:
    """A bare word as int or float; anything else is an error."""
    if _INT.match(word):
        return int(word)
    if _FLOAT.match(word):
        return float(word)
    raise DiskReadError(f"LVM metadata: bare word {word!r} is not a value")


@malformed_as_disk_read_error
def parse(text: str) -> Section:
    """Parse LVM2 metadata text into nested sections.

    LVM2 のメタデータテキストを入れ子のセクションに解析する。
    """
    return _Parser(_tokenize(text)).section_body(top_level=True)
