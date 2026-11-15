"""Secret-like strings in file contents: found to flag them in the manifest, masked in
the archives and patches.

Only shapes that rarely mean anything else are looked for, in text files of up to
SCAN_MAX_BYTES (a NUL byte means binary, which is not scanned):

  private-key        -----BEGIN ... PRIVATE KEY----- through its END line (the body)
  aws-access-key     AKIA / ASIA and 16 upper-case letters or digits
  aws-secret-key     aws_secret_access_key = <40 characters>
  github-token       ghp_ / gho_ / ghu_ / ghs_ / ghr_ and 36 or more, github_pat_...
  slack-token        xoxb- / xoxp- / xoxa- / xoxr- / xoxs- ...
  url-password       scheme://user:<password>@host
  password           password / passwd / secret / token / api_key / access_key /
                     client_secret ... given a value, unless the value is a reference
                     ($VAR, ${...}, %(...)s, <...>, a path, an unquoted call such as
                     getenv(...)) or empty. The forms: key = value and key: value
                     (ini, YAML, JSON, .env, properties, $password = "..."),
                     'key' => 'value' (PHP and Ruby), define('KEY', 'value')
                     (wp-config.php), <key>value</key> (XML)
What is not looked for: a value after a space only (redis' "requirepass x"), and
anything a program builds at run time.

What is masked is the value only, so the file keeps its shape (key names, lines).
Findings carry the kind and the line, never the value.

ファイルの中身の秘密らしい文字列。manifest で印を付け、アーカイブとパッチでは伏せる。ほかの
意味になりにくい形だけを、SCAN_MAX_BYTES までのテキストファイル（NUL を含めばバイナリとして
調べない）で探す: 秘密鍵のブロック、AWS のアクセスキー・シークレット、GitHub・Slack の
トークン、URL に埋め込んだパスワード、password・secret・token・api_key などへの値の代入（値が
参照 $VAR・${...}・%(...)s・<...>・パス・引用符なしの関数呼び出し、または空なら除く）。代入の
形は、key = 値 と key: 値（ini・YAML・JSON・.env・properties・$password = "..."）、
'key' => '値'（PHP・Ruby）、define('KEY', '値')（wp-config.php）、<key>値</key>（XML）。
空白だけで区切る形（redis の requirepass x）と、プログラムが実行時に組み立てる値は探さない。
伏せるのは値だけで、ファイルの形（キー名・行）は残す。見つけたものは種類と行だけを持ち、値は
持たない。
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

SCAN_MAX_BYTES = 1 << 20
MASK = b"***MASKED***"

_KEY_WORDS = (
    rb"password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|"
    rb"secret[_-]?key|client[_-]?secret|auth[_-]?token|private[_-]?key"
)
# A key that names a secret, with what may stand before it in the same name (db_, app.).
_KEY = rb"(?:[a-z0-9_.-]*[_.-])?(?:" + _KEY_WORDS + rb")"
# A private key block, its two lines looked for apart (see _private_keys).
_KEY_BEGIN = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----\r?\n")
_KEY_END = re.compile(rb"\r?\n-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
# (kind, pattern, the group that holds the value). The file comes from the analyzed disk
# and may hold anything: every pattern must stay linear in its size, so what repeats
# without an end in sight is bounded (the scheme and the two parts of a URL).
_PATTERNS: tuple[tuple[str, re.Pattern[bytes], int], ...] = (
    ("aws-access-key", re.compile(rb"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 1),
    (
        "aws-secret-key",
        re.compile(rb"(?i)aws_?secret_?access_?key[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})\b"),
        1,
    ),
    (
        "github-token",
        re.compile(rb"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
        1,
    ),
    ("slack-token", re.compile(rb"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"), 1),
    (
        "url-password",
        re.compile(rb"\b[a-zA-Z][a-zA-Z0-9+.-]{0,31}://[^\s:/@\"']{1,255}:([^\s@/\"']{1,1023})@"),
        1,
    ),
    (
        "password",
        re.compile(
            rb"(?im)(?:^|[\s\"'{,;$(\[])" + _KEY + rb"[\"']?"
            rb"[ \t]*[=:][ \t]*[\"']?([^\s\"'#;,]{4,})"
        ),
        1,
    ),
    # 'password' => 'value' (PHP arrays, Ruby hashes, Puppet): quoted values only, what
    # stands there unquoted is code.
    (
        "password",
        re.compile(
            rb"(?im)(?:^|[\s\"'{,;$(\[:])" + _KEY + rb"[\"']?"
            rb"[ \t]*=>[ \t]*[\"']([^\"'\r\n]{4,})[\"']"
        ),
        1,
    ),
    # define('DB_PASSWORD', 'value'): wp-config.php, whose AUTH_KEY, NONCE_SALT... sign
    # the sessions and are secrets as well.
    (
        "password",
        re.compile(
            rb"(?i)\bdefine\s*\(\s*[\"'](?:" + _KEY + rb"|[a-z0-9_]*_(?:key|salt))[\"']"
            rb"\s*,\s*[\"']([^\"'\r\n]{4,})[\"']"
        ),
        1,
    ),
    # <password>value</password>: Tomcat, Maven, JBoss.
    ("password", re.compile(rb"(?i)<" + _KEY + rb">([^<>\s]{4,})</"), 1),
)
_REFERENCE = re.compile(rb"^(?:\$|%\(|%\{|<|/|\{\{|\*+$|true$|false$|null$|none$)", re.IGNORECASE)
# A call or a lookup, as code has where a file of settings has a value: getenv("X"),
# os.environ["X"], env('X', ''). Only when no quote opens the value.
_CALL = re.compile(rb"^[A-Za-z_][A-Za-z0-9_.:\\>-]*[(\[]")


@dataclass(frozen=True)
class Finding:
    """One secret-like string: its kind, its line (from 1), and where its value is.

    秘密らしい文字列 1 つ: 種類、行（1 から）、値の位置。
    """

    kind: str
    line: int
    start: int
    end: int


def _private_keys(data: bytes) -> Iterator[tuple[int, int]]:
    """Where the bodies of the private key blocks are: from each BEGIN line to the first
    END line after it. The two lines are looked for apart, each once: one pattern for
    the whole block would search to the end of the file from every BEGIN without an END."""
    ends = [m.span() for m in _KEY_END.finditer(data)]
    starts = [start for start, _ in ends]
    free = 0  # where the block before this one ended
    for begin in _KEY_BEGIN.finditer(data):
        if begin.start() < free:
            continue
        i = bisect.bisect_left(starts, begin.end())
        if i == len(ends):
            return
        yield begin.end(), ends[i][0]
        free = ends[i][1]


def _candidates(data: bytes) -> Iterator[tuple[str, int, int]]:
    """(kind, where the value starts, where it ends) of everything that looks like a
    secret, the more exact kinds first."""
    for start, end in _private_keys(data):
        yield "private-key", start, end
    for kind, pattern, group in _PATTERNS:
        for m in pattern.finditer(data):
            start, end = m.span(group)
            value = data[start:end]
            if kind == "password" and (
                _REFERENCE.match(value)
                or (data[start - 1 : start] not in (b'"', b"'") and _CALL.match(value))
            ):
                continue
            yield kind, start, end


def find_secrets(data: bytes) -> list[Finding]:
    """The secret-like strings of a text file's content; none for binary or larger files.

    テキストファイルの中身の秘密らしい文字列。バイナリと大きすぎるファイルは調べない。
    """
    if len(data) > SCAN_MAX_BYTES or b"\0" in data:
        return []
    # Kept in order of their place, never overlapping: a candidate is compared with its
    # two neighbours only (a file may be made of nothing but findings).
    taken: list[tuple[int, int, str]] = []
    for kind, start, end in _candidates(data):
        i = bisect.bisect_left(taken, (start, end, kind))
        if (i and taken[i - 1][1] > start) or (i < len(taken) and taken[i][0] < end):
            continue  # already inside a finding of an earlier, more exact kind
        taken.insert(i, (start, end, kind))
    if not taken:
        return []
    newlines = [m.start() for m in re.finditer(rb"\n", data)]
    return [
        Finding(kind, bisect.bisect_left(newlines, start) + 1, start, end)
        for start, end, kind in taken
    ]


def mask(data: bytes, findings: Iterable[Finding]) -> bytes:
    """The content with each finding's value replaced by MASK.

    見つけた値をそれぞれ MASK に置き換えた中身。
    """
    out, at = [], 0
    for f in sorted(findings, key=lambda f: f.start):
        out += [data[at : f.start], MASK]
        at = f.end
    out.append(data[at:])
    return b"".join(out)


def described(findings: Iterable[Finding]) -> list[dict[str, object]]:
    """The manifest's "secrets" of a file: kind and line of each finding.

    manifest に載せる、ファイルの "secrets"（見つけたものの種類と行）。
    """
    return [{"kind": f.kind, "line": f.line} for f in findings]
