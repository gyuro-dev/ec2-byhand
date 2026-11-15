"""What cloud-init wrote at boot, read from its own log, /var/log/cloud-init.log.

An AMI's snapshot is taken before its first boot, so what cloud-init writes then
(the default user and its home, sudoers.d, authorized_keys, the hostname, the
network configuration...) differs from the baseline on every instance. The log
names it, each line "YYYY-MM-DD HH:MM:SS,mmm - <file>[<LEVEL>]: <message>" in UTC
(Amazon Linux 2 writes "Mon DD HH:MM:SS cloud-init[<pid>]: <file>[<LEVEL>]: <message>",
local time to the second and no year; the first line of each stage tells both):

  Writing to <path> - <mode>: ...      util.write_file, by any module
  Running command ['useradd', <user>, ...]   (or "Running hidden command ...")
                                       the user's home (from /etc/passwd), mail
                                       spool and the account files
  Running command ['usermod' | 'groupadd' | 'passwd' | 'chpasswd', ...]
                                       the account files
  Running command ['hostnamectl', 'set-hostname', ...]   /etc/hostname
  Rendered netplan config ...          /etc/netplan/50-cloud-init.yaml
  Running module <name> ...            the module that does what follows
  Cloud-init v. ... running '<stage>'  a stage, before its first module

Each such line gives a window: from its time to that of the next line, with
WINDOW_SLACK on both sides (the log has milliseconds; a directory can be made just
before the line that names the file in it). A path was written by cloud-init when
its ctime, which userland cannot set, falls in a window for that path or, if it is
new since the baseline, for a path below it (a file written into a directory changes
the directory, but not the mode or owner of one that was there). Anything changed
afterwards, by hand or by a runcmd script, has a later ctime and stays hand work.
Rotated logs (cloud-init.log.1, .gz) are read too; when cloud-init ran but its log
is gone, nothing is attributed, and the caller warns.

cloud-init が起動時に書いたものを、cloud-init 自身のログ /var/log/cloud-init.log から読む。
AMI のスナップショットは初回起動の前なので、cloud-init がそのとき書くもの（既定のユーザーと
ホーム、sudoers.d、authorized_keys、ホスト名、ネットワークの設定など）は、どのインスタンスでも
baseline と違う。ログ（時刻は UTC）には「Writing to <パス>」、useradd などのコマンド、
hostnamectl、netplan の書き出し、モジュールとステージの始まりが残る。各行は、その時刻から次の
行の時刻までの窓になる（両側に WINDOW_SLACK の余裕。ログはミリ秒で、ディレクトリはその中の
ファイルを名指す行の少し前に作られることがある）。ctime（ユーザーが設定できない）が、そのパス
の窓か、baseline 以降にできたパスならその下のパスの窓に入っていれば cloud-init が書いたもの。
あとで手や runcmd で変えたものは ctime が後になるので手作業に残る。ローテートされたログ
（.1、.gz）も読む。cloud-init が動いたのにログが無いときは何も振り分けず、呼び出し側が警告
する。
"""

from __future__ import annotations

import ast
import gzip
import posixpath
import re
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from diskread.errors import DiskReadError
from diskread.fs import Stat
from diskread.source import SystemSource

LOG_DIR = "/var/log"
LOG_NAME = "cloud-init.log"
RAN_MARK = "/var/lib/cloud/instance"  # exists once cloud-init has run
WINDOW_SLACK_NS = 10**9
ACCOUNT_FILES = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/subuid",
    "/etc/subgid",
)
COMMAND_WRITES = {
    "useradd": ACCOUNT_FILES,
    "usermod": ACCOUNT_FILES,
    "groupadd": ("/etc/group", "/etc/gshadow"),
    "passwd": ("/etc/shadow",),
    "chpasswd": ("/etc/shadow",),
}
NETPLAN_FILE = "/etc/netplan/50-cloud-init.yaml"

_LINE = re.compile(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),(\d{3}) - [^\[\]\s]+\[[A-Z]+\]: (.*)")
# Amazon Linux 2 (cloud-init 19.3): "Nov 15 01:33:51 cloud-init[1725]: util.py[DEBUG]: ..."
_SYSLOG_LINE = re.compile(
    r"([A-Z][a-z]{2}) +(\d{1,2}) (\d\d:\d\d:\d\d) cloud-init\[\d+\]: [^\[\]\s]+\[[A-Z]+\]: (.*)"
)
_STAGE_AT = re.compile(
    r"running '[^']+' at [A-Z][a-z]{2}, (\d{1,2}) ([A-Z][a-z]{2}) (\d{4}) (\d\d:\d\d:\d\d) \+0000"
)
_MONTHS = {
    name: n
    for n, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}
_WRITE = re.compile(r"Writing to (/\S*) - ")
_COMMAND = re.compile(r"Running (?:hidden )?command(?: to protect sensitive [^:]*:)?\s*(\[.*?\])")
_MODULE = re.compile(r"Running module (\S+) ")
_STAGE = re.compile(r"Cloud-init v\. \S+ running '([^']+)'")


@dataclass(frozen=True)
class Window:
    """When a module of cloud-init wrote something, in ns since the epoch (UTC).

    cloud-init のモジュールが何かを書いた時間帯（UTC のエポックからのナノ秒）。
    """

    module: str
    begin_ns: int
    end_ns: int

    def holds(self, ns: int) -> bool:
        """Whether `ns` falls inside the window, slack included.

        `ns` が窓（余裕を含む）の中にあるか。
        """
        return self.begin_ns - WINDOW_SLACK_NS <= ns <= self.end_ns + WINDOW_SLACK_NS


@dataclass
class CloudInit:
    """What cloud-init's log says it wrote: windows by path, and by home directory
    for the users it added (everything below them).

    cloud-init のログが示す、書いたものの窓。パスごとと、追加したユーザーのホーム（その下の
    すべて）ごと。
    """

    ran: bool  # cloud-init ran on this system (/var/lib/cloud/instance exists)
    logs: list[str] = field(default_factory=list)  # the log files read
    lines: int = 0  # log lines understood
    first_ns: int | None = None  # the first line's time: the instance's first boot
    by_path: dict[str, list[Window]] = field(default_factory=dict)  # named by the log
    by_dir: dict[str, list[Window]] = field(default_factory=dict)  # above what was named
    by_home: dict[str, list[Window]] = field(default_factory=dict)
    modules: list[str] = field(default_factory=list)  # in the order they first wrote

    @property
    def log_missing(self) -> bool:
        """cloud-init ran, but no line of its log could be read.

        cloud-init は動いたが、ログが 1 行も読めない。
        """
        return self.ran and self.lines == 0

    def written_by(self, path: str, st: Stat, *, created: bool) -> str | None:
        """The module that last wrote `path` as it is now, or None. `created`: the path
        is new since the baseline (or there is none). Only then can a write below a
        directory, or a user's creation, explain it: they make paths, but do not change
        the mode or owner of one that was there.

        `path` を今の状態に書いたモジュール。cloud-init でなければ None。`created` は baseline
        以降にできたパス（baseline が無いときも）。そのときだけ、下への書き込みやユーザーの作成
        で説明がつく: それらはパスを作るが、もとからあるパスの mode や所有者は変えない。
        """
        windows = list(self.by_path.get(path, ()))
        if created:
            windows += self.by_dir.get(path, ())
            for home, more in self.by_home.items():
                if path == home or path.startswith(home + "/"):
                    windows += more
        return next((w.module for w in windows if w.holds(st.ctime_ns)), None)

    def _add(self, path: str, w: Window) -> None:
        """A write of `path`; the directories above it change too."""
        self.by_path.setdefault(path, []).append(w)
        while path != "/":
            path = posixpath.dirname(path)
            self.by_dir.setdefault(path, []).append(w)
        if w.module not in self.modules:
            self.modules.append(w.module)


def _homes(src: SystemSource) -> dict[str, str]:
    """user -> home directory, from /etc/passwd."""
    out: dict[str, str] = {}
    try:
        blob = src.read("/etc/passwd")
    except DiskReadError:
        return out
    for line in (blob or b"").decode("utf-8", "replace").splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[5].startswith("/"):
            out[parts[0]] = parts[5].rstrip("/") or "/"
    return out


def _log_files(src: SystemSource) -> Iterator[tuple[str, str]]:
    """(path, text) of cloud-init.log and its rotated copies, oldest first."""
    names = [n for n in src.try_listdir(LOG_DIR) or [] if n.startswith(LOG_NAME)]

    def age(name: str) -> int:  # cloud-init.log.2.gz is older than .1, which is older than none
        rest = name[len(LOG_NAME) :].removesuffix(".gz").lstrip(".")
        return int(rest) if rest.isdigit() else (0 if not rest else -1)

    for name in sorted((n for n in names if age(n) >= 0), key=age, reverse=True):
        path = f"{LOG_DIR}/{name}"
        try:
            blob = src.read(path)
            if blob is not None and name.endswith(".gz"):
                blob = gzip.decompress(blob)
        except (DiskReadError, OSError, EOFError, zlib.error):  # unreadable, or not gzip after all
            continue
        if blob is not None:
            yield path, blob.decode("utf-8", "replace")


def _command(message: str) -> list[str] | None:
    m = _COMMAND.search(message)
    if not m:
        return None
    try:
        argv = ast.literal_eval(m.group(1))
    except (ValueError, SyntaxError):
        return None
    if isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv):
        return argv
    return None


def _effects(message: str, homes: dict[str, str]) -> tuple[list[str], list[str]]:
    """(paths, homes) one log message says were written."""
    m = _WRITE.search(message)
    if m:
        return [m.group(1)], []
    if message.startswith("Rendered netplan config"):
        return [NETPLAN_FILE], []
    argv = _command(message)
    if argv is None:
        return [], []
    name = posixpath.basename(argv[0])
    if name == "hostnamectl" and "set-hostname" in argv:
        return ["/etc/hostname"], []
    paths = list(COMMAND_WRITES.get(name, ()))
    if name == "useradd":
        user = next((a for a in argv[1:] if not a.startswith("-")), None)
        home = homes.get(user) if user else None
        if user:
            paths += [f"/var/spool/mail/{user}", f"/var/mail/{user}"]
        return paths, [home] if home else []
    return paths, []


def _time_ns(stamp: str, ms: str) -> int | None:
    """A log line's time in ns; None for digits that are no date (a damaged line)."""
    try:
        t = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None
    return (int(t.timestamp()) * 1000 + int(ms)) * 10**6


def _syslog_lines(found: list[re.Match[str]]) -> list[tuple[int, str]]:
    """(time in ns, message) of lines in the form Amazon Linux 2 logs them:
    "Nov 15 01:33:51 cloud-init[1725]: util.py[DEBUG]: <message>", local time to the
    second and no year. Each stage begins with a line that also says the moment in full
    and in UTC ("... running 'init' at Sun, 15 Nov 2026 01:33:51 +0000"): that gives the
    year, and how far the server's clock is from UTC. Lines before the first of those
    are read by it too."""
    out: list[tuple[int, str]] = []

    def local(m: re.Match[str], y: int) -> datetime:
        hour, minute, second = (int(x) for x in m.group(3).split(":"))
        return datetime(y, _MONTHS[m.group(1)], int(m.group(2)), hour, minute, second)

    def stage(m: re.Match[str]) -> tuple[int, timedelta] | None:
        """(year, local time - UTC) from a stage line, if this is one that can be read."""
        at = _STAGE_AT.search(m.group(4))
        if not at or at.group(2) not in _MONTHS or m.group(1) not in _MONTHS:
            return None
        try:
            hour, minute, second = (int(x) for x in at.group(4).split(":"))
            utc = datetime(
                int(at.group(3)), _MONTHS[at.group(2)], int(at.group(1)), hour, minute, second
            )
            # The year the line's own date is in: the one that puts it next to that moment.
            near = min((utc.year - 1, utc.year, utc.year + 1), key=lambda y: abs(local(m, y) - utc))
            minutes = round((local(m, near) - utc) / timedelta(minutes=15)) * 15
        except ValueError:  # 31 Feb, 25 o'clock
            return None
        return near, timedelta(minutes=minutes)

    first = next((s for s in map(stage, found) if s is not None), None)
    if first is None:
        return []  # no line says the year: the times cannot be told
    year, offset = first
    last: datetime | None = None
    for m in found:
        if m.group(1) not in _MONTHS:
            continue
        told = stage(m)
        if told is not None:
            year, offset = told
        try:
            t = local(m, year)
            if last is not None and t < last - timedelta(days=180):  # past New Year
                year += 1
                t = local(m, year)
        except ValueError:
            continue
        last = t
        out.append((int((t - offset).replace(tzinfo=UTC).timestamp()) * 10**9, m.group(4)))
    return out


def _lines(text: str) -> list[tuple[int, str]]:
    """(time in ns, message) of every line of a log that is in one of the two forms
    cloud-init's packages configure: its own default, with a full date and milliseconds,
    or the syslog-like one of Amazon Linux 2."""
    rows = text.splitlines()
    found = [m for m in map(_LINE.fullmatch, rows) if m]
    if found:
        timed = [(_time_ns(m.group(1), m.group(2)), m.group(3)) for m in found]
        return [(ns, message) for ns, message in timed if ns is not None]
    return _syslog_lines([m for m in map(_SYSLOG_LINE.fullmatch, rows) if m])


def read_cloud_init(src: SystemSource) -> CloudInit | None:
    """What cloud-init wrote, from its log; None if it never ran here and left no log.

    cloud-init が書いたものをログから読む。動いた形跡もログも無ければ None。
    """
    ran = src.try_listdir(RAN_MARK) is not None
    logs = list(_log_files(src))
    if not ran and not logs:
        return None
    out = CloudInit(ran)
    homes = _homes(src)
    lines: list[tuple[int, str]] = []  # one stream, oldest first: a window may end in the next file
    for path, text in logs:
        out.logs.append(path)
        lines += _lines(text)
    out.lines = len(lines)
    if lines:
        out.first_ns = lines[0][0]
    module = "?"
    for i, (begin, message) in enumerate(lines):
        stage = _STAGE.search(message)
        if stage:
            module = stage.group(1)
        found = _MODULE.match(message)
        if found:
            module = found.group(1).replace("-", "_")
        paths, new_homes = _effects(message, homes)
        if not paths and not new_homes:
            continue
        after = lines[i + 1][0] if i + 1 < len(lines) else begin  # the next line, or this one
        w = Window(module, begin, max(begin, after))
        for p in paths:
            out._add(p, w)
        for h in new_homes:
            out.by_home.setdefault(h, []).append(w)
    return out
