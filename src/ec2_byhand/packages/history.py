"""Package manager transaction history: which command installed what, when.

dnf 4 (AL2023, RHEL 8/9): /var/lib/dnf/history.sqlite (libdnf "swdb"),
  trans(id, dt_begin, dt_end, cmdline, state) and
  trans_item(trans_id, item_id, action) joined with rpm(item_id, name,
  epoch, version, release, arch). A snapshot taken while dnf was running
  may hold the newest transaction only in history.sqlite-wal, so it is
  opened together with the WAL. (After dnf exits, the WAL file usually
  stays but its contents are already in the main file.)
yum 3 (AL2, RHEL 7): /var/lib/yum/history/history-YYYY-MM-DD.sqlite, one
  file per period: trans_beg(tid, timestamp), trans_end(tid, timestamp),
  trans_cmdline(tid, cmdline), trans_data_pkgs(tid, pkgtupid, state) with
  pkgtups(pkgtupid, name, arch, epoch, version, release).
apt (Debian/Ubuntu): /var/log/apt/history.log and rotated history.log.N.gz,
  stanzas of "Start-Date:", "Commandline:", "Install:"/"Upgrade:"/... and
  "End-Date:", package lists like "tzdata:amd64 (2024a-1, 2026e-1), ...".
  Logs are rotated away over time, so older history may be gone. The dates
  are local time without a zone, so they are read with the server's own
  /etc/localtime (UTC if it has none). When the zone was changed since the
  baseline (ZoneChange), what was logged before the change is read in the zone
  of then.

パッケージマネージャのトランザクション履歴: どのコマンドが・何を・いつ入れたか。dnf 4（AL2023,
RHEL 8/9）は /var/lib/dnf/history.sqlite（実行中に取ったスナップショットに備えて WAL ごと開く
）。yum 3（AL2, RHEL 7）は期間ごとの history-*.sqlite。apt は /var/log/apt/history.log と輪番
の .gz（古い履歴は消えていることがある）。apt の日時はゾーンの無いローカル時刻なので、サーバー
自身の /etc/localtime で読む（無ければ UTC）。baseline のあとでゾーンを変えていたら
（ZoneChange）、変更の前の記録は当時のゾーンで読む。
"""

from __future__ import annotations

import gzip
import io
import re
import sqlite3
import tempfile
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import Any, Protocol
from zoneinfo import ZoneInfo

from diskread.errors import MALFORMED_DATA_ERRORS, DiskReadError

# libdnf TransactionItemAction -> dnf's action_name
DNF_ACTIONS = {
    1: "Install",
    2: "Downgrade",
    3: "Downgraded",
    4: "Obsolete",
    5: "Obsoleted",
    6: "Upgrade",
    7: "Upgraded",
    8: "Removed",
    9: "Reinstall",
    10: "Reinstalled",
    11: "Reason Change",
}
APT_ACTIONS = ("Install", "Reinstall", "Upgrade", "Downgrade", "Remove", "Purge")


class ListingSource(Protocol):
    """What the history readers need: read a file, list a directory.

    履歴のリーダーが必要とするもの: ファイルを読む・ディレクトリを一覧する。
    """

    def read(self, path: str) -> bytes | None: ...

    def listdir(self, path: str) -> list[str] | None: ...


@dataclass(frozen=True)
class HistoryItem:
    """One package action inside a transaction.

    トランザクション内のパッケージ操作 1 つ。
    """

    name: str
    arch: str | None
    evr: str  # the version this action is about (for apt Upgrade/Downgrade: the new one)
    action: str  # as the package manager names it ("Install", "Upgrade", "Removed", ...)
    old_evr: str | None = None  # apt Upgrade/Downgrade: the version before


@dataclass(frozen=True)
class Transaction:
    """One package-manager run: when, what command, which items.

    パッケージマネージャの実行 1 回: いつ・どのコマンドで・何をしたか。
    """

    source: str  # "dnf", "yum" or "apt"
    id: int
    begin: int | None  # seconds since the epoch
    end: int | None
    cmdline: str | None
    items: tuple[HistoryItem, ...]


def _evr(epoch: int | str | None, version: str, release: str) -> str:
    """epoch/version/release as the manager prints it (epoch only when meaningful)."""
    e = str(epoch) if epoch not in (None, "", 0, "0") else ""
    return (f"{e}:" if e else "") + f"{version}-{release}"


def _query(db: bytes, extra: dict[str, bytes], sql: list[str]) -> list[list[tuple[Any, ...]]]:
    """Run queries on a database copied (with its -wal / -journal) to a temp dir."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "history.sqlite"
        path.write_bytes(db)
        for suffix, data in extra.items():
            if data:
                (Path(tmp) / f"history.sqlite{suffix}").write_bytes(data)
        con = sqlite3.connect(path)
        try:
            con.execute("PRAGMA trusted_schema = OFF")  # the database comes from the snapshot
            return [con.execute(q).fetchall() for q in sql]
        except sqlite3.DatabaseError as err:
            raise DiskReadError(f"package history database: {err}") from err
        finally:
            con.close()


def _read_dnf(src: ListingSource) -> list[Transaction]:
    """Transactions from dnf's history.sqlite (opened with its WAL)."""
    base = "/var/lib/dnf/history.sqlite"
    db = src.read(base)
    if db is None:
        return []
    trans, items = _query(
        db,
        {"-wal": src.read(base + "-wal") or b""},
        [
            "SELECT id, dt_begin, dt_end, cmdline FROM trans ORDER BY id",
            (
                "SELECT ti.trans_id, r.name, r.arch, r.epoch, r.version, r.release, ti.action "
                "FROM trans_item ti JOIN rpm r ON r.item_id = ti.item_id"
            ),
        ],
    )
    by_trans: dict[int, list[HistoryItem]] = {}
    for tid, name, arch, epoch, version, release, action in items:
        by_trans.setdefault(tid, []).append(
            HistoryItem(
                name, arch, _evr(epoch, version, release), DNF_ACTIONS.get(action, str(action))
            )
        )
    return [
        Transaction("dnf", tid, b, e, cmd, tuple(by_trans.get(tid, []))) for tid, b, e, cmd in trans
    ]


def _read_yum(src: ListingSource) -> list[Transaction]:
    """Transactions from yum's per-period history-*.sqlite files."""
    d = "/var/lib/yum/history"
    names = [n for n in src.listdir(d) or [] if re.fullmatch(r"history-[\d-]+\.sqlite", n)]
    out: list[Transaction] = []
    for name in sorted(names):
        db = src.read(f"{d}/{name}")
        if db is None:
            continue
        beg, end, cmd, items = _query(
            db,
            {"-journal": src.read(f"{d}/{name}-journal") or b""},
            [
                "SELECT tid, timestamp FROM trans_beg",
                "SELECT tid, timestamp FROM trans_end",
                "SELECT tid, cmdline FROM trans_cmdline",
                (
                    "SELECT d.tid, p.name, p.arch, p.epoch, p.version, p.release, d.state "
                    "FROM trans_data_pkgs d JOIN pkgtups p ON p.pkgtupid = d.pkgtupid"
                ),
            ],
        )
        ends: dict[int, int] = dict(end)
        cmds: dict[int, str] = dict(cmd)
        by_trans: dict[int, list[HistoryItem]] = {}
        for tid, pname, arch, epoch, version, release, state in items:
            by_trans.setdefault(tid, []).append(
                HistoryItem(pname, arch, _evr(epoch, version, release), state)
            )
        for tid, ts in sorted(beg):
            out.append(
                Transaction(
                    "yum", tid, ts, ends.get(tid), cmds.get(tid), tuple(by_trans.get(tid, []))
                )
            )
    return out


_APT_PKG = re.compile(r"([^\s,()]+?)(?::([^\s:,()]+))? \(([^)]*)\)")


def zone_from(data: bytes | None) -> tzinfo:
    """The time zone a zoneinfo file's content describes (an /etc/localtime, so the
    rules are the server's, not this machine's); UTC if there is none to read.

    zoneinfo ファイルの中身（/etc/localtime）が表すタイムゾーン。規則はこのマシンのものではなく
    サーバーのもの。読めるものが無ければ UTC。
    """
    try:
        if data:
            return ZoneInfo.from_file(io.BytesIO(data))
    except MALFORMED_DATA_ERRORS:  # not a zoneinfo file
        pass
    return UTC


@dataclass(frozen=True)
class ZoneChange:
    """The server's time zone was changed: the zone it kept before, and when the change
    was made (epoch seconds). apt logs local time without the zone, so what it logged
    before the change has to be read in the zone of then.

    サーバーのタイムゾーンが変えられた: それまでのゾーンと、変えた時刻（エポック秒）。apt は
    ゾーンを書かずに現地時刻を記録するので、変更の前に記録された分は当時のゾーンで読む。
    """

    before: tzinfo
    at: int


def _local_zone(src: ListingSource) -> tzinfo:
    """The server's time zone, from its own /etc/localtime (a link into its zoneinfo)."""
    try:
        return zone_from(src.read("/etc/localtime"))
    except DiskReadError:
        return UTC


def _apt_time(text: str, zone: tzinfo, change: ZoneChange | None = None) -> int | None:
    """An apt history timestamp, which is local time in `zone`, as epoch seconds. With
    a `change` of the zone: a time that lies before the change in both zones was written
    in the zone of then. (A zone moved west leaves a few hours before the change that
    read as after it in the new zone; those are taken as written in the new one.)"""
    try:
        local = datetime.strptime(" ".join(text.split()), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    now = int(local.replace(tzinfo=zone).timestamp())
    if change is not None and now < change.at:
        then = int(local.replace(tzinfo=change.before).timestamp())
        if then < change.at:
            return then
    return now


def parse_apt_history(
    text: str, first_id: int = 1, zone: tzinfo = UTC, change: ZoneChange | None = None
) -> list[Transaction]:
    """Transactions from one apt history.log text. apt writes local time
    without saying which: `zone` is the zone the server keeps, and `change` says
    whether it kept another one before (see ZoneChange).

    apt の history.log のテキスト 1 本からトランザクションを読む。apt はどのゾーンかを書かずに
    ローカル時刻を記録するので、`zone` にサーバーの今のタイムゾーンを、`change` に以前は別の
    ゾーンだったかどうか（ZoneChange 参照）を渡す。
    """
    out: list[Transaction] = []
    for block in re.split(r"\n\s*\n", text.strip()):
        fields = {}
        for line in block.splitlines():
            key, sep, value = line.partition(": ")
            if sep:
                fields[key.strip()] = value.strip()
        if "Start-Date" not in fields:
            continue
        items = []
        for action in APT_ACTIONS:
            for name, arch, versions in _APT_PKG.findall(fields.get(action, "")):
                vs = [v.strip() for v in versions.split(",") if v.strip() != "automatic"]
                new = vs[-1] if vs else ""
                old = vs[0] if action in ("Upgrade", "Downgrade") and len(vs) == 2 else None
                items.append(HistoryItem(name, arch or None, new, action, old))
        out.append(
            Transaction(
                "apt",
                first_id + len(out),
                _apt_time(fields["Start-Date"], zone, change),
                _apt_time(fields.get("End-Date", ""), zone, change),
                fields.get("Commandline"),
                tuple(items),
            )
        )
    return out


def _read_apt(src: ListingSource, change: ZoneChange | None = None) -> list[Transaction]:
    """Transactions from history.log and its rotated .gz files, oldest first."""
    d = "/var/log/apt"
    names = src.listdir(d) or []
    logs = [n for n in names if re.fullmatch(r"history\.log(\.\d+(\.gz)?)?", n)]

    def age(n: str) -> int:  # history.log.3.gz is older than history.log.1
        m = re.search(r"\.(\d+)", n)
        return int(m.group(1)) if m else 0

    text = []
    for name in sorted(logs, key=age, reverse=True):
        data = src.read(f"{d}/{name}") or b""
        if name.endswith(".gz"):
            try:
                data = gzip.decompress(data)
            except (OSError, EOFError, zlib.error):
                continue
        text.append(data.decode("utf-8", "replace"))
    return parse_apt_history("\n\n".join(text), zone=_local_zone(src), change=change)


def read_history(src: ListingSource, zone_change: ZoneChange | None = None) -> list[Transaction]:
    """All recorded transactions, oldest first (empty if no history is kept).
    `zone_change` tells apt's log, which has local times, that the server's time zone
    was another one before (dnf and yum record UTC).

    記録されている全トランザクションを古い順で（履歴が無ければ空）。`zone_change` は、現地時刻で
    書かれる apt のログに、サーバーのタイムゾーンが以前は別だったことを伝える（dnf と yum は
    UTC で記録する）。
    """
    for reader in (_read_dnf, _read_yum):
        found = reader(src)
        if found:
            return found
    return _read_apt(src, zone_change)
