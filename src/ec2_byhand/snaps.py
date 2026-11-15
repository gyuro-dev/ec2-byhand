"""Snaps (Ubuntu's snapd): which are installed, read from snapd's own state.

  /var/lib/snapd/state.json   data.snaps.<name>: type, current revision, channel
                              and the revisions kept (sequence); changes.<id>:
                              kind ("install-snap"...), summary, snap-names, times
  /var/lib/snapd/seed/seed.yaml   the snaps the image came with (seeded at first boot)

A snap brings files of its own that are not hand work: the squashfs
(/var/lib/snapd/snaps/<name>_<rev>.snap), its mountpoints and links under /snap
(/snap/<name>/..., /snap/bin/<name>[.<app>]), and the units snapd writes into
/etc/systemd/system (snap-<name>-<rev>.mount, with "-" escaped as \\x2d, and
snap.<name>.<app>.<type>). Of its data, /var/snap/<name>, only the bare directories
snapd makes (<rev>, common, current) come with it: what is put in them is judged as
any other path, configuration can live there.

Ubuntu の snapd の snap を、snapd 自身の状態から読む。state.json（data.snaps に種類・今の
版・チャネル・残している版、changes に操作の種類・要約・対象の snap・時刻）と seed.yaml（イメージ
に入っていた snap）。snap に付いてくるファイルは手作業ではない: squashfs（/var/lib/snapd/snaps）、
/snap の下のマウントポイントとリンク、snapd が /etc/systemd/system に書く unit（snap-<名前>-<版>
.mount。「-」は \\x2d にエスケープ。snap.<名前>.<アプリ>.<種類>）。データの /var/snap/<名前> は、
snapd が作るディレクトリ（版、common、current）だけが付いてくるもので、中に置かれたものは設定の
こともあるので、ほかのパスと同じに判定する。
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from diskread.errors import DiskReadError
from diskread.source import SystemSource

STATE = "/var/lib/snapd/state.json"
SEED = "/var/lib/snapd/seed/seed.yaml"
SNAPS_DIR = "/var/lib/snapd/snaps"
UNIT_DIR = "/etc/systemd/system"
VAR_SNAP = "/var/snap"
_SEED_NAME = re.compile(r"^\s*(?:-\s+)?name:\s*(\S+)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class Snap:
    """One installed snap.

    入っている snap 1 つ。
    """

    name: str
    type: str | None
    revision: str | None
    channel: str | None
    revisions: tuple[str, ...]  # every revision snapd keeps on disk
    seeded: bool  # the image came with it
    via: dict[str, Any] | None  # the snapd change that installed it, if recorded


def _unit_name(name: str) -> str:
    return name.replace("-", "\\x2d")


def _via(changes: dict[str, Any], name: str) -> dict[str, Any] | None:
    """The latest install change naming this snap."""
    found = None
    for ch in changes.values():
        if not isinstance(ch, dict) or not str(ch.get("kind", "")).startswith("install"):
            continue
        data = ch.get("data")
        names = data.get("snap-names") if isinstance(data, dict) else None
        if isinstance(names, list) and name in names:
            found = {
                "kind": ch.get("kind"),
                "summary": ch.get("summary"),
                "time": ch.get("spawn-time"),
            }
    return found


def read_snaps(src: SystemSource) -> tuple[list[Snap] | None, str | None]:
    """(the installed snaps, why the state could not be read). (None, None) without
    snapd's state.

    （入っている snap、状態が読めなかった理由）。snapd の状態が無ければ (None, None)。
    """
    try:
        blob = src.read(STATE)
    except DiskReadError as err:
        return None, str(err)
    if blob is None:
        return None, None
    try:
        state = json.loads(blob)
        snaps = state["data"]["snaps"]
        changes = state.get("changes") or {}
        if not isinstance(snaps, dict) or not isinstance(changes, dict):
            raise TypeError("snaps or changes is not an object")
    except (ValueError, KeyError, TypeError) as err:
        return None, f"{STATE}: {err}"
    try:
        seed_text = (src.read(SEED) or b"").decode("utf-8", "replace")
    except DiskReadError:
        seed_text = ""
    seeded = set(_SEED_NAME.findall(seed_text))
    out = []
    for name, st in sorted(snaps.items()):
        if not isinstance(st, dict):
            continue
        sequence = [s for s in st.get("sequence") or [] if isinstance(s, dict)]
        revisions = tuple(str(s["revision"]) for s in sequence if s.get("revision"))
        out.append(
            Snap(
                name=name,
                type=st.get("type"),
                revision=str(st["current"]) if st.get("current") else None,
                channel=st.get("channel"),
                revisions=revisions,
                seeded=name in seeded,
                via=_via(changes, name),
            )
        )
    return out, None


def unit_owners(snaps: Iterable[Snap]) -> dict[str, str]:
    """Names of the units snapd writes for these snaps (mounts exactly; app units by
    their prefix, ending in ".") -> the snap.

    snapd がこれらの snap のために書く unit の名前（マウントは完全な名前、アプリの unit は「.」で
    終わる前置き）→ その snap。
    """
    out: dict[str, str] = {}
    for s in snaps:
        for rev in s.revisions or ((s.revision,) if s.revision else ()):
            out[f"snap-{_unit_name(s.name)}-{rev}.mount"] = s.name
        out[f"snap.{s.name}."] = s.name
    return out


def unit_snap(unit: str, owners: dict[str, str]) -> str | None:
    """The snap a unit (a file name under /etc/systemd/system) belongs to.

    unit（/etc/systemd/system の下のファイル名）が属する snap。
    """
    if unit in owners:
        return owners[unit]
    if unit.startswith("snap."):
        prefix = unit[: unit.index(".", 5) + 1] if "." in unit[5:] else ""
        return owners.get(prefix)
    return None


def snap_paths(snaps: list[Snap], paths: Iterable[str]) -> dict[str, str]:
    """path -> snap, for the paths of `paths` that come with a snap (see the module).

    `paths` のうち、snap に付いてくるパス → その snap。
    """
    names = {s.name for s in snaps}
    owners = unit_owners(snaps)
    files = {f"{SNAPS_DIR}/{s.name}_{rev}.snap": s.name for s in snaps for rev in s.revisions}
    # The bare data directories snapd makes (/var/snap/<name>, <rev>, common, current):
    # what is put in them is judged as any other path.
    for s in snaps:
        base = f"{VAR_SNAP}/{s.name}"
        files[base] = s.name
        for leaf in (*s.revisions, "common", "current"):
            files[f"{base}/{leaf}"] = s.name
    out: dict[str, str] = {}
    for p in paths:
        if p in files:
            out[p] = files[p]
        elif p.startswith("/snap/"):
            first = p[len("/snap/") :].split("/", 1)
            if first[0] in names:
                out[p] = first[0]
            elif first[0] == "bin" and len(first) > 1:
                app = first[1].split("/", 1)[0].split(".", 1)[0]
                if app in names:
                    out[p] = app
        elif p.startswith(UNIT_DIR + "/") and p.count("/") == UNIT_DIR.count("/") + 1:
            owner = unit_snap(p.rsplit("/", 1)[1], owners)
            if owner is not None:
                out[p] = owner
    return out


def compare_snaps(
    now: list[Snap] | None, then: list[Snap] | None, has_baseline: bool
) -> tuple[list[dict[str, Any]] | None, int]:
    """The manifest's "snaps" section and how many did not change. With a baseline,
    only those added, removed or refreshed (revision or channel); without one, all of
    them, as "present". None when neither side has snapd's state.

    manifest の "snaps" 節と、変わらなかった数。baseline があれば増えた・消えた・更新された（版か
    チャネル）ものだけ、無ければ全部を "present" で。どちらにも snapd の状態が無ければ None。
    """
    if now is None and then is None:
        return None, 0
    cur = {s.name: s for s in now or []}
    old = {s.name: s for s in then or []}
    out: list[dict[str, Any]] = []
    unchanged = 0
    for name in sorted(cur.keys() | old.keys()):
        c, o = cur.get(name), old.get(name)
        if not has_baseline:
            status = "present"
        elif o is None:
            status = "added"
        elif c is None:
            status = "removed"
        elif (c.revision, c.channel) != (o.revision, o.channel):
            status = "refreshed"
        else:
            unchanged += 1
            continue
        s = c or o
        assert s is not None  # the name is on one side at least
        item: dict[str, Any] = {
            "name": name,
            "type": s.type,
            "revision": s.revision,
            "channel": s.channel,
            "status": status,
            "seeded": s.seeded,
        }
        if status == "refreshed" and o is not None:
            item["from"] = {"revision": o.revision, "channel": o.channel}
        if c is not None and c.via is not None:
            item["via"] = c.via
        out.append(item)
    return out, unchanged
