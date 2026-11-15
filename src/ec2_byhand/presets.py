"""What `systemctl preset` would enable, as rpm runs it when a package is first
installed (%systemd_post), worked out from the files on disk.

  presets   /etc/systemd/system-preset, /usr/local/lib/systemd/system-preset,
            /usr/lib/systemd/system-preset, /lib/systemd/system-preset: *.preset, a
            file in an earlier directory hiding one of the same name in a later one,
            read in the order of their names. "enable PATTERN" / "disable PATTERN",
            fnmatch patterns; the first line that matches decides; no match enables.
  [Install] WantedBy= / RequiredBy= (links in <target>.wants/ or .requires/) and
            Alias= (a link of that name) of the unit file. A template (name@.service)
            is enabled with its DefaultInstance=, or the instances the preset line
            names; without either it gets no link.

rpm keeps no record of what a package enabled, unlike deb-systemd-helper; this is
how a service enabled on install and disabled by hand afterwards can be seen.

rpm がパッケージを初めて入れたときに実行する `systemctl preset`（%systemd_post）が何を有効に
するかを、ディスク上のファイルから計算する。preset（4 つの system-preset ディレクトリの
*.preset。前のディレクトリの同名のファイルが後ろを隠し、名前の順に読む。「enable / disable
パターン」の最初に当たった行で決まり、どれにも当たらなければ有効）と、unit の [Install]
（WantedBy=・RequiredBy= で <target>.wants/・.requires/ にリンク、Alias= でその名前のリンク。
テンプレートは DefaultInstance= か preset の行が挙げるインスタンスで有効になり、どちらも無ければ
リンクはできない）。rpm は deb-systemd-helper と違って何を有効にしたかを記録しないので、入れた
ときに有効になり、あとで手で止めたサービスはこうして見つける。
"""

from __future__ import annotations

import fnmatch

from diskread.errors import DiskReadError
from diskread.source import SystemSource

PRESET_DIRS = (
    "/etc/systemd/system-preset",
    "/usr/local/lib/systemd/system-preset",
    "/usr/lib/systemd/system-preset",
    "/lib/systemd/system-preset",
)
SYSTEMD_DIR = "/etc/systemd/system"
UNIT_SUFFIXES = (".service", ".socket", ".timer", ".path", ".target", ".mount")


def _read(src: SystemSource, path: str) -> str:
    try:
        return (src.read(path) or b"").decode("utf-8", "replace")
    except DiskReadError:
        return ""


class Presets:
    """The preset lines of a system, in the order systemd applies them.

    システムの preset の行を、systemd が当てはめる順に持つ。
    """

    def __init__(self, src: SystemSource) -> None:
        chosen: dict[str, str] = {}
        for d in PRESET_DIRS:
            for name in src.try_listdir(d) or []:
                if name.endswith(".preset") and name not in chosen:
                    chosen[name] = f"{d}/{name}"
        self.lines: list[tuple[bool, str, tuple[str, ...]]] = []
        for name in sorted(chosen):
            for raw in _read(src, chosen[name]).splitlines():
                fields = raw.split()
                if len(fields) >= 2 and fields[0] in ("enable", "disable"):
                    self.lines.append((fields[0] == "enable", fields[1], tuple(fields[2:])))

    def verdict(self, unit: str) -> tuple[bool, tuple[str, ...]]:
        """(enable it, the instances named for a template) for a unit name.

        unit の名前について（有効にするか、テンプレートなら挙げられたインスタンス）。
        """
        for enable, pattern, instances in self.lines:
            if fnmatch.fnmatchcase(unit, pattern):
                return enable, instances
        return True, ()


def _install(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            section = line
        elif section == "[Install]" and "=" in line and not line.startswith(("#", ";")):
            key, _, value = line.partition("=")
            out.setdefault(key.strip(), []).extend(value.split())
    return out


def preset_links(src: SystemSource, presets: Presets, unit_path: str) -> list[str]:
    """The links `systemctl preset` would make for the unit file at `unit_path`; none
    when the preset disables it or it has nothing to enable.

    `unit_path` の unit ファイルについて `systemctl preset` が作るリンク。preset が無効にする
    か、有効にするものが無ければ空。
    """
    unit = unit_path.rsplit("/", 1)[-1]
    if not unit.endswith(UNIT_SUFFIXES):
        return []
    enable, named = presets.verdict(unit)
    if not enable:
        return []
    install = _install(_read(src, unit_path))
    names = [unit]
    if "@." in unit:  # a template
        instances = list(named) or install.get("DefaultInstance", [])[:1]
        names = [unit.replace("@.", f"@{i}.") for i in instances]
    links = [
        f"{SYSTEMD_DIR}/{target}.{kind}/{name}"
        for name in names
        for key, kind in (("WantedBy", "wants"), ("RequiredBy", "requires"))
        for target in install.get(key, [])
    ]
    links += [f"{SYSTEMD_DIR}/{alias}" for alias in install.get("Alias", [])]
    return links
