"""Directories systemd makes by itself, from what it is told to make.

Some directories appear on the first boot of every instance and belong to no package,
so they would look like hand work: systemd makes them, as its configuration says.

  tmpfiles.d   /etc/tmpfiles.d, /usr/local/lib/tmpfiles.d, /usr/lib/tmpfiles.d,
               /lib/tmpfiles.d: *.conf, a file in an earlier directory hiding one of
               the same name in a later one. "d /var/log/private 0700 root root -":
               type, path, mode... Types d, D, v, q, Q make a directory
               (systemd-tmpfiles-setup.service, at boot); "-" is the default mode.
  units        StateDirectory=, CacheDirectory=, LogsDirectory=,
               ConfigurationDirectory= in the [Service] of a unit under
               /etc/systemd/system, /usr/lib/systemd/system or /lib/systemd/system:
               names below /var/lib, /var/cache, /var/log, /etc, made when the service
               starts, with *DirectoryMode= (0755 by default). With DynamicUser=yes the
               first three live in .../private/<name>, linked from .../<name>.

Only the directories themselves are told, with the mode they get, never their
contents (a StateDirectory= holds the service's data). A path with a specifier ("%")
is skipped: it is filled in at run time.

systemd が自分で作るディレクトリを、作るように言われている設定から読む。初回起動でどの
インスタンスにも現れ、どのパッケージにも属さないので、手作業に見えてしまうもの。tmpfiles.d
（/etc・/usr/local/lib・/usr/lib・/lib の tmpfiles.d/*.conf。前のディレクトリの同名のファイル
が後ろを隠す。種別 d・D・v・q・Q がディレクトリを作る）と、unit の StateDirectory=・
CacheDirectory=・LogsDirectory=・ConfigurationDirectory=（/var/lib・/var/cache・/var/log・/etc
の下の名前。モードは *DirectoryMode=、既定は 0755。DynamicUser=yes なら前の 3 つは
.../private/<名前> にでき、.../<名前> からリンクされる）。伝えるのはディレクトリそのものと
そのモードだけで、中身は含めない（StateDirectory= にはサービスのデータがある）。指定子（%）を
含むパスは、実行時に決まるので飛ばす。
"""

from __future__ import annotations

import posixpath

from diskread.errors import DiskReadError
from diskread.source import SystemSource

TMPFILES_DIRS = (
    "/etc/tmpfiles.d",
    "/usr/local/lib/tmpfiles.d",
    "/usr/lib/tmpfiles.d",
    "/lib/tmpfiles.d",
)
UNIT_DIRS = ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system")
MAKES_DIR = frozenset("dDvqQ")
DIRECTORY_SETTINGS = {  # setting -> (base, its mode setting, under private/ with DynamicUser)
    "StateDirectory": ("/var/lib", "StateDirectoryMode", True),
    "CacheDirectory": ("/var/cache", "CacheDirectoryMode", True),
    "LogsDirectory": ("/var/log", "LogsDirectoryMode", True),
    "ConfigurationDirectory": ("/etc", "ConfigurationDirectoryMode", False),
}


def _read(src: SystemSource, path: str) -> str | None:
    try:
        blob = src.read(path)
    except DiskReadError:
        return None
    return None if blob is None else blob.decode("utf-8", "replace")


def _mode(text: str) -> int | None:
    try:
        return int(text, 8)
    except ValueError:
        return None


def _configs(src: SystemSource, dirs: tuple[str, ...], suffix: str) -> list[str]:
    """Paths of the config files, a name in an earlier directory hiding the later ones,
    in the order of their names (as systemd reads them)."""
    chosen: dict[str, str] = {}
    for d in dirs:
        for name in src.try_listdir(d) or []:
            if name.endswith(suffix) and name not in chosen:
                chosen[name] = f"{d}/{name}"
    return [chosen[n] for n in sorted(chosen)]


def _tmpfiles(src: SystemSource, out: dict[str, int | None]) -> None:
    for conf in _configs(src, TMPFILES_DIRS, ".conf"):
        for line in (_read(src, conf) or "").splitlines():
            fields = line.split()
            if len(fields) < 2 or fields[0].startswith("#") or "%" in fields[1]:
                continue
            kind, path = fields[0].rstrip("!-=~^+"), fields[1]
            if kind not in MAKES_DIR or not path.startswith("/"):
                continue
            mode = _mode(fields[2].lstrip("~:")) if len(fields) > 2 else None
            out.setdefault(posixpath.normpath(path), mode)  # the first line for a path wins


def _settings(text: str) -> dict[str, str]:
    """The settings of a unit's [Service] section (the last of each, as systemd does for
    these; an empty value resets)."""
    out: dict[str, str] = {}
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            section = line
        elif section == "[Service]" and "=" in line and not line.startswith(("#", ";")):
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if key in DIRECTORY_SETTINGS and out.get(key) and value:
                out[key] += " " + value  # these lists add up
            else:
                out[key] = value
    return out


def _units(src: SystemSource, out: dict[str, int | None]) -> None:
    for unit in _configs(src, UNIT_DIRS, ".service"):
        text = _read(src, unit)
        if not text or "Directory=" not in text:
            continue
        settings = _settings(text)
        dynamic = settings.get("DynamicUser", "").lower() in ("yes", "true", "1", "on")
        for key, (base, mode_key, private) in DIRECTORY_SETTINGS.items():
            mode = _mode(settings.get(mode_key, "0755"))
            for item in settings.get(key, "").split():
                name = item.split(":", 1)[0].strip("/")
                if not name or "%" in name or ".." in name.split("/"):
                    continue
                if dynamic and private:
                    out.setdefault(f"{base}/private", 0o700)
                    out.setdefault(f"{base}/private/{name}", mode)
                out.setdefault(f"{base}/{name}", mode)
                for parent in _parents(name):  # a/b makes a too
                    out.setdefault(f"{base}/{parent}", mode)


def _parents(name: str) -> list[str]:
    parts = name.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]


def service_dirs(src: SystemSource) -> dict[str, int | None]:
    """path -> the mode systemd gives it (None: not said), for every directory systemd
    is configured to make.

    systemd が作るように設定されているディレクトリの、パス → systemd が付けるモード（None は
    指定なし）。
    """
    out: dict[str, int | None] = {}
    _tmpfiles(src, out)
    _units(src, out)
    return out
