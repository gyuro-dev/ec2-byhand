"""dpkg database: /var/lib/dpkg/status plus per-package files in info/.

status is a sequence of RFC 822-style stanzas ("Field: value", continued
on lines starting with a space) separated by blank lines. Fields used:
Package, Status ("want flag status"), Architecture, Version, Conffiles.
info/<pkg>.list (or <pkg>:<arch>.list for Multi-Arch: same packages)
lists the package's paths; info/<pkg>.md5sums holds "md5  relative/path".

dpkg データベース: /var/lib/dpkg/status と info/ のパッケージ別ファイル。status は RFC 822 風
スタンザの並び。info/<pkg>.list がそのパッケージのパス一覧で、info/<pkg>.md5sums が「md5  相対
パス」を持つ。
"""

from __future__ import annotations

from collections.abc import Callable

from diskread.errors import DiskReadError, malformed_as_disk_read_error
from diskread.source import clean_path
from ec2_byhand.packages.model import OnDamage, Package, PackageFile

# dpkg-query's db:Status-Abbrev letters.
WANT = {"unknown": "u", "install": "i", "hold": "h", "deinstall": "r", "purge": "p"}
STATE = {
    "not-installed": "n",
    "config-files": "c",
    "half-installed": "H",
    "unpacked": "U",
    "half-configured": "F",
    "triggers-awaited": "W",
    "triggers-pending": "t",
    "installed": "i",
}


def parse_stanzas(text: str) -> list[dict[str, str]]:
    """RFC 822-style stanzas as dicts, continuation lines joined with newlines.

    RFC 822 風のスタンザを dict の列にする。継続行は改行でつなぐ。
    """
    out: list[dict[str, str]] = []
    cur: dict[str, str] = {}
    last: str | None = None
    for line in text.splitlines():
        if not line.strip():
            if cur:
                out.append(cur)
            cur, last = {}, None
        elif line[0] in " \t" and last is not None:
            cur[last] += "\n" + line.strip()
        elif ":" in line:
            key, _, value = line.partition(":")
            last = key.strip()
            cur[last] = value.strip()
    if cur:
        out.append(cur)
    return out


def status_abbrev(status: str) -> str:
    """The three-letter dpkg-query abbreviation of a Status value ("ii "...).

    Status の値の dpkg-query 風 3 文字表記（「ii 」など）。
    """
    want, flag, state = ([*status.split(), "", "", ""])[:3]
    return WANT.get(want, "?") + STATE.get(state, "?") + (" " if flag == "ok" else "R")


def _epoch(version: str) -> int | None:
    """The epoch of a dpkg version, or None if it has none or an unusable one."""
    epoch, sep, _ = version.partition(":")
    try:
        return int(epoch) if sep and epoch.isascii() and epoch.isdigit() else None
    except ValueError:  # more digits than int() accepts
        return None


@malformed_as_disk_read_error
def read_dpkg(
    status: bytes,
    read_info: Callable[[str], bytes | None],
    on_damage: OnDamage | None = None,
) -> list[Package]:
    """`read_info(name)` returns the bytes of /var/lib/dpkg/info/<name>, or None.
    A status that is not one raises DiskReadError; an empty one has no packages.
    A removed package whose conffiles remain ("rc") is not among the packages.
    An info file that cannot be read goes to `on_damage` (without one, it raises)
    and the package stays, without what that file would have told.

    `read_info(name)` は /var/lib/dpkg/info/<name> のバイト列を返す（無ければ None）。status で
    ない内容なら DiskReadError。空の status はパッケージ 0 件。削除済みで設定ファイルだけが残る
    パッケージ（「rc」）は含めない。読めない info ファイルは `on_damage` に渡し（無ければ例外）、
    パッケージはそのファイルの情報を欠いたまま残す。
    """

    def read_or_report(name: str) -> bytes | None:
        try:
            return read_info(name)
        except DiskReadError as err:
            if on_damage is None:
                raise
            on_damage(f"dpkg info/{name}: {err}")
            return None

    stanzas = parse_stanzas(status.decode("utf-8", "replace"))
    # The parser skips lines it cannot use, so damage would otherwise read as
    # "no packages". NUL: a crash can leave zeros where the text was not yet written.
    if b"\0" in status or (status.strip() and not any("Package" in st for st in stanzas)):
        raise DiskReadError("dpkg status: damaged (binary data or no package entries)")
    packages = []
    for st in stanzas:
        name, version = st.get("Package"), st.get("Version")
        if not name or not version:
            continue
        abbrev = status_abbrev(st.get("Status", ""))
        # Not installed, or removed with only its conffiles left ("rc", what `apt remove`
        # leaves): the package is gone, so it must not pass for an installed one.
        if abbrev[1] in ("n", "c"):
            continue
        arch = st.get("Architecture")
        packages.append(
            Package(
                manager="dpkg",
                name=name,
                arch=arch,
                epoch=_epoch(version),
                version=version,
                release=None,
                status=abbrev,
                files=_files(name, arch, st.get("Conffiles", ""), read_or_report),
            )
        )
    return packages


def _files(
    name: str, arch: str | None, conffiles: str, read_info: Callable[[str], bytes | None]
) -> tuple[PackageFile, ...]:
    """A package's PackageFile list from its .list, .md5sums and Conffiles."""
    stem = None
    listing = None
    for candidate in ([f"{name}:{arch}"] if arch else []) + [name]:
        listing = read_info(f"{candidate}.list")
        if listing is not None:
            stem = candidate
            break
    if listing is None or stem is None:
        return ()
    md5 = {}
    sums = read_info(f"{stem}.md5sums")
    if sums:
        for line in sums.decode("utf-8", "surrogateescape").splitlines():
            md5sum, _, rel = line.partition("  ")
            if rel:
                md5["/" + rel] = md5sum
    conf = {}
    for line in conffiles.splitlines():
        parts = line.split()
        # "obsolete" conffiles and "newconffile" placeholders are not verified.
        if len(parts) >= 2 and "obsolete" not in parts[2:] and parts[1] != "newconffile":
            conf[parts[0]] = parts[1]
    out = []
    for path in listing.decode("utf-8", "surrogateescape").splitlines():
        # "/." is dpkg's own line for the root. Anything else that is not a plain
        # absolute path (a ".." in it) is no file of the package: left to be listed as
        # what no package owns.
        if not path or not (path == "/." or clean_path(path)):
            continue
        digest = md5.get(path) or conf.get(path)
        out.append(
            PackageFile(
                path=path,
                digest=digest,
                digest_algo="md5" if digest else None,
                is_config=path in conf,
            )
        )
    return tuple(out)
