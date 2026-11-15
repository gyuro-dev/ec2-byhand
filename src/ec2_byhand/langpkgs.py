"""Grey-zone files that are installed, but not by the OS package manager.

Language packages: `pip install` and `npm install` put thousands of
files outside rpm/dpkg. Rather than listing each as hand-placed, they are
grouped per package:
  pip  <site>/<name>-<ver>.dist-info/{METADATA, RECORD, INSTALLER}, where
       RECORD lists every file (relative to <site>) with sha256 (urlsafe
       base64, no padding) and size, so edited or deleted files are found,
       as rpm -V does for rpm files. <site> is a site-packages or dist-packages
       directory, or any directory when the .dist-info has a RECORD (`pip install
       --target DIR`). Old <name>.egg-info/installed-files.txt lists files
       (relative to the egg-info dir) without hashes.
  npm  <dir>/node_modules/[@scope/]<name>/package.json, global or an app's own,
       outermost node_modules only; files are everything below that directory.
       npm records no hashes, so edits are only suspected from the times: npm does
       not keep a tarball's mtimes, so a file much newer than the install is listed
       as edited_after_install. The install's time is that of node_modules/
       .package-lock.json (npm 7+, local), else the package's own package.json.
       The links npm makes in a bin directory for a package's commands go with the
       package (ec2_byhand.analyze, which knows every path of the tree).

Alternatives: update-alternatives / alternatives keep each group's state
in /var/lib/alternatives/<name> (RHEL) or /var/lib/dpkg/alternatives/<name>
(Debian): line 1 "auto" or "manual", line 2 the master link (e.g.
/usr/bin/python), then slave name/link pairs, a blank line, and the
candidates. The links themselves are /etc/alternatives/<name> and the
master/slave links pointing to it. "manual" means someone chose by hand.

OS のパッケージマネージャ以外で入った、グレーゾーンのファイル。pip install や npm install
は何千ものファイルを rpm / dpkg の外に置くので、1 つずつ hand_placed にせずパッケージ単位にま
とめる（pip は RECORD の sha256 とサイズで改変・欠落も見つける。rpm -V が rpm のファイルにする
のと同じ。npm はハッシュを持たないので、時刻から編集の候補を出す: npm は tarball の mtime を
引き継がないので、導入時刻よりかなり新しいファイルを edited_after_install に挙げる。導入時刻は
node_modules/.package-lock.json（npm 7 以降のローカル）か、無ければそのパッケージの
package.json の mtime）。pip のパッケージは、site-packages の下でなくても RECORD のある
.dist-info があれば見分ける（pip install --target DIR）。npm がパッケージのコマンドのために
bin に張るリンクは、パッケージと一緒に扱う（ec2_byhand.analyze）。alternatives は
/var/lib/alternatives などの状態ファイルから読み、「manual」は人が選んだ印。
"""

from __future__ import annotations

import base64
import bisect
import contextlib
import csv
import hashlib
import io
import json
import posixpath
import re
import tarfile
import zlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from diskread.blockdev import BlockDevice, read_chunks, will_read
from diskread.errors import DiskReadError
from diskread.fs import Filesystem, FileType, Stat
from diskread.source import SystemSource

SITE_DIRS = ("site-packages", "dist-packages")
ALTERNATIVES_STATE = ("/var/lib/alternatives", "/var/lib/dpkg/alternatives")


@dataclass
class LanguagePackage:
    """One pip / npm package: its files, and which were modified or deleted.

    pip / npm のパッケージ 1 つ: ファイル一覧と、その中の改変・欠落。
    """

    ecosystem: str  # "pypi" or "npm"
    name: str
    version: str | None
    location: str  # site-packages / node_modules directory holding it
    meta_dir: str  # the .dist-info / .egg-info / package directory
    installer: str | None = None
    files: set[str] = field(default_factory=set)  # absolute paths
    modified: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    edited_after_install: list[str] = field(default_factory=list)  # npm: suspected, not proven
    verified_by: str | None = None  # npm: "npm-cache" when compared with its own tarball
    unverified: list[str] = field(default_factory=list)  # pip: over the size limit, so not read


def _norm(path: str) -> str:
    """A path with // collapsed and ./ removed."""
    return posixpath.normpath(path)


def _install_root(site: str) -> str:
    """The directory a pip package in `site` may have files under: the prefix of a
    site-packages directory (three levels up, lib/pythonX.Y/site-packages: its scripts
    go to bin, its data to share), or the directory itself for `pip install --target`.
    A RECORD is a file anyone can write: a line that climbs further ("../../../../root/x")
    must not make that path a file of the package, and so hide it from the hand-placed."""
    if posixpath.basename(site) in SITE_DIRS:
        return posixpath.normpath(posixpath.join(site, "../../.."))
    return site


def _within(path: str, root: str) -> bool:
    return root == "/" or path == root or path.startswith(root + "/")


def _regular_file(src: SystemSource, path: str) -> tuple[Filesystem, int, Stat] | None:
    """(filesystem, inode, stat) of the regular file at `path`, or None if it is not one."""
    found = src.resolve(path, follow_last=False)
    if found is None:
        return None
    st = src.stat(*found)
    return (*found, st) if st.type is FileType.REG else None


def _sha256_b64(content: BlockDevice) -> str:
    """SHA-256 of the file in RECORD's urlsafe-base64 form (no padding)."""
    h = hashlib.sha256()
    for chunk in read_chunks(content):
        h.update(chunk)
    return base64.urlsafe_b64encode(h.digest()).rstrip(b"=").decode()


@dataclass(frozen=True)
class _Check:
    """A file of a pip package to hash against its RECORD line, `row` of the RECORD."""

    pkg: LanguagePackage
    row: int
    path: str
    fs: Filesystem
    ino: int
    digest: str


def _check_all(checks: list[_Check], flagged: dict[int, list[tuple[int, str]]]) -> None:
    """Hash every file to check, all told to the disk first (will_read), in inode order:
    one at a time, a disk read over a network waits for each (an app's virtualenv holds
    thousands of small files). A file that differs, or cannot be read, is flagged."""
    opened: list[tuple[_Check, BlockDevice]] = []
    for c in sorted(checks, key=lambda c: (id(c.fs), c.ino)):
        try:
            content = c.fs.open(c.ino)
        except DiskReadError:  # cannot show it is intact
            flagged[id(c.pkg)].append((c.row, c.path))
            continue
        will_read(content)
        opened.append((c, content))
    for c, content in opened:
        try:
            same = _sha256_b64(content) == c.digest
        except DiskReadError:
            same = False
        if not same:
            flagged[id(c.pkg)].append((c.row, c.path))


def _metadata(text: str) -> dict[str, str]:
    """Name/value headers of a METADATA / PKG-INFO text."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            break  # headers end at the first blank line; the body follows
        key, sep, value = line.partition(":")
        if sep and key not in out:
            out[key.strip()] = value.strip()
    return out


def _record_rows(text: str) -> list[list[str]]:
    """The rows of a RECORD text, up to the first line csv cannot parse."""
    rows: list[list[str]] = []
    with contextlib.suppress(csv.Error):  # e.g. a field over csv's size limit: not pip's doing
        rows.extend(row for row in csv.reader(io.StringIO(text)) if row and row[0])
    return rows


def _pip_dist_info(
    src: SystemSource,
    meta_dir: str,
    max_file_size: int | None,
    checks: list[_Check],
    flagged: dict[int, list[tuple[int, str]]],
) -> LanguagePackage:
    """One pip package from its .dist-info directory. The files RECORD has a hash for
    go to `checks`, hashed later all together (_check_all); `flagged` collects, by
    RECORD row, the files found modified, so that pkg.modified keeps RECORD's order."""
    site = posixpath.dirname(meta_dir)
    meta = _metadata(
        (src.try_read(meta_dir + "/METADATA", told=True) or b"").decode("utf-8", "replace")
    )
    name = (
        meta.get("Name")
        or posixpath.basename(meta_dir).removesuffix(".dist-info").rsplit("-", 1)[0]
    )
    installer = (src.try_read(meta_dir + "/INSTALLER", told=True) or b"").decode("utf-8", "replace")
    pkg = LanguagePackage(
        "pypi", name, meta.get("Version"), site, meta_dir, installer=installer.strip() or None
    )
    rows = flagged.setdefault(id(pkg), [])
    record = (src.try_read(meta_dir + "/RECORD", told=True) or b"").decode("utf-8", "replace")
    root = _install_root(site)
    for n, row in enumerate(_record_rows(record)):
        path = _norm(posixpath.join(site, row[0]))
        if not _within(path, root):
            continue  # not the package's to claim: judged as any other path
        pkg.files.add(path)
        digest = row[1] if len(row) > 1 else ""
        if not digest.startswith("sha256="):
            continue  # RECORD itself, and .pyc files compiled after install
        recorded_size = row[2] if len(row) > 2 else ""
        try:
            file = _regular_file(src, path)
            if file is None:
                pkg.missing.append(path)
                continue
            fs, ino, st = file
            if recorded_size.isdigit() and int(recorded_size) != st.size:  # no read needed
                rows.append((n, path))
            elif max_file_size is not None and st.size > max_file_size:
                pkg.unverified.append(path)
            else:
                checks.append(_Check(pkg, n, path, fs, ino, digest[len("sha256=") :]))
        except DiskReadError:  # cannot show it is intact
            rows.append((n, path))
    pkg.files.add(meta_dir)
    return pkg


def _pip_egg_info(src: SystemSource, meta_dir: str, listing: bytes) -> LanguagePackage:
    """One pip package from an old .egg-info directory (no hashes to check), with its
    installed-files.txt already read (`listing`)."""
    meta = _metadata(
        (src.try_read(meta_dir + "/PKG-INFO", told=True) or b"").decode("utf-8", "replace")
    )
    name = (
        meta.get("Name") or posixpath.basename(meta_dir).removesuffix(".egg-info").split("-", 1)[0]
    )
    pkg = LanguagePackage("pypi", name, meta.get("Version"), posixpath.dirname(meta_dir), meta_dir)
    root = _install_root(posixpath.dirname(meta_dir))
    for line in listing.decode("utf-8", "replace").splitlines():
        if line.strip():
            path = _norm(posixpath.join(meta_dir, line.strip()))
            if not _within(path, root):
                continue  # not the package's to claim: judged as any other path
            pkg.files.add(path)
            if src.resolve(path, follow_last=False) is None:
                pkg.missing.append(path)
    pkg.files.add(meta_dir)
    return pkg


NPM_DIR = "/node_modules/"
# What follows the outermost node_modules; a nested package does not match, as
# its files already belong to the package holding it. Dot names are npm's own.
_NPM_PACKAGE = re.compile(r"((?:@[^/]+/)?[^/@.][^/]*)/package\.json\Z")
# How much newer than the install a file must be to count as edited. Checked against
# real npm 10: install scripts finish before the lockfile is written, but package.json
# is written first (a build comes later), and `cp -r` of a tree scatters the times.
NPM_EDIT_MARGIN_NS = 600 * 10**9


def _npm_name_and_version(package_json: bytes) -> tuple[str | None, str | None]:
    """ "name" and "version" of a package.json, each None unless it really is a string."""
    try:
        data = json.loads(package_json.decode("utf-8", "replace"))
    except ValueError:
        return None, None
    if not isinstance(data, dict):
        return None, None
    name, version = data.get("name"), data.get("version")
    return (
        name if isinstance(name, str) else None,
        version if isinstance(version, str) else None,
    )


def _below(sorted_paths: list[str], directory: str) -> set[str]:
    """The directory and what lies below it, found by bisection: an app's node_modules
    has thousands of packages, and scanning every path for each would take minutes."""
    prefix = directory + "/"
    out = {directory}
    for p in sorted_paths[bisect.bisect_left(sorted_paths, prefix) :]:
        if not p.startswith(prefix):
            break
        out.add(p)
    return out


def _regular_file_mtime(src: SystemSource, path: str, stats: Mapping[str, Stat]) -> int | None:
    """The mtime of the regular file at `path`; None if it is not one or cannot be read.
    A path among `stats` is not looked up again."""
    st = stats.get(path)
    if st is None:
        try:
            found = src.resolve(path, follow_last=False)
            if found is None:
                return None
            st = src.stat(*found)
        except DiskReadError:
            return None
    return st.mtime_ns if st.type is FileType.REG else None


def _npm_edited_after_install(
    src: SystemSource, pkg: LanguagePackage, package_json: str, stats: Mapping[str, Stat]
) -> list[str]:
    """The package's files much newer than its install (see the module docstring)."""
    installed = _regular_file_mtime(src, f"{pkg.location}/.package-lock.json", stats)
    if installed is None:
        installed = _regular_file_mtime(src, package_json, stats)
    if installed is None:
        return []
    out = []
    for path in sorted(pkg.files):
        mtime = _regular_file_mtime(src, path, stats)
        if mtime is not None and mtime > installed + NPM_EDIT_MARGIN_NS:
            out.append(path)
    return out


def _npm_package(
    src: SystemSource, path: str, sorted_paths: list[str], stats: Mapping[str, Stat]
) -> LanguagePackage | None:
    """One npm package from its package.json; its files are everything below it."""
    m = _npm_match(path)
    if not m:
        return None
    location, rel = path.partition(NPM_DIR)[0] + NPM_DIR.rstrip("/"), m.group(1)
    pkg_dir = f"{location}/{rel}"
    name, version = _npm_name_and_version(src.try_read(path, told=True) or b"")
    pkg = LanguagePackage("npm", name or rel, version, location, pkg_dir, installer="npm")
    pkg.files = _below(sorted_paths, pkg_dir)
    pkg.edited_after_install = _npm_edited_after_install(src, pkg, path, stats)
    return pkg


def _npm_match(path: str) -> re.Match[str] | None:
    """Whether `path` is the package.json of a package directly in an outermost
    node_modules (the only ones _npm_package reads), as the match of what follows."""
    if posixpath.basename(path) != "package.json" or NPM_DIR not in path:
        return None
    return _NPM_PACKAGE.match(path.partition(NPM_DIR)[2])


def _metadata_files(src: SystemSource, path: str) -> list[str]:
    """The metadata files _package_at reads for `path`, in the order it reads them
    (what find_language_packages tells the disk before reading any): exactly those,
    since what is told and not read is a request paid for nothing. A package.json
    deeper in a package, or in a nested node_modules, is not read; nor is the PKG-INFO
    of an .egg-info without installed-files.txt."""
    parent, base = posixpath.split(path)
    if _pip_target(src, path):
        return [f"{path}/METADATA", f"{path}/INSTALLER", f"{path}/RECORD"]
    if posixpath.basename(parent) in SITE_DIRS:
        if base.endswith(".egg-info") and src.is_file(f"{path}/installed-files.txt"):
            return [f"{path}/installed-files.txt", f"{path}/PKG-INFO"]
    elif _npm_match(path):
        return [path]
    return []


def _pip_target(src: SystemSource, path: str) -> bool:
    """Whether `path` is the .dist-info of a pip package: in a site directory, or
    anywhere else when it has a RECORD (`pip install --target DIR`, a vendored tree)."""
    parent, base = posixpath.split(path)
    if not base.endswith(".dist-info"):
        return False
    return posixpath.basename(parent) in SITE_DIRS or src.is_file(f"{path}/RECORD")


def _package_at(
    src: SystemSource,
    path: str,
    sorted_paths: list[str],
    max_file_size: int | None,
    stats: Mapping[str, Stat],
    checks: list[_Check],
    flagged: dict[int, list[tuple[int, str]]],
) -> LanguagePackage | None:
    """The language package whose metadata is at `path`, if that is what `path` is.
    Its metadata files were told to the disk (_metadata_files): read with told=True."""
    parent, base = posixpath.split(path)
    if _pip_target(src, path):
        return _pip_dist_info(src, path, max_file_size, checks, flagged)
    if posixpath.basename(parent) in SITE_DIRS:
        if base.endswith(".egg-info"):
            listing = src.try_read(path + "/installed-files.txt", told=True)
            if listing is not None:
                return _pip_egg_info(src, path, listing)
    elif _npm_match(path):
        return _npm_package(src, path, sorted_paths, stats)
    return None


# npm's cache (cacache) keeps each tarball by its integrity: content-v2/sha512/aa/bb/rest.
NPM_CACHE = ".npm/_cacache"


def _npm_caches(src: SystemSource) -> list[str]:
    """The npm caches on the system: root's and each home's."""
    homes = ["/root"] + [f"/home/{u}" for u in sorted(src.try_listdir("/home") or [])]
    return [f"{h}/{NPM_CACHE}" for h in homes if src.try_listdir(f"{h}/{NPM_CACHE}") is not None]


def _cache_file(cache: str, integrity: str) -> str | None:
    """Where cacache keeps the tarball of an integrity string (its sha512 part)."""
    for part in integrity.split():
        algo, _, b64 = part.partition("-")
        if algo != "sha512":
            continue
        try:
            hexed = base64.b64decode(b64, validate=True).hex()
        except ValueError:
            return None
        return f"{cache}/content-v2/sha512/{hexed[:2]}/{hexed[2:4]}/{hexed[4:]}"
    return None


def _npm_lock(src: SystemSource, location: str) -> dict[str, str]:
    """Package directory -> integrity, from the lockfile of a node_modules directory: npm's
    own node_modules/.package-lock.json (npm 7+), else the project's package-lock.json."""
    root = posixpath.dirname(location)
    for lock in (f"{location}/.package-lock.json", f"{root}/package-lock.json"):
        blob = src.try_read(lock)
        if blob is None:
            continue
        try:
            packages = json.loads(blob.decode("utf-8", "replace")).get("packages")
        except (ValueError, AttributeError):
            continue
        if not isinstance(packages, dict):
            continue
        return {
            _norm(f"{root}/{key}"): entry["integrity"]
            for key, entry in packages.items()
            if key.startswith("node_modules/")
            and isinstance(entry, dict)
            and isinstance(entry.get("integrity"), str)
        }
    return {}


def _tarball_files(blob: bytes, directory: str) -> dict[str, tuple[int, str]] | None:
    """path -> (size, sha256 as RECORD writes it) of the regular files of an npm tarball,
    placed below `directory` (the tarball's first path component is dropped)."""
    out = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            for member in tar:
                if not member.isreg():
                    continue
                parts = member.name.split("/")[1:]
                if not parts or ".." in parts:
                    continue
                data = tar.extractfile(member)
                if data is None:
                    continue
                digest = base64.urlsafe_b64encode(hashlib.sha256(data.read()).digest())
                rel = "/".join(parts)
                out[_norm(f"{directory}/{rel}")] = (member.size, digest.rstrip(b"=").decode())
    except (tarfile.TarError, OSError, EOFError, zlib.error):  # not the tarball it should be
        return None
    return out


NPM_REGISTRY = "https://registry.npmjs.org"
NPM_KEY = "make-fetch-happen:request-cache:"  # how npm keys a download in cacache's index


def _npm_registry(src: SystemSource) -> str:
    """The registry npm downloads from: "registry=" of the global or root npmrc."""
    for rc in ("/root/.npmrc", "/etc/npmrc", "/usr/etc/npmrc"):
        for line in (src.try_read(rc) or b"").decode("utf-8", "replace").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "registry" and value.strip():
                return value.strip().rstrip("/")
    return NPM_REGISTRY


def _indexed_integrity(src: SystemSource, caches: list[str], url: str) -> str | None:
    """The integrity cacache's index records for a download URL: the bucket is named by
    the SHA-256 of the key; each line is "<sha1 of the JSON>\t<JSON>", the last wins."""
    key = NPM_KEY + url
    hexed = hashlib.sha256(key.encode()).hexdigest()
    for cache in caches:
        bucket = src.try_read(f"{cache}/index-v5/{hexed[:2]}/{hexed[2:4]}/{hexed[4:]}")
        found = None
        for line in (bucket or b"").decode("utf-8", "replace").splitlines():
            check, _, text = line.partition("\t")
            if not text or hashlib.sha1(text.encode()).hexdigest() != check:
                continue  # torn or damaged: cacache skips such lines too
            try:
                entry = json.loads(text)
            except ValueError:
                continue
            if isinstance(entry, dict) and entry.get("key") == key:
                integrity = entry.get("integrity")
                found = integrity if isinstance(integrity, str) else None
        if found:
            return found
    return None


def _npm_dirs_by_index(
    src: SystemSource, pkg: LanguagePackage, caches: list[str], registry: str
) -> dict[str, str] | None:
    """Package directory -> integrity for a package with no lockfile entry (a global
    install): its own directory and every nested one, from the name and version in each
    package.json and the download URL npm would use. None if any is not found."""
    prefix = pkg.meta_dir + NPM_DIR
    nested = sorted(
        posixpath.dirname(p)
        for p in pkg.files
        if p.startswith(prefix)
        and posixpath.basename(p) == "package.json"
        and _NPM_PACKAGE.match(p.rpartition(NPM_DIR)[2])
    )
    dirs = [pkg.meta_dir, *nested]
    out = {}
    for directory in dirs:
        name, version = _npm_name_and_version(src.try_read(f"{directory}/package.json") or b"")
        if not name or not version:
            return None
        url = f"{registry}/{name}/-/{name.rpartition('/')[2]}-{version}.tgz"
        integrity = _indexed_integrity(src, caches, url)
        if integrity is None:
            return None
        out[directory] = integrity
    return out


def _cached_tarball(src: SystemSource, caches: list[str], integrity: str) -> str | None:
    """The cache file holding the tarball of `integrity`, in any of the caches."""
    for cache in caches:
        at = _cache_file(cache, integrity)
        if at is not None and src.is_file(at):
            return at
    return None


def _npm_verify(
    src: SystemSource,
    found: list[LanguagePackage],
    max_file_size: int | None,
    checks: list[_Check],
    flagged: dict[int, list[tuple[int, str]]],
) -> None:
    """Compare npm packages with their own tarballs in the system's npm cache, found by
    the lockfile's integrity, or for a package no lockfile lists (a global install) by the
    cache's index of its download URL (nothing is downloaded). A package whose every directory
    (its own and its nested dependencies') has its tarball there is verified exactly:
    `modified` and `missing` instead of the guess from the times. Others keep the guess."""
    caches = _npm_caches(src)
    npm = [p for p in found if p.ecosystem == "npm"]
    if not caches or not npm:
        return
    locks: dict[str, dict[str, str]] = {}
    registry = _npm_registry(src)
    plans: list[tuple[LanguagePackage, list[tuple[str, str]]]] = []
    for pkg in npm:
        if pkg.location not in locks:
            locks[pkg.location] = _npm_lock(src, pkg.location)
        prefix = pkg.meta_dir + "/"
        dirs: dict[str, str] | None = {
            d: i
            for d, i in locks[pkg.location].items()
            if d == pkg.meta_dir or d.startswith(prefix)
        }
        if not dirs or pkg.meta_dir not in dirs:
            dirs = _npm_dirs_by_index(src, pkg, caches, registry)
        if not dirs:
            continue
        tarballs = []
        for directory, integrity in sorted(dirs.items()):
            at = _cached_tarball(src, caches, integrity)
            if at is None:
                break
            tarballs.append((directory, at))
        else:
            plans.append((pkg, tarballs))
    src.will_read_files([at for _, tarballs in plans for _, at in tarballs])
    for pkg, tarballs in plans:
        expected: dict[str, tuple[int, str]] = {}
        for directory, at in tarballs:
            files = _tarball_files(src.try_read(at, told=True) or b"", directory)
            if files is None:
                break
            expected.update(files)
        else:
            _expect(src, pkg, expected, max_file_size, checks, flagged)


def _expect(
    src: SystemSource,
    pkg: LanguagePackage,
    expected: dict[str, tuple[int, str]],
    max_file_size: int | None,
    checks: list[_Check],
    flagged: dict[int, list[tuple[int, str]]],
) -> None:
    """Check a package's files against what its tarballs hold, as pip's against RECORD."""
    rows = flagged.setdefault(id(pkg), [])
    pkg.edited_after_install = []
    pkg.verified_by = "npm-cache"
    for n, (path, (size, digest)) in enumerate(sorted(expected.items())):
        try:
            file = _regular_file(src, path)
        except DiskReadError:
            rows.append((n, path))
            continue
        if file is None:
            pkg.missing.append(path)
            continue
        fs, ino, st = file
        if st.size != size:
            rows.append((n, path))
        elif max_file_size is not None and st.size > max_file_size:
            pkg.unverified.append(path)
        else:
            checks.append(_Check(pkg, n, path, fs, ino, digest))


def find_language_packages(
    src: SystemSource,
    candidates: Iterable[str],
    max_file_size: int | None = None,
    stats: Mapping[str, Stat] | None = None,
) -> list[LanguagePackage]:
    """Language packages whose metadata is among `candidates` (unowned paths).
    Files over `max_file_size` bytes are not read to check them (LanguagePackage.unverified).
    `stats` is what a walk already knows of the paths: those are not looked up again.

    メタデータが `candidates`（無所属パス）の中にある言語パッケージ。`max_file_size` バイトを超える
    ファイルは照合のために読まない（LanguagePackage.unverified）。`stats` は walk が既に持っている
    パスごとの stat で、そこにあるパスは引き直さない。
    """
    stats = stats or {}
    paths = sorted(set(candidates))
    # Every metadata file told first, then every file RECORD hashes: one at a time over
    # a network, an app server's thousands of small files would each be waited for.
    src.will_read_files([f for p in paths for f in _metadata_files(src, p)])
    checks: list[_Check] = []
    flagged: dict[int, list[tuple[int, str]]] = {}
    found: list[LanguagePackage] = []
    for p in paths:
        try:
            pkg = _package_at(src, p, paths, max_file_size, stats, checks, flagged)
        except DiskReadError:  # its files stay listed one by one: the safer mistake
            continue
        if pkg is not None:
            found.append(pkg)
    _npm_verify(src, found, max_file_size, checks, flagged)
    _check_all([c for c in checks if any(c.pkg is pkg for pkg in found)], flagged)
    for pkg in found:
        pkg.modified = [path for _, path in sorted(flagged.get(id(pkg), []))]
    return found


@dataclass(frozen=True)
class Alternative:
    """One alternatives group as its state file describes it.

    状態ファイルが記述する alternatives のグループ 1 つ。
    """

    name: str
    mode: str  # "auto" or "manual"
    link: str  # master link, e.g. /usr/bin/python
    current: str | None  # where /etc/alternatives/<name> points now
    links: tuple[str, ...]  # every path the group manages, /etc/alternatives entries included


def find_alternatives(src: SystemSource) -> list[Alternative]:
    """Every alternatives group found in the known state directories.

    既知の状態ディレクトリから見つかる alternatives のグループ全部。
    """
    out = []
    for state_dir in ALTERNATIVES_STATE:
        try:
            names = src.listdir(state_dir) or []
        except DiskReadError:
            continue
        for name in names:
            state = src.try_read(f"{state_dir}/{name}") or b""
            lines = state.decode("utf-8", "replace").splitlines()
            if len(lines) < 2 or lines[0] not in ("auto", "manual"):
                continue
            links = [lines[1], f"/etc/alternatives/{name}"]
            i = 2
            while i + 1 < len(lines) and lines[i]:  # slave name / slave link pairs
                links += [lines[i + 1], f"/etc/alternatives/{lines[i]}"]
                i += 2
            current = None
            try:
                found = src.resolve(f"/etc/alternatives/{name}", follow_last=False)
                if found is not None and src.stat(*found).type is FileType.LNK:
                    current = found[0].readlink(found[1]).decode("utf-8", "replace")
            except DiskReadError:
                pass
            out.append(Alternative(name, lines[0], lines[1], current, tuple(links)))
    return sorted(out, key=lambda a: a.name)
