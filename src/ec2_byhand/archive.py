"""after.tar.gz, before.tar.gz and patches/ from a manifest.

  after.tar.gz   current versions: hand-placed paths (1), files written during a
                 package run (package_scripts, as hand work may be among them)
                 or by cloud-init at boot (cloud_init: user-data's write_files is
                 the user's own) and modified package files (2) that still exist
                 and, with a baseline, changed since it
  before.tar.gz  baseline versions (only with a baseline): those of the first
                 two that were modified, deleted paths (directories with
                 everything below them), and package files modified since
                 the baseline
  patches/       unified diffs for text files present in both

Tar entries keep type, permissions, owner (numeric), mtime, symlink
targets, device numbers and xattrs (as SCHILY.xattr.* PAX records, which
GNU tar restores with --xattrs). Archives are reproducible: entries are
sorted and gzip carries no timestamp. Paths flagged sensitive are left out
unless asked for, and swap files always; every skipped path is listed with
a reason.

manifest から after.tar.gz・before.tar.gz・patches/ を作る。tar のエントリは種別・権限・所有者
（数値）・mtime・リンク先・デバイス番号・xattr を保ち、アーカイブは再現可能（エントリはソート
済みで gzip に時刻を入れない）。secret らしいパスは指定がなければ中身を入れず、スワップファイ
ルは常に入れない。飛ばしたものは全て理由付きで列挙する。
"""

from __future__ import annotations

import difflib
import gzip
import io
import re
import stat as _stat
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from diskread.blockdev import BlockDevice, read_chunks, will_read
from diskread.errors import DiskReadError
from diskread.fs import Filesystem, FileType, Stat, valid_name
from diskread.source import SystemSource, clean_path
from ec2_byhand.secrets import SCAN_MAX_BYTES, find_secrets, mask
from ec2_byhand.sensitive import DEFAULT, Sensitive, is_swap, tell_swap_check

PATCH_MAX_BYTES = 1 << 20
SPOOL_MEMORY_BYTES = 16 << 20  # larger files wait for the tar in a temporary file
# XFS shows ACLs both raw and converted; keep only the standard names.
SKIP_XATTRS = {"trusted.SGI_ACL_FILE", "trusted.SGI_ACL_DEFAULT"}
# What a name from the analyzed disk may hold but a file name here may not: what
# Windows treats specially (a backslash separates, "C:" names a drive, trailing
# dots and spaces vanish, so ".. " is ".."), control characters, undecodable bytes.
# "%" is included so that every name still maps to a different patch file.
_PATCH_NAME_UNSAFE = re.compile(r'[<>:"\\|?*%\x00-\x1f\x7f\udc80-\udcff]|[. ]+(?=/|\Z)')


@dataclass
class ArchiveOptions:
    """What write_outputs may include: sensitive contents (and secret-like strings
    unmasked), a size cap; and what counts as sensitive by its path.

    write_outputs が何を入れてよいか: secret らしい中身（と、伏せない秘密らしい文字列）、
    サイズ上限。パスで秘密とみなすもの。
    """

    include_sensitive: bool = False
    max_file_size: int | None = None  # bytes; larger regular files are skipped
    sensitive: Sensitive = DEFAULT

    @property
    def mask(self) -> bool:
        """Whether secret-like strings are masked in what is written.

        秘密らしい文字列を、書き出すものの中で伏せるか。
        """
        return not self.include_sensitive


@dataclass
class _Stats:
    """Entry count and skip list of one archive."""

    entries: int = 0
    skipped: list[dict[str, Any]] = field(default_factory=list)
    masked: list[dict[str, Any]] = field(default_factory=list)  # entries with values masked


def _spooled(dev: BlockDevice, directory: Path) -> tempfile.SpooledTemporaryFile[bytes]:
    """The device's bytes in a temporary file, all read before the tar sees any of them.

    tarfile writes an entry's header first and cannot take it back: if a bad
    block then cut the data short, every later entry would land at the wrong
    offset and the rest of the archive would be lost.
    """
    # Closed by the caller's `with`; below the output directory, which has room for the archive.
    spool = tempfile.SpooledTemporaryFile(max_size=SPOOL_MEMORY_BYTES, dir=str(directory))  # noqa: SIM115
    try:
        for chunk in read_chunks(dev):
            spool.write(chunk)
    except BaseException:
        spool.close()
        raise
    spool.seek(0)
    return spool


def output_files(outdir: Path) -> list[Path]:
    """The files a run leaves in `outdir`, those that are there: manifest.json,
    report.txt, the two archives and the patches (*.diff below patches/). Whatever else
    the directory holds is not the run's: it is neither replaced by a later run nor
    uploaded.

    実行が `outdir` に残すファイルのうち、今あるもの: manifest.json、report.txt、2 つの
    アーカイブ、パッチ（patches/ の下の *.diff）。そのディレクトリにあるほかのものは実行のもの
    ではなく、次の実行が置き換えることも、アップロードすることもない。
    """
    names = ("manifest.json", "report.txt", "after.tar.gz", "before.tar.gz")
    named = [outdir / name for name in names]
    patches = sorted(p for p in (outdir / "patches").rglob("*.diff") if p.is_file())
    return [p for p in named if p.is_file()] + patches


def printable(text: str) -> str:
    """`text` with undecodable bytes and control characters written as escapes:
    names from the analyzed disk must not act on a terminal or forge a line.

    解析対象のディスクから来た名前が端末を操作したり行を偽造したりしないように、デコードできな
    いバイトと制御文字をエスケープして書いた `text`。
    """
    raw = text.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")
    return "".join(c if c.isprintable() else c.encode("unicode_escape").decode() for c in raw)


def pax_time(ns: int) -> str:
    """A PAX time value with full nanosecond precision, e.g. "-0.876543211".

    ナノ秒精度そのままの PAX 時刻値（例「-0.876543211」）。
    """
    sign = "-" if ns < 0 else ""
    sec, frac = divmod(abs(ns), 1_000_000_000)
    return f"{sign}{sec}.{frac:09d}"


def manifest_path(entry: dict[str, Any]) -> str:
    """The exact path of a manifest entry (path_hex wins when present).

    manifest エントリの正確なパス（path_hex があればそちらが勝つ）。
    """
    if "path_hex" in entry:
        return bytes.fromhex(entry["path_hex"]).decode("utf-8", "surrogateescape")
    path: str = entry["path"]
    return path


def _skipped_item(archive: str, path: str, reason: str) -> dict[str, Any]:
    """One entry of the manifest's archives.skipped list."""
    return {
        "archive": archive,
        "path": path.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace"),
        "reason": reason,
    }


class _TarWriter:
    """One output tar.gz: reproducible entries, skip tracking, hard-link folding."""

    def __init__(self, path: Path, name: str, opts: ArchiveOptions) -> None:
        self.name = name
        self.opts = opts
        self.stats = _Stats()
        self._spool_dir = path.parent
        # close() closes tar, then gzip, then the file, so no `with` here.
        self._file = path.open("wb")
        self._gz = gzip.GzipFile(filename="", mode="wb", fileobj=self._file, mtime=0)
        self._tar = tarfile.open(  # noqa: SIM115
            fileobj=self._gz,
            mode="w",
            format=tarfile.PAX_FORMAT,
            encoding="utf-8",
            errors="surrogateescape",
        )
        self._done: set[str] = set()
        self._dirs_seen: set[tuple[int, int]] = set()  # recursion guard for corrupt trees
        # (filesystem, inode) -> first name written, so further names of a
        # hard-linked file become tar hard links instead of second copies.
        self._links: dict[tuple[int, int], str] = {}
        # Found by add_all for _add_entry: the opened content, and whether it is swap.
        self._opened: dict[tuple[int, int], BlockDevice] = {}
        self._swap: dict[tuple[int, int], bool] = {}

    def close(self) -> None:
        """Close tar, gzip and file, in that order."""
        self._tar.close()
        self._gz.close()
        self._file.close()

    def _skip(self, path: str, reason: str) -> None:
        """Record that `path` was left out and why."""
        self.stats.skipped.append(_skipped_item(self.name, path, reason))

    def add_all(self, src: SystemSource, paths: list[str]) -> None:
        """add() each path, in this order, having first told the disks what that reads:
        one file after another, each waits for its blocks (a server whose files no
        package owns are gigabytes reads them all again here)."""
        contents: list[tuple[tuple[int, int], BlockDevice]] = []
        linked: set[tuple[int, int]] = set(self._links)
        for path in paths:
            found = self._content_to_add(src, path, linked)
            if found is not None:
                contents.append(found)
                self._opened[found[0]] = found[1]
        for _, content in contents:
            tell_swap_check(content)
        for key, content in contents:
            try:
                self._swap[key] = is_swap(content)
            except DiskReadError:
                continue  # add meets it again and skips the path as a read error
        for key, content in contents:
            if self._swap.get(key) is False:
                will_read(content)
        for path in paths:
            self.add(src, path)

    def _content_to_add(
        self, src: SystemSource, path: str, linked: set[tuple[int, int]]
    ) -> tuple[tuple[int, int], BlockDevice] | None:
        """The content _add_entry will read for `path`, if any: what add_all tells.
        `linked` stands for the hard links written by then."""
        if (
            path in self._done
            or not clean_path(path)
            or (self.opts.sensitive.match(path) and not self.opts.include_sensitive)
        ):
            return None
        try:
            found = src.resolve(path, follow_last=False)
            if found is None:
                return None
            fs, ino = found
            st = src.stat(fs, ino)
            if st.type is not FileType.REG:
                return None
            if self.opts.max_file_size is not None and st.size > self.opts.max_file_size:
                return None
            key = (id(fs), ino)
            if st.nlink > 1:
                if key in linked:
                    return None  # a link to what is already in
                linked.add(key)
            return key, fs.open(ino)
        except DiskReadError:
            return None  # add meets it again and skips the path as a read error

    def add(self, src: SystemSource, path: str, recursive: bool = False) -> None:
        """Add `path` (and, with recursive, a deleted directory's old contents) to the tar."""
        if path in self._done:
            return
        self._done.add(path)
        if not clean_path(path):
            # "/opt/x/../../etc/shadow" is /etc/shadow under another name: the checks
            # that go by the path (sensitive, noise) would not know it, and the archive
            # would hold a member that climbs out of where it is unpacked.
            self._skip(path, "invalid-path")
            return
        try:
            found = src.resolve(path, follow_last=False)
            if found is None:
                self._skip(path, "missing")
                return
            fs, ino = found
            st = src.stat(fs, ino)
            self._add_entry(fs, ino, st, path)
            children = []
            if recursive and st.type is FileType.DIR:
                key = (id(fs), ino)
                if key not in self._dirs_seen:  # corrupt metadata can make the tree loop
                    self._dirs_seen.add(key)
                    children = sorted(fs.listdir(ino))
        except (
            DiskReadError
        ):  # damaged metadata (a directory itself may be in, without its contents)
            self._skip(path, "read-error")
            return
        for name, _child in children:
            below = path.rstrip("/") + "/" + name.decode("utf-8", "surrogateescape")
            if valid_name(name):
                self.add(src, below, recursive=True)
            else:  # "..", or a "/" in it: no name (the walk reports such as damage)
                self._skip(below, "invalid-path")

    def _add_entry(self, fs: Filesystem, ino: int, st: Stat, path: str) -> None:
        """Write one tar entry, carrying type, mode, owner, times, xattrs and link targets."""
        if self.opts.sensitive.match(path) and not self.opts.include_sensitive:
            self._skip(path, "sensitive")
            return
        if st.type is FileType.SOCK:
            self._skip(path, "socket")
            return
        if (
            st.type is FileType.REG
            and self.opts.max_file_size is not None
            and st.size > self.opts.max_file_size
        ):
            self._skip(path, "too-large")
            return
        info = tarfile.TarInfo(path.lstrip("/") or ".")
        info.mode = _stat.S_IMODE(st.mode)
        info.uid, info.gid = st.uid, st.gid
        info.mtime = st.mtime_ns / 1e9
        content = None
        key = (id(fs), ino)
        linked = st.type is not FileType.DIR and st.nlink > 1
        if linked and key in self._links:
            info.type, info.linkname = tarfile.LNKTYPE, self._links[key]
        elif st.type is FileType.REG:
            info.type, info.size = tarfile.REGTYPE, st.size
            opened = self._opened.pop(key, None)
            content = fs.open(ino) if opened is None else opened
            if content.size != st.size:
                raise DiskReadError(f"{st.size} bytes by its inode, {content.size} readable")
            swap = self._swap.pop(key, None)
            if swap is None:
                swap = is_swap(content)
            if swap:
                self._skip(path, "swap")  # memory pages: secrets, and nothing to migrate
                return
        elif st.type is FileType.DIR:
            info.type = tarfile.DIRTYPE
        elif st.type is FileType.LNK:
            info.type = tarfile.SYMTYPE
            info.linkname = fs.readlink(ino).decode("utf-8", "surrogateescape")
        elif st.type in (FileType.CHR, FileType.BLK):
            info.type = tarfile.CHRTYPE if st.type is FileType.CHR else tarfile.BLKTYPE
            info.devmajor, info.devminor = st.rdev or (0, 0)
        elif st.type is FileType.FIFO:
            info.type = tarfile.FIFOTYPE
        # Exact nanoseconds: tarfile would write the float, which cannot hold
        # them at today's magnitudes (x.999999999 s rounds up a whole second).
        pax = {"mtime": pax_time(st.mtime_ns)}
        for k, v in fs.xattrs(ino).items():
            if k not in SKIP_XATTRS:
                pax[f"SCHILY.xattr.{k}"] = v.decode("utf-8", "surrogateescape")
        info.pax_headers = pax
        if content is None:
            self._tar.addfile(info)
        elif self.opts.mask and st.size <= SCAN_MAX_BYTES:
            raw = content.read_at(0, st.size)
            if len(raw) != st.size:
                raise DiskReadError(f"{st.size} bytes by its inode, {len(raw)} read")
            found = find_secrets(raw)
            if found:
                raw = mask(raw, found)
                info.size = len(raw)
                self.stats.masked.append(
                    {"archive": self.name, "path": path, "kinds": sorted({f.kind for f in found})}
                )
            self._tar.addfile(info, io.BytesIO(raw))
        else:
            with _spooled(content, self._spool_dir) as data:
                self._tar.addfile(info, data)
        self.stats.entries += 1
        if linked:
            self._links.setdefault(key, info.name)


def _text_to_read(src: SystemSource, path: str, max_file_size: int | None) -> BlockDevice | None:
    """The content _read_text will read for `path`, if any (what write_outputs tells)."""
    try:
        found = src.resolve(path, follow_last=False)
        if found is None:
            return None
        st = src.stat(*found)
        if st.type is not FileType.REG or st.size > PATCH_MAX_BYTES:
            return None
        if max_file_size is not None and st.size > max_file_size:
            return None
        return found[0].open(found[1])
    except DiskReadError:
        return None


def _read_text(
    src: SystemSource, path: str, max_file_size: int | None = None, masked: bool = False
) -> tuple[list[str] | None, str | None]:
    """The file's lines if it is a small, readable UTF-8 text file, else (None, why a
    patch is missing). No reason when none is owed: a binary file has no text diff, and
    the archive already lists a path it could not read or left out as too large
    (a file over `max_file_size` is not read for a patch either)."""
    try:
        found = src.resolve(path, follow_last=False)
        if found is None:
            return None, None
        fs, ino = found
        st = src.stat(fs, ino)
        if st.type is not FileType.REG:
            return None, None
        if max_file_size is not None and st.size > max_file_size:
            return None, None
        if st.size > PATCH_MAX_BYTES:
            return None, "patch-too-large"
        dev = fs.open(ino)
        data = dev.read_at(0, dev.size)
    except DiskReadError:
        return None, None
    if b"\0" in data:
        return None, None
    if masked:
        data = mask(data, find_secrets(data))
    try:
        # Lines as patch(1) counts them: str.splitlines would also break at \f, \x85...
        return list(io.StringIO(data.decode("utf-8"), newline="\n")), None
    except UnicodeDecodeError:  # e.g. EUC-JP or Shift_JIS comments on an old server
        return None, "patch-not-utf8"


def _patch_name(path: str) -> str:
    """The patches/ file name for a path: a different one for every path, and one
    that stays below patches/ on any OS, whatever the analyzed disk calls its files."""

    def escape(match: re.Match[str]) -> str:
        return "".join(f"%{ord(c) & 0xFF:02X}" for c in match.group())

    return _PATCH_NAME_UNSAFE.sub(escape, path.lstrip("/")) + ".diff"


def _unified_diff(old: list[str], new: list[str], name: str) -> str:
    """A unified diff patch(1) and git apply accept, marking a last line without a newline."""
    out = []
    for line in difflib.unified_diff(old, new, fromfile=f"a/{name}", tofile=f"b/{name}"):
        out.append(line)
        if not line.endswith("\n"):
            out.append("\n\\ No newline at end of file\n")
    return "".join(out)


def write_outputs(
    manifest: dict[str, Any],
    current: SystemSource,
    baseline: SystemSource | None,
    outdir: Path,
    opts: ArchiveOptions | None = None,
) -> dict[str, Any]:
    """Write the archives and patches; return the manifest's "archives" section.

    アーカイブとパッチを書き、manifest の "archives" 節を返す。
    """
    opts = opts or ArchiveOptions()
    outdir.mkdir(parents=True, exist_ok=True)
    # Files written during a package run: the manifest cannot rule out hand work among them.
    # And what cloud-init wrote: user-data's write_files is the user's own configuration.
    scripts = [
        f
        for key in ("package_scripts", "cloud_init")
        for group in manifest.get(key, [])
        for f in group["files"]
    ]
    hand = manifest["hand_placed"] + scripts
    modified = manifest["modified_package_files"]

    after = _TarWriter(outdir / "after.tar.gz", "after", opts)
    try:
        paths = [manifest_path(h) for h in hand]
        # Not those the baseline already had as they are (since_baseline false: the AMI
        # shipped them so, like /boot's initramfs): the baseline brings them back.
        paths += [
            manifest_path(m)
            for m in modified
            if m["problems"] != ["missing"] and m["since_baseline"] is not False
        ]
        paths += [
            f
            for lp in manifest.get("language_packages", [])
            if lp["status"] != "removed"  # its files are the baseline's, and gone
            for f in lp["modified"] + lp["edited_after_install"]
        ]
        after.add_all(current, sorted(set(paths)))
    finally:
        after.close()
    result: dict[str, Any] = {
        "after": {"file": "after.tar.gz", "entries": after.stats.entries},
        "before": None,
        "patches": {"dir": "patches", "files": 0},
        "skipped": list(after.stats.skipped),
        "masked": list(after.stats.masked),
    }

    pairs: list[str] = []
    if baseline is not None:
        before = _TarWriter(outdir / "before.tar.gz", "before", opts)
        try:
            modified_hand = [manifest_path(h) for h in hand if h["status"] == "modified"]
            since = [
                manifest_path(m)
                for m in modified
                if m["since_baseline"] and m["problems"] != ["created-since-baseline"]
            ]
            lang = [
                f
                for lp in manifest.get("language_packages", [])
                if lp["status"] != "added"
                for f in lp["modified"] + lp["missing"] + lp["edited_after_install"]
            ]
            plain = sorted(set(modified_hand + since + lang))
            before.add_all(baseline, plain)
            for d in sorted(manifest_path(x) for x in manifest["deleted"]):
                before.add(baseline, d, recursive=True)
        finally:
            before.close()
        result["before"] = {"file": "before.tar.gz", "entries": before.stats.entries}
        result["skipped"] += before.stats.skipped
        result["masked"] += before.stats.masked
        pairs = [
            p
            for p in plain
            if clean_path(p) and not (opts.sensitive.match(p) and not opts.include_sensitive)
        ]

    for p in pairs:  # told first, as they are read: the old, then the new
        for side in (baseline, current):
            content = _text_to_read(side, p, opts.max_file_size)  # type: ignore[arg-type]
            if content is not None:
                will_read(content)
    for p in pairs:
        old, why_old = _read_text(baseline, p, opts.max_file_size, opts.mask)  # type: ignore[arg-type]
        new, why_new = _read_text(current, p, opts.max_file_size, opts.mask)
        why = why_old or why_new
        if why:
            result["skipped"].append(_skipped_item("patches", p, why))
            continue
        if old is None or new is None or old == new:
            continue
        target = outdir / "patches" / _patch_name(p)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            # newline="": "\n" stays "\n" on Windows too, or the patch would not apply.
            target.write_text(
                _unified_diff(old, new, printable(p.lstrip("/"))), "utf-8", newline=""
            )
        except OSError:  # too long, reserved on this OS, or /x and /x.diff/y both changed
            result["skipped"].append(_skipped_item("patches", p, "patch-not-written"))
            continue
        result["patches"]["files"] += 1
    return result
