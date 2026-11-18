"""Compare package files with what is on disk, and find unowned files.

verify_packages mirrors `rpm -V` (rpmfilesVerify in rpm 4.16) and
`dpkg --verify`, reading everything offline through a SystemSource:

rpm, per file, starting from its FILEVERIFYFLAGS:
  - state "not installed" / "netshared": not checked at all;
    "replaced": only whether it exists; "wrong color": no content checks
  - missing (lstat fails) is reported unless %ghost or %missingok
  - a directory that is now a symlink to a directory is followed
  - symlinks: no mode check; anything else: no link-target check
  - only regular files: size and digest checks
  - %ghost: no content or link checks; mode compares permissions only
  - owner: matches by name or by uid (names from the snapshot's /etc/passwd
    and /etc/group, as rpm looks them up on the running system)
  mtime, device numbers and capabilities are not checked here.
dpkg: every listed path must exist (directories too); files with a
recorded md5 (md5sums and conffiles) must also match it.

Beyond rpm -V, given a baseline snapshot: regular files whose content rpm
never checks (%ghost, or %verify(not md5) such as /etc/passwd from setup)
are compared with the baseline instead, since they include much of what
admins edit (/etc/hostname, /etc/selinux/config, /etc/default/grub).
"content-since-baseline": both exist and the content differs;
"created-since-baseline": the baseline does not have it. A symlink whose target rpm
does not check (a %ghost: /etc/localtime after `timedatectl set-timezone`) is compared
with the baseline's the same way, when its package is at the same version there (the
links of a package installed since are the package's own doing): "link" when that was
no link or pointed elsewhere.

dpkg records no mode, owner or link target, so dpkg --verify cannot see those
change. Given the baseline's package database, a file of a package at the same
version as in the baseline is compared with the baseline's copy instead: "mode",
"user", "group", "link", and for files without a recorded md5 the two
*-since-baseline problems above. A package upgraded since may change them on its
own, so it is not compared. Without a baseline such changes stay invisible.

Neither records extended attributes. For a package at the same version in the
baseline, rpm or dpkg, a file's attributes (capabilities, ACLs, user.*; the SELinux
label aside) are compared with the baseline's copy: "xattrs" (a `setcap` by hand).

File contents are read as little as possible, since over the EBS direct APIs
every read is billed: a size that differs needs no read, ReadLimits keeps noise
and files over --max-file-size unread, each file is read once, and all are read
in inode order so that the block cache is not thrown away between packages.
The disk is told beforehand what will be read, so that it can fetch ahead.

unowned_paths lists every path of the tree no package lists, comparing
physical locations: a package path's parent directory is resolved through
symlinks (merged /usr: /bin/ls and /usr/bin/ls are one file).

パッケージのファイルをディスク上の実物と照合し、どのパッケージにも属さないファイルを見つける。
verify_packages は rpm -V と dpkg --verify をオフラインで再現する（規則は上のとおり）。
baseline があれば、rpm が内容を見ないファイル（%ghost や %verify(not md5)。管理者がよく編集す
る /etc/hostname などを含む）は baseline と比較する: 両方にあって中身が違えば
content-since-baseline、baseline に無ければ created-since-baseline。dpkg は権限・所有者・リン
ク先を記録しないので dpkg --verify では見えない。baseline のパッケージ DB があれば、baseline と
同じ版のパッケージのファイルは baseline の実物と比べる（アップグレードで変わるものは比べない）。
baseline が無ければ、これらの変更は見えない。拡張属性はどちらも記録しないので、rpm でも dpkg
でも、baseline と同じ版のパッケージのファイルは拡張属性（ケーパビリティ・ACL・user.* など。
SELinux のラベルは除く）を baseline の実物と比べる（xattrs。手での setcap など）。ファイルの中
身はできるだけ読まない（EBS direct
APIs 越しでは読むたびに課金される）: サイズが違えば読まず、ReadLimits でノイズと
--max-file-size を超えるファイルを読まず、同じファイルは 1 回だけ、inode 順に読んでブロックキャッ
シュを無駄にしない。読む範囲は前もってディスクに告げ、先読みできるようにする。unowned_paths
は、どのパッケージも挙げない木の中の全パスを、物理位置で比べて列挙する（merged /usr を考慮）。
"""

from __future__ import annotations

import hashlib
import posixpath
import stat as _stat
from collections.abc import Callable, Container
from dataclasses import dataclass, field
from typing import Any

from diskread.blockdev import BlockDevice, read_chunks, will_read
from diskread.errors import DiskReadError
from diskread.fs import Filesystem, FileType, Stat
from diskread.source import SystemSource
from ec2_byhand.archive import SKIP_XATTRS
from ec2_byhand.packages.model import PackageDB, PackageFile

SELINUX_LABEL = "security.selinux"
# SELinux's own: the label, and the digest a recursive restorecon leaves on a directory
# to skip it next time (cloud-init does one on /etc/ssh at first boot, seen on AL2023).
SELINUX_XATTRS = frozenset({SELINUX_LABEL, "security.sehash"})


def xattr_settings(attrs: dict[str, bytes]) -> dict[str, bytes]:
    """Of a path's extended attributes, those that are settings someone made: ACLs,
    capabilities (setcap), user.* and the like. Not SELinux's own (the label every file
    has and a policy update relabels, the digest restorecon leaves); not XFS's raw
    copies of the ACLs.

    パスの拡張属性のうち、誰かが設定したもの: ACL・ケーパビリティ（setcap）・user.* など。
    SELinux 自身のもの（どのファイルにもあってポリシーの更新で付け直されるラベル、restorecon
    が残すハッシュ）と、XFS の ACL の生のコピーは除く。
    """
    return {
        name: value
        for name, value in attrs.items()
        if name not in SELINUX_XATTRS and name not in SKIP_XATTRS
    }


# rpmvf_e
VERIFY_DIGEST, VERIFY_SIZE, VERIFY_LINKTO, VERIFY_USER, VERIFY_GROUP = 1, 2, 4, 8, 16
VERIFY_MTIME, VERIFY_MODE, VERIFY_RDEV, VERIFY_CAPS = 32, 64, 128, 256
VERIFY_ALL = 0xFFFFFFFF
# rpmfileAttrs
RPMFILE_MISSINGOK, RPMFILE_GHOST = 8, 64
# rpmfileState
STATE_REPLACED, STATE_NOTINSTALLED, STATE_NETSHARED, STATE_WRONGCOLOR = 1, 2, 3, 4


@dataclass(frozen=True)
class FileProblem:
    """One file that failed verification, and how.

    照合に落ちたファイル 1 つと、その内容。
    """

    path: str
    package: str
    arch: str | None
    # "missing", "content", "size", "mode", "link", "user", "group", "xattrs", "unreadable",
    # "content-since-baseline", "created-since-baseline" (see the module docstring)
    problems: frozenset[str]
    is_config: bool
    error: str | None = None  # why it is "unreadable" (e.g. a metadata checksum mismatch)
    mode: int | None = None  # as the package recorded it (rpm only): the type of a missing file


def _new_hash(algo: str) -> Any:
    """A hashlib object for `algo` (from the rpm header, so maybe an unknown one)."""
    try:
        # Comparing with what the package recorded, not security: md5 must work on FIPS hosts too.
        return hashlib.new(algo, usedforsecurity=False)
    except ValueError as err:
        raise DiskReadError(f"unsupported file digest algorithm {algo}") from err


def _digests(content: BlockDevice, algos: list[str]) -> list[str]:
    """The content's hex digests with each of `algos`, read once."""
    hashes = [_new_hash(algo) for algo in algos]
    for chunk in read_chunks(content):
        for h in hashes:
            h.update(chunk)
    return [h.hexdigest() for h in hashes]


@dataclass
class ReadLimits:
    """Which file contents verification may read, and what the size limit left unverified.

    照合がどのファイルの中身を読んでよいかと、サイズ上限のために照合しなかったもの。
    """

    max_file_size: int | None = None
    skip: Callable[[str], bool] | None = None  # paths whose content does not matter (noise)
    too_large: set[str] = field(default_factory=set)


class _ContentReader:
    """File digests for one verification, read once each and in inode order. A first
    pass over the checks only notes what they would read (see verify_packages)."""

    def __init__(self, limits: ReadLimits) -> None:
        self._limits = limits
        self._digests: dict[tuple[int, int, str], str] = {}
        self._planned: dict[tuple[int, int, str], Filesystem] | None = {}

    def may_read(self, path: str, st: Stat) -> bool:
        """Whether this file's content may be read at all."""
        limits = self._limits
        if limits.skip is not None and limits.skip(path):
            return False
        if limits.max_file_size is not None and st.size > limits.max_file_size:
            limits.too_large.add(path)
            return False
        return True

    def digest(self, fs: Filesystem, ino: int, algo: str) -> str:
        """The hex digest; while planning, a note to read it and an empty answer."""
        key = (id(fs), ino, algo)
        known = self._digests.get(key)
        if known is not None:
            return known
        if self._planned is not None:
            self._planned[key] = fs
            return ""
        (known,) = _digests(fs.open(ino), [algo])
        self._digests[key] = known
        return known

    def read_planned(self) -> None:
        """End the planning and read everything noted, in inode order, each file once
        for all its digests. All are opened first and their contents told to the disk
        as what will be read (will_read), so that a disk read over a network can fetch
        ahead. A file that cannot be opened is left to the check, which meets the same
        error and reports it."""
        planned, self._planned = self._planned or {}, None
        files: dict[tuple[int, int], tuple[Filesystem, list[str]]] = {}
        for key in sorted(planned):
            files.setdefault(key[:2], (planned[key], []))[1].append(key[2])
        opened: list[tuple[Filesystem, int, BlockDevice, list[str]]] = []
        for (_, ino), (fs, algos) in files.items():
            try:
                for algo in algos:
                    _new_hash(algo)
                content = fs.open(ino)
            except DiskReadError:
                continue
            will_read(content)
            opened.append((fs, ino, content, algos))
        for fs, ino, content, algos in opened:
            try:
                digests = _digests(content, algos)
            except DiskReadError:
                continue
            for algo, digest in zip(algos, digests, strict=True):
                self._digests[(id(fs), ino, algo)] = digest


def _id_maps(src: SystemSource, path: str) -> tuple[dict[int, str], dict[str, int]]:
    """uid -> first name and name -> id from an /etc/passwd- or /etc/group-style file."""
    by_id: dict[int, str] = {}
    by_name: dict[str, int] = {}
    data = src.try_read(path)
    for line in (data or b"").decode("utf-8", "replace").splitlines():
        parts = line.split(":")
        if len(parts) >= 3 and parts[2].isdigit():
            by_id.setdefault(int(parts[2]), parts[0])
            by_name.setdefault(parts[0], int(parts[2]))
    return by_id, by_name


def _owner_ok(
    actual: int, expected: str | None, by_id: dict[int, str], by_name: dict[str, int]
) -> bool:
    """Whether the actual uid/gid matches the recorded owner by name or by id."""
    name = by_id.get(actual)
    namematch = name is not None and expected is not None and name == expected
    idmatch = expected is not None and by_name.get(expected) == actual
    return namematch or idmatch


def _content_since_baseline(
    path: str,
    fs: Filesystem,
    ino: int,
    st: Stat,
    baseline: SystemSource,
    reader: _ContentReader,
) -> set[str]:
    """How a regular file whose content no package records compares with the baseline's."""
    found = baseline.resolve(path, follow_last=True)
    if found is None or baseline.stat(*found).type is not FileType.REG:
        return {"created-since-baseline"}
    if baseline.stat(*found).size != st.size:
        return {"content-since-baseline"}
    if not reader.may_read(path, st):
        return set()
    same = reader.digest(*found, "sha256") == reader.digest(fs, ino, "sha256")
    return set() if same else {"content-since-baseline"}


def _link_since_baseline(path: str, fs: Filesystem, ino: int, baseline: SystemSource) -> set[str]:
    """How a symlink whose target no package records compares with the baseline's:
    `timedatectl set-timezone` makes /etc/localtime, a %ghost, a link to the zone."""
    found = baseline.resolve(path, follow_last=False)
    if found is None:
        return {"created-since-baseline"}
    bfs, bino = found
    if baseline.stat(bfs, bino).type is not FileType.LNK or bfs.readlink(bino) != fs.readlink(ino):
        return {"link"}
    return set()


def _verify_rpm(
    src: SystemSource,
    f: PackageFile,
    users: tuple[dict[int, str], dict[str, int]],
    groups: tuple[dict[int, str], dict[str, int]],
    baseline: SystemSource | None,
    reader: _ContentReader,
    same_package: bool = False,
) -> set[str]:
    """rpm -V for one file; the module docstring lists the rules. `same_package`: the
    baseline has the file's package at this version, so what the package's own scripts
    made (the links of a package installed since) is there too."""
    state = f.state or 0
    if state in (STATE_NOTINSTALLED, STATE_NETSHARED):
        return set()
    flags = VERIFY_ALL if f.verify is None else f.verify
    if state == STATE_WRONGCOLOR:
        flags &= ~(VERIFY_DIGEST | VERIFY_SIZE | VERIFY_MTIME | VERIFY_RDEV)
    ghost = bool(f.flags & RPMFILE_GHOST)

    found = src.resolve(f.path, follow_last=False)
    if found is None:
        return set() if f.flags & (RPMFILE_MISSINGOK | RPMFILE_GHOST) else {"missing"}
    if state == STATE_REPLACED:
        return set()
    fs, ino = found
    st = src.stat(fs, ino)
    fmode = f.mode or 0
    if _stat.S_ISDIR(fmode) and st.type is FileType.LNK:
        target = src.resolve(f.path, follow_last=True)
        if target is None:
            return set() if f.flags & (RPMFILE_MISSINGOK | RPMFILE_GHOST) else {"missing"}
        fs, ino = target
        st = src.stat(fs, ino)

    if st.type is FileType.LNK:
        flags &= ~VERIFY_MODE
    else:
        flags &= ~VERIFY_LINKTO
    if st.type is not FileType.REG:
        flags &= ~(VERIFY_DIGEST | VERIFY_SIZE | VERIFY_MTIME | VERIFY_CAPS)
    if ghost:
        flags &= ~(VERIFY_DIGEST | VERIFY_SIZE | VERIFY_MTIME | VERIFY_LINKTO)

    problems = set()
    if flags & VERIFY_DIGEST and f.digest and f.digest_algo:
        size_differs = f.size is not None and st.size != f.size  # then no read is needed
        if size_differs or (
            reader.may_read(f.path, st) and reader.digest(fs, ino, f.digest_algo) != f.digest
        ):
            problems.add("content")
    if flags & VERIFY_LINKTO and fs.readlink(ino).decode("utf-8", "surrogateescape") != (
        f.link_to or ""
    ):
        problems.add("link")
    if flags & VERIFY_SIZE and f.size is not None and st.size != f.size:
        problems.add("size")
    if flags & VERIFY_MODE:
        meta, actual = fmode, st.mode
        if ghost:  # comparing the type of a %ghost is meaningless
            meta, actual = meta & ~0o170000, actual & ~0o170000
        if meta != actual:
            problems.add("mode")
    if flags & VERIFY_USER and not _owner_ok(st.uid, f.user, *users):
        problems.add("user")
    if flags & VERIFY_GROUP and not _owner_ok(st.gid, f.group, *groups):
        problems.add("group")
    unchecked = ghost or (f.verify is not None and not f.verify & VERIFY_DIGEST)
    if baseline is not None and unchecked and st.type is FileType.REG and state != STATE_WRONGCOLOR:
        problems |= _content_since_baseline(f.path, fs, ino, st, baseline, reader)
    unchecked_link = st.type is FileType.LNK and not flags & VERIFY_LINKTO
    if baseline is not None and same_package and unchecked_link:
        problems |= _link_since_baseline(f.path, fs, ino, baseline)
    return problems


def _verify_dpkg(src: SystemSource, f: PackageFile, reader: _ContentReader) -> set[str]:
    # dpkg --verify checks that every listed path exists (directories too),
    # and the content of those with a recorded md5.
    """dpkg --verify for one file: it must exist, and match its md5 if recorded."""
    if f.path in ("/", "/."):
        return set()
    if src.resolve(f.path, follow_last=False) is None:
        return {"missing"}
    if not f.digest:
        return set()
    target = src.resolve(f.path, follow_last=True)
    if target is None:
        return {"content"}
    fs, ino = target
    st = src.stat(fs, ino)
    if st.type is not FileType.REG:
        return {"content"}
    if not reader.may_read(f.path, st):
        return set()
    return {"content"} if reader.digest(fs, ino, "md5") != f.digest else set()


def _dpkg_since_baseline(
    src: SystemSource, f: PackageFile, baseline: SystemSource, reader: _ContentReader
) -> set[str]:
    """What dpkg does not record, compared with the baseline's copy of the file."""
    found = None if f.path in ("/", "/.") else src.resolve(f.path, follow_last=False)
    if found is None:
        return set()  # _verify_dpkg reports it missing
    before = baseline.resolve(f.path, follow_last=False)
    if before is None:
        return set() if f.digest else {"created-since-baseline"}
    fs, ino = found
    st = src.stat(fs, ino)
    bfs, bino = before
    bst = baseline.stat(bfs, bino)
    if st.type is FileType.LNK and bst.type is FileType.DIR:  # as rpm -V does (merged /usr)
        target = src.resolve(f.path, follow_last=True)
        if target is None:
            return {"link"}
        fs, ino = target
        st = src.stat(fs, ino)
    problems = set()
    if st.type is FileType.LNK and bst.type is FileType.LNK:
        if fs.readlink(ino) != bfs.readlink(bino):
            problems.add("link")
    elif st.mode != bst.mode:
        problems.add("mode")
    if st.uid != bst.uid:
        problems.add("user")
    if st.gid != bst.gid:
        problems.add("group")
    if not f.digest and st.type is FileType.REG and bst.type is FileType.REG:
        problems |= _content_since_baseline(f.path, fs, ino, st, baseline, reader)
    return problems


def _xattrs_since_baseline(src: SystemSource, f: PackageFile, baseline: SystemSource) -> set[str]:
    """A `setcap`, `setfacl` or `setfattr` on a package file: its extended attributes
    (the SELinux label aside) compared with the baseline's copy. Neither rpm nor dpkg
    can tell: dpkg records none, and some packages' scripts set them (iputils' ping on
    Debian gets cap_net_raw), which an upgrade does again; so only for a package at the
    same version in the baseline."""
    if f.path in ("/", "/."):
        return set()
    found = src.resolve(f.path, follow_last=False)
    before = baseline.resolve(f.path, follow_last=False)
    if found is None or before is None:
        return set()  # missing, or new since: said otherwise
    fs, ino = found
    bfs, bino = before
    if xattr_settings(fs.xattrs(ino)) != xattr_settings(bfs.xattrs(bino)):
        return {"xattrs"}
    return set()


def verify_packages(
    src: SystemSource,
    db: PackageDB,
    baseline: SystemSource | None = None,
    only_paths: Container[str] | None = None,
    base_db: PackageDB | None = None,
    limits: ReadLimits | None = None,
) -> list[FileProblem]:
    """Package files that differ from what their package installed (and,
    for files rpm does not check, from the baseline). With `only_paths`,
    only those paths are checked: verifying a whole side reads the content
    of every package file, which over the EBS direct APIs is thousands of
    billed requests, so the baseline side is limited to the paths the
    current side flagged. `base_db` is the baseline's package database, which
    dpkg's comparison with the baseline needs (see the module docstring).
    `limits` keeps some file contents unread; those files are not called changed.

    パッケージが入れたものと違うファイル（rpm が内容を見ないファイルは baseline との比較で）。
    `only_paths` を渡すとそのパスだけ照合する。片側全体の照合は全パッケージファイルの中身を読む
    ので、EBS direct APIs 越しでは数千回の課金リクエストになる。baseline 側は current 側で引っか
    かったパスだけに絞る。`base_db` は baseline のパッケージ DB で、dpkg を baseline と比べるのに
    使う（モジュール docstring 参照）。`limits` で読まなかったファイルは、変わったとは報告しない。
    """
    users = _id_maps(src, "/etc/passwd")
    groups = _id_maps(src, "/etc/group")
    same_version: set[tuple[str, str | None, str]] = set()
    if baseline is not None and base_db is not None and base_db.manager == db.manager:
        same_version = {(p.name, p.arch, p.evr) for p in base_db.packages}
    reader = _ContentReader(limits or ReadLimits())

    def check_every_file(planning: bool) -> list[FileProblem]:
        compared: set[str] = set()  # a directory is listed by many packages: report it once
        attrs_compared: set[str] = set()
        out = []
        for pkg in db.packages:
            against_baseline = (pkg.name, pkg.arch, pkg.evr) in same_version
            for f in pkg.files:
                if only_paths is not None and f.path not in only_paths:
                    continue
                error = None
                try:
                    if db.manager == "rpm":
                        problems = _verify_rpm(
                            src, f, users, groups, baseline, reader, against_baseline
                        )
                    else:
                        problems = _verify_dpkg(src, f, reader)
                        if baseline is not None and against_baseline and f.path not in compared:
                            compared.add(f.path)
                            problems |= _dpkg_since_baseline(src, f, baseline, reader)
                except DiskReadError as err:  # damaged metadata: cannot tell, so say so
                    problems, error = {"unreadable"}, str(err)
                # Read no content, so not needed to plan the reads. On its own: attributes
                # that cannot be read must not hide what was found of the file itself.
                if (
                    not planning
                    and baseline is not None
                    and against_baseline
                    and f.path not in attrs_compared
                ):
                    attrs_compared.add(f.path)
                    try:
                        problems |= _xattrs_since_baseline(src, f, baseline)
                    except DiskReadError as err:
                        problems.add("unreadable")
                        error = error or f"extended attributes: {err}"
                if problems:
                    out.append(
                        FileProblem(
                            f.path,
                            pkg.name,
                            pkg.arch,
                            frozenset(problems),
                            f.is_config,
                            error,
                            f.mode,
                        )
                    )
        return out

    # The same checks twice, so that what gets read cannot differ from what they need:
    # the first time only notes the contents, which are then read in inode order.
    check_every_file(planning=True)
    reader.read_planned()
    return check_every_file(planning=False)


def physical_path(src: SystemSource, path: str, parents: dict[str, str] | None = None) -> str:
    """`path` with its parent directory resolved through symlinks (the last
    component is kept): where the entry physically sits in the tree.

    親ディレクトリのシンボリックリンクを解決した `path`（最後の要素はそのまま）: そのエントリ
    が木の中で物理的に居る場所。
    """
    if path in ("/", "/."):
        return "/"
    d, b = posixpath.split(path.rstrip("/"))
    cache = parents if parents is not None else {}
    if d not in cache:
        try:
            cache[d] = src.realpath(d) or d
        except DiskReadError:  # e.g. a symlink loop: keep the path as listed
            cache[d] = d
    r = cache[d]
    return ("" if r == "/" else r) + "/" + b


def owned_paths(src: SystemSource, db: PackageDB) -> set[str]:
    """Physical paths of everything the packages list.

    パッケージが挙げる全ファイルの物理パス。
    """
    parents: dict[str, str] = {}
    return {physical_path(src, f.path, parents) for pkg in db.packages for f in pkg.files}


def unowned_paths(src: SystemSource, db: PackageDB) -> list[tuple[str, FileType]]:
    """Every path in the tree that no package lists (hand-placed or generated).

    どのパッケージも挙げない、木の中の全パス（手置きか生成物）。
    """
    owned = owned_paths(src, db)
    out = []
    for path, _fs, _ino, st in src.walk():
        p = path.decode("utf-8", "surrogateescape")
        if p not in owned:
            out.append((p, st.type))
    return out
