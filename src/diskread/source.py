"""Read files by path from a filesystem or a whole mounted system.

What a program wants often lies under /var, which may be its own volume, or
behind a symlink (Fedora points /var/lib/rpm at /usr/lib/sysimage/rpm). So
paths are resolved component by component, switching filesystems at
mountpoints and following symlinks (absolute ones from the system root),
the way the kernel resolves them.

ファイルシステム（またはマウント済みのシステム全体）から、パスでファイルを読む。読みたいものが
別ボリュームになりがちな /var の下や、シンボリックリンクの先（Fedora の /var/lib/rpm は
/usr/lib/sysimage/rpm を指す）にあることも多いので、カーネルと同じようにパスを 1 要素ずつ解決し、
マウントポイントでファイルシステムを切り替え、リンク（絶対ならシステムルートから）を辿る。
"""

from __future__ import annotations

import posixpath
from collections.abc import Callable, Iterator

from diskread.blockdev import will_read
from diskread.errors import DiskReadError
from diskread.fs import Filesystem, FileType, Stat, valid_name, will_list
from diskread.system import System, walk_mounts

MAX_SYMLINKS = 40  # Linux's limit (ELOOP)
# A resolved path: its filesystem, inode, and physical place (components, no symlinks).
type _Found = tuple[Filesystem, int, tuple[bytes, ...]]
# read() is for configuration and package databases. A size beyond this is
# damage (or a sparse file put there on purpose), not something to allocate.
MAX_READ_BYTES = 4 << 30


def clean_path(path: str) -> bool:
    """Whether `path` is absolute and names its place plainly: no "..", ".", doubled or
    trailing "/". Lists read from a disk (a package's files, a RECORD) may hold any text;
    one that resolves somewhere else than it says must not be taken for a path.

    `path` が絶対パスで、場所をそのまま指しているか（「..」「.」、重なった・末尾の「/」が無い）。
    ディスクから読む一覧（パッケージのファイル、RECORD）にはどんな文字列もあり得る。書いてある
    のと違う場所に解決されるものを、パスとして扱ってはいけない。
    """
    return path.startswith("/") and not path.startswith("//") and posixpath.normpath(path) == path


class SystemSource:
    """Path-based reads over one or more mounted filesystems (see the module docstring).

    マウントされたファイルシステム群に対するパスでの読み取り（モジュール docstring 参照）。
    """

    def __init__(self, mounts: dict[bytes, Filesystem]) -> None:
        if b"/" not in mounts:
            raise ValueError("a root filesystem (b'/') is required")
        self._mounts = mounts
        # By filesystem, then by inode number: a tuple for a key would be one more
        # object for every path of the tree.
        self._dirs: dict[int, dict[int, dict[bytes, int]]] = {id(fs): {} for fs in mounts.values()}
        self._stats: dict[int, dict[int, Stat]] = {id(fs): {} for fs in mounts.values()}
        # Paths resolved with their symlinks followed, by their components: the
        # parent directories, mostly, which the files of a tree are looked up under
        # by the thousands (verifying packages, archiving). A miss is remembered too.
        self._resolved: dict[tuple[bytes, ...], _Found | None] = {}

    @classmethod
    def from_system(cls, system: System) -> SystemSource:
        """A source over every mount of an assembled System.

        組み上げた System の全マウントに対する読み取り口。
        """
        return cls({m.mountpoint: m.fs for m in system.mounts})

    @classmethod
    def from_fs(cls, fs: Filesystem) -> SystemSource:
        """A source over a single filesystem mounted at /.

        単一のファイルシステムを / にマウントしたものとして読む。
        """
        return cls({b"/": fs})

    @property
    def mounts(self) -> dict[bytes, Filesystem]:
        """mountpoint -> filesystem, as given.

        渡されたままの mountpoint → filesystem。
        """
        return dict(self._mounts)

    # --- cached lookups -------------------------------------------------------

    def stat(self, fs: Filesystem, ino: int) -> Stat:
        """stat with the result cached, since verify stats the same paths repeatedly.

        結果をキャッシュする stat（verify が同じパスを何度も stat するため）。
        """
        stats = self._stats.setdefault(id(fs), {})
        st = stats.get(ino)
        if st is None:
            st = stats[ino] = fs.stat(ino)
        return st

    def _children(self, fs: Filesystem, ino: int) -> dict[bytes, int]:
        """name -> inode of a directory, cached."""
        dirs = self._dirs.setdefault(id(fs), {})
        d = dirs.get(ino)
        if d is None:
            d = dirs[ino] = dict(fs.listdir(ino))
        return d

    # --- resolution -----------------------------------------------------------

    def _lookup(self, path: str, follow_last: bool) -> tuple[Filesystem, int, bytes] | None:
        """(filesystem, inode, physical path) of an absolute path."""
        comps = tuple(p for p in path.encode("utf-8", "surrogateescape").split(b"/") if p)
        try:
            found = self._resolve(comps, follow_last, 0)
        except RecursionError:  # symlinks that lead through ever longer paths
            raise DiskReadError(f"too many levels of symbolic links: {path}") from None
        if found is None:
            return None
        fs, ino, physical = found
        return fs, ino, b"/" + b"/".join(physical)

    def _resolve(self, comps: tuple[bytes, ...], follow_last: bool, hops: int) -> _Found | None:
        """The path `comps` resolved, a component at a time from the longest beginning
        of it already resolved (each is remembered). `hops` counts the symlinks followed
        so far. Forward, not by recursion over the components: a disk may hold a path
        many hundreds deep, which the walk lists and a recursion would not survive."""
        if follow_last and comps in self._resolved:
            return self._resolved[comps]
        known = max(len(comps) - 1, 0)
        while known and comps[:known] not in self._resolved:
            known -= 1
        root = self._mounts[b"/"]
        found: _Found | None = self._resolved[comps[:known]] if known else (root, root.root_ino, ())
        for end in range(known + 1, len(comps) + 1):
            follow = follow_last or end < len(comps)  # always in the middle of a path
            if found is not None:
                found = self._step(found, comps[:end], follow, hops)
            if follow:
                self._resolved[comps[:end]] = found
        return found

    def _step(
        self, parent: _Found, comps: tuple[bytes, ...], follow_last: bool, hops: int
    ) -> _Found | None:
        """The last component of `comps` looked up in `parent`, its resolved parent, the
        way the kernel does it: a mountpoint shows the mounted root, a symlink is followed
        (always in the middle of a path, at its end only with `follow_last`)."""
        fs, ino, physical = parent
        name = comps[-1]
        if name == b".":
            return parent
        if name == b"..":  # the parent of the physical place; the root is its own
            return self._resolve(physical[:-1], True, hops)
        if self.stat(fs, ino).type is not FileType.DIR:
            return None
        child = self._children(fs, ino).get(name)
        if child is None:
            return None
        here = (*physical, name)
        mounted = self._mounts.get(b"/" + b"/".join(here))
        if mounted is not None:
            return mounted, mounted.root_ino, here
        if follow_last and self.stat(fs, child).type is FileType.LNK:
            if hops >= MAX_SYMLINKS:
                raise DiskReadError(
                    "too many levels of symbolic links: /"
                    + b"/".join(comps).decode("utf-8", "replace")
                )
            link = fs.readlink(child)
            target = tuple(p for p in link.split(b"/") if p)
            base = () if link.startswith(b"/") else physical
            return self._resolve(base + target, True, hops + 1)
        return fs, child, here

    def resolve(self, path: str, follow_last: bool = True) -> tuple[Filesystem, int] | None:
        """(filesystem, inode) of an absolute path; like stat(2), or lstat(2)
        with follow_last=False.

        絶対パスの (filesystem, inode)。stat(2) 相当で、follow_last=False なら lstat(2) 相当。
        """
        found = self._lookup(path, follow_last)
        return None if found is None else (found[0], found[1])

    def realpath(self, path: str) -> str | None:
        """The physical path with every symlink resolved, or None if it does not exist.

        全てのシンボリックリンクを解決した物理パス。存在しなければ None。
        """
        found = self._lookup(path, True)
        return None if found is None else found[2].decode("utf-8", "surrogateescape")

    def listdir(self, path: str) -> list[str] | None:
        """Names in a directory (following symlinks), or None if it is not one.

        ディレクトリ内の名前（リンクは辿る）。ディレクトリでなければ None。
        """
        found = self.resolve(path)
        if found is None or self.stat(*found).type is not FileType.DIR:
            return None
        # Names only: an entry called "..", or holding a "/", joined to the path would
        # lead the caller somewhere else (the walk reports those as damage).
        names = (n for n in self._children(*found) if valid_name(n))
        return sorted(n.decode("utf-8", "surrogateescape") for n in names)

    def try_listdir(self, path: str) -> list[str] | None:
        """Like listdir, for what the analysis can do without: a directory that cannot
        be read (itself, or one on the way to it) counts as absent.

        listdir と同じだが、無くても解析を続けられるもの用: 読めないディレクトリ（それ自身か、
        そこへ至る途中のもの）は無いものとして扱う。
        """
        try:
            return self.listdir(path)
        except DiskReadError:
            return None

    def read(self, path: str, *, told: bool = False) -> bytes | None:
        """Bytes of the regular file at `path` (following symlinks), or None.
        `told`: will_read_files already told the disk of it, in the order of the reads.

        `path` の通常ファイルのバイト列（シンボリックリンクは辿る）。無ければ None。`told`:
        will_read_files で読む順にディスクへ告げ済み。
        """
        found = self.resolve(path)
        if found is None:
            return None
        fs, ino = found
        if self.stat(fs, ino).type is not FileType.REG:
            return None
        dev = fs.open(ino)
        if dev.size > MAX_READ_BYTES:
            raise DiskReadError(f"{path}: {dev.size} bytes is too large to read into memory")
        if not told:
            will_read(dev)  # an rpm database is megabytes: over a network, fetch it ahead
        return dev.read_at(0, dev.size)

    def is_file(self, path: str) -> bool:
        """Whether `path` (following symlinks) is a regular file, which read would read.

        `path`（シンボリックリンクは辿る）が通常ファイルか。read が読むものか。
        """
        try:
            found = self.resolve(path)
            return found is not None and self.stat(*found).type is FileType.REG
        except DiskReadError:
            return False  # cannot tell: read raises, and the caller decides

    def will_read_files(self, paths: list[str]) -> None:
        """Tell the disks that these files will be read whole, in this order, and then
        read them with `read(path, told=True)`: many small files are then fetched ahead
        instead of one at a time. A file read would not read is left out.

        これらのファイルをこの順に丸ごと読むとディスクに告げる。その後 `read(path, told=True)`
        で読む。小さなファイルが多くても 1 つずつ待たずに先読みできる。read が読まないファイルは
        除く。
        """
        for path in paths:
            try:
                found = self.resolve(path)
                if found is None or self.stat(*found).type is not FileType.REG:
                    continue
                dev = found[0].open(found[1])
            except DiskReadError:
                continue  # only a hint: the read meets the error and reports it
            if dev.size <= MAX_READ_BYTES:
                will_read(dev)

    def try_read(self, path: str, *, told: bool = False) -> bytes | None:
        """Like read, for data the analysis can do without: unreadable counts as absent.

        read と同じだが、無くても解析を続けられるデータ用: 読めなければ無いものとして扱う。
        """
        try:
            return self.read(path, told=told)
        except DiskReadError:
            return None

    def walk(
        self,
        on_error: Callable[[bytes, DiskReadError], None] | None = None,
        prune: Callable[[bytes], bool] | None = None,
    ) -> Iterator[tuple[bytes, Filesystem, int, Stat]]:
        """Every path of the mounted tree (see diskread.system.walk_mounts).
        Paths satisfying `prune` are neither yielded nor entered. The walk
        goes through this source's stat and directory caches, so resolving
        paths afterwards does not read the same metadata again
        (which matters when each read is an EBS direct API request).

        マウント済みの木の全パス（diskread.system.walk_mounts 参照）。`prune` に合うパスは出さず、
        中にも入らない。walk はこの読み口の stat とディレクトリのキャッシュを通るので、
        後からのパス解決で同じメタデータを読み直さない（
        読み 1 回ごとに EBS direct API を呼ぶときに効く）。
        """

        def listdir(fs: Filesystem, ino: int) -> list[tuple[bytes, int]]:
            return list(self._children(fs, ino).items())

        def tell(fs: Filesystem, ino: int) -> None:
            if ino not in self._dirs.get(id(fs), ()):  # a cached one is not read again
                will_list(fs, ino)

        yield from walk_mounts(
            self._mounts, on_error, listdir=listdir, stat=self.stat, prune=prune, tell=tell
        )
