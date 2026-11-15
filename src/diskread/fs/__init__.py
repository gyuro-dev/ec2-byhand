"""Filesystem-independent types and helpers shared by the ext4, XFS and FAT readers.

各ファイルシステムのリーダーが共有する、ファイルシステム非依存の型とヘルパー。
"""

from __future__ import annotations

import contextlib
import stat as _stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from diskread.blockdev import BlockDevice
from diskread.errors import DiskReadError, malformed_as_disk_read_error


class FileType(StrEnum):
    """An inode's type as a short lowercase name ("reg", "dir", ...).

    inode の種別（「reg」「dir」などの短い小文字名）。
    """

    REG = "reg"
    DIR = "dir"
    LNK = "lnk"
    CHR = "chr"
    BLK = "blk"
    FIFO = "fifo"
    SOCK = "sock"


_TYPES = {
    _stat.S_IFREG: FileType.REG,
    _stat.S_IFDIR: FileType.DIR,
    _stat.S_IFLNK: FileType.LNK,
    _stat.S_IFCHR: FileType.CHR,
    _stat.S_IFBLK: FileType.BLK,
    _stat.S_IFIFO: FileType.FIFO,
    _stat.S_IFSOCK: FileType.SOCK,
}


def file_type(mode: int) -> FileType:
    """The FileType in `mode`'s S_IFMT bits; DiskReadError if unknown.

    `mode` の S_IFMT ビットが表す FileType。未知なら DiskReadError。
    """
    try:
        return _TYPES[_stat.S_IFMT(mode)]
    except KeyError:
        raise DiskReadError(f"unknown file type in mode {mode:#o}") from None


@dataclass(frozen=True, slots=True)  # slots: one is kept for every path that is walked
class Stat:
    """What stat(2) would report for an inode, as Linux computes it.

    その inode について stat(2) が返す内容（Linux の計算に合わせる）。
    """

    ino: int
    mode: int  # including the S_IFMT type bits
    uid: int
    gid: int
    size: int
    nlink: int
    blocks: int  # in 512-byte units, like st_blocks
    atime_ns: int
    mtime_ns: int
    ctime_ns: int
    btime_ns: int | None  # None when the filesystem does not record it
    rdev: tuple[int, int] | None  # (major, minor) for device nodes
    _type: FileType | None = field(default=None, init=False, repr=False, compare=False)

    @property
    def type(self) -> FileType:
        """The FileType encoded in `mode`. Asked for on every path step of every lookup:
        worked out once and kept.

        `mode` が表す FileType。パス解決の各段で毎回聞かれるので、1 度求めて覚えておく。
        """
        found = self._type
        if found is None:
            found = file_type(self.mode)
            object.__setattr__(self, "_type", found)  # frozen: this is only a memo
        return found


class Filesystem(Protocol):
    """What every filesystem reader provides; walk() and lookup() build on it.

    各ファイルシステムリーダーが提供する読み取り口。walk() と lookup() はこの上に載る。
    """

    fs_type: str  # "ext4" (also for ext2 / ext3), "xfs" or "vfat", as detect_fs names them

    @property
    def is_dirty(self) -> bool:
        """Whether it may hold changes only in its journal or log, which are not replayed.

        変更がジャーナルやログにしか無い可能性があるか（それらは再生しない）。
        """
        ...

    @property
    def root_ino(self) -> int:
        """The root directory's inode number.

        ルートディレクトリの inode 番号。
        """
        ...

    def stat(self, ino: int) -> Stat:
        """What stat(2) would report for the inode.

        その inode の stat(2) 相当の情報。
        """
        ...

    def listdir(self, ino: int) -> list[tuple[bytes, int]]:
        """Directory entries as (name, inode), without "." and "..".

        ディレクトリの (名前, inode) の一覧。「.」と「..」は含まない。
        """
        ...

    def open(self, ino: int) -> BlockDevice:
        """The contents of a regular file (holes read as zeros).

        通常ファイルの内容（穴はゼロとして読める）。
        """
        ...

    def readlink(self, ino: int) -> bytes:
        """The symlink's target, as raw bytes.

        シンボリックリンクのリンク先（生のバイト列）。
        """
        ...

    def xattrs(self, ino: int) -> dict[str, bytes]:
        """Extended attributes as getxattr(2) would return them.

        getxattr(2) が返す形の拡張属性。
        """
        ...


def reads_disk_metadata[T](cls: type[T]) -> type[T]:
    """Class decorator for a filesystem reader: whatever its Filesystem methods
    make of malformed metadata comes out as DiskReadError.

    ファイルシステムリーダーのクラスデコレータ: Filesystem のメソッドが壊れたメタデータで何を起
    こしても DiskReadError として出す。
    """
    # will_list too, where a reader has it: it parses the same metadata as listdir.
    for name in ("stat", "listdir", "open", "readlink", "xattrs", "will_list"):
        if hasattr(cls, name):
            setattr(cls, name, malformed_as_disk_read_error(getattr(cls, name)))
    return cls


def valid_name(name: bytes) -> bool:
    """Whether a directory entry's name is one a path can hold: not empty, without "/"
    or NUL, and not "." or "..". A disk can hold any bytes; a name that is none would
    lead a path somewhere else than under its directory.

    ディレクトリエントリの名前が、パスに入れられるものか: 空でなく、「/」も NUL も含まず、
    「.」「..」でもない。ディスクにはどんなバイト列もあり得て、名前でないものを繋ぐと、パスが
    そのディレクトリの下ではない場所を指してしまう。
    """
    return bool(name) and b"/" not in name and b"\0" not in name and name not in (b".", b"..")


INODE_CACHE = 1 << 18  # inodes a filesystem keeps the bytes of (262,144)
PARSED_INODES = 1 << 13  # and those it keeps parsed too (8,192): the ones in use


@runtime_checkable
class ListsAhead(Protocol):
    """A filesystem that can tell its disk where a directory's entries are.

    ディレクトリの中身がどこにあるかをディスクに告げられるファイルシステム。
    """

    def will_list(self, ino: int) -> None:
        """Tell the disk (will_read) the blocks listdir(ino) will read, nothing more.

        listdir(ino) が読むブロックだけをディスクに告げる（will_read）。
        """
        ...


def will_list(fs: Filesystem, ino: int) -> None:
    """Tell the disk under `fs` where directory `ino`'s entries are, when it can say:
    a hint only, nothing is read but the directory's own metadata, and an error is
    left to listdir, which meets it again.

    `fs` の下のディスクに、ディレクトリ `ino` の中身の位置を告げる（告げられる場合）。ヒント
    にすぎず、読むのはディレクトリ自身のメタデータだけ。エラーは listdir に任せる。
    """
    if isinstance(fs, ListsAhead):
        with contextlib.suppress(DiskReadError):
            fs.will_list(ino)


def walk(
    fs: Filesystem,
    on_error: Callable[[bytes, DiskReadError], None] | None = None,
    prune: Callable[[bytes], bool] | None = None,
    listdir: Callable[[int], list[tuple[bytes, int]]] | None = None,
    stat: Callable[[int], Stat] | None = None,
    tell: Callable[[int], None] | None = None,
) -> Iterator[tuple[bytes, int, Stat]]:
    """Yield (path, inode, stat) for every reachable file, root first, a level of
    directories at a time.

    Paths are absolute byte strings ("/", "/etc", "/etc/passwd"). Each
    directory is entered once even if corrupt metadata creates a cycle.

    By default the first DiskReadError aborts the walk. With `on_error`,
    the error is reported with the path it concerns and that entry (or
    that directory's contents) is skipped, so one bad inode in a snapshot
    of a live system does not hide the rest of the tree.

    Entries whose path satisfies `prune` are neither yielded nor entered
    (used to hide what lies under a mountpoint). `listdir` and `stat`
    replace the filesystem's own calls, so a caller can route them through
    its caches (as SystemSource.walk does, to avoid re-reading the same
    metadata when it resolves paths after the walk).

    Breadth first: every directory of a level is told to the disk (`tell`, by
    default will_list) before any is listed, so that a disk read over a network
    fetches them all at once. Depth first, the next directory is known only once
    the one before is read, and each waited for its blocks (nine tenths of what an
    analysis over the EBS direct APIs waited for). With `listdir` given, `tell` is
    the caller's: only it knows which directories its listdir will read.

    到達できる全ファイルを (path, inode, stat) で、ルートから順に yield する。パスは絶対のバイ
    ト列。既定では最初の DiskReadError で中断し、`on_error` を渡すと該当パスを添えて報告してそ
    の項目（またはそのディレクトリの中身）だけを飛ばす。`prune` に合うパスは出さず、中にも入ら
    ない。`listdir` と `stat` を渡すとファイルシステム直呼びの代わりに使う（SystemSource.walk
    が自分のキャッシュ経由にして、walk 後のパス解決で同じメタデータを読み直さないため）。
    """

    def fail(path: bytes, err: DiskReadError) -> None:
        if on_error is None:
            raise err
        on_error(path, err)

    if tell is None and listdir is None:
        tell = lambda ino: will_list(fs, ino)  # noqa: E731
    listdir = fs.listdir if listdir is None else listdir
    stat = fs.stat if stat is None else stat
    root = fs.root_ino
    try:
        root_stat = stat(root)
    except DiskReadError as err:  # a volume whose root is damaged: nothing of it, said once
        fail(b"/", err)
        return
    yield b"/", root, root_stat
    seen_dirs = {root}
    level: list[tuple[bytes, int]] = [(b"", root)]
    while level:
        if tell is not None:
            for _, dir_ino in level:
                tell(dir_ino)
        below: list[tuple[bytes, int]] = []
        for prefix, dir_ino in level:
            try:
                entries = listdir(dir_ino)
            except DiskReadError as err:
                fail(prefix or b"/", err)
                continue
            for name, ino in entries:
                path = prefix + b"/" + name
                if not valid_name(name):
                    fail(path, DiskReadError(f"invalid name {name!r} in directory inode {dir_ino}"))
                    continue
                if prune is not None and prune(path):
                    continue
                try:
                    st = stat(ino)
                except DiskReadError as err:
                    fail(path, err)
                    continue
                if st.type is FileType.DIR and ino in seen_dirs:
                    fail(path, DiskReadError(f"directory inode {ino} reached twice"))
                    continue
                yield path, ino, st
                if st.type is FileType.DIR:
                    seen_dirs.add(ino)
                    below.append((path, ino))
        level = below


def lookup(fs: Filesystem, path: bytes | str) -> int:
    """Resolve an absolute path to an inode without following symlinks.

    絶対パスを、シンボリックリンクを辿らずに inode に解決する。
    """
    if isinstance(path, str):
        path = path.encode("utf-8", "surrogateescape")
    ino = fs.root_ino
    for part in path.split(b"/"):
        if not part:
            continue
        for name, child in fs.listdir(ino):
            if name == part:
                ino = child
                break
        else:
            raise FileNotFoundError(path)
    return ino


__all__ = [
    "FileType",
    "Filesystem",
    "Stat",
    "file_type",
    "lookup",
    "reads_disk_metadata",
    "valid_name",
    "walk",
]
