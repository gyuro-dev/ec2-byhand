"""Installed packages read offline from a filesystem's package database.

db = read_packages(FsSource(fs))      # rpm (SQLite or Berkeley DB) or dpkg
changes = diff_packages(db_before, db_after)

ファイルシステムのパッケージデータベースをオフラインで読む。使い方は上のとおり（read_packages
で読み、diff_packages で比べる）。
"""

from __future__ import annotations

import contextlib
import dataclasses
from typing import Protocol

from diskread.errors import DiskReadError
from diskread.source import SystemSource
from ec2_byhand.packages.diff import PackageChange, diff_packages
from ec2_byhand.packages.dpkg import read_dpkg
from ec2_byhand.packages.model import Manager, Package, PackageDB, PackageFile
from ec2_byhand.packages.rpmdb import read_bdb, read_sqlite

# Fedora 36+ moved the rpmdb; /var/lib/rpm is then a symlink to it.
RPM_DIRS = ("/usr/lib/sysimage/rpm", "/var/lib/rpm")
DPKG_DIR = "/var/lib/dpkg"


class FileSource(Protocol):
    """The minimal reading interface the package-database readers need.

    パッケージ DB のリーダーが必要とする最小の読み取り口。
    """

    def read(self, path: str) -> bytes | None:
        """Bytes of the regular file at an absolute path (following
        symlinks), or None if it does not exist.

        絶対パスにある通常ファイルのバイト列（シンボリックリンクは辿る）。存在しなければ None
        。
        """
        ...


def _database(
    manager: Manager, format: str, path: str, pkgs: list[Package], damaged: list[str]
) -> PackageDB:
    """The PackageDB of what was read; DiskReadError if damage left no package at all."""
    if damaged and not pkgs:
        raise DiskReadError(f"{path}: no package could be read (first: {damaged[0]})")
    return PackageDB(manager, format, path, tuple(pkgs), tuple(damaged))


def _read_rpm(src: FileSource) -> PackageDB | None:
    """The rpm database, wherever and in whichever format it is kept; None if there is none."""
    damaged: list[str] = []
    for d in RPM_DIRS:
        db = src.read(f"{d}/rpmdb.sqlite")
        if db is not None:
            wal = src.read(f"{d}/rpmdb.sqlite-wal")
            pkgs = read_sqlite(db, wal, damaged.append)
            return _database("rpm", "rpm-sqlite", f"{d}/rpmdb.sqlite", pkgs, damaged)
        db = src.read(f"{d}/Packages")
        if db is not None:
            pkgs = read_bdb(db, damaged.append)
            return _database("rpm", "rpm-bdb", f"{d}/Packages", pkgs, damaged)
    return None


def _read_dpkg(src: FileSource) -> PackageDB | None:
    """The dpkg database; None if there is none."""
    damaged: list[str] = []
    status = src.read(f"{DPKG_DIR}/status")
    if status is None:
        return None
    if not isinstance(src, SystemSource):
        pkgs = read_dpkg(status, lambda name: src.read(f"{DPKG_DIR}/info/{name}"), damaged.append)
        return _database("dpkg", "dpkg", f"{DPKG_DIR}/status", pkgs, damaged)
    # Ubuntu has two info files a package, a few KiB each, read one after another: a
    # first pass with empty contents finds which, in order, so that the disk is told
    # of them all before the real pass reads them (the same files: a file asked for
    # depends only on whether the ones before it exist).
    planned: list[str] = []

    def plan(name: str) -> bytes | None:
        path = f"{DPKG_DIR}/info/{name}"
        if not src.is_file(path):
            return None
        planned.append(path)
        return b""

    with contextlib.suppress(DiskReadError):  # the real pass meets it again and reports it
        read_dpkg(status, plan, lambda _: None)
    src.will_read_files(planned)
    pkgs = read_dpkg(
        status, lambda name: src.read(f"{DPKG_DIR}/info/{name}", told=True), damaged.append
    )
    return _database("dpkg", "dpkg", f"{DPKG_DIR}/status", pkgs, damaged)


def read_packages(src: FileSource) -> PackageDB | None:
    """Find and read the package database, or None if there is none. What cannot be
    read of it is listed in `damaged`; DiskReadError if no package at all can be read.
    A server can hold both kinds (the rpm tool installed on Debian leaves an empty rpm
    database): the system's own is the one with more packages. One that could not be
    read while the other had packages is listed in `damaged`, since its packages are
    missing from the result just as a damaged entry's would be.

    パッケージデータベースを見つけて読む。無ければ None。読めなかった部分は `damaged` に列挙
    し、1 つも読めなければ DiskReadError。両方の形式がある場合（Debian に rpm コマンドを入れる
    と空の rpm データベースができる）は、パッケージの多い方をそのシステムのものとする。片方が
    読めず、もう片方にパッケージがあったときは、読めなかった方を `damaged` に挙げる（その
    パッケージが結果から抜けるのは、壊れたエントリと同じため）。
    """
    found: list[PackageDB] = []
    unreadable: list[DiskReadError] = []
    for read in (_read_rpm, _read_dpkg):
        try:
            db = read(src)
        except DiskReadError as err:
            unreadable.append(err)
            continue
        if db is not None:
            found.append(db)
    # A database that cannot be read may be the system's own: only one that
    # did give packages can stand in for it.
    if unreadable and not any(db.packages for db in found):
        raise unreadable[0]
    chosen = max(found, key=lambda db: len(db.packages), default=None)  # a tie: rpm, listed first
    if chosen is not None and unreadable:
        notes = tuple(
            f"{err} (the {chosen.manager} database was used instead)" for err in unreadable
        )
        chosen = dataclasses.replace(chosen, damaged=chosen.damaged + notes)
    return chosen


__all__ = [
    "FileSource",
    "Package",
    "PackageChange",
    "PackageDB",
    "PackageFile",
    "diff_packages",
    "read_packages",
]
