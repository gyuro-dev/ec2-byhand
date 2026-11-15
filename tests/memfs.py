"""A tiny in-memory diskread Filesystem for unit tests. It records what was read:
`opened` (file contents) and `listed` (directories), by inode."""

from __future__ import annotations

import stat as _stat

from diskread import BytesDevice
from diskread.errors import DiskReadError
from diskread.fs import Stat


class MemFs:
    """Build with add_file / add_link; directories are created as needed."""

    fs_type = "memfs"
    is_dirty = False

    def __init__(self) -> None:
        self._next = 2
        self._nodes: dict[int, dict] = {1: {"mode": _stat.S_IFDIR | 0o755, "children": {}}}
        self.opened: list[int] = []
        self.listed: list[int] = []

    @property
    def root_ino(self) -> int:
        return 1

    def _dir(self, path: str) -> int:
        ino = 1
        for part in [p for p in path.split("/") if p]:
            children = self._nodes[ino]["children"]
            if part.encode() not in children:
                children[part.encode()] = self._new({"mode": _stat.S_IFDIR | 0o755, "children": {}})
            ino = children[part.encode()]
        return ino

    def _new(self, node: dict) -> int:
        ino, self._next = self._next, self._next + 1
        self._nodes[ino] = node
        return ino

    def ino(self, path: str) -> int:
        """The inode at `path`, which must exist."""
        ino = 1
        for part in [p for p in path.split("/") if p]:
            ino = self._nodes[ino]["children"][part.encode()]
        return ino

    def add_dir(self, path: str, mode: int = 0o755, ctime_ns: int = 0) -> None:
        node = self._nodes[self._dir(path)]
        node["mode"] = _stat.S_IFDIR | mode
        node["ctime_ns"] = ctime_ns

    def add_file(
        self,
        path: str,
        data: bytes = b"",
        mode: int = 0o644,
        mtime_ns: int = 0,
        ctime_ns: int | None = None,
    ) -> None:
        """ctime defaults to mtime, as when a file is written."""
        parent, _, name = path.rpartition("/")
        self._nodes[self._dir(parent)]["children"][name.encode()] = self._new(
            {
                "mode": _stat.S_IFREG | mode,
                "data": data,
                "mtime_ns": mtime_ns,
                "ctime_ns": mtime_ns if ctime_ns is None else ctime_ns,
            }
        )

    def add_link(self, path: str, target: str, ctime_ns: int = 0) -> None:
        parent, _, name = path.rpartition("/")
        self._nodes[self._dir(parent)]["children"][name.encode()] = self._new(
            {
                "mode": _stat.S_IFLNK | 0o777,
                "target": target.encode(),
                "mtime_ns": ctime_ns,
                "ctime_ns": ctime_ns,
            }
        )

    def add_hardlink(self, path: str, existing: str) -> None:
        parent, _, name = existing.rpartition("/")
        ino = self._nodes[self._dir(parent)]["children"][name.encode()]
        parent, _, name = path.rpartition("/")
        self._nodes[self._dir(parent)]["children"][name.encode()] = ino
        self._nodes[ino]["nlink"] = self._nodes[ino].get("nlink", 1) + 1

    def stat(self, ino: int) -> Stat:
        n = self._nodes[ino]
        size = len(n.get("data", n.get("target", b"")))
        return Stat(
            ino=ino,
            mode=n["mode"],
            uid=0,
            gid=0,
            size=size,
            nlink=n.get("nlink", 1),
            blocks=0,
            atime_ns=0,
            mtime_ns=n.get("mtime_ns", 0),
            ctime_ns=n.get("ctime_ns", 0),
            btime_ns=None,
            rdev=None,
        )

    def listdir(self, ino: int) -> list[tuple[bytes, int]]:
        self.listed.append(ino)
        if "children" not in self._nodes[ino]:
            raise DiskReadError(f"{ino} is not a directory")
        return sorted(self._nodes[ino]["children"].items())

    def open(self, ino: int) -> BytesDevice:
        self.opened.append(ino)
        return BytesDevice(self._nodes[ino]["data"])

    def readlink(self, ino: int) -> bytes:
        return self._nodes[ino]["target"]

    def set_xattr(self, path: str, name: str, value: bytes) -> None:
        self._nodes[self.ino(path)].setdefault("xattrs", {})[name] = value

    def xattrs(self, ino: int) -> dict[str, bytes]:
        return dict(self._nodes[ino].get("xattrs", {}))
