"""Dump what the Linux kernel sees in a mounted filesystem, as JSON.

Run as root inside WSL/Linux with the filesystem mounted read-only at ROOT:
    python3 fs_dump.py ROOT > expected.json

This is the ground truth the diskread filesystem parsers are tested
against. Paths are relative to ROOT and start with "/". Names that are not
valid UTF-8 survive the round trip via surrogateescape (json escapes the
lone surrogates as \\udcXX).
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import stat
import struct
import sys

root = sys.argv[1]
TYPES = {
    stat.S_IFREG: "reg",
    stat.S_IFDIR: "dir",
    stat.S_IFLNK: "lnk",
    stat.S_IFCHR: "chr",
    stat.S_IFBLK: "blk",
    stat.S_IFIFO: "fifo",
    stat.S_IFSOCK: "sock",
}


_libc = ctypes.CDLL(None, use_errno=True)
AT_FDCWD = -100
AT_SYMLINK_NOFOLLOW = 0x100
STATX_BTIME = 0x800


def birth_time_ns(path: str) -> int | None:
    """Birth time via statx(2); Python's os.stat does not expose it on Linux.

    struct statx: stx_mask is the u32 at offset 0, stx_btime is
    {s64 tv_sec; u32 tv_nsec} at offset 80; the struct is 256 bytes.
    """
    buf = ctypes.create_string_buffer(256)
    rc = _libc.statx(AT_FDCWD, os.fsencode(path), AT_SYMLINK_NOFOLLOW, STATX_BTIME, buf)
    if rc != 0:
        raise OSError(ctypes.get_errno(), "statx failed", path)
    (mask,) = struct.unpack_from("<I", buf, 0)
    if not mask & STATX_BTIME:
        return None
    sec, nsec = struct.unpack_from("<qI", buf, 80)
    return sec * 1_000_000_000 + nsec


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def entry(path: str, rel: str) -> dict:
    st = os.lstat(path)
    kind = TYPES[stat.S_IFMT(st.st_mode)]
    e = {
        "path": rel,
        "ino": st.st_ino,
        "type": kind,
        "mode": st.st_mode,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "size": st.st_size,
        "nlink": st.st_nlink,
        "blocks": st.st_blocks,
        "atime_ns": st.st_atime_ns,
        "mtime_ns": st.st_mtime_ns,
        "ctime_ns": st.st_ctime_ns,
        "btime_ns": birth_time_ns(path),
        "rdev": [os.major(st.st_rdev), os.minor(st.st_rdev)] if kind in ("chr", "blk") else None,
        "target": os.fsdecode(os.readlink(path)) if kind == "lnk" else None,
        "sha256": sha256(path) if kind == "reg" else None,
    }
    xattrs = {}
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError:  # e.g. vfat has no xattr support at all
        names = []
    for name in sorted(names):
        xattrs[name] = os.getxattr(path, name, follow_symlinks=False).hex()
    e["xattrs"] = xattrs
    return e


def main() -> None:
    out = [entry(root, "/")]
    stack = [(root, "")]
    while stack:
        d, rel = stack.pop()
        for de in os.scandir(d):
            child_rel = rel + "/" + de.name
            out.append(entry(de.path, child_rel))
            if de.is_dir(follow_symlinks=False):
                stack.append((de.path, child_rel))
    out.sort(key=lambda e: os.fsencode(e["path"]))
    json.dump({"files": out}, sys.stdout, indent=1)


main()
