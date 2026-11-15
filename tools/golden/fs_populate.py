"""Fill a freshly made filesystem with a deterministic tree of tricky files.

Run as root inside WSL/Linux with the filesystem mounted at ROOT:
    python3 fs_populate.py ROOT

Everything here exists to exercise a parser code path: directory formats,
holes, unwritten extents, many-extent files, symlink storage, hard links,
special files, ownership, permissions, timestamps, xattrs and ACLs.
Uses only the standard library plus setfacl, so it runs on stock Python 3.
"""

from __future__ import annotations

import contextlib
import os
import random
import socket
import stat
import subprocess
import sys

root = sys.argv[1]
rng = random.Random(20261024)


def p(*parts: str) -> str:
    return os.path.join(root, *parts)


def write(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


def randbytes(n: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(n)) if n < 4096 else rng.randbytes(n)


# --- regular files: sizes and storage layouts --------------------------------
os.makedirs(p("etc", "app", "conf.d"))
write(p("etc", "app", "app.conf"), b"listen=0.0.0.0:8080\nworkers=4\n")
write(p("etc", "app", "conf.d", "10-override.conf"), b"workers=8\n")
write(p("empty"), b"")
write(p("small.txt"), b"hello\n")  # fits inline when inline_data is on
write(p("exactly-60.bin"), b"6" * 60)  # the boundary of ext4's i_block
write(p("one-block.bin"), randbytes(4096))
write(p("medium.bin"), randbytes(200_000))
write(p("big.bin"), randbytes(3 << 20))

# Hole at the start, data in the middle, hole at the end.
with open(p("sparse.bin"), "wb") as f:
    f.seek(1 << 20)
    f.write(randbytes(5000))
    f.truncate(4 << 20)

# Data far out in a mostly-sparse file: reaches double indirect blocks with
# 4 KiB blocks and triple indirect blocks with 1 KiB blocks (block-mapped).
with open(p("far-sparse.bin"), "wb") as f:
    for off in (0, 1 << 20, 70 << 20):
        f.seek(off)
        f.write(randbytes(3000))
    f.truncate(72 << 20)

# 4 KiB of data every 8 KiB: hundreds of extents, forcing an extent tree.
with open(p("fragmented.bin"), "wb") as f:
    for i in range(400):
        f.seek(i * 8192)
        f.write(randbytes(4096))

# Preallocated (unwritten) space must read back as zeros.
with open(p("prealloc.bin"), "wb") as f:
    os.posix_fallocate(f.fileno(), 0, 1 << 20)
    f.seek(4096)
    f.write(b"x" * 100)

# --- names --------------------------------------------------------------------
write(p("L" * 255), b"longest name\n")
write(p("日本語ファイル.txt"), "こんにちは\n".encode())
write(p("emoji-🎉.txt"), b"party\n")
write(os.path.join(os.fsencode(root), b"bad-utf8-\xff\xfe"), b"not utf-8\n")
write(p("with space and 'quote'"), b"spaces\n")

# A big directory (hashed/btree formats) with holes from deletions.
os.mkdir(p("bigdir"))
for i in range(3000):
    write(p("bigdir", f"file-{i:05d}-{'x' * 40}"), f"{i}\n".encode())
for i in range(0, 3000, 3):
    os.unlink(p("bigdir", f"file-{i:05d}-{'x' * 40}"))

# Medium directories that land on the intermediate on-disk formats.
for n in (5, 40, 200, 600):
    d = p(f"dir-{n}")
    os.mkdir(d)
    for i in range(n):
        write(os.path.join(d, f"entry-{i:04d}"), b"")

deep = root
for i in range(20):
    deep = os.path.join(deep, f"d{i}")
os.makedirs(deep)
write(os.path.join(deep, "leaf.txt"), b"deep\n")

# Deleted files must not show up.
write(p("deleted.txt"), b"gone\n")
os.unlink(p("deleted.txt"))

# --- links and special files --------------------------------------------------
os.symlink("small.txt", p("link-short"))
os.symlink("/" + "a/" * 100 + "target", p("link-long"))
# Longer than an XFS inode's literal area: stored in remote symlink blocks.
os.symlink("/" + "b/" * 499 + "end", p("link-very-long"))
os.symlink("x" * 59, p("link-59"))
os.symlink("y" * 60, p("link-60"))
os.symlink("does-not-exist", p("link-dangling"))
os.link(p("small.txt"), p("hardlink-to-small"))
os.link(p("small.txt"), p("etc", "hardlink-deep"))

os.mkdir(p("dev"))
os.mkfifo(p("dev", "fifo"))
os.mknod(p("dev", "null"), stat.S_IFCHR | 0o666, os.makedev(1, 3))
os.mknod(p("dev", "sda1"), stat.S_IFBLK | 0o660, os.makedev(8, 1))
os.mknod(p("dev", "bignum"), stat.S_IFCHR | 0o600, os.makedev(300, 70000))
s = socket.socket(socket.AF_UNIX)
s.bind(p("dev", "sock"))
s.close()

# --- ownership and permissions ------------------------------------------------
write(p("setuid"), b"#!/bin/sh\n")
os.chmod(p("setuid"), 0o4755)
write(p("setgid"), b"#!/bin/sh\n")
os.chmod(p("setgid"), 0o2711)
os.mkdir(p("sticky"))
os.chmod(p("sticky"), 0o1777)
write(p("no-perms"), b"secret\n")
os.chmod(p("no-perms"), 0)
write(p("owned-1000"), b"user\n")
os.chown(p("owned-1000"), 1000, 1000)
write(p("owned-big"), b"big ids\n")
os.chown(p("owned-big"), 70000, 4000000)  # needs the high 16 bits
os.lchown(p("link-short"), 1000, 1001)

# A short (fast) symlink carrying a huge xattr: with ext4 ea_inode the value
# moves to an EA inode whose blocks are charged to the symlink's i_blocks.
os.symlink("small.txt", p("link-fast-huge-xattr"))
with contextlib.suppress(OSError):
    os.setxattr(p("link-fast-huge-xattr"), "trusted.huge", randbytes(10000), follow_symlinks=False)
# A fast symlink whose xattr needs an xattr block: with bigalloc that block
# is charged to i_blocks as a whole cluster.
os.symlink("small.txt", p("link-fast-xattr-block"))
# Too big for the inode body, small enough for a 1 KiB xattr block.
with contextlib.suppress(OSError):
    os.setxattr(p("link-fast-xattr-block"), "trusted.mid", randbytes(600), follow_symlinks=False)

# --- xattrs and ACLs -----------------------------------------------------------
write(p("xattr-small"), b"x\n")
os.setxattr(p("xattr-small"), "user.comment", b"hi")
os.setxattr(p("xattr-small"), "user.empty", b"")
os.setxattr(p("xattr-small"), "trusted.flag", b"\x01\x02")
write(p("xattr-big"), b"x\n")
try:
    # Too big for the inode; lands in an xattr block, or an EA inode with
    # ea_inode. With 1 KiB ext4 blocks and no ea_inode it does not fit at all.
    os.setxattr(p("xattr-big"), "user.big", randbytes(3000))
except OSError:
    os.setxattr(p("xattr-big"), "user.big", randbytes(700))
# Bigger than a block: only possible with ext4 ea_inode (or XFS).
with contextlib.suppress(OSError):
    os.setxattr(p("xattr-big"), "user.huge", randbytes(10000))
write(p("xattr-many"), b"x\n")
for i in range(30):
    try:
        os.setxattr(p("xattr-many"), f"user.k{i:02d}", f"value-{i}".encode() * 3)
    except OSError:
        break  # the xattr block is full (1 KiB ext4 blocks)
# Enough xattrs to need more than one block: XFS node-form attr fork.
write(p("xattr-lots"), b"x\n")
for i in range(400):
    try:
        os.setxattr(p("xattr-lots"), f"user.lot{i:03d}", f"{i:03d}".encode() * 10)
    except OSError:
        break  # ext4 keeps xattrs in one block
with contextlib.suppress(OSError):
    os.setxattr(p("xattr-small"), "security.test", b"label")

write(p("acl-file"), b"acl\n")
subprocess.run(["setfacl", "-m", "u:1000:rwx,g:1001:r-x,m::rwx", p("acl-file")], check=True)
os.mkdir(p("acl-dir"))
subprocess.run(["setfacl", "-d", "-m", "u:1000:rwx", p("acl-dir")], check=True)

# --- timestamps (last, since creating entries bumps directory times) ----------
NS = 123_456_789
for name, sec in [
    ("small.txt", 0),
    ("empty", -1),  # 1969-12-31 23:59:59
    ("one-block.bin", -(2**31)),  # 1901
    ("medium.bin", 2**31 - 1),  # 2038-01-19
    ("big.bin", 2**31),  # just past the 32-bit limit
    ("sparse.bin", 4102444800),  # 2100-01-01
]:
    t = sec * 1_000_000_000 + NS
    os.utime(p(name), ns=(t, t))
os.utime(
    p("link-short"),
    ns=(1_600_000_000_000_000_001, 1_600_000_000_999_999_999),
    follow_symlinks=False,
)
os.utime(p("etc"), ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))
