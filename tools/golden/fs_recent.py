"""Make "recent" changes on a populated filesystem, like a live server would.

    python3 fs_recent.py ROOT BATCH TOUCHED_JSON

BATCH is "synced" (run before `sync`) or "unsynced" (run after it, right
before the filesystem is shut down). The paths each batch touches,
including every parent directory whose entries or times change, are
appended to TOUCHED_JSON so tests can tell recent changes apart from the
untouched baseline.
"""

from __future__ import annotations

import json
import os
import random
import sys

root, batch, touched_file = sys.argv[1:]
rng = random.Random(batch)
touched: set[str] = set()


def p(rel: str) -> str:
    return os.path.join(root, rel.lstrip("/"))


def touch(rel: str) -> None:
    """Record rel and all its ancestors (their mtime/ctime/size change)."""
    rel = "/" + rel.strip("/")
    while True:
        touched.add(rel)
        if rel == "/":
            return
        rel = os.path.dirname(rel)


def write(rel: str, data: bytes) -> None:
    with open(p(rel), "wb") as f:
        f.write(data)
    touch(rel)


if batch == "synced":
    os.mkdir(p("recent"))
    write("recent/new-small.txt", b"added recently\n")
    write("recent/new-big.bin", rng.randbytes(2 << 20))
    for i in range(500):  # grow an existing big directory
        write(f"bigdir/recent-{i:04d}-{'y' * 30}", f"{i}\n".encode())
    os.rename(p("with space and 'quote'"), p("renamed-recently"))
    touch("with space and 'quote'")
    touch("renamed-recently")
    for i in range(0, 200, 2):
        os.unlink(p(f"dir-200/entry-{i:04d}"))
        touch(f"dir-200/entry-{i:04d}")
elif batch == "unsynced":
    write("etc/app/app.conf", b"listen=0.0.0.0:9090\nworkers=16\n")
    write("recent/after-sync.txt", b"never synced\n")
    os.chmod(p("setuid"), 0o755)
    touch("setuid")
    os.setxattr(p("xattr-small"), "user.recent", b"new")
    touch("xattr-small")
    os.unlink(p("exactly-60.bin"))
    touch("exactly-60.bin")
    with open(p("medium.bin"), "ab") as f:
        f.write(rng.randbytes(10_000))
    touch("medium.bin")
else:
    sys.exit(f"unknown batch {batch}")

try:
    with open(touched_file) as f:
        touched |= set(json.load(f))
except FileNotFoundError:
    pass
with open(touched_file, "w") as f:
    json.dump(sorted(touched), f)
