"""Compare a diskread Filesystem against the kernel's view from fs_dump.py."""

from __future__ import annotations

import hashlib

from diskread.fs import Filesystem, FileType, walk


def _decode(b: bytes) -> str:
    # Match fs_dump.py on Linux; os.fsdecode is strict on Windows.
    return b.decode("utf-8", "surrogateescape")


FIELDS = (
    "ino",
    "mode",
    "uid",
    "gid",
    "size",
    "nlink",
    "blocks",
    "atime_ns",
    "mtime_ns",
    "ctime_ns",
    "btime_ns",
)


def _sha256(fs: Filesystem, ino: int) -> str:
    dev = fs.open(ino)
    h = hashlib.sha256()
    chunk = 1 << 20
    for off in range(0, dev.size, chunk):
        h.update(dev.read_at(off, min(chunk, dev.size - off)))
    return h.hexdigest()


def actual_entries(fs: Filesystem, on_error=None) -> dict[str, dict]:
    out = {}
    for path, ino, st in walk(fs, on_error):
        e = {f: getattr(st, f) for f in FIELDS}
        e["type"] = str(st.type)
        e["rdev"] = list(st.rdev) if st.rdev else None
        e["target"] = _decode(fs.readlink(ino)) if st.type is FileType.LNK else None
        e["sha256"] = _sha256(fs, ino) if st.type is FileType.REG else None
        e["xattrs"] = {k: v.hex() for k, v in fs.xattrs(ino).items()}
        out[_decode(path)] = e
    return out


def differences(fs: Filesystem, expected_files: list[dict], limit: int = 30) -> list[str]:
    expected = {e["path"]: e for e in expected_files}
    actual = actual_entries(fs)
    diffs = [f"missing: {path!r}" for path in sorted(set(expected) - set(actual))]
    diffs.extend(f"unexpected: {path!r}" for path in sorted(set(actual) - set(expected)))
    for path in sorted(set(expected) & set(actual)):
        exp, got = expected[path], actual[path]
        diffs.extend(
            f"{path!r} {key}: expected {exp[key]!r}, got {got[key]!r}"
            for key in ("type", *FIELDS, "rdev", "target", "sha256", "xattrs")
            if exp[key] != got[key]
        )
    return diffs[:limit] + ([f"... and {len(diffs) - limit} more"] if len(diffs) > limit else [])
