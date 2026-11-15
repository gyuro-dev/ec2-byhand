"""Do the contents ec2-byhand wrote match what the server really held?
usage: contents.py TRUTH_DIR OUTPUT_DIR   (OUTPUT_DIR: manifest.json, the archives, patches/)

compare.py and fields.py check which paths are reported; this checks what was taken out:
  - every entry of after.tar.gz against the tree recorded on the instance after the
    changes (state2.json: sha256, type, mode, owner, link target), and every entry of
    before.tar.gz against the tree recorded before them (state1.json)
  - every sha256 and size the manifest gives for a hand-placed file, against state2
  - every patch, applied with patch(1) to the file of before.tar.gz: it must give the
    file of after.tar.gz
A file with values masked differs from the server's on purpose and is counted apart.
Exits 1 if anything does not match."""

from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import sys
import tarfile
import tempfile
from collections import Counter
from pathlib import Path

truth, out = Path(sys.argv[1]), Path(sys.argv[2])
states = {
    "after": json.loads((truth / "state2.json").read_text(encoding="utf-8")),
    "before": json.loads((truth / "state1.json").read_text(encoding="utf-8")),
}
m = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
masked = {(x["archive"], x["path"]) for x in m["archives"].get("masked", [])}
bad = 0


def open_tar(name):
    return tarfile.open(out / f"{name}.tar.gz", encoding="utf-8", errors="surrogateescape")


def shown(path):
    return path.encode("unicode_escape").decode()


def mismatches(info, tar, e, is_masked):
    """How one tar entry differs from the recorded entry `e` of the same path."""
    found = []
    if stat.S_IMODE(info.mode) != e["m"]:
        found.append("mode")
    if (info.uid, info.gid) != (e["u"], e["g"]):
        found.append("owner")
    if info.isreg() or info.islnk():
        to_hash = info.isreg() and "h" in e and not is_masked  # a hard link has no data
        if not stat.S_ISREG(e["t"]):
            found.append("type")
        elif to_hash and hashlib.sha256(tar.extractfile(info).read()).hexdigest() != e["h"]:
            found.append("content")
    elif info.issym():
        if not stat.S_ISLNK(e["t"]) or info.linkname != e.get("l"):
            found.append("link")
    elif info.isdir() and not stat.S_ISDIR(e["t"]):
        found.append("type")
    return found


for archive, state in states.items():
    if not (out / f"{archive}.tar.gz").exists():
        continue
    result, examples = Counter(), {}
    with open_tar(archive) as tar:
        for info in tar:
            path = "/" + info.name
            e = state.get(path)
            is_masked = (archive, path) in masked
            found = (
                ["not in the recorded tree"] if e is None else mismatches(info, tar, e, is_masked)
            )
            if found:
                key = "MISMATCH " + ",".join(found)
                examples.setdefault(key, path)
            else:
                key = "masked on purpose" if is_masked else "as on the server"
            result[key] += 1
    bad += sum(n for key, n in result.items() if key.startswith("MISMATCH"))
    print(f"{archive}.tar.gz:", dict(result))
    for key, path in examples.items():
        print("   e.g.", key, "->", shown(path))

result = Counter()
for h in m["hand_placed"]:
    path = h["path"]
    if "path_hex" in h:
        path = bytes.fromhex(h["path_hex"]).decode("utf-8", "surrogateescape")
    e = states["after"].get(path)
    if e is None:
        result["MISMATCH not in the recorded tree"] += 1
    elif "sha256" in h:
        result["sha256 as recorded" if h["sha256"] == e.get("h") else "MISMATCH sha256"] += 1
    if e is not None and h["type"] == "reg" and h["size"] != e.get("s"):
        result["MISMATCH size"] += 1
bad += sum(n for key, n in result.items() if key.startswith("MISMATCH"))
print("manifest hand_placed:", dict(result))

result = Counter()
diffs = sorted((out / "patches").rglob("*.diff"))
if diffs and (out / "before.tar.gz").exists():
    with (
        tempfile.TemporaryDirectory() as tmp,
        open_tar("before") as before,
        open_tar("after") as after,
    ):
        target = Path(tmp) / "file"
        for diff in diffs:
            text = diff.read_bytes()
            name = text.split(b"\n", 1)[0][len(b"--- a/") :].decode()
            try:
                old, new = before.extractfile(name).read(), after.extractfile(name).read()
            except (KeyError, AttributeError):
                result["MISMATCH no pair of regular files in the archives"] += 1
                print("   no pair:", shown(name))
                continue
            target.write_bytes(old)
            done = subprocess.run(
                ["patch", "-s", "--binary", str(target)],
                input=text,
                capture_output=True,
                check=False,
            )
            if done.returncode:
                result["MISMATCH patch(1) refuses it"] += 1
                print("   refused:", shown(name))
            elif target.read_bytes() != new:
                result["MISMATCH applies but gives another file"] += 1
                print("   differs:", shown(name))
            else:
                result["applies and gives the current file"] += 1
bad += sum(n for key, n in result.items() if key.startswith("MISMATCH"))
print("patches:", dict(result))
sys.exit(1 if bad else 0)
