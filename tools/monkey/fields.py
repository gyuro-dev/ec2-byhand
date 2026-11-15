"""For hand-placed files ec2-byhand calls modified: do its `changed` fields match the truth?
And for added ones: are type, mode, owner and sha256 what the truth recorded?
usage: fields.py TRUTH_DIR MANIFEST"""

from __future__ import annotations

import json
import stat
import sys
from collections import Counter
from pathlib import Path

d = Path(sys.argv[1])
truth = json.loads((d / "truth.json").read_text(encoding="utf-8"))
s2 = json.loads((d / "state2.json").read_text(encoding="utf-8"))
m = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
NAMES = {
    "h": "sha256",
    "s": "size",
    "m": "mode",
    "u": "uid",
    "g": "gid",
    "l": "target",
    "t": "type",
    "r": "rdev",
    "mt": "mtime",
    "x": "xattrs",
    "se": "selinux",
}
TYPES = {stat.S_IFREG: "reg", stat.S_IFDIR: "dir", stat.S_IFLNK: "lnk", stat.S_IFIFO: "fifo"}

bad = Counter()
examples = {}
for h in m["hand_placed"]:
    p = h["path"]
    if "path_hex" in h:  # the name as the disk has it
        p = bytes.fromhex(h["path_hex"]).decode("utf-8", "surrogateescape")
    e = s2.get(p)
    if h["status"] == "modified":
        want = {NAMES[f] for f in truth["changed"].get(p, [])}
        if "sha256" in want and "size" in want:
            want.discard("sha256")  # a different size needs no read: reported as a size change
        got = set(h.get("changed", []))
        if "sha256" in got and "size" in want:
            got.discard("sha256")
        if got != want:
            key = f"modified: truth {sorted(want)} vs ec2-byhand {sorted(got)}"
            bad[key] += 1
            examples.setdefault(key, p)
    if e is None:
        bad["not in state2"] += 1
        continue
    if TYPES.get(e["t"]) != h["type"]:
        bad[f"type {TYPES.get(e['t'])} vs {h['type']}"] += 1
    if f"{e['m']:04o}" != h["mode"]:
        bad["mode"] += 1
        examples.setdefault("mode", p)
    if (e["u"], e["g"]) != (h["uid"], h["gid"]):
        bad["owner"] += 1
        examples.setdefault("owner", p)
    if e.get("h") and h.get("sha256") and e["h"] != h["sha256"]:
        bad["sha256"] += 1
        examples.setdefault("sha256", p)
    if e.get("l") is not None and e["l"] != h.get("target"):
        bad["target"] += 1
        examples.setdefault("target", p)
print("hand_placed checked:", len(m["hand_placed"]), "mismatches:", dict(bad) or "none")
for k, p in examples.items():
    print("  e.g.", k, "->", p.encode("unicode_escape").decode())
print("statuses:", Counter(h["status"] for h in m["hand_placed"]))
print("skipped from archives:", Counter(s["reason"] for s in m["archives"]["skipped"]))
print("warnings:", [w["code"] for w in m["warnings"]])
