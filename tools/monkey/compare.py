"""Compare an ec2-byhand manifest with the monkey test's truth.
usage: compare.py TRUTH_DIR MANIFEST

Every change of the truth that the noise rules do not hide must be reported somewhere:
  - a file of a package that was added, removed or upgraded: by packages.changes
  - a file of a package left as it was: in modified_package_files, since_baseline
  - a file of a language package (pip, npm), the directories made for it and the
    commands linked for it: by language_packages
  - a link under /etc/systemd/system: by services
  - anything else: in hand_placed (added / modified) or deleted (or below a deleted dir)
And everything reported in hand_placed, deleted and modified_package_files (since the
baseline) must be a change of the truth. Prints what is missed and what is extra.

Not compared by ec2-byhand, and counted apart here: the mtime alone, and the SELinux
label of a package's file. A directory systemd made as it is told is counted by
ec2-byhand without its name: such are printed as UNSURE."""

from __future__ import annotations

import json
import posixpath
import stat
import sys
from collections import Counter, defaultdict
from pathlib import Path

from diskread.fs import FileType
from ec2_byhand.noise import NoiseFilter

TYPES = {
    stat.S_IFREG: FileType.REG,
    stat.S_IFDIR: FileType.DIR,
    stat.S_IFLNK: FileType.LNK,
    stat.S_IFIFO: FileType.FIFO,
    stat.S_IFSOCK: FileType.SOCK,
    stat.S_IFCHR: FileType.CHR,
    stat.S_IFBLK: FileType.BLK,
}

d = Path(sys.argv[1])
truth = json.loads((d / "truth.json").read_text(encoding="utf-8"))
s1 = json.loads((d / "state1.json").read_text(encoding="utf-8"))
s2 = json.loads((d / "state2.json").read_text(encoding="utf-8"))
l1 = json.loads((d / "lists1.json").read_text(encoding="utf-8"))
l2 = json.loads((d / "lists2.json").read_text(encoding="utf-8"))
m = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
noise = NoiseFilter().with_baseline()


def owners(text):
    out = {}
    for line in text.splitlines():
        path, _, name = line.partition("\t")
        if path.startswith("/"):
            out.setdefault(path, name)
    return out


def versions(lines):
    return dict(x.split(" ", 1) for x in lines if x)


_own = json.loads((d / "owners.json").read_text(encoding="utf-8"))
own1, own2 = _own["before"], _own["after"]  # from the snapshots' rpm databases
v1, v2 = versions(l1["packages"]), versions(l2["packages"])
changed_pkgs = {n for n in v1.keys() | v2.keys() if v1.get(n) != v2.get(n)}
reported_pkgs = {c["name"] for c in m["packages"]["changes"]}


def exact(item):
    """The item's path as the disk has it (the manifest escapes what is not UTF-8)."""
    if "path_hex" in item:
        return bytes.fromhex(item["path_hex"]).decode("utf-8", "surrogateescape")
    return item["path"]


hand = {exact(h): h for h in m["hand_placed"]}
for key in ("package_scripts", "cloud_init"):
    for group in m.get(key, []):
        for f in group["files"]:
            hand[exact(f)] = f
deleted = [exact(x) for x in m["deleted"]]
mpf = {exact(x): x for x in m["modified_package_files"]}
services = {x["path"] for x in m["services"]}
lang = m["language_packages"]


def ftype(p):
    e = s2.get(p) or s1.get(p)
    return TYPES.get(e["t"]) if e else None


def under_deleted(p):
    return any(p == x or p.startswith(x.rstrip("/") + "/") for x in deleted)


def in_lang(p):
    for lp in lang:
        loc = lp["location"]
        if p.startswith(loc + "/"):
            return True
    return False


def holds_only_lang(p):
    """A directory made for language packages and holding nothing else that changed:
    ~/.local/lib/python3.9/site-packages and the directories above it, which ec2-byhand
    reports with the packages, not one by one."""
    below = [q for q in everything if q.startswith(p + "/")]
    return bool(below) and all(
        in_lang(q) or any(lp["location"].startswith(q + "/") or lp["location"] == q for lp in lang)
        for q in below
    )


def physical(path, state):
    """`path` with the links among its directories followed, as `state` recorded them:
    on AL2023 /usr/lib/node_modules is a link (to what alternatives chose)."""
    for _ in range(40):  # a loop of links ends here
        parts = path.split("/")
        for n in range(2, len(parts)):
            prefix = "/".join(parts[:n])
            e = state.get(prefix)
            if e and "l" in e:
                target = posixpath.join(posixpath.dirname(prefix), e["l"])
                path = posixpath.normpath(posixpath.join(target, *parts[n:]))
                break
        else:
            return path
    return path


def link_into_lang(p):
    """A command npm links for a package: /usr/local/bin/cowthink -> ../lib/node_modules/..."""
    state = s2 if p in s2 else s1
    e = state.get(p)
    if not e or "l" not in e:
        return False
    target = posixpath.normpath(posixpath.join(posixpath.dirname(p), e["l"]))
    return in_lang(physical(target, state))


def console_script(p):
    """pip's and npm's commands, which their packages list: bin/pip3.9 for pip."""
    name = posixpath.basename(p)
    return posixpath.dirname(p).endswith("/bin") and any(
        x["status"] in ("added", "removed") and name.startswith(x["name"]) for x in lang
    )


everything = set(truth["added"]) | set(truth["removed"])
service_dirs = m["noise"]["by_rule"].get("service-directories", 0)
unsure = []  # added directories that may be among those service directories
missed = defaultdict(list)
explained = Counter()
for kind, paths in (
    ("added", truth["added"]),
    ("removed", truth["removed"]),
    ("changed", list(truth["changed"])),
):
    for p in paths:
        fields = truth["changed"].get(p, [])
        if kind == "changed" and set(fields) <= {"mt"}:
            explained["mtime-only (not compared)"] += 1
            continue
        rule = noise.match(p, ftype(p))
        if rule:
            explained[f"noise:{rule}"] += 1
            continue
        pkg = own2.get(p) or own1.get(p)
        if pkg is not None and pkg in changed_pkgs:
            if pkg in reported_pkgs:
                explained["package change"] += 1
            else:
                missed["package change not reported"].append(f"{p} ({pkg})")
            continue
        if pkg is not None and kind == "changed" and set(fields) <= {"se", "mt"}:
            # ec2-byhand compares labels and other extended attributes of hand-placed
            # paths only: a package's own scripts relabel its files.
            explained["label of a package file (not compared)"] += 1
            continue
        if pkg is not None:
            x = mpf.get(p)
            if x and x["since_baseline"]:
                explained["modified package file"] += 1
            elif kind == "added" and p in hand:
                explained["package path, hand-placed"] += 1
            else:
                missed[f"package file {kind} {fields}"].append(f"{p} ({pkg})")
            continue
        if in_lang(p) and p not in hand:
            explained["language package"] += 1  # also one put elsewhere: pip --target
            continue
        if any(d in p for d in ("/site-packages/", "/dist-packages/", "/node_modules/")):
            if in_lang(p) or p in hand:
                explained["language package"] += 1
            else:
                missed[f"language file {kind}"].append(p)
            continue
        if p in services or (p.startswith("/etc/systemd/system/") and p.endswith(".wants")):
            explained["service"] += 1  # a .wants directory goes with the links in it
            continue
        if p not in hand and (console_script(p) or holds_only_lang(p) or link_into_lang(p)):
            explained["language package"] += 1  # listed by the package, or made for it
            continue
        if kind == "removed":
            if under_deleted(p):
                explained["deleted"] += 1
            else:
                missed["removed, not in deleted"].append(p)
        elif p in hand:
            explained["hand_placed"] += 1
        elif kind == "added" and ftype(p) is FileType.DIR and service_dirs:
            # ec2-byhand counts these without naming them, so they cannot be told apart
            # here: a directory systemd made as a unit's StateDirectory= says.
            unsure.append(p)
        elif posixpath.dirname(p) and p.startswith("/etc/systemd/system/"):
            missed["systemd path not in services"].append(p)
        else:
            missed[f"{kind} {fields}, not in hand_placed"].append(p)

# A removed directory that held nothing but what is explained went with it: pip removes
# /usr/local/bin when its console script was the last thing there (Ubuntu, 2026-11-14).
gone = missed.get("removed, not in deleted", [])
still = {q for items in missed.values() for q in items}
for p in list(gone):
    below = [q for q in truth["removed"] if q.startswith(p.rstrip("/") + "/")]
    if below and not any(q in still for q in below):
        gone.remove(p)
        explained["directory emptied of what is explained"] += 1
if not gone:
    missed.pop("removed, not in deleted", None)

changes = set(truth["added"]) | set(truth["removed"]) | set(truth["changed"])
extra = defaultdict(list)
for p, h in hand.items():
    if p not in changes:
        extra[f"hand_placed {h.get('status')}"].append(p)
for p in deleted:
    if not any(x == p or x.startswith(p.rstrip("/") + "/") for x in truth["removed"]):
        extra["deleted"].append(p)
for p, x in mpf.items():
    if x["since_baseline"] and p not in changes:
        extra[f"modified_package_files {x['problems']}"].append(p)

print("explained:", dict(explained.most_common()))
print(
    "truth changes:",
    len(changes),
    "reported:",
    len(hand),
    "hand,",
    len(deleted),
    "deleted,",
    sum(1 for x in mpf.values() if x["since_baseline"]),
    "package files since baseline",
)
for title, group in (("MISSED", missed), ("EXTRA", extra)):
    n = sum(len(v) for v in group.values())
    print(f"\n{title}: {n}")
    for reason, items in sorted(group.items(), key=lambda kv: -len(kv[1])):
        print(f"  {len(items):5}  {reason}")
        for p in items[:12]:
            print(f"           {p.encode('unicode_escape').decode()}")

if unsure:
    print(f"\nUNSURE: {len(unsure)} added directories not reported one by one, with")
    print(f"  {service_dirs} counted as noise under service-directories (made by systemd)")
    for p in unsure[:12]:
        print(f"           {p.encode('unicode_escape').decode()}")

c = m.get("containers") or {}
print("\ncontainers:", json.dumps(c, ensure_ascii=False)[:1500])
print(
    "docker before:", l1["images"].split("\n"), l1["containers"].split("\n"), l1["volumes"].split()
)
print(
    "docker after: ", l2["images"].split("\n"), l2["containers"].split("\n"), l2["volumes"].split()
)
print("packages changed (truth):", sorted(changed_pkgs))
print("packages changed (ec2-byhand):", sorted(reported_pkgs))
print("language packages:", [(x["name"], x["status"], x["modified"]) for x in lang])
print("services:", [(x["unit"], x["status"]) for x in m["services"]])
