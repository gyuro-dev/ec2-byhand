"""Dump dnf / yum transaction history as JSON using the package manager's
own Python API (the ground truth for ec2_byhand.packages.history).

Runs inside a container (see pkgdb_inside.sh): python3 for dnf 4, python2
for yum 3 on Amazon Linux 2. Output: a JSON list of transactions
  {"id", "begin", "end", "cmdline", "packages": [{"name", "arch", "evr", "action"}]}
"""

from __future__ import print_function

import json
import sys


def evr(e, v, r):
    e = str(e or "0")
    return ("%s:" % e if e not in ("0", "None") else "") + "%s-%s" % (v, r)


def dnf_history():
    import dnf

    base = dnf.Base()
    out = []
    for t in base.history.old():
        pkgs = []
        for p in t.packages():
            pkgs.append({"name": p.name, "arch": p.arch, "evr": evr(p.epoch, p.version, p.release),
                         "action": p.action_name})
        out.append({"id": t.tid, "begin": t.beg_timestamp, "end": t.end_timestamp,
                    "cmdline": t.cmdline, "packages": sorted(pkgs, key=lambda p: (p["name"], p["action"]))})
    return out


def yum_history():
    import yum

    yb = yum.YumBase()
    yb.preconf.init_plugins = False
    out = []
    for t in yb.history.old():
        pkgs = []
        for p in t.trans_data:
            pkgs.append({"name": p.name, "arch": p.arch, "evr": evr(p.epoch, p.version, p.release),
                         "action": p.state})
        out.append({"id": t.tid, "begin": t.beg_timestamp, "end": t.end_timestamp,
                    "cmdline": t.cmdline, "packages": sorted(pkgs, key=lambda p: (p["name"], p["action"]))})
    return out


try:
    data = dnf_history()
except ImportError:
    data = yum_history()
json.dump(sorted(data, key=lambda t: t["id"]), sys.stdout, indent=1)
