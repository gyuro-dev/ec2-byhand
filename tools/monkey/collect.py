"""Collect the monkey test's truth from its snapshots, over the EBS direct APIs.

usage: collect.py OUTDIR BEFORE_SNAPSHOT... AFTER_SNAPSHOT...   (as many of each)

Copies /var/tmp/monkey/{truth,ops,lists1,lists2,state1,state2}.json and log.txt out of
the "after" pair, and writes owners.json: which package owns each path on each side,
read from the snapshots' own rpm databases as physical paths (through /bin -> usr/bin).
Credentials and region come from the environment (AWS_PROFILE, AWS_REGION).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import boto3

from ec2_byhand.aws.ebs import EbsSnapshotDevice
from ec2_byhand.cli import open_disks
from ec2_byhand.packages import read_packages
from ec2_byhand.packages.verify import physical_path

FILES = ("truth.json", "ops.json", "lists1.json", "lists2.json", "state1.json", "state2.json")


def main() -> None:
    out = Path(sys.argv[1])
    ids = sys.argv[2:]
    sides = {"before": ids[: len(ids) // 2], "after": ids[len(ids) // 2 :]}
    client = boto3.Session().client("ebs")
    out.mkdir(parents=True, exist_ok=True)
    owners = {}
    for label, snapshots in sides.items():
        devices = {f"disk{i}": EbsSnapshotDevice(client, s) for i, s in enumerate(snapshots)}
        src = open_disks(devices, label).source
        db = read_packages(src)
        parents: dict[str, str] = {}
        owners[label] = {
            physical_path(src, f.path, parents): p.name for p in db.packages for f in p.files
        }
        print(label, len(db.packages), "packages", len(owners[label]), "paths")
        if label == "after":
            for name in (*FILES, "log.txt"):
                blob = src.read(f"/var/tmp/monkey/{name}")
                print(name, None if blob is None else len(blob))
                if blob is not None:
                    (out / name).write_bytes(blob)
    (out / "owners.json").write_text(json.dumps(owners), encoding="utf-8")


if __name__ == "__main__":
    main()
