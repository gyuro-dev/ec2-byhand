"""Write version pairs for build_vercmp.sh to have rpm and dpkg judge.

    python3 vercmp_pairs.py OUTDIR

OUTDIR/rpm-pairs.tsv and OUTDIR/dpkg-pairs.tsv hold one "A<TAB>B" pair per
line: every real version found in the pkgdb-* golden data paired with its
neighbours, plus hand-picked edge cases of each algorithm.
"""

from __future__ import annotations

import itertools
import random
import sys
from pathlib import Path

out = Path(sys.argv[1])
rng = random.Random(1)

RPM_EDGE = [
    "1.0",
    "1.0.0",
    "1.0a",
    "1.0.a",
    "1.0~rc1",
    "1.0~rc2",
    "1.0~rc1~git1",
    "1.0^",
    "1.0^git1",
    "1.0^git2",
    "1.01",
    "1.0.1",
    "1.0~rc1^git1",
    "2.0.1a",
    "5.5p1",
    "5.5p2",
    "5.5p10",
    "10xyz",
    "10.1xyz",
    "xyz10",
    "xyz10.1",
    "xyz.4",
    "8.0",
    "8.0.0",
    "a+",
    "a_",
    "+a",
    "_a",
    "1..0",
    "1.-0",
    "001",
    "1",
    "0",
    "",
    "a",
    "b",
    "aa",
    "1a",
    "1b",
    "a1",
    "1.1.1",
    "1_1",
    "2~",
    "2^",
    "1.2.3-r1",
    "1:1.0-1",
    "0:1.0-1",
    "2:0.1-1",
    "1.0-1.el8",
    "1.0-1.el8_10",
    "1.0-1.el8_9",
    "1.0-10.amzn2",
    "1.0-10.amzn2.0.1",
    "3.0.8-1.amzn2023",
    "3.0.8-1.amzn2023.0.1",
]
DPKG_EDGE = [
    "1.0",
    "1.0-0",
    "1.0-1",
    "1.0~rc1",
    "1.0~rc1-1",
    "1.0+git1",
    "1.0.0",
    "1.0a",
    "1.0~",
    "1.0~~",
    "1.0~~a",
    "1:0.9",
    "2.0",
    "0:2.0",
    "2.0-1ubuntu1",
    "2.0-1",
    "2.0-1ubuntu0.1",
    "2.0-1build1",
    "1.2.3+dfsg-1",
    "1.2.3+dfsg1-1",
    "1.2.3-1+deb12u1",
    "1.2.3-1~bpo12+1",
    "9",
    "10",
    "1.10",
    "1.9",
    "a",
    "A",
    "1a",
    "1A",
    "1.",
    "1+",
    "1-a",
    "2024a-2ubuntu1",
    "2024b-0ubuntu0.24.04",
    "0.60",
    "2026.10.12-0ubuntu0.24.04.1",
    "3.0-13ubuntu0.2",
    "6.0-28ubuntu4.1",
]


def evr_from_tsv(line: str) -> str:
    _name, epoch, version, release = line.split("\t")[:4]
    return (
        f"{epoch}:{version}-{release}" if epoch not in ("0", "(none)") else f"{version}-{release}"
    )


def real_versions(kind: str) -> list[str]:
    found: set[str] = set()
    for tsv in out.glob("pkgdb-*/*/expected.tsv"):
        rpm_case = (tsv.parent / "rpm").exists()
        if (kind == "rpm") != rpm_case:
            continue
        for line in tsv.read_text().splitlines():
            if not line.strip():
                continue
            found.add(evr_from_tsv(line) if kind == "rpm" else line.split("\t")[2])
    return sorted(found)


def pairs(versions: list[str], edge: list[str]) -> list[tuple[str, str]]:
    out_pairs = set(itertools.product(edge, edge))
    vs = sorted(set(versions))
    if not vs:
        sys.exit("no versions found: run build_pkgdb.sh first (its package lists are read here)")
    for a, b in itertools.pairwise(vs):  # neighbours in sorted order: close calls
        out_pairs.add((a, b))
        out_pairs.add((b, a))
    for _ in range(1500):  # plus random far pairs
        out_pairs.add((rng.choice(vs), rng.choice(vs)))
    for v in vs[:300]:
        out_pairs.add((v, v))
    return sorted(p for p in out_pairs if "\t" not in p[0] + p[1])


for kind, edge in (("rpm", RPM_EDGE), ("dpkg", DPKG_EDGE)):
    ps = pairs(real_versions(kind), edge)
    if kind == "dpkg":
        ps = [p for p in ps if p[0] and p[1]]  # dpkg rejects empty versions
    (out / f"{kind}-pairs.tsv").write_text("".join(f"{a}\t{b}\n" for a, b in ps))
    print(f"{kind}: {len(ps)} pairs")
