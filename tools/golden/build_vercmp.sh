#!/usr/bin/env bash
# Have rpm and dpkg themselves compare version pairs (ground truth for the
# version comparison in ec2_byhand.packages).
#
# Run inside WSL (or any Linux with Docker), after build_pkgdb.sh:
#   wsl -u root -- bash tools/golden/build_vercmp.sh tests/golden/out
#
# Writes OUTDIR/vercmp/{rpm,dpkg}.tsv: "A<TAB>B<TAB>-1|0|1".
# rpm: rpm.labelCompare in Amazon Linux 2023 (rpm 4.16, with ~ and ^).
# dpkg: dpkg --compare-versions in Ubuntu 24.04.
set -euo pipefail

out=$(realpath -m "${1:?usage: build_vercmp.sh OUTDIR}")
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out/vercmp"
python3 "$here/vercmp_pairs.py" "$out" > /dev/null
mv "$out/rpm-pairs.tsv" "$out/dpkg-pairs.tsv" "$out/vercmp/"

docker run --rm -i -v "$out/vercmp:/v" amazonlinux:2023 python3 - <<'PY'
import rpm

def evr(s):
    epoch, _, rest = s.rpartition(":") if ":" in s else ("", "", s)
    version, _, release = rest.partition("-")
    return (epoch or None, version, release or None)

with open("/v/rpm-pairs.tsv") as f, open("/v/rpm.tsv", "w") as out:
    for line in f:
        a, b = line.rstrip("\n").split("\t")
        try:
            r = rpm.labelCompare(evr(a), evr(b))
        except ValueError:  # rpm rejects it (e.g. an empty version)
            continue
        out.write(f"{a}\t{b}\t{r}\n")
PY

docker run --rm -v "$out/vercmp:/v" ubuntu:24.04 bash -c '
while IFS=$(printf "\t") read -r a b; do
    if dpkg --compare-versions "$a" lt "$b" 2> /dev/null; then r=-1
    elif dpkg --compare-versions "$a" eq "$b" 2> /dev/null; then r=0
    elif dpkg --compare-versions "$a" gt "$b" 2> /dev/null; then r=1
    else continue  # invalid version for dpkg
    fi
    printf "%s\t%s\t%s\n" "$a" "$b" "$r"
done < /v/dpkg-pairs.tsv > /v/dpkg.tsv'
rm "$out/vercmp/rpm-pairs.tsv" "$out/vercmp/dpkg-pairs.tsv"
wc -l "$out/vercmp/rpm.tsv" "$out/vercmp/dpkg.tsv"
