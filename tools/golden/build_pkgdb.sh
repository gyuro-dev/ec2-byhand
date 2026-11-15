#!/usr/bin/env bash
# Build package-database golden data in distribution containers.
#
# Run inside WSL (or any Linux with Docker):
#   wsl -u root -- bash tools/golden/build_pkgdb.sh tests/golden/out [CASE...]
#
# Each case writes tests/golden/out/pkgdb-<case>/{before,after}/ with the
# package database files as they sit on disk and expected.tsv from rpm or
# dpkg-query, plus scenario.txt naming the packages that were upgraded,
# downgraded, removed and added (pkgdb_inside.sh).
set -euo pipefail

out=$(realpath -m "${1:?usage: build_pkgdb.sh OUTDIR [CASE...]}")
shift
here=$(cd "$(dirname "$0")" && pwd)

declare -A IMAGE=(
    [al2023]=amazonlinux:2023   # rpm 4.16, SQLite rpmdb
    [al2]=amazonlinux:2         # rpm 4.11, Berkeley DB rpmdb
    [el8]=almalinux:8           # rpm 4.14, Berkeley DB rpmdb
    [el9]=almalinux:9           # rpm 4.16, SQLite rpmdb
    [ubuntu2404]=ubuntu:24.04   # dpkg
)
cases=("$@")
if [ ${#cases[@]} -eq 0 ]; then
    mapfile -t cases < <(printf '%s\n' "${!IMAGE[@]}" | sort)
fi

for name in "${cases[@]}"; do
    dest="$out/pkgdb-$name"
    rm -rf "$dest"
    mkdir -p "$dest"
    docker run --rm -v "$here:/tools:ro" -v "$dest:/out" "${IMAGE[$name]}" \
        bash /tools/pkgdb_inside.sh /out
    echo "built pkgdb-$name"
done
