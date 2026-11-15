#!/usr/bin/env bash
# Runs inside a chroot of the exported container tree (see build_verify.sh)
# and records the package manager's own verdicts:
#   verify.txt   rpm -Va / dpkg --verify output
#   unowned.txt  every path (find /) that no package owns
#
#   verify_chroot.sh WORKDIR    (WORKDIR is skipped by the scan)
#
# Ownership compares physical locations, like the kernel would resolve
# them: for each listed and each found path, the parent directory is
# resolved with readlink -f (so /bin/ls and /usr/bin/ls are the same file
# when /bin is a symlink to usr/bin) and the last component is kept.
set -uo pipefail
out=$1

canon() {
    while IFS= read -r p; do
        [ "$p" = "/" ] || [ "$p" = "/." ] && { echo "/"; continue; }
        d=$(dirname "$p"); b=$(basename "$p")
        r=$(readlink -f "$d" 2> /dev/null) || r=$d
        [ "$r" = "/" ] && echo "/$b" || echo "$r/$b"
    done
}

if command -v rpm > /dev/null && [ -d /var/lib/rpm ]; then
    rpm -Va > "$out/verify.txt" 2> /dev/null
    rpm -qa --qf '[%{FILENAMES}\n]' | canon | sort -u > "$out/owned"
else
    dpkg --verify > "$out/verify.txt" 2> /dev/null
    dpkg-query -W -f '${binary:Package}\n' | while read -r p; do dpkg-query -L "$p"; done \
        | grep '^/' | canon | sort -u > "$out/owned"
fi
find / -mindepth 1 -path "$out" -prune -o -print | canon | sort -u > "$out/all"
comm -23 "$out/all" "$out/owned" > "$out/unowned.txt"
echo "verify lines: $(wc -l < "$out/verify.txt"), unowned: $(wc -l < "$out/unowned.txt")"
