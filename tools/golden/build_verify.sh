#!/usr/bin/env bash
# Build "hand-modified server" images with the package manager's verdicts,
# plus the same server's earlier "AMI" state as a baseline.
#
# Run inside WSL (or any Linux with Docker) as root:
#   wsl -u root -- bash tools/golden/build_verify.sh tests/golden/out [CASE...]
#
# Per case, in one container (so Docker's own files are the same in both):
#   verify_inside.sh pre  -> export the tree -> verify-<case>-before.img
#   verify_inside.sh post -> export the tree -> verify-<case>.img
# and, in a chroot of the post tree, verify_chroot.sh records rpm -Va /
# dpkg --verify and the unowned files. Trees become ext4 images with
# mkfs.ext4 -d. verify-<case>/ holds verify.txt, unowned.txt, scenario.txt.
set -euo pipefail

out=$(realpath -m "${1:?usage: build_verify.sh OUTDIR [CASE...]}")
shift
here=$(cd "$(dirname "$0")" && pwd)
declare -A IMAGE=(
    [al2023]=amazonlinux:2023   # SQLite rpmdb
    [el8]=almalinux:8           # Berkeley DB rpmdb, merged /usr
    [ubuntu2404]=ubuntu:24.04   # dpkg
)
cases=("$@")
if [ ${#cases[@]} -eq 0 ]; then
    mapfile -t cases < <(printf '%s\n' "${!IMAGE[@]}" | sort)
fi
work=$(mktemp -d)
trap 'docker rm -f ec2byhand-verify > /dev/null 2>&1 || true; rm -rf "$work"' EXIT

# export_tree DIR: the container's filesystem, owners and xattrs preserved
export_tree() {
    rm -rf "$1"
    mkdir -p "$1"
    docker export ec2byhand-verify | tar -x -p --numeric-owner --xattrs -C "$1"
}

# make_image DIR IMAGE: an ext4 image holding exactly DIR
make_image() {
    local used
    used=$(du -sm "$1" | cut -f1)
    rm -f "$work/tmp.img"
    truncate -s "$((used * 3 / 2 + 64))M" "$work/tmp.img"
    mkfs.ext4 -q -F -d "$1" "$work/tmp.img"
    cp --sparse=always "$work/tmp.img" "$2"
    echo "  $(basename "$2"): ${used} MB tree"
}

for name in "${cases[@]}"; do
    dest="$out/verify-$name"
    rm -rf "$dest"
    mkdir -p "$dest"
    docker rm -f ec2byhand-verify > /dev/null 2>&1 || true
    docker run -d --name ec2byhand-verify -v "$here:/tools:ro" "${IMAGE[$name]}" sleep infinity > /dev/null

    docker exec ec2byhand-verify bash /tools/verify_inside.sh pre
    export_tree "$work/before"
    docker exec ec2byhand-verify bash /tools/verify_inside.sh post > "$dest/scenario.txt"
    # Real ctimes: docker export / tar / mkfs.ext4 -d keep mtime but reset ctime,
    # and ctime is what tells install-script output from hand work.
    docker exec ec2byhand-verify sh -c "find / -xdev -printf '%C@\t%p\n' > /.ctimes"
    docker stop -t 0 ec2byhand-verify > /dev/null
    export_tree "$work/root"
    mv "$work/root/.ctimes" "$work/ctimes.tsv"
    docker rm -f ec2byhand-verify > /dev/null

    # Work files live in /.golden, which the scan skips and which is removed
    # before the image is made.
    mkdir "$work/root/.golden"
    cp "$here/verify_chroot.sh" "$work/root/.golden/"
    # Nothing is mounted on /dev in the chroot: where the tree has no /dev/null (it
    # depends on the Docker that exported it), the script's "2> /dev/null" makes a
    # regular file, which is not part of the scenario: out of the tree and of the list.
    had_null=0
    if [ -e "$work/root/dev/null" ]; then had_null=1; fi
    chroot "$work/root" bash /.golden/verify_chroot.sh /.golden
    if [ "$had_null" = 0 ]; then
        rm -f "$work/root/dev/null"
        sed -i '/^\/dev\/null$/d' "$work/root/.golden/unowned.txt"
    fi
    mv "$work/root/.golden/verify.txt" "$work/root/.golden/unowned.txt" "$dest/"
    rm -rf "$work/root/.golden"
    # mkfs.ext4 -d adds /lost+found, which no package owns either.
    { cat "$dest/unowned.txt"; echo /lost+found; } | sort -u > "$work/unowned.sorted"
    mv "$work/unowned.sorted" "$dest/unowned.txt"

    make_image "$work/before" "$out/verify-$name-before.img"
    make_image "$work/root" "$out/verify-$name.img"
    # Put the real ctimes back on the unowned paths (the ones whose origin matters).
    python3 - "$work/ctimes.tsv" "$dest/unowned.txt" > "$work/debugfs.cmds" <<'PY'
import sys
ctimes = {}
for line in open(sys.argv[1], encoding="utf-8", errors="surrogateescape"):
    t, _, p = line.rstrip("\n").partition("\t")
    ctimes[p] = int(float(t))
for p in open(sys.argv[2], encoding="utf-8", errors="surrogateescape").read().splitlines():
    if p in ctimes and '"' not in p:
        print(f'set_inode_field "{p}" ctime @{ctimes[p]}')
PY
    debugfs -w -f "$work/debugfs.cmds" "$out/verify-$name.img" > /dev/null 2>&1
    echo "  restored ctime on $(wc -l < "$work/debugfs.cmds") unowned paths"
    echo "built verify-$name"
done
