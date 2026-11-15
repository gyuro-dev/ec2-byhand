#!/usr/bin/env bash
# Build "EBS snapshot of a running server" images: point-in-time copies of
# a mounted filesystem whose journal/log may still hold changes that have
# not been written back to their final place.
#
# Run inside WSL (or any Linux) as root:
#   wsl -u root -- bash tools/golden/build_dirty.sh tests/golden/out [CASE...]
#
# Per case:
#   1. mkfs, populate the baseline tree (fs_populate.py), unmount cleanly
#   2. mount through a device-mapper linear device, make "synced" changes,
#      sync, make "unsynced" changes (fs_recent.py records touched paths)
#   3. wait DELAY seconds, letting the kernel commit/write back on its own
#      (frozen-* cases: fsfreeze first, as AWS recommends for consistency)
#   4. snapshot: suspend the dm device (I/O held, filesystem not asked to
#      flush), copy the image, resume. Like an EBS snapshot, the copy holds
#      exactly the writes that had reached the device -> <case>.img
#   5. on a copy, let the kernel replay the journal/log and dump what it
#      sees -> <case>.json (the view a perfect reader would produce)
# Needs: e2fsprogs, xfsprogs, dmsetup, Docker for the docker:* cases.
set -euo pipefail

out=$(realpath -m "${1:?usage: build_dirty.sh OUTDIR [CASE...]}")
shift
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
work=$(mktemp -d)
mnt="$work/mnt"
mkdir -p "$mnt"
dm=ec2byhand-snap
loop=
cleanup() {
    dmsetup resume "$dm" 2> /dev/null || true
    umount "$mnt" 2> /dev/null || true
    dmsetup remove "$dm" 2> /dev/null || true
    [ -n "$loop" ] && losetup -d "$loop" 2> /dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

declare -A MKFS DELAY
MKFS[dirty-ext4-0s]="mkfs.ext4 -q -F";               DELAY[dirty-ext4-0s]=0
MKFS[dirty-ext4-7s]="mkfs.ext4 -q -F";               DELAY[dirty-ext4-7s]=7
MKFS[dirty-ext4-40s]="mkfs.ext4 -q -F";              DELAY[dirty-ext4-40s]=40
MKFS[dirty-xfs-0s]="docker:al2023 mkfs.xfs -q -f";   DELAY[dirty-xfs-0s]=0
MKFS[dirty-xfs-7s]="docker:al2023 mkfs.xfs -q -f";   DELAY[dirty-xfs-7s]=7
MKFS[dirty-xfs-40s]="docker:al2023 mkfs.xfs -q -f";  DELAY[dirty-xfs-40s]=40
# fsfreeze right before the snapshot, as recommended for consistent EBS
# snapshots: the filesystem should then look cleanly unmounted.
MKFS[frozen-ext4]="mkfs.ext4 -q -F";                 DELAY[frozen-ext4]=0
MKFS[frozen-xfs]="docker:al2023 mkfs.xfs -q -f";     DELAY[frozen-xfs]=0
# A log that has wrapped around several times (churn writes ~10x its size),
# so the ring holds two cycles: what log_state's head search must handle on
# any long-running server. 16 MiB is larger than the search window. The
# -clean case is unmounted before the copy instead of snapshotted.
MKFS[wrapped-xfs-0s]="docker:al2023 mkfs.xfs -q -f -l size=16m";     DELAY[wrapped-xfs-0s]=0
MKFS[wrapped-xfs-frozen]="docker:al2023 mkfs.xfs -q -f -l size=16m"; DELAY[wrapped-xfs-frozen]=0
MKFS[wrapped-xfs-clean]="docker:al2023 mkfs.xfs -q -f -l size=16m";  DELAY[wrapped-xfs-clean]=0

cases=("$@")
if [ ${#cases[@]} -eq 0 ]; then
    mapfile -t cases < <(printf '%s\n' "${!MKFS[@]}" | sort)
fi

for name in "${cases[@]}"; do
    img="$work/$name.img"
    rm -f "$img" "$work/touched.json"
    size=128M
    [[ $name == wrapped-* ]] && size=512M
    truncate -s "$size" "$img"
    mkfs=${MKFS[$name]}
    if [[ $mkfs == docker:* ]]; then
        tag=${mkfs%% *}
        bash "$here/docker_mkfs.sh" "${tag#docker:}" "$img" ${mkfs#* } > /dev/null
    else
        $mkfs "$img" > /dev/null
    fi

    mount -o loop "$img" "$mnt"
    python3 "$here/fs_populate.py" "$mnt"
    umount "$mnt"

    loop=$(losetup -f --show "$img")
    dmsetup create "$dm" --table "0 $(blockdev --getsz "$loop") linear $loop 0"
    mount "/dev/mapper/$dm" "$mnt"
    if [[ $name == wrapped-* ]]; then
        python3 - "$mnt/churn" <<'PY'
import os, sys
d = sys.argv[1]
os.mkdir(d)
for i in range(60000):
    p = f"{d}/f{i % 64}"
    with open(p, "wb") as f:
        f.write(b"x" * 100)
        os.fsync(f.fileno())
    os.unlink(p)
os.rmdir(d)
PY
    fi
    python3 "$here/fs_recent.py" "$mnt" synced "$work/touched.json"
    sync
    python3 "$here/fs_recent.py" "$mnt" unsynced "$work/touched.json"
    sleep "${DELAY[$name]}"

    if [[ $name == *-clean ]]; then
        umount "$mnt"
        cp "$img" "$out/$name.img"
    else
        if [[ $name == *frozen* ]]; then fsfreeze -f "$mnt"; fi
        dmsetup suspend --nolockfs "$dm"
        cp "$img" "$out/$name.img"
        dmsetup resume "$dm"
        if [[ $name == *frozen* ]]; then fsfreeze -u "$mnt"; fi
        umount "$mnt"
    fi
    dmsetup remove "$dm"
    losetup -d "$loop"
    loop=

    # Let the kernel recover a copy of the snapshot, then record what it sees.
    cp "$out/$name.img" "$work/replay.img"
    mount -o loop "$work/replay.img" "$mnt"
    umount "$mnt"
    mount -o loop,ro "$work/replay.img" "$mnt"
    python3 "$here/fs_dump.py" "$mnt" > "$work/files.json"
    umount "$mnt"

    python3 - "$name" "$mkfs" "${DELAY[$name]}" "$work/touched.json" "$work/files.json" > "$out/$name.json" <<'PY'
import json, sys
name, mkfs, delay, touched, files = sys.argv[1:]
json.dump({
    "image": name + ".img",
    "mkfs": mkfs,
    "delay_seconds": int(delay),
    "touched": json.load(open(touched)),
    **json.load(open(files)),
}, sys.stdout, indent=1)
PY
    echo "built $name"
done
