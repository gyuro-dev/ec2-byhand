#!/usr/bin/env bash
# Build FAT golden images and the kernel's view under several mount options.
#
# Run inside WSL (or any Linux) as root:
#   wsl -u root -- bash tools/golden/build_vfat.sh tests/golden/out
#
# FAT stores no owners, permissions or inode numbers: the kernel derives
# them from mount options. So each image is dumped once per option set and
# the JSON records the options, which the reader is given as well.
# Writes vfat-<fat>.img and vfat-<fat>-<options name>.json.
# Needs: dosfstools.
set -euo pipefail

out=$(realpath -m "${1:?usage: build_vfat.sh OUTDIR}")
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
work=$(mktemp -d)
mnt="$work/mnt"
mkdir -p "$mnt"
trap 'umount "$mnt" 2> /dev/null || true; rm -rf "$work"' EXIT

# image name -> size, mkfs command
declare -A SIZE MKFS
SIZE[vfat-fat32]=64M; MKFS[vfat-fat32]="mkfs.vfat -F 32 -s 1 -n EFI"
SIZE[vfat-fat16]=32M; MKFS[vfat-fat16]="mkfs.vfat -F 16 -s 2 -n DATA16"
SIZE[vfat-fat12]=8M;  MKFS[vfat-fat12]="mkfs.vfat -F 12 -n SMALL"

# options name -> mount options used for the dump. "al2023" is the
# /boot/efi line of Amazon Linux 2023's fstab.
declare -A OPTS
OPTS[default]="utf8,tz=UTC"
OPTS[al2023]="uid=0,gid=0,umask=0077,shortname=winnt,utf8,tz=UTC"
OPTS[owned]="uid=1000,gid=1001,fmask=0133,dmask=0022,utf8,tz=UTC"

for name in $(printf '%s\n' "${!MKFS[@]}" | sort); do
    img="$work/$name.img"
    truncate -s "${SIZE[$name]}" "$img"
    ${MKFS[$name]} "$img" > /dev/null
    mount -o loop,utf8 "$img" "$mnt"
    python3 "$here/fat_populate.py" "$mnt"
    umount "$mnt"
    # shortname=winnt stores all-lower / all-upper 8.3 names without a long
    # name, using the case bits instead.
    mount -o loop,utf8,shortname=winnt "$img" "$mnt"
    mkdir "$mnt/winnt"
    for f in lower.txt UPPER.TXT lower.TXT UPPER.txt; do echo "$f" > "$mnt/winnt/$f"; done
    umount "$mnt"
    cp "$img" "$out/"

    for opt in $(printf '%s\n' "${!OPTS[@]}" | sort); do
        mount -o "loop,ro,${OPTS[$opt]}" "$img" "$mnt"
        python3 "$here/fs_dump.py" "$mnt" > "$work/files.json"
        umount "$mnt"
        python3 - "$name" "${MKFS[$name]}" "${OPTS[$opt]}" "$work/files.json" > "$out/$name-$opt.json" <<'PY'
import json, sys
name, mkfs, options, files = sys.argv[1:]
json.dump({"image": name + ".img", "mkfs": mkfs, "mount_options": options,
           **json.load(open(files))}, sys.stdout, indent=1)
PY
        echo "built $name-$opt"
    done
done
