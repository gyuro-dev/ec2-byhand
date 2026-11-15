#!/usr/bin/env bash
# Build filesystem golden images and the kernel's view of every file in them.
#
# Run inside WSL (or any Linux) as root:
#   wsl -u root -- bash tools/golden/build_fs.sh tests/golden/out [CASE...]
#
# For each case: make the filesystem, mount it, fill it with fs_populate.py,
# unmount cleanly, overwrite preallocated-but-unwritten blocks with garbage
# (fs_poison.py), remount read-only and dump every file with fs_dump.py.
# Writes <case>.img and <case>.json; the JSON also records the mkfs command.
# Needs: e2fsprogs, xfsprogs, acl, and Docker for the docker:* cases.
set -euo pipefail

out=$(realpath -m "${1:?usage: build_fs.sh OUTDIR [CASE...]}")
shift
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
work=$(mktemp -d)
mnt="$work/mnt"
mkdir -p "$mnt"
trap 'umount "$mnt" 2> /dev/null || true; rm -rf "$work"' EXIT

# case name -> image size, mkfs command (the image path is appended).
# A "docker:TAG " prefix runs mkfs inside tools/golden/docker/TAG.Dockerfile,
# so we can test the on-disk defaults of other distributions' mkfs.
declare -A SIZE MKFS
SIZE[ext4-default]=128M; MKFS[ext4-default]="mkfs.ext4 -q -F"
SIZE[ext4-1k]=128M;      MKFS[ext4-1k]="mkfs.ext4 -q -F -b 1024"
SIZE[ext4-inode128]=128M; MKFS[ext4-inode128]="mkfs.ext4 -q -F -I 128"
SIZE[ext4-inline]=128M;  MKFS[ext4-inline]="mkfs.ext4 -q -F -O inline_data"
SIZE[ext4-noextents]=128M; MKFS[ext4-noextents]="mkfs.ext4 -q -F -O ^extent,^flex_bg,^64bit"
SIZE[ext4-noextents-1k]=128M; MKFS[ext4-noextents-1k]="mkfs.ext4 -q -F -b 1024 -O ^extent,^flex_bg,^64bit"
SIZE[ext4-nohtree]=128M; MKFS[ext4-nohtree]="mkfs.ext4 -q -F -O ^dir_index,^metadata_csum"
SIZE[ext4-metabg]=128M;  MKFS[ext4-metabg]="mkfs.ext4 -q -F -O meta_bg,^resize_inode"
SIZE[ext4-ea-inode]=128M; MKFS[ext4-ea-inode]="mkfs.ext4 -q -F -O ea_inode"
SIZE[ext4-bigalloc]=256M; MKFS[ext4-bigalloc]="mkfs.ext4 -q -F -O bigalloc -C 16384"
SIZE[xfs-wsl]=128M;      MKFS[xfs-wsl]="mkfs.xfs -f"
SIZE[xfs-1k]=128M;       MKFS[xfs-1k]="mkfs.xfs -f -b size=1024"
SIZE[xfs-dirblk16k]=128M; MKFS[xfs-dirblk16k]="mkfs.xfs -f -n size=16384"
SIZE[xfs-el9]=128M;      MKFS[xfs-el9]="docker:el9 mkfs.xfs -f"
SIZE[xfs-el8]=128M;      MKFS[xfs-el8]="docker:el8 mkfs.xfs -f"
SIZE[ext4-el9]=128M;     MKFS[ext4-el9]="docker:el9 mkfs.ext4 -F"
SIZE[ext4-el8]=128M;     MKFS[ext4-el8]="docker:el8 mkfs.ext4 -F"
SIZE[ext4-al2023]=128M;  MKFS[ext4-al2023]="docker:al2023 mkfs.ext4 -F"
SIZE[xfs-al2]=128M;      MKFS[xfs-al2]="docker:al2 mkfs.xfs -f"
SIZE[xfs-al2023]=128M;   MKFS[xfs-al2023]="docker:al2023 mkfs.xfs -f"
SIZE[xfs-latest]=128M;   MKFS[xfs-latest]="docker:latest mkfs.xfs -f"
SIZE[xfs-latest-1k]=128M; MKFS[xfs-latest-1k]="docker:latest mkfs.xfs -f -b size=1024"
# XFS v4 (crc=0): the WSL kernel cannot mount it. These cases run inside an
# AlmaLinux 8 VM via vm_almalinux8.sh, with EL8's xfsprogs, and are left
# out of the default case list.
SIZE[xfs-v4]=128M;        MKFS[xfs-v4]="mkfs.xfs -f -m crc=0"
SIZE[xfs-v4-noftype]=128M; MKFS[xfs-v4-noftype]="mkfs.xfs -f -m crc=0 -n ftype=0"  # EL8 defaults to ftype=1
SIZE[xfs-v4-1k]=128M;     MKFS[xfs-v4-1k]="mkfs.xfs -f -m crc=0 -b size=1024"
# Version 1 inodes (pre-NLINK filesystems): made from a v4 image by xfs_inode1.py (POST).
SIZE[xfs-v4-inode1]=128M; MKFS[xfs-v4-inode1]="mkfs.xfs -f -m crc=0"
declare -A NEEDS_VM=([xfs-v4]=1 [xfs-v4-noftype]=1 [xfs-v4-1k]=1 [xfs-v4-inode1]=1)
# 64-bit inode numbers: an inode number is (AG << (agblklog + inopblog)) |
# inode-in-AG, so with AGs over 2^27 4k blocks (agblklog 28) and 8 inodes
# per block everything from AG 2 on is above 2^32, and shortform
# directories that point there switch to 8-byte numbers (i8count). New directories rotate
# over the AGs. The 4 TiB image is sparse and is stored packed
# (sparse_pack.py); -K skips discard, -l keeps the log small.
SIZE[xfs-ino64]=4T;       MKFS[xfs-ino64]="mkfs.xfs -f -K -d agcount=5 -l size=64m"
declare -A PACK=([xfs-ino64]=1)
# Commands run on the unmounted image after populating ("$img" is set).
# ext4-nohtree: punch a hole into a linear directory; the kernel reports
# "directory contains a hole" and skips it.
declare -A POST=([ext4-nohtree]="debugfs -w -R 'punch /dir-600 1 1'"
                 [xfs-v4-inode1]="python3 $here/xfs_inode1.py")
# Cases whose format has no unwritten extents to poison.
declare -A NO_UNWRITTEN=([ext4-noextents]=1 [ext4-noextents-1k]=1)

cases=("$@")
if [ ${#cases[@]} -eq 0 ]; then
    mapfile -t cases < <(for c in "${!MKFS[@]}"; do [ -z "${NEEDS_VM[$c]:-}" ] && echo "$c"; done | sort)
fi

for name in "${cases[@]}"; do
    img="$work/$name.img"
    rm -f "$img"
    truncate -s "${SIZE[$name]}" "$img"
    mkfs=${MKFS[$name]}
    if [[ $mkfs == docker:* ]]; then
        tag=${mkfs%% *}
        tag=${tag#docker:}
        bash "$here/docker_mkfs.sh" "$tag" "$img" ${mkfs#* } > "$work/mkfs.out"
    else
        $mkfs "$img" > "$work/mkfs.out"
    fi

    if ! mount -o loop "$img" "$mnt" 2> "$work/mount.err"; then
        # The newest mkfs (docker:latest) switches on features only a recent kernel
        # mounts (parent pointers and exchange-range need Linux 6.10): where this kernel
        # is older (a CI runner), those cases are left out and their tests skip.
        if [[ $mkfs == docker:latest* ]]; then
            echo "skipped $name: this kernel ($(uname -r)) cannot mount it: $(tr '\n' ' ' < "$work/mount.err")"
            rm -f "$img"
            continue
        fi
        cat "$work/mount.err" >&2
        exit 1
    fi
    python3 "$here/fs_populate.py" "$mnt"
    python3 "$here/fs_poison.py" collect ${NO_UNWRITTEN[$name]:+--allow-none} "$mnt" prealloc.bin > "$work/unwritten.json"
    umount "$mnt"
    python3 "$here/fs_poison.py" apply "$img" "$work/unwritten.json"
    if [ -n "${POST[$name]:-}" ]; then eval "${POST[$name]} \"\$img\"" > /dev/null 2>&1; fi

    mount -o loop,ro "$img" "$mnt"
    python3 "$here/fs_dump.py" "$mnt" > "$work/files.json"
    umount "$mnt"

    image=$name.img
    [ -n "${PACK[$name]:-}" ] && image=$name.img.sparse.gz
    python3 - "$image" "$mkfs" "$work/mkfs.out" "$work/files.json" > "$out/$name.json" <<'PY2'
import json, sys
image, mkfs, mkfs_out, files = sys.argv[1:]
data = json.load(open(files))
json.dump({"image": image, "mkfs": mkfs, "mkfs_output": open(mkfs_out).read(), **data},
          sys.stdout, indent=1)
PY2
    if [ -n "${PACK[$name]:-}" ]; then
        python3 "$here/sparse_pack.py" "$img" "$out/$image"
    else
        cp "$img" "$out/"
    fi
    rm -f "$img"
    echo "built $name"
done
