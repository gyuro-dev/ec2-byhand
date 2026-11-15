#!/usr/bin/env bash
# Build partition-table golden images and their expected output.
#
# Run inside WSL (or any Linux) as root:
#   wsl -u root -- bash tools/golden/build_partition.sh tests/golden/out
#
# For each case this writes <case>.img and <case>.json, where the JSON is
# `sfdisk --json` output: the kernel-side tooling's view of the table.
#
# Note: `sgdisk -q` silently skips writing the table, so it is not used.
set -euo pipefail

out=${1:?usage: build_partition.sh OUTDIR}
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

expect() {
    local name=$1
    sfdisk --json "$work/$name.img" > "$work/$name.json"
    cp "$work/$name.img" "$work/$name.json" "$out/"
    echo "built $name"
}

# GPT laid out like Amazon Linux 2023: root is p1, BIOS boot p127, EFI p128.
truncate -s 64M "$work/gpt-al2023.img"
sgdisk \
    -n 128:2048:+10M  -t 128:EF00 -c 128:EFI \
    -n 127:0:+1M      -t 127:EF02 -c 127:BIOS-BOOT \
    -n 1:0:0          -t 1:8300   -c 1:root \
    "$work/gpt-al2023.img" > /dev/null
expect gpt-al2023

# An EBS volume grown from 64 MiB to 96 MiB without growpart/sgdisk -e: the
# backup GPT header stays at the old end, where alternate_lba points.
truncate -s 64M "$work/gpt-grown.img"
sgdisk -n 1:2048:0 -t 1:8300 -c 1:root "$work/gpt-grown.img" > /dev/null
truncate -s 96M "$work/gpt-grown.img"
expect gpt-grown

# GPT with an LVM partition and a non-ASCII partition name.
truncate -s 64M "$work/gpt-lvm.img"
sgdisk \
    -n 1:2048:+8M -t 1:8300 -c 1:boot \
    -n 2:0:0      -t 2:8E00 -c 2:"データ" \
    "$work/gpt-lvm.img" > /dev/null
expect gpt-lvm

# MBR with two primary partitions, the first bootable.
truncate -s 64M "$work/mbr-basic.img"
sfdisk -q "$work/mbr-basic.img" <<'EOF'
label: dos
label-id: 0x12345678
start=2048, size=20480, type=83, bootable
start=22528, type=8e
EOF
expect mbr-basic

# MBR with an extended partition holding two logical partitions.
truncate -s 64M "$work/mbr-extended.img"
sfdisk -q "$work/mbr-extended.img" <<'EOF'
label: dos
label-id: 0xcafef00d
start=2048, size=16384, type=83
start=18432, type=5
start=20480, size=16384, type=83
start=38912, type=82
EOF
expect mbr-extended
