#!/usr/bin/env bash
# Download the official AlmaLinux 8 cloud image used by vm_almalinux8.sh
# into /root/.cache/ec2byhand-vm and verify it against AlmaLinux's CHECKSUM
# file. Run inside WSL as root:
#   wsl -u root -- bash tools/golden/fetch_almalinux8.sh
set -euo pipefail

url=https://repo.almalinux.org/almalinux/8/cloud/x86_64/images
name=AlmaLinux-8-GenericCloud-latest.x86_64.qcow2
dir=/root/.cache/ec2byhand-vm
mkdir -p "$dir"
cd "$dir"
curl -sSLf -o CHECKSUM "$url/CHECKSUM"
if [ ! -f "$name" ]; then
    curl -sSLf -o "$name.part" "$url/$name"
    mv "$name.part" "$name"
fi
grep " $name\$" CHECKSUM | sha256sum -c -
qemu-img info "$name" | head -4
