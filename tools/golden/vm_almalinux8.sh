#!/usr/bin/env bash
# Run golden builds that need another kernel inside an AlmaLinux 8 VM.
#
# The WSL kernel refuses XFS v4 (crc=0); RHEL 8's 4.18 kernel still mounts
# it. This boots the official AlmaLinux 8 cloud image under QEMU/KVM, runs
# the unchanged build_fs.sh there (with EL8's own xfsprogs), and copies the
# images and JSON back.
#
# Run inside WSL (or any Linux with /dev/kvm) as root:
#   wsl -u root -- bash tools/golden/vm_almalinux8.sh tests/golden/out xfs-v4 xfs-v4-noftype xfs-v4-1k
#
# Needs qemu-system-x86, qemu-utils, cloud-image-utils and, in
# /root/.cache/ec2byhand-vm, the image from
#   https://repo.almalinux.org/almalinux/8/cloud/x86_64/images/AlmaLinux-8-GenericCloud-latest.x86_64.qcow2
# The image is never modified: the VM runs on a throwaway overlay.
set -euo pipefail

out=$(realpath -m "${1:?usage: vm_almalinux8.sh OUTDIR CASE...}")
shift
[ $# -gt 0 ] || { echo "name the build_fs.sh cases to run" >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
base=/root/.cache/ec2byhand-vm/AlmaLinux-8-GenericCloud-latest.x86_64.qcow2
[ -f "$base" ] || { echo "missing $base (see the header of this script)" >&2; exit 1; }
mkdir -p "$out"
work=$(mktemp -d)
port=2299

cleanup() {
    if [ -f "$work/qemu.pid" ]; then kill "$(cat "$work/qemu.pid")" 2> /dev/null || true; fi
    rm -rf "$work"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N "" -f "$work/key"
cat > "$work/user-data" <<EOF
#cloud-config
users:
  - name: golden
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys: ["$(cat "$work/key.pub")"]
packages: [python39, xfsprogs, acl, attr, tar]
runcmd:
  - [alternatives, --set, python3, /usr/bin/python3.9]
EOF
echo "instance-id: ec2byhand-golden" > "$work/meta-data"
cloud-localds "$work/seed.img" "$work/user-data" "$work/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$work/disk.qcow2" 20G

qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 \
    -display none -daemonize -pidfile "$work/qemu.pid" -serial "file:$work/console.log" \
    -drive "file=$work/disk.qcow2,if=virtio" \
    -drive "file=$work/seed.img,if=virtio,format=raw" \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$port-:22" -device virtio-net-pci,netdev=n0

vm() {
    ssh -i "$work/key" -p "$port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR -o ConnectTimeout=5 golden@127.0.0.1 "$@"
}
for _ in $(seq 1 120); do
    if vm true 2> /dev/null; then break; fi
    sleep 5
done
vm 'cloud-init status --wait > /dev/null; uname -r; python3 --version; mkfs.xfs -V'

tar -C "$here" -cf - fs_populate.py fs_dump.py fs_poison.py xfs_inode1.py sparse_pack.py build_fs.sh | vm 'rm -rf g && mkdir g && tar -C g -xf -'
vm "sudo bash g/build_fs.sh /tmp/golden-out $*"
vm 'sudo tar -C /tmp/golden-out -cf - .' | tar -C "$out" -xf -
vm 'sudo poweroff' 2> /dev/null || true
echo "copied: $*"
