#!/usr/bin/env bash
# Build a two-disk "server" and the kernel's view of it fully mounted.
#
# Run inside WSL (or any Linux) as root:
#   wsl -u root -- bash tools/golden/build_system.sh tests/golden/out
#
# system-a.img: GPT, p1 = /boot (ext4, LABEL=boot), p3 = /boot/efi (FAT32,
#   by UUID, Amazon Linux 2023's mount options, nested under /boot),
#   p2 = LVM PV of VG ec2dsys with LVs root (xfs, /), var (xfs, /var),
#   opt (ext4, /opt)
# system-b.img: whole-disk xfs, mounted on /data by UUID
# The root's /etc/fstab uses /dev/mapper/..., LABEL=, /dev/VG/LV, UUID=,
# plus tmpfs, swap and a /dev/xvdf1 line that cannot be resolved from disk
# contents. Files written into the root's /opt and /var before mounting are
# hidden by the mounts. system.json holds fs_dump.py of the mounted tree.
set -euo pipefail

# mkfs.xfs 5.19 and later refuses a filesystem under 300 MB. These three together lift
# that (an fstests escape hatch, as in docker_mkfs.sh) so the golden images stay small.
export TEST_DIR=1 TEST_DEV=1 QA_CHECK_FS=1

out=$(realpath -m "${1:?usage: build_system.sh OUTDIR}")
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
work=$(mktemp -d)
mnt="$work/mnt"
mkdir -p "$mnt"
vg=ec2dsys
la= lb=
cleanup() {
    umount -R "$mnt" 2> /dev/null || true
    vgchange -q -an "$vg" < /dev/null > /dev/null 2>&1 || true
    [ -n "$la" ] && losetup -d "$la" 2> /dev/null || true
    [ -n "$lb" ] && losetup -d "$lb" 2> /dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT
export LVM_SUPPRESS_FD_WARNINGS=1
if vgs "$vg" > /dev/null 2>&1; then echo "VG $vg already exists" >&2; exit 1; fi

truncate -s 448M "$work/system-a.img"
truncate -s 128M "$work/system-b.img"
sgdisk -n 1:2048:+64M -t 1:8300 -c 1:boot -n 3:0:+40M -t 3:EF00 -c 3:"EFI System Partition"     -n 2:0:0 -t 2:8E00 -c 2:lvm "$work/system-a.img" > /dev/null
la=$(losetup -f --show --partscan "$work/system-a.img")
lb=$(losetup -f --show "$work/system-b.img")
pvcreate -q "${la}p2" < /dev/null > /dev/null
vgcreate -q -s 4M "$vg" "${la}p2" < /dev/null > /dev/null
lvcreate -q -L 160M -n root "$vg" < /dev/null > /dev/null
lvcreate -q -L 96M -n var "$vg" < /dev/null > /dev/null
lvcreate -q -L 64M -n opt "$vg" < /dev/null > /dev/null
udevadm settle 2> /dev/null || true

mkfs.ext4 -q -F -L boot "${la}p1"
mkfs.vfat -F 32 -s 1 -n EFI "${la}p3" > /dev/null
mkfs.xfs -q -f "/dev/$vg/root"
mkfs.xfs -q -f "/dev/$vg/var"
mkfs.ext4 -q -F "/dev/$vg/opt"
mkfs.xfs -q -f "$lb"
opt_uuid=$(blkid -s UUID -o value "/dev/$vg/opt")
data_uuid=$(blkid -s UUID -o value "$lb")
efi_uuid=$(blkid -s UUID -o value "${la}p3")
efi_opts="defaults,uid=0,gid=0,umask=0077,shortname=winnt"

# --- fill the root, including files that the mounts will hide --------------
mount "/dev/$vg/root" "$mnt"
mkdir -p "$mnt"/{etc,boot,var,opt,data,legacy,tmp,usr/local/bin}
cat > "$mnt/etc/fstab" <<FSTAB
# /etc/fstab of the golden system
/dev/mapper/$vg-root  /        xfs    defaults  0 0
LABEL=boot            /boot    ext4   defaults  1 2
UUID=$efi_uuid  /boot/efi  vfat  $efi_opts,x-systemd.automount  0 2
/dev/$vg/var          /var     xfs    defaults  0 0
UUID=$opt_uuid  /opt  ext4  defaults  0 2
UUID=$data_uuid  /data  xfs  defaults,nofail  0 0
tmpfs                 /tmp     tmpfs  defaults  0 0
/swapfile             none     swap   sw        0 0
/dev/xvdf1            /legacy  ext4   nofail    0 0
FSTAB
echo server01 > "$mnt/etc/hostname"
printf '#!/bin/sh\necho tool\n' > "$mnt/usr/local/bin/tool"
echo "hidden by the /opt mount" > "$mnt/opt/SHADOWED"
echo "hidden by the /var mount" > "$mnt/var/SHADOWED"

mount "${la}p1" "$mnt/boot"
mkdir -p "$mnt/boot/efi"
mount -o "$efi_opts" "${la}p3" "$mnt/boot/efi"
mount "/dev/$vg/var" "$mnt/var"
mount "/dev/$vg/opt" "$mnt/opt"
mount "$lb" "$mnt/data"
echo "fake kernel" > "$mnt/boot/vmlinuz-6.1"
mkdir -p "$mnt/boot/efi/EFI/BOOT" "$mnt/boot/efi/EFI/amzn"
head -c 100000 /dev/urandom > "$mnt/boot/efi/EFI/BOOT/BOOTX64.EFI"
echo "configfile /boot/grub2/grub.cfg" > "$mnt/boot/efi/EFI/amzn/grub.cfg"
mkdir -p "$mnt/var/lib/rpm" "$mnt/var/log" "$mnt/opt/app/bin" "$mnt/data/blobs"
echo "rpmdb" > "$mnt/var/lib/rpm/rpmdb.sqlite"
echo "log line" > "$mnt/var/log/app.log"
printf '#!/bin/sh\nexec /opt/app/bin/server\n' > "$mnt/opt/app/run.sh"
head -c 200000 /dev/urandom > "$mnt/opt/app/bin/server"
head -c 500000 /dev/urandom > "$mnt/data/blobs/blob.bin"
umount -R "$mnt"

# --- the kernel's view of the mounted system --------------------------------
mount -o ro "/dev/$vg/root" "$mnt"
mount -o ro "${la}p1" "$mnt/boot"
mount -o "ro,$efi_opts" "${la}p3" "$mnt/boot/efi"
mount -o ro "/dev/$vg/var" "$mnt/var"
mount -o ro "/dev/$vg/opt" "$mnt/opt"
mount -o ro "$lb" "$mnt/data"
python3 "$here/fs_dump.py" "$mnt" > "$out/system.json"
umount -R "$mnt"
vgchange -q -an "$vg" < /dev/null > /dev/null
losetup -d "$la"; la=
losetup -d "$lb"; lb=
cp "$work/system-a.img" "$work/system-b.img" "$out/"
echo "built system"
