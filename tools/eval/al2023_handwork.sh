#!/usr/bin/env bash
# End-to-end check on the real Amazon Linux 2023 image: boot it, do
# typical hand work over SSH, shut down cleanly and keep the disk as the
# "after" image. The untouched image is the "before" (the AMI).
#
# Run inside WSL (or any Linux with /dev/kvm) as root:
#   bash tools/eval/al2023_handwork.sh QCOW2 OUTDIR
#
# QCOW2 is the official KVM image from
#   https://cdn.amazonlinux.com/al2023/os-images/latest/kvm/
# (check SHA256SUMS and its signature first). It is never modified: the VM
# runs on an overlay. Writes OUTDIR/before.img, OUTDIR/after.img (raw,
# sparse) and OUTDIR/scenario.txt (what was done). The VM needs network
# access for dnf.
set -euo pipefail

base=$(realpath "${1:?usage: al2023_handwork.sh QCOW2 OUTDIR}")
out=$(realpath -m "${2:?usage: al2023_handwork.sh QCOW2 OUTDIR}")
mkdir -p "$out"
work=$(mktemp -d)
port=2298

cleanup() {
    if [ -f "$work/qemu.pid" ]; then kill "$(cat "$work/qemu.pid")" 2> /dev/null || true; fi
    rm -rf "$work"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N "" -f "$work/key"
cat > "$work/user-data" <<EOC
#cloud-config
ssh_authorized_keys: ["$(cat "$work/key.pub")"]
EOC
echo "instance-id: ec2byhand-eval" > "$work/meta-data"
cloud-localds "$work/seed.img" "$work/user-data" "$work/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$work/disk.qcow2"

qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 \
    -display none -daemonize -pidfile "$work/qemu.pid" -serial "file:$work/console.log" \
    -drive "file=$work/disk.qcow2,if=virtio" \
    -drive "file=$work/seed.img,if=virtio,format=raw" \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$port-:22" -device virtio-net-pci,netdev=n0

vm() {
    ssh -i "$work/key" -p "$port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR -o ConnectTimeout=5 ec2-user@127.0.0.1 "$@"
}
for _ in $(seq 1 120); do
    if vm true 2> /dev/null; then break; fi
    sleep 5
done
vm 'cloud-init status --wait > /dev/null; uname -r; cat /etc/system-release'

# The hand work. Each line of scenario.txt names one change and where it
# should show up in manifest.json.
vm 'sudo bash -s' > "$out/scenario.txt" <<'EOS'
set -euo pipefail
exec 3>&1 1>&2
say() { echo "$*" >&3; }

dnf -y -q install nginx tree
say "packages.changes added: nginx, tree (and dependencies)"
for pkg in nano rsync; do
    if rpm -q "$pkg" > /dev/null 2>&1; then
        dnf -y -q remove "$pkg"
        say "packages.changes removed: $pkg"
        break
    fi
done

sed -i 's/^#\?ClientAliveInterval.*/ClientAliveInterval 120/' /etc/ssh/sshd_config
grep -q '^ClientAliveInterval 120' /etc/ssh/sshd_config || echo 'ClientAliveInterval 120' >> /etc/ssh/sshd_config
say "modified_package_files: /etc/ssh/sshd_config (config, content)"

cat > /etc/nginx/conf.d/myapp.conf <<'C'
server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; } }
C
say "hand_placed: /etc/nginx/conf.d/myapp.conf"

mkdir -p /opt/myapp
printf 'print("hello")\n' > /opt/myapp/app.py
say "hand_placed: /opt/myapp, /opt/myapp/app.py"

cat > /etc/systemd/system/myapp.service <<'C'
[Unit]
Description=my app
[Service]
ExecStart=/usr/bin/python3 /opt/myapp/app.py
[Install]
WantedBy=multi-user.target
C
systemctl enable myapp.service nginx.service 2> /dev/null
say "hand_placed: /etc/systemd/system/myapp.service; services: myapp, nginx enabled"

printf '#!/bin/sh\necho hi\n' > /usr/local/bin/hello
chmod 755 /usr/local/bin/hello
say "hand_placed: /usr/local/bin/hello"

chmod 0700 /usr/bin/tracepath
say "modified_package_files: /usr/bin/tracepath (mode, $(rpm -qf /usr/bin/tracepath))"

useradd -m alice
say "modified_package_files: /etc/passwd, /etc/group, /etc/shadow ... ; hand_placed: /home/alice"

echo 'net.core.somaxconn = 4096' > /etc/sysctl.d/90-tuning.conf  # AL2023 has no cron by default
say "hand_placed: /etc/sysctl.d/90-tuning.conf"

install -d -m 700 /root/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForEc2ByhandEvaluationOnly000000000 admin' >> /root/.ssh/authorized_keys
say "hand_placed (sensitive): /root/.ssh/authorized_keys"

EOS
cat "$out/scenario.txt"

vm 'sudo poweroff' 2> /dev/null || true
for _ in $(seq 1 60); do
    [ -f "$work/qemu.pid" ] && kill -0 "$(cat "$work/qemu.pid")" 2> /dev/null || break
    sleep 2
done
rm -f "$work/qemu.pid"
qemu-img convert -O raw "$base" "$out/before.img"
qemu-img convert -O raw "$work/disk.qcow2" "$out/after.img"
chmod 644 "$out"/*.img "$out/scenario.txt"
echo "wrote $out/before.img $out/after.img"
