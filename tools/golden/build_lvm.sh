#!/usr/bin/env bash
# Build LVM2 golden images and their expected output.
#
# Run inside WSL (or any Linux) as root:
#   wsl -u root -- bash tools/golden/build_lvm.sh tests/golden/out
#
# Each case writes one or more <case>*.img files and <case>.json. The JSON
# holds what LVM itself reports (vgs/pvs/lvs) plus the SHA-256 of every LV
# read through device-mapper, which is the ground truth for our reader.
set -euo pipefail

out=$(realpath -m "${1:?usage: build_lvm.sh OUTDIR}")
mkdir -p "$out"
work=$(mktemp -d)
loops=()
vgs_made=()

cleanup() {
    for vg in "${vgs_made[@]}"; do
        vgchange -q -an "$vg" < /dev/null > /dev/null 2>&1 || true
    done
    for l in "${loops[@]}"; do
        losetup -d "$l" 2> /dev/null || true
    done
    rm -rf "$work"
}
trap cleanup EXIT

# lvm complains loudly about inherited file descriptors; it is harmless.
export LVM_SUPPRESS_FD_WARNINGS=1
lvm_q() { "$@" -q < /dev/null > /dev/null; }

attach() {
    # attach IMAGE [--partscan] -> sets LOOP. Not used as $(attach ...)
    # because the subshell would lose the loops+= bookkeeping.
    LOOP=$(losetup -f --show ${2:-} "$1")
    loops+=("$LOOP")
}

# Refuse to run over leftovers from an earlier, interrupted run.
for vg in gvg1 gvg2 gvg3 gvg4; do
    if vgs "$vg" > /dev/null 2>&1 || [ -e "/dev/$vg" ]; then
        echo "VG $vg already exists; clean up first (dmsetup remove_all; losetup -D; rm -rf /dev/$vg)" >&2
        exit 1
    fi
done

# write_expected CASE VG PARTITION IMAGE...
write_expected() {
    local name=$1 vg=$2 part=$3
    shift 3
    udevadm settle 2> /dev/null || true
    vgs --reportformat json --units b --nosuffix -o vg_name,vg_uuid,vg_extent_size,vg_seqno "$vg" > "$work/vgs.json"
    pvs --reportformat json -o pv_name,pv_uuid -S "vg_name=$vg" > "$work/pvs.json"
    lvs --reportformat json --units b --nosuffix -a \
        -o lv_name,lv_uuid,lv_size,seg_count,lv_layout "$vg" > "$work/lvs.json"
    python3 - "$work" "$name" "$vg" "$part" "$@" > "$out/$name.json" <<'PY'
import hashlib, json, os, sys

work, name, vg, part = sys.argv[1:5]
images = sys.argv[5:]

def report(f, key):
    return json.load(open(os.path.join(work, f)))["report"][0][key]

def backing(dev):
    # /dev/loop3p2 -> /dev/loop3 -> image basename
    base = dev
    if "p" in os.path.basename(dev)[4:]:
        base = dev[: dev.rindex("p")]
    with open(f"/sys/block/{os.path.basename(base)}/loop/backing_file") as f:
        return os.path.basename(f.read().strip())

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

v = report("vgs.json", "vg")[0]
lvs = []
for lv in report("lvs.json", "lv"):
    lv_name = lv["lv_name"]
    hidden = lv_name.startswith("[")
    path = f"/dev/mapper/{vg.replace('-', '--')}-{lv_name.strip('[]').replace('-', '--')}"
    lvs.append({
        "name": lv_name.strip("[]"),
        "hidden": hidden,
        "uuid": lv["lv_uuid"],
        "size": int(lv["lv_size"]),
        "segments": int(lv["seg_count"]),
        "layout": lv["lv_layout"],
        "sha256": sha256(path) if os.path.exists(path) else None,
    })

json.dump({
    "images": images,
    "partition": None if part == "-" else int(part),
    "vg": {
        "name": v["vg_name"],
        "uuid": v["vg_uuid"],
        "extent_size": int(v["vg_extent_size"]),
        "seqno": int(v["vg_seqno"]),
    },
    "pvs": [{"image": backing(p["pv_name"]), "uuid": p["pv_uuid"]}
            for p in report("pvs.json", "pv")],
    "lvs": lvs,
}, sys.stdout, indent=2, ensure_ascii=False)
PY
    vgchange -q -an "$vg" < /dev/null > /dev/null
    for img in "$@"; do cp "$work/$img" "$out/"; done
    echo "built $name"
}

fill() {
    # fill VG/LV with random data so its hash is meaningful
    dd if=/dev/urandom of="/dev/$1" bs=1M status=none conv=fsync 2> /dev/null || true
}

# --- lvm-whole: PV on the whole disk, non-contiguous and oddly named LVs ----
truncate -s 64M "$work/lvm-whole.img"
attach "$work/lvm-whole.img"; l=$LOOP
lvm_q pvcreate "$l"
lvm_q vgcreate -s 1M gvg1 "$l"; vgs_made+=(gvg1)
lvm_q lvcreate -L 8M -n root gvg1
lvm_q lvcreate -L 4M -n data gvg1
lvm_q lvcreate -L 4M -n var gvg1
lvm_q lvextend -L +4M gvg1/data          # data now has two segments
lvm_q lvcreate -L 2M -n app.v2+x_y gvg1
lvm_q lvcreate -L 2M -n with-dash gvg1
for lv in root data var app.v2+x_y with-dash; do fill "gvg1/$lv"; done
write_expected lvm-whole gvg1 - lvm-whole.img

# --- lvm-2mda: two metadata copies on one PV (start and end of the disk) -----
truncate -s 32M "$work/lvm-2mda.img"
attach "$work/lvm-2mda.img"; l=$LOOP
lvm_q pvcreate --pvmetadatacopies 2 "$l"
lvm_q vgcreate -s 1M gvg4 "$l"; vgs_made+=(gvg4)
lvm_q lvcreate -L 8M -n root gvg4
fill gvg4/root
write_expected lvm-2mda gvg4 - lvm-2mda.img

# --- lvm-gpt: PV on partition 2 of a GPT disk, like RHEL ---------------------
truncate -s 64M "$work/lvm-gpt.img"
sgdisk -n 1:2048:+8M -t 1:8300 -n 2:0:0 -t 2:8E00 "$work/lvm-gpt.img" > /dev/null
attach "$work/lvm-gpt.img" --partscan; l=$LOOP
lvm_q pvcreate "${l}p2"
lvm_q vgcreate -s 4M gvg2 "${l}p2"; vgs_made+=(gvg2)
lvm_q lvcreate -L 16M -n root gvg2
lvm_q lvcreate -L 8M -n swap gvg2
fill gvg2/root; fill gvg2/swap
write_expected lvm-gpt gvg2 2 lvm-gpt.img

# --- lvm-multi: VG over two disks; a linear LV spanning both, and a striped LV
truncate -s 32M "$work/lvm-multi-a.img" "$work/lvm-multi-b.img"
attach "$work/lvm-multi-a.img"; la=$LOOP
attach "$work/lvm-multi-b.img"; lb=$LOOP
lvm_q pvcreate "$la" "$lb"
lvm_q vgcreate -s 1M gvg3 "$la" "$lb"; vgs_made+=(gvg3)
# Striped first: it needs free extents on both disks.
lvm_q lvcreate -i 2 -I 64k -L 8M -n striped gvg3
lvm_q lvcreate -L 40M -n span gvg3 "$la" "$lb"
fill gvg3/span; fill gvg3/striped
write_expected lvm-multi gvg3 - lvm-multi-a.img lvm-multi-b.img
