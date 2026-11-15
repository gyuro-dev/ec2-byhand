#!/usr/bin/env bash
# Smart monkey test of ec2-byhand on a real EC2 instance (AL2023 or Ubuntu 24.04): random but
# seeded hand work on a server, then ec2-byhand's report compared with what really changed.
#
#   SUBNET=subnet-0123... AWS_PROFILE=... bash tools/monkey/run.sh OUTDIR
#
# What happens:
#   1. a t3.small from the latest AL2023 (or Ubuntu 24.04) AMI, with a 16 GiB root, a
#      100 GiB data volume (/srv/data: XFS, ext4 on Ubuntu) and a 1 GiB one that fstab
#      names by its device (/srv/extra: /dev/sdg on AL2023, by id on Ubuntu), runs
#      monkey.py from user-data: phase 1 makes a base
#      (packages, pip, npm, Docker, Podman, users with packages of their own, a service,
#      600 files, 1.2 GB of big files),
#      records the whole tree and stops writing (fsfreeze) for snapshot 1, the baseline
#   2. phase 2 changes it: fixed scenarios (dnf install / remove, pip, npm, Docker,
#      users, services, package files edited / chmod / deleted, a sparse 2 GiB file,
#      a big file changed in place; users and their homes, pip --user / venv / --target,
#      Docker build, Podman as root and rootless, an admin's settings, secrets, ACLs and
#      capabilities, odd file names) and 400 seeded random operations; records the tree
#      again (truth.json: what changed) and stops for snapshot 2, the server now
#   3. here: collect.py takes the truth out of the snapshots, ec2-byhand compares them
#      (snapshot 2 against snapshot 1), and compare.py / fields.py check every change
#      of the truth is reported where it belongs, and nothing else is
#      contents.py then checks what was taken out: the archives' entries and the
#      manifest's hashes against the recorded trees, and every patch with patch(1)
#      Before the instance goes, ec2-byhand also runs as on a live server:
#      --instance-id against snapshot 1 given by id (instance-run/), where the baseline's
#      disks get their device names from the instance
#   4. the instance is terminated and the snapshots deleted (KEEP_SNAPSHOTS=1 keeps them)
#
# Settings: DISTRO=ubuntu for Ubuntu 24.04 (default al2023); SEED (default 20261114)
# picks the random operations; FREEZE=0 snapshots the
# busy filesystems without fsfreeze; AWS_REGION as usual. Needs the AWS CLI and uv.
# Takes about 15 minutes. Costs well under a dollar: the instance and 116 GiB of gp3 for
# that time, four snapshots for a few minutes, and reading them back (~6 GiB of data
# transfer out, which is free within the monthly 100 GB).
#
# Writes OUTDIR/{instance.txt,snaps.txt,truth/,ec2-byhand/,instance-run/,compare.txt,fields.txt,contents.txt}.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
out=$(mkdir -p "${1:?usage: run.sh OUTDIR}" && cd "$1" && pwd)
if command -v cygpath > /dev/null; then  # Git Bash: the AWS CLI and uv want Windows paths
    here=$(cygpath -m "$here"); repo=$(cygpath -m "$repo"); out=$(cygpath -m "$out")
fi
: "${SUBNET:?set SUBNET to a subnet with internet access (dnf, pip, npm, Docker Hub)}"
seed=${SEED:-20261114}
distro=${DISTRO:-al2023}
freeze=${FREEZE:-1}
export AWS_PAGER="" MSYS_NO_PATHCONV=1

aws sts get-caller-identity --query Account --output text > /dev/null

b64=$(gzip -9c "$here/monkey.py" | base64 -w0)
cat > "$out/userdata.sh" <<EOF
#!/bin/bash
shutdown -h +240 "ec2-byhand monkey test auto-terminate"
mkdir -p /var/tmp/monkey
echo '$b64' | base64 -d | gunzip > /var/tmp/monkey/monkey.py
cd /var/tmp/monkey && MONKEY_SEED=$seed MONKEY_FREEZE=$freeze python3 monkey.py > log.txt 2>&1
EOF

case $distro in
    al2023) param=/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 ;;
    ubuntu) param=/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id ;;
    *) echo "DISTRO is al2023 or ubuntu" >&2; exit 2 ;;
esac
ami=$(aws ssm get-parameter --name "$param" --query Parameter.Value --output text)
root_dev=$(aws ec2 describe-images --image-ids "$ami" --query 'Images[0].RootDeviceName' --output text)
disks='[{"DeviceName":"'$root_dev'","Ebs":{"VolumeSize":16,"VolumeType":"gp3","DeleteOnTermination":true}},{"DeviceName":"/dev/sdf","Ebs":{"VolumeSize":100,"VolumeType":"gp3","DeleteOnTermination":true}},{"DeviceName":"/dev/sdg","Ebs":{"VolumeSize":1,"VolumeType":"gp3","DeleteOnTermination":true}}]'
inst=$(aws ec2 run-instances --image-id "$ami" --instance-type t3.small --subnet-id "$SUBNET" \
    --user-data "file://$out/userdata.sh" --instance-initiated-shutdown-behavior terminate \
    --metadata-options HttpTokens=required,InstanceMetadataTags=enabled \
    --credit-specification CpuCredits=standard \
    --block-device-mappings "$disks" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=ec2-byhand-monkey-$distro},{Key=purpose,Value=ec2-byhand-verification},{Key=stage,Value=1},{Key=snap,Value=0}]" \
        "ResourceType=volume,Tags=[{Key=purpose,Value=ec2-byhand-verification}]" \
    --query 'Instances[0].InstanceId' --output text)
echo "$inst $ami $distro seed=$seed freeze=$freeze" | tee "$out/instance.txt"
: > "$out/snaps.txt"

cleanup() {
    [ -n "${inst:-}" ] || return 0
    aws ec2 terminate-instances --instance-ids "$inst" --output text > /dev/null || true
    if [ "${KEEP_SNAPSHOTS:-0}" != 1 ]; then
        # By this run's tag, not by snaps.txt alone: a run stopped between making the
        # snapshots and writing them down would leave them (another run's are not touched).
        tagged=$(aws ec2 describe-snapshots --owner-ids self --filters "Name=tag:monkey-run,Values=$inst" \
            --query 'Snapshots[].SnapshotId' --output text 2> /dev/null || true)
        for s in $( { awk '{print $3}' "$out/snaps.txt"; echo "$tagged" | tr '\t' '\n'; } | sort -u); do
            aws ec2 delete-snapshot --snapshot-id "$s" || true
        done
    fi
}
trap cleanup EXIT

seen() {  # wait until the console shows $1 (or a failure); 90 minutes at most
    for _ in $(seq 1 1080); do
        console=$(aws ec2 get-console-output --instance-id "$inst" --latest --output text 2> /dev/null || true)
        if echo "$console" | grep -q "MONKEY-FAILED"; then
            echo "$console" | grep "MONKEY-FAILED" | tail -1
            return 1
        fi
        if echo "$console" | grep -q "$1"; then return 0; fi
        sleep 5
    done
    echo "timeout waiting for $1"
    return 1
}

snap() {  # $1 = label; appends "label device snapshot" lines to snaps.txt
    aws ec2 create-snapshots --instance-specification "InstanceId=$inst,ExcludeBootVolume=false" \
        --description "ec2-byhand monkey $1" \
        --tag-specifications "ResourceType=snapshot,Tags=[{Key=purpose,Value=ec2-byhand-verification},{Key=Name,Value=monkey-$1},{Key=monkey-run,Value=$inst}]" \
        --query 'Snapshots[].[VolumeId,SnapshotId]' --output text | while read -r vol sid; do
        dev=$(aws ec2 describe-volumes --volume-ids "$vol" --query 'Volumes[0].Attachments[0].Device' --output text)
        echo "$1 $dev $sid" | tee -a "$out/snaps.txt"
    done
}

trio() {  # $1 = label -> "ROOT DATA EXTRA" snapshot ids
    echo "$(awk -v l="$1" -v r="$root_dev" '$1==l && $2==r {print $3}' "$out/snaps.txt")" \
        "$(awk -v l="$1" '$1==l && $2=="/dev/sdf" {print $3}' "$out/snaps.txt")" \
        "$(awk -v l="$1" '$1==l && $2=="/dev/sdg" {print $3}' "$out/snaps.txt")"
}

start=$(date +%s)
seen MONKEY-FREEZE-1
echo "phase 1 done after $(( $(date +%s) - start ))s"
snap baseline
aws ec2 create-tags --resources "$inst" --tags Key=snap,Value=1 Key=stage,Value=2
seen MONKEY-FREEZE-2
echo "phase 2 done after $(( $(date +%s) - start ))s"
snap current
aws ec2 create-tags --resources "$inst" --tags Key=snap,Value=2
seen MONKEY-DONE
# shellcheck disable=SC2046  # the snapshot ids are words
aws ec2 wait snapshot-completed --snapshot-ids $(awk '{print $3}' "$out/snaps.txt")
echo "snapshots completed after $(( $(date +%s) - start ))s"

read -r base_root base_data base_extra <<< "$(trio baseline)"
read -r cur_root cur_data cur_extra <<< "$(trio current)"
cd "$repo"
# As on a live server: its own snapshots now, against the backup given by id. A failure
# here is reported and the test goes on.
uv run ec2-byhand --instance-id "$inst" --baseline-snapshot "$base_root" "$base_data" "$base_extra" \
    --no-archives -o "$out/instance-run" --force > "$out/instance-run.txt" 2>&1 \
    || echo "the --instance-id run failed: see instance-run.txt"
echo "--instance-id run done after $(( $(date +%s) - start ))s"
aws ec2 terminate-instances --instance-ids "$inst" --output text > /dev/null

uv run python -X utf8 "$here/collect.py" "$out/truth" \
    "$base_root" "$base_data" "$base_extra" "$cur_root" "$cur_data" "$cur_extra"
uv run ec2-byhand --current-snapshot "$cur_root" "$cur_data" "$cur_extra" \
    --baseline-snapshot "$base_root" "$base_data" "$base_extra" \
    -o "$out/ec2-byhand" --force | tee "$out/ec2-byhand.txt"
uv run python -X utf8 "$here/compare.py" "$out/truth" "$out/ec2-byhand/manifest.json" | tee "$out/compare.txt"
uv run python -X utf8 "$here/fields.py" "$out/truth" "$out/ec2-byhand/manifest.json" | tee "$out/fields.txt"
uv run python -X utf8 "$here/contents.py" "$out/truth" "$out/ec2-byhand" | tee "$out/contents.txt"
echo "done after $(( $(date +%s) - start ))s"
