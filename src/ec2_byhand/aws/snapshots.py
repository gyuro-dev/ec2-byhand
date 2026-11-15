"""Which EBS snapshots to compare: an instance's disks now, and its AMI's.

current  CreateSnapshots on the instance: one crash-consistent snapshot
         per attached EBS volume, taken at the same moment (what LVM
         across volumes needs). Instance store volumes are not included.
baseline the AMI the instance was launched from: the snapshot of each EBS
         mapping in the image's block device mappings.

Snapshots made here are tagged ec2-byhand=<instance id> so they can be found
and are deleted after the analysis unless kept (delete_snapshots).

どの EBS スナップショットを比べるか: 今のインスタンスのディスクと、その AMI のもの。current は
CreateSnapshots で全 EBS ボリュームを同時に取る（クラッシュ整合。ボリュームをまたぐ LVM に必要
）。baseline は起動元 AMI のブロックデバイスマッピングのスナップショット。ここで作ったスナップ
ショットには ec2-byhand=<instance id> のタグを付け、残す指定がなければ解析後に消す。
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ec2_byhand.messages import msg

TAG_KEY = "ec2-byhand"


class AwsSourceError(Exception):
    """The instance, image or snapshots cannot be used (message says why).

    そのインスタンス・イメージ・スナップショットは使えない（理由はメッセージにある）。
    """


@dataclass(frozen=True)
class Disk:
    """One disk of a side: its device name and the snapshot that holds it.

    片側のディスク 1 本: デバイス名と、それを収めたスナップショット。
    """

    device: str  # device name in the instance or image mapping, e.g. /dev/xvda
    snapshot_id: str
    volume_id: str | None = None  # the volume it was taken from, when this run took it


@dataclass(frozen=True)
class Instance:
    """What describe_instance read: image, root device and EBS volumes.

    describe_instance が読んだもの: AMI・ルートデバイス・EBS ボリューム。
    """

    instance_id: str
    image_id: str
    root_device: str
    volumes: dict[str, str]  # device name -> volume id (EBS only)


def describe_instance(ec2: Any, instance_id: str) -> Instance:
    """The instance's image id, root device and EBS volumes, via DescribeInstances.

    DescribeInstances で、インスタンスの AMI・ルートデバイス・EBS ボリュームを得る。
    """
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    found = [i for r in resp["Reservations"] for i in r["Instances"]]
    if not found:
        raise AwsSourceError(msg("instance_not_found", instance=instance_id))
    inst = found[0]
    volumes = {
        m["DeviceName"]: m["Ebs"]["VolumeId"]
        for m in inst.get("BlockDeviceMappings", [])
        if "Ebs" in m
    }
    if not volumes:
        raise AwsSourceError(msg("instance_no_volumes", instance=instance_id))
    return Instance(instance_id, inst["ImageId"], inst.get("RootDeviceName", ""), volumes)


def snapshot_instance(ec2: Any, inst: Instance) -> list[Disk]:
    """Start a snapshot of every EBS volume of the instance (not waited for:
    the caller records them first, so they are cleaned up whatever happens).

    インスタンスの全 EBS ボリュームのスナップショットを開始する。完了は待たない: 呼び出し側が
    先に記録しておき、何があっても後片付けできるように。
    """
    resp = ec2.create_snapshots(
        InstanceSpecification={"InstanceId": inst.instance_id, "ExcludeBootVolume": False},
        Description=f"ec2-byhand: {inst.instance_id}",
        TagSpecifications=[
            {"ResourceType": "snapshot", "Tags": [{"Key": TAG_KEY, "Value": inst.instance_id}]}
        ],
    )
    by_volume = {s["VolumeId"]: s["SnapshotId"] for s in resp["Snapshots"]}
    disks = [
        Disk(dev, by_volume[vol], vol)
        for dev, vol in sorted(inst.volumes.items())
        if vol in by_volume
    ]
    disks += [
        Disk(vol, snap, vol)
        for vol, snap in sorted(by_volume.items())
        if vol not in inst.volumes.values()
    ]
    return disks


# What DescribeSnapshots gives a snapshot copied from another one: no volume of its own.
NO_VOLUME = "vol-ffffffff"


def snapshot_volumes(ec2: Any, snapshot_ids: list[str]) -> dict[str, str]:
    """snapshot id -> the volume it was taken from (DescribeSnapshots); a copy has none.

    スナップショット ID → 取った元のボリューム（DescribeSnapshots）。コピーには無い。
    """
    response = ec2.describe_snapshots(SnapshotIds=snapshot_ids)
    return {
        s["SnapshotId"]: s["VolumeId"]
        for s in response.get("Snapshots", [])
        if s.get("VolumeId") and s["VolumeId"] != NO_VOLUME
    }


POLL_SECONDS = 15  # how often the snapshots waited for are looked at


def wait_for_snapshots(
    ec2: Any, disks: list[Disk], on_wait: Callable[[dict[str, str]], None] | None = None
) -> None:
    """Wait until every snapshot is completed, however long that takes: the first
    snapshot of a large volume can take hours, and a limit would throw the wait away
    (the caller deletes the snapshots when the run ends). `on_wait` is called after
    each look that found them unfinished, with every snapshot's progress ("37%"). A
    snapshot that ends in error raises AwsSourceError.

    全スナップショットの完了を、どれだけかかっても待つ: 大きなボリュームの最初のスナップショット
    は数時間かかることがあり、上限で打ち切ると待った分が無駄になる（実行が終わると呼び出し側が
    スナップショットを消すため）。`on_wait` は、見に行って未完了だったたびに、各スナップショット
    の進み具合（"37%"）を渡して呼ばれる。エラーで終わったスナップショットは AwsSourceError。
    """
    ids = [d.snapshot_id for d in disks]
    while True:
        found = ec2.describe_snapshots(SnapshotIds=ids)["Snapshots"]
        for s in found:
            if s.get("State") == "error":
                why = s.get("StateMessage") or s["State"]
                raise AwsSourceError(msg("snapshot_failed", snapshot=s["SnapshotId"], why=why))
        if len(found) == len(ids) and all(s.get("State") == "completed" for s in found):
            return
        if on_wait is not None:
            on_wait({s["SnapshotId"]: s.get("Progress", "") for s in found})
        time.sleep(POLL_SECONDS)


def image_disks(ec2: Any, image_id: str) -> list[Disk]:
    """The snapshots behind an AMI's EBS mappings.

    AMI の EBS マッピングの背後にあるスナップショット。
    """
    try:
        resp = ec2.describe_images(ImageIds=[image_id])
    except ec2.exceptions.ClientError as err:
        code = err.response.get("Error", {}).get("Code", "")
        if code.startswith("InvalidAMIID"):
            raise AwsSourceError(msg("ami_cannot_be_described", image=image_id, code=code)) from err
        raise
    if not resp["Images"]:
        raise AwsSourceError(msg("ami_not_found", image=image_id))
    disks = [
        Disk(m["DeviceName"], m["Ebs"]["SnapshotId"])
        for m in resp["Images"][0].get("BlockDeviceMappings", [])
        if m.get("Ebs", {}).get("SnapshotId")
    ]
    if not disks:
        raise AwsSourceError(msg("ami_no_snapshots", image=image_id))
    return sorted(disks, key=lambda d: d.device)


def delete_snapshots(ec2: Any, disks: list[Disk]) -> list[tuple[Disk, str]]:
    """Delete the snapshots this run created. Every snapshot is attempted
    even if one deletion fails (snapshots cost money until deleted); the
    failures are returned for the caller to report, not raised.

    この実行で作ったスナップショットを消す。1 つの削除に失敗しても全部を試す（スナップショット
    は消すまで課金される）。失敗は raise せず、呼び出し側が報告できるように返す。
    """
    from botocore.exceptions import BotoCoreError, ClientError

    failed = []
    for d in disks:
        try:
            ec2.delete_snapshot(SnapshotId=d.snapshot_id)
        except (BotoCoreError, ClientError) as err:  # refused, or the network went away
            failed.append((d, str(err)))
    return failed
