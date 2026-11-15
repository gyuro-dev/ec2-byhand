"""fstab device names that only mean something on EC2.

A volume attached as /dev/sdf shows up in Linux as /dev/sdf or /dev/xvdf, and on
Nitro instances udev links /dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol...
to it, because the NVMe serial number of an EBS volume is its volume id (without
the dash). diskread knows nothing of this and asks ebs_device_volume.

EC2 でだけ意味を持つ fstab のデバイス名。/dev/sdf で接続したボリュームは Linux では /dev/sdf か
/dev/xvdf に見え、Nitro インスタンスでは udev が
/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol... のリンクを作る（EBS の NVMe シリアル番号は、
ダッシュを除いたボリューム ID なので）。diskread はこれを知らず、ebs_device_volume に尋ねる。
"""

from __future__ import annotations

import re

from diskread.system import Volume

# /dev/sdf1 and /dev/xvdf1 as Linux names them; "/dev/xvdfp1" as scan names a partition
# of the disk "/dev/xvdf"; "/dev/sda1p1" of "/dev/sda1", the EC2 API's usual root name.
_SD_OR_XVD = re.compile(r"/dev/(?:sd|xvd)([a-z]+?)(?:\d+(?=p))?p?(\d*)\Z")
BY_ID = "/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_"
EBS_NAMES = ("/dev/sd", "/dev/xvd")  # how the names of _SD_OR_XVD start
_BY_VOLUME_ID = re.compile(re.escape(BY_ID) + r"(vol[0-9a-f]+)(?:_\d+)?(?:-part(\d+))?\Z")


def _sd_or_xvd(name: str) -> tuple[str, str] | None:
    """(disk letters, partition number or "") of a /dev/sd* or /dev/xvd* name."""
    m = _SD_OR_XVD.match(name)
    return (m.group(1), m.group(2)) if m else None


def _name_on_instance(volume: Volume, attached: dict[str, str]) -> str:
    """The volume's name as scan would give it had its disk been named as the instance
    attaches it; its own name when `attached` does not know the disk."""
    device = attached.get(volume.serial) if volume.serial else None
    if device is None:
        return volume.name
    return device if volume.partition is None else f"{device}p{volume.partition}"


def ebs_device_volume(
    spec: str, volumes: list[Volume], attached: dict[str, str] | None = None
) -> Volume | None:
    """The volume an fstab spec names in EC2's terms, if it does (a diskread DeviceResolver).
    `attached` gives, by serial number, the device name the instance has each of its
    volumes under: a disk read from a snapshot given by id is called "disk1", and only
    its volume tells that it is /dev/sdf.

    fstab の指定が EC2 の名前で指すボリューム。無ければ None（diskread の DeviceResolver）。
    `attached` は、インスタンスが各ボリュームを接続しているデバイス名をシリアル番号で引く表。
    ID で渡したスナップショットのディスクは「disk1」という名前なので、それが /dev/sdf だと
    分かるのは元のボリュームからだけ。
    """
    device = _sd_or_xvd(spec)
    if device is not None:
        names = attached or {}
        return next((v for v in volumes if _sd_or_xvd(_name_on_instance(v, names)) == device), None)
    by_id = _BY_VOLUME_ID.match(spec)
    if by_id is not None:
        serial, number = by_id.group(1), int(by_id.group(2)) if by_id.group(2) else None
        return next((v for v in volumes if v.serial == serial and v.partition == number), None)
    return None
