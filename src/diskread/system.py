"""Put a whole machine back together: disks -> partitions / LVM ->
filesystems -> mounted as /etc/fstab says.

On RHEL-style servers /, /var, /opt and /home are often separate logical
volumes, and data lives on extra EBS volumes. Reading only the root
filesystem would show those as empty directories, so this module scans
every disk, finds the root filesystem, resolves its fstab entries to the
volumes found, and walks the combined tree the way the kernel would show
it when everything is mounted.

Device paths depend on the kernel's naming at boot and cannot be resolved
from disk contents. A caller that knows how its platform names devices can
pass that knowledge in (DeviceResolver). A number like /dev/nvme1n1p1 only says
in which order the devices answered at boot, so such an entry is mounted only
when exactly one unmounted volume fits it, and that guess is reported
(System.inferred); otherwise it is unresolved.

マシン全体を組み立て直す: ディスク → パーティション / LVM → ファイルシステム → /etc/fstab どお
りのマウント。ルートだけ読むと別ボリュームの /var などが空に見えるので、全ディスクを走査してル
ートを見つけ、fstab のエントリを見つかったボリュームに解決し、全部マウントしたときにカーネルが
見せる木を歩く。デバイスパスはディスクの中身からは解決できない。プラットフォームのデバイス名の
付け方を知っている呼び出し側は、その知識を渡せる（DeviceResolver）。/dev/nvme1n1p1 の番号は
起動時に応答した順番でしかないので、条件に合う未マウントのボリュームが 1 つだけのときにマウント
し、推定したことを報告する（System.inferred）。それ以外は未解決にする。
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from diskread.blockdev import BlockDevice
from diskread.errors import DiskReadError
from diskread.fs import Filesystem, FileType, Stat, lookup, walk
from diskread.fs.detect import detect_fs, fs_identity, open_fs
from diskread.fs.fat import Vfat
from diskread.lvm import find_volume_groups, read_label
from diskread.partition import read_partition_table

MBR_EXTENDED_TYPES = {"05", "0f", "85"}
MAX_FSTAB_BYTES = 1 << 20
READABLE_FSTYPES = {"ext2", "ext3", "ext4", "xfs", "vfat", "auto"}
# Entries that never refer to a local block device we could read.
IGNORED_FSTYPES = {
    "swap",
    "tmpfs",
    "devtmpfs",
    "proc",
    "sysfs",
    "devpts",
    "cgroup",
    "cgroup2",
    "nfs",
    "nfs4",
    "cifs",
    "smbfs",
    "efs",
    "lustre",
    "fuse",
    "fuse.s3fs",
    "none",
    "securityfs",
    "debugfs",
    "hugetlbfs",
    "mqueue",
    "binfmt_misc",
    "autofs",
}


@dataclass
class Volume:
    """Something that may hold a filesystem: a disk, a partition or an LV.

    ファイルシステムを持ちうるもの: ディスク・パーティション・論理ボリューム。
    """

    name: str  # e.g. "disk0", "disk0p2", "lvm:sysvg/root"
    device: BlockDevice
    fs_type: str | None = None
    fs: Filesystem | None = None
    uuid: str | None = None
    label: str | None = None
    partuuid: str | None = None
    partlabel: str | None = None
    lvm: tuple[str, str] | None = None  # (VG name, LV name)
    error: str | None = None  # why this volume could not be opened
    partition: int | None = None  # its number on the disk; None for a whole disk or an LV
    serial: str | None = None  # the disk's serial number, if the caller knows it


@dataclass(frozen=True)
class FstabEntry:
    """One fstab line: spec, mountpoint, filesystem type and options.

    fstab の 1 行: spec・マウントポイント・ファイルシステム種別・オプション。
    """

    line: int
    spec: str
    mountpoint: str
    fstype: str
    options: str


@dataclass(frozen=True)
class Mount:
    """A filesystem mounted at one mountpoint of the assembled system.

    組み上げたシステムの 1 つのマウントポイントにマウントされたファイルシステム。
    """

    mountpoint: bytes
    volume: Volume
    entry: FstabEntry | None  # None for the root found without an fstab "/" line
    # The filesystem as mounted. Same as volume.fs, except for vfat, whose
    # owners and permissions come from this entry's mount options.
    fs: Filesystem


@dataclass
class System:
    """The assembled machine: its volumes, the root, and the mounts in walk order.

    組み上げたマシン: ボリューム・ルート・マウント一覧（walk の順）。
    """

    volumes: list[Volume]
    root: Volume
    mounts: list[Mount]  # root first, then by mountpoint depth
    unresolved: list[tuple[FstabEntry, str]] = field(default_factory=list)
    ignored: list[FstabEntry] = field(default_factory=list)
    # Mounted by elimination: nothing in the entry says this is the volume.
    inferred: list[tuple[FstabEntry, Volume]] = field(default_factory=list)


# --- scanning ---------------------------------------------------------------


def _open_leaf(vol: Volume, verify_checksums: bool) -> Volume:
    """Detect and open the filesystem on one volume; failures go to Volume.error."""
    try:
        kind = detect_fs(vol.device)
        if kind is None:
            return vol
        fs = open_fs(vol.device, verify_checksums=verify_checksums)
        vol.fs_type, vol.fs = kind, fs
        vol.uuid, vol.label = fs_identity(fs)
    except DiskReadError as err:
        vol.error = str(err)
    return vol


def scan(
    disks: dict[str, BlockDevice],
    verify_checksums: bool = False,
    serials: dict[str, str] | None = None,
) -> list[Volume]:
    """Find every filesystem on the given disks, including inside LVM.

    Errors on one volume are recorded in Volume.error, not raised. With
    verify_checksums the filesystems check metadata checksums as they read
    (see open_fs). `serials` gives disks' serial numbers by name, which the
    /dev/disk/by-id entries of an fstab refer to.

    渡したディスク上の全ファイルシステムを、LVM の中も含めて見つける。個々のボリュームのエラー
    は Volume.error に記録し、raise しない。verify_checksums を立てると読みながらメタデータの
    チェックサムを確かめる（open_fs 参照）。`serials` はディスク名ごとのシリアル番号で、fstab の
    /dev/disk/by-id の指定と突き合わせる。
    """
    volumes: list[Volume] = []
    pvs: list[BlockDevice] = []
    for disk_name, dev in disks.items():
        serial = (serials or {}).get(disk_name)
        try:
            table = read_partition_table(dev)
        except DiskReadError as err:
            volumes.append(Volume(disk_name, dev, error=f"partition table: {err}", serial=serial))
            continue
        leaves: list[Volume] = []
        if table is None:
            leaves.append(Volume(disk_name, dev, serial=serial))
        else:
            for part in table.partitions:
                if table.scheme == "mbr" and part.type in MBR_EXTENDED_TYPES:
                    continue
                if table.scheme == "gpt":
                    partuuid, partlabel = part.uuid.lower() if part.uuid else None, part.name
                else:
                    partuuid, partlabel = f"{table.disk_id[2:]}-{part.number:02x}", None
                name = f"{disk_name}p{part.number}"
                try:
                    device = part.open(dev)
                except DiskReadError as err:  # e.g. it runs past the end of the disk
                    volumes.append(
                        Volume(
                            name,
                            dev,
                            partuuid=partuuid,
                            partlabel=partlabel,
                            error=str(err),
                            partition=part.number,
                            serial=serial,
                        )
                    )
                    continue
                leaves.append(
                    Volume(
                        name,
                        device,
                        partuuid=partuuid,
                        partlabel=partlabel,
                        partition=part.number,
                        serial=serial,
                    )
                )
        for leaf in leaves:
            try:
                is_pv = read_label(leaf.device) is not None
            except DiskReadError as err:
                leaf.error = f"LVM label: {err}"
                volumes.append(leaf)
                continue
            if is_pv:
                pvs.append(leaf.device)
            else:
                volumes.append(_open_leaf(leaf, verify_checksums))

    if pvs:
        unreadable: list[str] = []
        try:
            vgs = find_volume_groups(pvs, unreadable)
        except DiskReadError as err:
            volumes.append(Volume("lvm", pvs[0], error=str(err)))
            vgs = []
        # A PV whose metadata cannot be read costs its own volume group, not the rest.
        volumes += [Volume("lvm", pvs[0], error=message) for message in unreadable]
        for vg in vgs:
            for lv in vg.lvs.values():
                if not lv.visible:
                    continue
                name = f"lvm:{vg.name}/{lv.name}"
                try:
                    dev = vg.open_lv(lv.name)
                except DiskReadError as err:
                    volumes.append(Volume(name, pvs[0], lvm=(vg.name, lv.name), error=str(err)))
                    continue
                volumes.append(
                    _open_leaf(Volume(name, dev, lvm=(vg.name, lv.name)), verify_checksums)
                )
    return volumes


# --- fstab --------------------------------------------------------------------

_OCTAL = re.compile(r"\\([0-7]{3})")


def _unescape(field_: str) -> str:
    """Undo fstab's octal escapes (\\040 and friends)."""
    return _OCTAL.sub(lambda m: chr(int(m.group(1), 8)), field_)


def parse_fstab(text: bytes) -> list[FstabEntry]:
    """Parse fstab text into entries, ignoring comments and too-short lines.

    fstab のテキストをエントリに解析する。コメントと列の足りない行は無視。
    """
    out = []
    for n, raw in enumerate(text.decode("utf-8", "surrogateescape").splitlines(), 1):
        fields = raw.split()
        # A comment starts a line, or (as people write it) follows the fields. A "#"
        # inside a field is part of it: LABEL=data#1, /mnt/a#b.
        for i, word in enumerate(fields):
            if word.startswith("#"):
                fields = fields[:i]
                break
        if len(fields) < 3:
            continue
        spec, mountpoint, fstype = (_unescape(f) for f in fields[:3])
        options = fields[3] if len(fields) > 3 else "defaults"
        out.append(FstabEntry(n, spec, mountpoint, fstype, options))
    return out


def _split_mapper_name(name: str) -> tuple[str, str] | None:
    """'my--vg-root' -> ('my-vg', 'root'): a single '-' separates VG and LV."""
    i = 0
    while i < len(name):
        if name[i] == "-":
            if name[i + 1 : i + 2] == "-":
                i += 2
                continue
            return name[:i].replace("--", "-"), name[i + 1 :].replace("--", "-")
        i += 1
    return None


def _unescape_udev(value: str) -> str:
    """Undo udev's \\xNN escapes in by-label / by-partlabel names."""
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), value)


_NVME_NAME = re.compile(r"/dev/nvme\d+n\d+(?:p(\d+))?\Z")
# What a caller knows about device names on its platform: (spec, volumes) -> the volume.
DeviceResolver = Callable[[str, list[Volume]], Volume | None]


def resolve_spec(
    spec: str, volumes: list[Volume], resolve_device: DeviceResolver | None = None
) -> Volume | None:
    """Find the volume an fstab device spec refers to, if it can be known.
    `resolve_device` is asked about a spec that nothing on the disks identifies.

    fstab のデバイス指定が指すボリュームを、分かる範囲で見つける。ディスクの中身から特定できない
    指定は `resolve_device` に尋ねる。
    """
    key, _, value = spec.partition("=")
    value = value.strip('"')
    by_link = {
        "/dev/disk/by-uuid/": "UUID",
        "/dev/disk/by-label/": "LABEL",
        "/dev/disk/by-partuuid/": "PARTUUID",
        "/dev/disk/by-partlabel/": "PARTLABEL",
    }
    for prefix, kind in by_link.items():
        if spec.startswith(prefix):
            key, value = kind, _unescape_udev(spec[len(prefix) :])

    def first(pred: Callable[[Volume], bool]) -> Volume | None:
        return next((v for v in volumes if pred(v)), None)

    if key == "UUID":
        return first(lambda v: v.uuid is not None and v.uuid.lower() == value.lower())
    if key == "LABEL":
        return first(lambda v: v.label == value)
    if key == "PARTUUID":
        return first(lambda v: v.partuuid is not None and v.partuuid.lower() == value.lower())
    if key == "PARTLABEL":
        return first(lambda v: v.partlabel == value)
    lv: tuple[str, str] | None = None
    if spec.startswith("/dev/mapper/"):
        lv = _split_mapper_name(spec[len("/dev/mapper/") :])
    elif spec.startswith("/dev/") and spec.count("/") == 3:
        _, _, vg, name = spec.split("/")
        lv = (vg, name)
    if lv is not None:
        return first(lambda v: v.lvm == lv)
    return resolve_device(spec, volumes) if resolve_device is not None else None


def _fits_nvme_entry(e: FstabEntry, v: Volume) -> bool:
    """Whether the volume could be what this /dev/nvme... entry means: the partition
    number and the filesystem type are all such a name and its line give away."""
    m = _NVME_NAME.match(e.spec)
    if m is None or v.fs is None or v.lvm is not None:
        return False
    number = int(m.group(1)) if m.group(1) else None
    fstype = {"ext2": "ext4", "ext3": "ext4"}.get(e.fstype.lower(), e.fstype.lower())
    return v.partition == number and fstype in ("auto", v.fs_type)


def _mount(e: FstabEntry, mp: bytes, vol: Volume) -> Mount:
    """A Mount of this volume as the fstab entry asks."""
    assert vol.fs is not None
    fs = Vfat(vol.device, e.options) if isinstance(vol.fs, Vfat) else vol.fs
    return Mount(mp, vol, e, fs)


def _mountpoint(e: FstabEntry) -> bytes:
    """The entry's mountpoint in the form Mount holds it."""
    return e.mountpoint.rstrip("/").encode("utf-8", "surrogateescape") or b"/"


def _mount_by_elimination(
    system: System, by_mountpoint: dict[bytes, Mount], entries: list[FstabEntry]
) -> None:
    """Mount each /dev/nvme... entry that exactly one unmounted volume fits, when no
    other such entry could want that volume; the rest are unresolved."""
    taken = {id(m.volume) for m in by_mountpoint.values()}
    fits = {
        e.line: [v for v in system.volumes if id(v) not in taken and _fits_nvme_entry(e, v)]
        for e in entries
    }
    wanted = Counter(id(v) for candidates in fits.values() for v in candidates)
    for e in entries:
        candidates = fits[e.line]
        if len(candidates) == 1 and wanted[id(candidates[0])] == 1:
            by_mountpoint[_mountpoint(e)] = _mount(e, _mountpoint(e), candidates[0])
            system.inferred.append((e, candidates[0]))
        elif candidates:
            system.unresolved.append(
                (e, f"NVMe numbers depend on the boot; {len(candidates)} volumes fit this entry")
            )
        else:
            system.unresolved.append((e, "device not found among the scanned volumes"))


# --- assembling -----------------------------------------------------------------


def _read_fstab(fs: Filesystem) -> list[FstabEntry] | None:
    """The parsed /etc/fstab of this filesystem, or None if it has none."""
    try:
        ino = lookup(fs, "/etc/fstab")
    except FileNotFoundError:
        return None
    if fs.stat(ino).type is not FileType.REG:
        return None
    dev = fs.open(ino)
    if dev.size > MAX_FSTAB_BYTES:
        raise DiskReadError(f"/etc/fstab: implausible size {dev.size}")
    return parse_fstab(dev.read_at(0, dev.size))


def assemble(
    volumes: list[Volume],
    root: Volume | None = None,
    resolve_device: DeviceResolver | None = None,
) -> System:
    """Pick the root filesystem and mount the others per its /etc/fstab.

    The root is the volume whose fstab mounts itself on "/"; if no fstab
    line resolves that way, the only volume that has an /etc/fstab. Pass
    `root` to choose explicitly (e.g. two OS disks attached). `resolve_device`
    is asked about fstab specs the disks themselves do not identify.

    ルートのファイルシステムを選び、その /etc/fstab どおりに残りをマウントする。ルートは自分自
    身を「/」にマウントする fstab を持つボリューム。それで決まらなければ、/etc/fstab を持つ唯
    一のボリューム。`root` で明示もできる（OS ディスクが 2 本挿さっている場合など）。ディスクの
    中身から特定できない fstab の指定は `resolve_device` に尋ねる。
    """
    fstabs: dict[int, list[FstabEntry]] = {}
    for v in volumes:
        if v.fs is not None:
            try:
                entries = _read_fstab(v.fs)
            except DiskReadError:
                entries = None
            if entries is not None:
                fstabs[id(v)] = entries

    if root is None:
        self_rooted = [
            v
            for v in volumes
            if id(v) in fstabs
            and any(
                e.mountpoint == "/" and resolve_spec(e.spec, volumes, resolve_device) is v
                for e in fstabs[id(v)]
            )
        ]
        candidates = self_rooted or [v for v in volumes if id(v) in fstabs]
        if len(candidates) != 1:
            names = ", ".join(v.name for v in candidates) or "none"
            raise DiskReadError(
                f"cannot tell which volume is the root filesystem (candidates: {names})"
            )
        root = candidates[0]
    if root.fs is None:
        raise DiskReadError(f"root volume {root.name} has no readable filesystem")

    system = System(volumes=volumes, root=root, mounts=[])
    by_mountpoint: dict[bytes, Mount] = {b"/": Mount(b"/", root, None, root.fs)}
    by_elimination: list[FstabEntry] = []
    for e in fstabs.get(id(root), []):
        fstype = e.fstype.lower()
        if (
            fstype in IGNORED_FSTYPES
            or "bind" in e.options.split(",")
            or not e.mountpoint.startswith("/")
        ):
            system.ignored.append(e)
            continue
        vol = resolve_spec(e.spec, volumes, resolve_device)
        mp = _mountpoint(e)
        if vol is None and _NVME_NAME.match(e.spec) and fstype in READABLE_FSTYPES:
            if mp != b"/":
                by_elimination.append(e)
                continue
            if _fits_nvme_entry(e, root):  # this fstab is on the root, and says it is the root
                vol = root
        if vol is None:
            system.unresolved.append((e, "device not found among the scanned volumes"))
        elif fstype not in READABLE_FSTYPES:
            system.unresolved.append((e, f"filesystem type {e.fstype} is not supported"))
        elif vol.fs is None:
            system.unresolved.append((e, f"{vol.name}: {vol.error or 'no readable filesystem'}"))
        else:
            # A later line for the same mountpoint hides an earlier one, as in the kernel.
            by_mountpoint[mp] = _mount(e, mp, vol)
    _mount_by_elimination(system, by_mountpoint, by_elimination)
    system.unresolved.sort(key=lambda item: item[0].line)
    system.mounts = sorted(
        by_mountpoint.values(),
        key=lambda m: (m.mountpoint != b"/", m.mountpoint.count(b"/"), m.mountpoint),
    )
    return system


def walk_mounts(
    mounts: dict[bytes, Filesystem],
    on_error: Callable[[bytes, DiskReadError], None] | None = None,
    listdir: Callable[[Filesystem, int], list[tuple[bytes, int]]] | None = None,
    stat: Callable[[Filesystem, int], Stat] | None = None,
    prune: Callable[[bytes], bool] | None = None,
    tell: Callable[[Filesystem, int], None] | None = None,
) -> Iterator[tuple[bytes, Filesystem, int, Stat]]:
    """Yield (path, filesystem, inode, stat) for a tree made of several mounts.

    Like the kernel, a mountpoint shows the mounted filesystem's root, and
    whatever the parent filesystem has under that directory is hidden.
    Inode numbers are only unique within one filesystem. `listdir` and
    `stat` take (filesystem, inode) and replace the filesystems' own calls
    (see diskread.fs.walk). Paths satisfying `prune` are neither yielded nor
    entered, a mountpoint among them included.

    複数のマウントから成る木を (path, filesystem, inode, stat) で辿る。カーネルと同じく、マウ
    ントポイントはマウントされたファイルシステムのルートを見せ、親側がその下に持つものは隠れる
    。inode 番号はファイルシステム内でだけ一意。`listdir` と `stat` は (filesystem, inode) を
    取り、ファイルシステム直呼びの代わりに使われる（diskread.fs.walk 参照）。`prune` に合うパス
    はマウントポイントも含めて出さず、中にも入らない。
    """
    order = sorted(mounts, key=lambda mp: (mp != b"/", mp.count(b"/"), mp))
    for mp in order:
        if prune is not None and mp != b"/" and prune(mp):
            continue
        fs = mounts[mp]
        base = b"" if mp == b"/" else mp

        def full(rel: bytes, mp: bytes = mp, base: bytes = base) -> bytes:
            return mp if rel == b"/" else base + rel

        def is_other_mount(rel: bytes, full: Callable[[bytes], bytes] = full) -> bool:
            return full(rel) in mounts or (prune is not None and prune(full(rel)))

        report = (
            None if on_error is None else (lambda rel, err, full=full: on_error(full(rel), err))
        )
        ld = None if listdir is None else (lambda ino, fs=fs: listdir(fs, ino))
        st_of = None if stat is None else (lambda ino, fs=fs: stat(fs, ino))
        tl = None if tell is None else (lambda ino, fs=fs: tell(fs, ino))
        for rel, ino, st in walk(fs, report, prune=is_other_mount, listdir=ld, stat=st_of, tell=tl):
            yield full(rel), fs, ino, st


def walk_system(
    system: System, on_error: Callable[[bytes, DiskReadError], None] | None = None
) -> Iterator[tuple[bytes, Mount, int, Stat]]:
    """walk_mounts over the system's mounts, yielding the Mount instead of the filesystem.

    システムのマウント群に対する walk_mounts。filesystem の代わりに Mount を返す。
    """
    by_mountpoint = {m.mountpoint: m for m in system.mounts}
    by_fs = {id(m.fs): m for m in system.mounts}
    for path, fs, ino, st in walk_mounts({mp: m.fs for mp, m in by_mountpoint.items()}, on_error):
        yield path, by_fs[id(fs)], ino, st
