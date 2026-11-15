"""Volume groups and logical volumes built from LVM2 text metadata.

Supported segment types: "striped" (stripe_count 1 is what LVM calls
linear). Anything else (thin, raid, mirror, snapshot, cache, ...) is
reported as unsupported per LV; the rest of the VG still opens.

LVM2 テキストメタデータから組み立てたボリュームグループと論理ボリューム。対応するセグメント種
別は「striped」（stripe_count 1 が LVM の言う linear）。それ以外（thin, raid, mirror, ...）は
LV 単位で非対応として報告し、VG の残りは開く。
"""

from __future__ import annotations

import bisect
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from diskread.blockdev import BlockDevice, check_range, will_read
from diskread.errors import DiskReadError, UnsupportedError
from diskread.lvm import config
from diskread.lvm.label import PVLabel, read_label, read_metadata_text

SECTOR = 512


@dataclass(frozen=True)
class PhysicalVolume:
    """One PV as the metadata describes it; `device` is None if it was not scanned.

    メタデータが記述する PV。走査したデバイスに無ければ `device` は None。
    """

    key: str  # name inside the metadata, e.g. "pv0"
    uuid: str
    pe_start: int  # bytes from the start of the PV device
    pe_count: int
    device: BlockDevice | None  # None if the PV was not among the scanned devices


@dataclass(frozen=True)
class Stripe:
    """One stripe: a PV and the first physical extent on it.

    ストライプ 1 本: PV と、その上の先頭物理エクステント。
    """

    pv: str  # PhysicalVolume.key
    start_extent: int


@dataclass(frozen=True)
class Segment:
    """A run of the LV's logical extents mapped onto one or more stripes.

    1 つ以上のストライプに対応づく、LV の論理エクステントの区間。
    """

    start_extent: int
    extent_count: int
    type: str
    stripes: list[Stripe]
    stripe_size: int  # bytes; 0 for a single stripe


@dataclass(frozen=True)
class LogicalVolume:
    """One logical volume: its status and segments, sized in extents.

    論理ボリューム 1 つ: 状態とセグメント（大きさはエクステント単位）。
    """

    name: str
    uuid: str
    status: list[str]
    segments: list[Segment]
    extent_size: int  # bytes

    @property
    def size(self) -> int:
        """Size in bytes.

        サイズ（バイト）。
        """
        return sum(s.extent_count for s in self.segments) * self.extent_size

    @property
    def visible(self) -> bool:
        """Whether LVM shows a device node for this LV.

        LVM がこの LV のデバイスノードを見せるか。
        """
        return "VISIBLE" in self.status

    @property
    def unsupported_reason(self) -> str | None:
        """Why this LV cannot be read, or None if it can.

        この LV を読めない理由。読めるなら None。
        """
        for s in self.segments:
            if s.type != "striped":
                return f"segment type {s.type!r}"
        return None


@dataclass
class VolumeGroup:
    """One volume group, assembled from the metadata copy with the highest seqno.

    ボリュームグループ 1 つ。seqno が最大のメタデータコピーから組み立てる。
    """

    name: str
    uuid: str
    seqno: int
    extent_size: int  # bytes
    pvs: dict[str, PhysicalVolume]
    lvs: dict[str, LogicalVolume]
    metadata: config.Section = field(repr=False)
    # Unreadable metadata copies that were skipped because another copy of
    # the VG metadata was usable (e.g. a copy caught mid-update in a snapshot).
    warnings: list[str] = field(default_factory=list)

    @property
    def missing_pvs(self) -> list[PhysicalVolume]:
        """PVs the metadata lists but that were not among the scanned devices.

        メタデータにはあるが、走査したデバイスの中に無かった PV。
        """
        return [pv for pv in self.pvs.values() if pv.device is None]

    def open_lv(self, name: str) -> LogicalVolumeDevice:
        """Open the named LV as a block device.

        名前の LV をブロックデバイスとして開く。
        """
        try:
            lv = self.lvs[name]
        except KeyError:
            raise DiskReadError(f"no LV {name!r} in VG {self.name!r}") from None
        return LogicalVolumeDevice(self, lv)


class LogicalVolumeDevice:
    """A logical volume exposed as a block device.

    ブロックデバイスとして見せる論理ボリューム。
    """

    def __init__(self, vg: VolumeGroup, lv: LogicalVolume) -> None:
        reason = lv.unsupported_reason
        if reason:
            raise UnsupportedError(f"LV {vg.name}/{lv.name}: {reason}")
        for seg in lv.segments:
            for st in seg.stripes:
                pv = vg.pvs.get(st.pv)
                if pv is None:
                    raise DiskReadError(f"LV {lv.name} references unknown PV {st.pv!r}")
                if pv.device is None:
                    raise DiskReadError(f"LV {lv.name} needs missing PV {pv.uuid}")
        self._vg = vg
        self._lv = lv
        self._size = lv.size
        # Byte offset where each segment starts within the LV, for bisect.
        self._seg_starts = [s.start_extent * lv.extent_size for s in lv.segments]

    @property
    def size(self) -> int:
        return self._size

    @property
    def lv(self) -> LogicalVolume:
        """The LogicalVolume this device reads.

        このデバイスが読む LogicalVolume。
        """
        return self._lv

    def _pieces(self, offset: int, length: int) -> Iterator[tuple[BlockDevice, int, int]]:
        """[offset, offset + length) as (PV device, byte offset, bytes) in order."""
        while length > 0:
            i = bisect.bisect_right(self._seg_starts, offset) - 1
            seg = self._lv.segments[i]
            seg_off = offset - self._seg_starts[i]
            seg_len = seg.extent_count * self._lv.extent_size
            dev, phys, run = self._map(seg, seg_off)
            n = min(length, seg_len - seg_off, run)
            yield dev, phys, n
            offset += n
            length -= n

    def read_at(self, offset: int, length: int) -> bytes:
        check_range(self._size, offset, length)
        out = bytearray()
        for dev, phys, n in self._pieces(offset, length):
            out += dev.read_at(phys, n)
        return bytes(out)

    def will_read(self, offset: int, length: int) -> None:
        check_range(self._size, offset, length)
        for dev, phys, n in self._pieces(offset, length):
            will_read(dev, phys, n)

    def _map(self, seg: Segment, seg_off: int) -> tuple[BlockDevice, int, int]:
        """Map a segment offset to (PV device, byte offset, bytes until the next boundary)."""
        es = self._lv.extent_size
        if len(seg.stripes) == 1:
            st = seg.stripes[0]
            pv = self._vg.pvs[st.pv]
            phys = pv.pe_start + st.start_extent * es + seg_off
            return pv.device, phys, seg.extent_count * es - seg_off  # type: ignore[return-value]

        # Striped: chunks of stripe_size rotate across the stripes.
        n = len(seg.stripes)
        chunk, within = divmod(seg_off, seg.stripe_size)
        row, idx = divmod(chunk, n)
        st = seg.stripes[idx]
        pv = self._vg.pvs[st.pv]
        phys = pv.pe_start + st.start_extent * es + row * seg.stripe_size + within
        return pv.device, phys, seg.stripe_size - within  # type: ignore[return-value]


def _int(d: config.Section, key: str, where: str) -> int:
    """`d[key]` as an int, or a DiskReadError naming `where`."""
    v = d.get(key)
    if not isinstance(v, int):
        raise DiskReadError(f"LVM metadata: {where}: {key} missing or not an integer")
    return v


def _str(d: config.Section, key: str, where: str) -> str:
    """`d[key]` as a str, or a DiskReadError naming `where`."""
    v = d.get(key)
    if not isinstance(v, str):
        raise DiskReadError(f"LVM metadata: {where}: {key} missing or not a string")
    return v


def _section(d: config.Section, key: str, where: str) -> config.Section:
    """`d[key]` as a subsection (missing means empty), or a DiskReadError naming `where`."""
    v = d.get(key, {})
    if not isinstance(v, dict):
        raise DiskReadError(f"LVM metadata: {where}: {key} is not a section")
    return v


def _parse_segment(name: str, seg: config.Section, extent_size: int) -> Segment:
    """One `segmentN` section as a validated Segment."""
    where = f"LV {name}"
    seg_type = _str(seg, "type", where)
    start = _int(seg, "start_extent", where)
    count = _int(seg, "extent_count", where)
    if start < 0 or count <= 0:
        raise DiskReadError(f"LVM metadata: {where}: bad segment extents")
    stripes: list[Stripe] = []
    stripe_size = 0
    if seg_type == "striped":
        raw = seg.get("stripes")
        if not isinstance(raw, list) or len(raw) % 2 or not raw:
            raise DiskReadError(f"LVM metadata: {where}: bad stripes list")
        for pv, pe in zip(raw[0::2], raw[1::2], strict=True):
            if not isinstance(pv, str) or not isinstance(pe, int) or pe < 0:
                raise DiskReadError(f"LVM metadata: {where}: bad stripe entry")
            stripes.append(Stripe(pv, pe))
        if _int(seg, "stripe_count", where) != len(stripes):
            raise DiskReadError(f"LVM metadata: {where}: stripe_count mismatch")
        if len(stripes) > 1:
            stripe_size = _int(seg, "stripe_size", where) * SECTOR
            if stripe_size <= 0 or count % len(stripes):
                raise DiskReadError(f"LVM metadata: {where}: bad striped segment")
    return Segment(start, count, seg_type, stripes, stripe_size)


def build_volume_group(
    metadata: config.Section, devices_by_pv_uuid: dict[str, BlockDevice]
) -> VolumeGroup:
    """Build the VolumeGroup from one parsed metadata text, binding PVs to devices by UUID.

    解析済みメタデータ 1 本から VG を組み立て、PV を UUID でデバイスに結びつける。
    """
    vg_names = [k for k, v in metadata.items() if isinstance(v, dict)]
    if len(vg_names) != 1:
        raise DiskReadError(f"LVM metadata has {len(vg_names)} top-level sections, expected 1")
    vg_name = vg_names[0]
    vg = metadata[vg_name]
    assert isinstance(vg, dict)
    where = f"VG {vg_name}"
    extent_size = _int(vg, "extent_size", where) * SECTOR
    if extent_size <= 0:
        raise DiskReadError(f"LVM metadata: {where}: bad extent_size")

    pvs: dict[str, PhysicalVolume] = {}
    for key, pv in _section(vg, "physical_volumes", where).items():
        if not isinstance(pv, dict):
            continue
        uuid = _str(pv, "id", f"PV {key}")
        pvs[key] = PhysicalVolume(
            key=key,
            uuid=uuid,
            pe_start=_int(pv, "pe_start", f"PV {key}") * SECTOR,
            pe_count=_int(pv, "pe_count", f"PV {key}"),
            device=devices_by_pv_uuid.get(uuid),
        )

    lvs: dict[str, LogicalVolume] = {}
    for name, lv in _section(vg, "logical_volumes", where).items():
        if not isinstance(lv, dict):
            continue
        status = lv.get("status", [])
        segment_count = _int(lv, "segment_count", f"LV {name}")
        segments = []
        for i in range(1, segment_count + 1):
            seg = lv.get(f"segment{i}")
            if not isinstance(seg, dict):
                raise DiskReadError(f"LVM metadata: LV {name}: segment{i} missing")
            segments.append(_parse_segment(name, seg, extent_size))
        segments.sort(key=lambda s: s.start_extent)
        expected = 0
        for s in segments:
            if s.start_extent != expected:
                raise DiskReadError(f"LVM metadata: LV {name}: segments are not contiguous")
            expected += s.extent_count
        lvs[name] = LogicalVolume(
            name=name,
            uuid=_str(lv, "id", f"LV {name}"),
            status=[s for s in status if isinstance(s, str)] if isinstance(status, list) else [],
            segments=segments,
            extent_size=extent_size,
        )

    return VolumeGroup(
        name=vg_name,
        uuid=_str(vg, "id", where),
        seqno=_int(vg, "seqno", where),
        extent_size=extent_size,
        pvs=pvs,
        lvs=lvs,
        metadata=metadata,
    )


def find_volume_groups(
    devices: Iterable[BlockDevice], unreadable: list[str] | None = None
) -> list[VolumeGroup]:
    """Scan devices for LVM2 PVs and assemble every volume group found.

    Pass all disks (or partitions) that may hold PVs of the same VG. For each
    VG the metadata copy with the highest seqno wins. Non-PV devices are
    ignored. PVs that belong to a VG but were not passed in show up in
    VolumeGroup.missing_pvs.

    A damaged metadata copy is skipped (and listed in VolumeGroup.warnings)
    as long as some copy covers the PV it sits on. A PV whose VG cannot be
    determined from any copy is said in `unreadable` (one message a copy) while
    the other volume groups are returned; without `unreadable`, DiskReadError is
    raised.

    デバイス群から LVM2 の PV を探し、見つかったボリュームグループをすべて組み立てる。同じ VG
    の PV を持ちうるディスク（やパーティション）を全部渡すこと。VG ごとに seqno が最大のメタデ
    ータコピーが勝つ。壊れたコピーは、その PV を別のコピーが賄えれば飛ばして警告する。どのコピー
    からも VG が決められない PV は `unreadable` に書き（コピーごとに 1 件）、ほかの VG は返す。
    `unreadable` を渡さなければ DiskReadError。
    """
    labels: list[tuple[PVLabel, BlockDevice]] = []
    for dev in devices:
        label = read_label(dev)
        if label is not None:
            labels.append((label, dev))
    devices_by_uuid = {label.uuid: dev for label, dev in labels}

    best: dict[str, tuple[int, config.Section]] = {}
    errors: dict[str, list[str]] = {}  # PV uuid -> unreadable copies on it
    for label, dev in labels:
        for mda in label.metadata_areas:
            try:
                text = read_metadata_text(dev, mda)
                if text is None:
                    continue
                md = config.parse(text.text)
                vg = build_volume_group(md, {})
            except DiskReadError as err:
                errors.setdefault(label.uuid, []).append(
                    f"PV {label.uuid}: metadata area at {mda.offset}: {err}"
                )
                continue
            prev = best.get(vg.uuid)
            if prev is None or vg.seqno > prev[0]:
                best[vg.uuid] = (vg.seqno, md)

    vgs = [build_volume_group(md, devices_by_uuid) for _, md in best.values()]
    for pv_uuid, msgs in errors.items():
        owners = [vg for vg in vgs if any(pv.uuid == pv_uuid for pv in vg.pvs.values())]
        for vg in owners:
            vg.warnings.extend(msgs)
        if not owners:
            # Its own volume group is lost; the others are not its to take along.
            if unreadable is None:
                raise DiskReadError("; ".join(msgs))
            unreadable.extend(msgs)
    return vgs
