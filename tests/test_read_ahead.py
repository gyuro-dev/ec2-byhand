"""will_read: what each layer tells the disk below it must be what its reads then ask
for, in the same order. A disk that fetches ahead (EBS) fetches what it is told, so
a range told and never read is a request paid for nothing, and a range read but
not told goes back to one request at a time."""

from __future__ import annotations

import base64
import hashlib
import json
from contextlib import ExitStack
from pathlib import Path

import pytest
from conftest import GOLDEN_DIR, golden_cases, require_golden
from memfs import MemFs

from diskread import BlockDevice, BytesDevice, FileDevice, SliceDevice
from diskread.blockdev import ReadAhead, read_chunks, will_read
from diskread.fs import FileType, walk
from diskread.fs.detect import open_fs
from diskread.fs.extents import MappedContent, Run
from diskread.lvm import find_volume_groups
from diskread.partition import read_partition_table
from diskread.source import SystemSource
from ec2_byhand.analyze import Snapshot, analyze
from ec2_byhand.archive import write_outputs
from ec2_byhand.langpkgs import find_language_packages
from ec2_byhand.packages import read_packages

Log = list[tuple[int, int, int]]  # (disk, start, end)


class Recorder:
    """A disk that notes what is read from it and what it is told will be."""

    def __init__(self, dev: BlockDevice, disk: int, reads: Log, told: Log) -> None:
        self._dev, self._disk, self._reads, self._told = dev, disk, reads, told

    @property
    def size(self) -> int:
        return self._dev.size

    def read_at(self, offset: int, length: int) -> bytes:
        self._reads.append((self._disk, offset, offset + length))
        return self._dev.read_at(offset, length)

    def will_read(self, offset: int, length: int) -> None:
        self._told.append((self._disk, offset, offset + length))


def _merged(log: Log) -> Log:
    """The ranges with each that continues the one before joined to it."""
    out: Log = []
    for disk, start, end in log:
        if out and out[-1][0] == disk and out[-1][2] == start:
            out[-1] = (disk, out[-1][1], end)
        elif end > start:
            out.append((disk, start, end))
    return out


def _told_then_read(dev: BlockDevice, reads: Log, told: Log) -> tuple[Log, Log]:
    """What `dev` tells and what it reads, both from the disks below it."""
    reads.clear()
    told.clear()
    will_read(dev)
    data = b"".join(read_chunks(dev, chunk_size=3000))  # chunks that cross runs and blocks
    assert reads, "nothing was read"
    assert len(data) == dev.size
    return _merged(told), _merged(reads)


def test_devices_that_cannot_fetch_ahead_are_not_told() -> None:
    assert not isinstance(BytesDevice(b"x"), ReadAhead)
    will_read(BytesDevice(b"abc"))  # nothing to tell, nothing happens


def test_mapped_content_tells_its_runs_and_skips_holes() -> None:
    reads: Log = []
    told: Log = []
    disk = Recorder(BytesDevice(bytes(range(256)) * 64), 0, reads, told)
    runs = [Run(1, 9, 2), Run(3, 2, 1, unwritten=True), Run(5, 4, 3)]
    content = MappedContent(SliceDevice(disk, 512, disk.size - 512), 1024, runs, 7 * 1024 + 100)
    assert (
        _told_then_read(content, reads, told)
        == ([(0, 512 + 9 * 1024, 512 + 11 * 1024), (0, 512 + 4 * 1024, 512 + 6 * 1024 + 100)],) * 2
    )
    told.clear()
    content.will_read(5 * 1024 + 10, 20)  # a part: only what reading that part reads
    assert told == [(0, 512 + 4 * 1024 + 10, 512 + 4 * 1024 + 30)]


FS_CASES = [
    GOLDEN_DIR / f"{name}.img"
    for name in ("ext4-default", "ext4-noextents", "ext4-bigalloc", "xfs-al2023", "xfs-v4")
]


@pytest.mark.parametrize("image", FS_CASES, ids=lambda p: p.stem)
def test_files_tell_what_reading_them_reads(image: Path) -> None:
    if not image.exists():
        require_golden([], "build_fs.sh")
    reads: Log = []
    told: Log = []
    with FileDevice(image) as f:
        fs = open_fs(Recorder(f, 0, reads, told))
        checked = 0
        for path, ino, st in walk(fs):
            if st.type is not FileType.REG or not st.size:
                continue
            content = fs.open(ino)
            if isinstance(content, BytesDevice):  # inline data: read with the inode
                continue
            told_ranges, read_ranges = _told_then_read(content, reads, told)
            assert told_ranges == read_ranges, path
            checked += 1
        assert checked


LVM_CASES = golden_cases(("lvm-",))


@pytest.mark.parametrize("case", LVM_CASES or [None], ids=(lambda p: p.stem) if LVM_CASES else None)
def test_logical_volumes_tell_what_reading_them_reads(case: Path | None) -> None:
    require_golden(LVM_CASES, "build_lvm.sh")
    assert case is not None
    expected = json.loads(case.read_text(encoding="utf-8"))
    reads: Log = []
    told: Log = []
    with ExitStack() as stack:
        pvs: list[BlockDevice] = []
        for disk, image in enumerate(expected["images"]):
            dev: BlockDevice = Recorder(
                stack.enter_context(FileDevice(GOLDEN_DIR / image)), disk, reads, told
            )
            if expected["partition"] is not None:
                table = read_partition_table(dev)
                assert table is not None
                dev = table.get(expected["partition"]).open(dev)
            pvs.append(dev)
        (vg,) = find_volume_groups(pvs)
        checked = 0
        for exp in expected["lvs"]:
            if exp["layout"] in ("linear", "striped"):
                told_ranges, read_ranges = _told_then_read(vg.open_lv(exp["name"]), reads, told)
                assert told_ranges == read_ranges, exp["name"]
                checked += 1
        assert checked


class _ToldFs(MemFs):
    """A MemFs whose files note what is read from them and what they are told will be."""

    def __init__(self, disk: int, reads: Log, told: Log) -> None:
        super().__init__()
        self._disk, self._reads, self._told = disk, reads, told

    def open(self, ino: int) -> BlockDevice:  # type: ignore[override]
        # One "disk" per file, numbered after the filesystem's, so ranges do not merge.
        return Recorder(super().open(ino), self._disk * 1000 + ino, self._reads, self._told)


def test_hand_placed_files_are_told_before_they_are_hashed() -> None:
    # Seen on Ubuntu: 1,700 files no package owns, hashed one block at a time.
    reads: Log = []
    told: Log = []
    before, after = _ToldFs(1, reads, told), _ToldFs(2, reads, told)
    for fs in (before, after):
        fs.add_file("/opt/app/same", b"same")  # compared, unchanged
        fs.add_file("/opt/app/edited", b"v1" if fs is before else b"v2")  # same size: compared
        fs.add_file("/opt/app/grown", b"x" if fs is before else b"xxxx")  # sizes differ
        fs.add_file("/opt/app/big", bytes(70_000))  # 40 KiB or more: checked for swap first
    after.add_file("/opt/app/new", b"new")
    analyze(
        Snapshot("after", SystemSource.from_fs(after)), Snapshot("b", SystemSource.from_fs(before))
    )
    assert reads, "nothing was read"
    assert sorted(_merged(told)) == sorted(_merged(reads))  # each read told, nothing told unread
    files_read = {disk for disk, _, _ in reads}
    assert len(files_read) == 8  # 5 now, and the 3 baseline copies of the same size


def test_a_whole_file_read_is_told_first() -> None:
    # The rpm database of AL2 is read whole, and is megabytes.
    reads: Log = []
    told: Log = []
    fs = _ToldFs(1, reads, told)
    fs.add_file("/var/lib/rpm/Packages", bytes(5000))
    assert SystemSource.from_fs(fs).read("/var/lib/rpm/Packages") == bytes(5000)
    assert told == reads == [(1000 + fs.ino("/var/lib/rpm/Packages"), 0, 5000)]


class _Events:
    """One log of what is told and what is read, in the order it happens."""

    def __init__(self) -> None:
        self.log: list[tuple[str, int]] = []


class _Log(list):  # type: ignore[type-arg]
    """A Log that also notes each entry in a shared _Events, as `kind`."""

    def __init__(self, events: _Events, kind: str) -> None:
        super().__init__()
        self._events, self._kind = events, kind

    def append(self, item: tuple[int, int, int]) -> None:
        super().append(item)
        self._events.log.append((self._kind, item[0]))


def test_dpkg_info_files_are_told_before_they_are_read() -> None:
    # Seen on Ubuntu 24.04: 1,200 info files of a few KiB, each told only as it was
    # read, so the read-ahead never had a next file to fetch.
    events = _Events()
    reads, told = _Log(events, "read"), _Log(events, "told")
    fs = _ToldFs(1, reads, told)
    status = ""
    for name, arch in (("a", "amd64"), ("b", None), ("c", "amd64")):
        status += f"Package: {name}\nStatus: install ok installed\nVersion: 1\n"
        status += f"Architecture: {arch}\n\n" if arch else "\n"
        stem = f"{name}:{arch}" if arch else name
        fs.add_file(f"/var/lib/dpkg/info/{stem}.list", f"/usr/bin/{name}\n".encode())
        if name != "c":  # one without md5sums
            sums = b"0" * 32 + f"  usr/bin/{name}\n".encode()
            fs.add_file(f"/var/lib/dpkg/info/{stem}.md5sums", sums)
    fs.add_file("/var/lib/dpkg/status", status.encode())
    status_disk = 1000 + fs.ino("/var/lib/dpkg/status")
    db = read_packages(SystemSource.from_fs(fs))
    assert db is not None
    assert [p.name for p in db.packages] == ["a", "b", "c"]
    assert _merged(told) == _merged(reads)  # the same ranges, in the same order
    info = [(kind, disk) for kind, disk in events.log if disk != status_disk]
    assert len({disk for _, disk in info}) == 5
    first_read = next(i for i, (kind, _) in enumerate(info) if kind == "read")
    assert first_read == 5  # all five told before the first is read


def test_archived_files_are_told_before_they_are_read(tmp_path: Path) -> None:
    # A server whose files no package owns are gigabytes reads them all again for
    # after.tar.gz, one file after another unless told first.
    events = _Events()
    reads, told = _Log(events, "read"), _Log(events, "told")
    fs = _ToldFs(1, reads, told)
    paths = ["/opt/app/a.conf", "/opt/app/big.bin", "/opt/app/c.conf"]
    fs.add_file(paths[0], b"a" * 10)
    fs.add_file(paths[1], bytes(70_000))  # 40 KiB or more: checked for swap first
    fs.add_file(paths[2], b"c" * 10)
    manifest = {
        "hand_placed": [{"path": p, "status": "added"} for p in paths],
        "modified_package_files": [],
        "deleted": [],
    }
    write_outputs(manifest, SystemSource.from_fs(fs), None, tmp_path)
    assert _merged(told) == _merged(reads)  # the same ranges, in the same order
    last_told = max(i for i, (kind, _) in enumerate(events.log) if kind == "told")
    read_after = {disk for kind, disk in events.log[last_told:] if kind == "read"}
    assert read_after == {1000 + fs.ino(p) for p in paths}  # all told before any is read


def _covered(ranges: Log) -> dict[int, list[tuple[int, int]]]:
    """Per disk, the ranges joined where they touch or overlap."""
    out: dict[int, list[tuple[int, int]]] = {}
    for disk, start, end in sorted(ranges):
        spans = out.setdefault(disk, [])
        if spans and start <= spans[-1][1]:
            spans[-1] = (spans[-1][0], max(spans[-1][1], end))
        else:
            spans.append((start, end))
    return out


@pytest.mark.parametrize("image", FS_CASES, ids=lambda p: p.stem)
def test_the_walk_tells_only_directories_it_lists(image: Path) -> None:
    # The walk goes a level at a time and tells every directory of a level before
    # listing any: what it tells must all be read (inodes are read without telling).
    if not image.exists():
        require_golden([], "build_fs.sh")
    reads: Log = []
    told: Log = []
    with FileDevice(image) as f:
        fs = open_fs(Recorder(f, 0, reads, told))
        paths = [path for path, _, _ in walk(fs)]
    assert told, "nothing was told"
    read = _covered(reads)
    for disk, start, end in told:
        assert any(s <= start and end <= e for s, e in read[disk]), (start, end)
    assert len(paths) == len(set(paths))


def _record_line(path: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{path},sha256={digest},{len(data)}\n"


def test_pip_and_npm_files_are_told_before_they_are_read() -> None:
    # An app's virtualenv holds thousands of small files, which RECORD has hashes for,
    # and node_modules hundreds of package.json: each was read one at a time.
    events = _Events()
    reads, told = _Log(events, "read"), _Log(events, "told")
    fs = _ToldFs(1, reads, told)
    site = "/opt/app/venv/lib/python3.12/site-packages"
    files = {"pkg/__init__.py": b"x = 1\n", "pkg/a.py": b"a = 1\n", "pkg/b.py": b"b = 1\n"}
    record = "".join(_record_line(p, d) for p, d in files.items()) + "pkg-1.0.dist-info/RECORD,,\n"
    for rel, data in files.items():
        fs.add_file(f"{site}/{rel}", b"a = 2\n" if rel == "pkg/a.py" else data)  # same size
    fs.add_file(f"{site}/pkg-1.0.dist-info/METADATA", b"Name: pkg\nVersion: 1.0\n")
    fs.add_file(f"{site}/pkg-1.0.dist-info/INSTALLER", b"pip\n")
    fs.add_file(f"{site}/pkg-1.0.dist-info/RECORD", record.encode())
    fs.add_file("/opt/web/node_modules/left-pad/package.json", b'{"name": "left-pad"}')
    src = SystemSource.from_fs(fs)
    candidates = [path.decode() for path, *_ in src.walk()]
    reads.clear()
    told.clear()
    events.log.clear()
    found = {p.name: p for p in find_language_packages(src, candidates)}
    assert found["pkg"].modified == [f"{site}/pkg/a.py"]
    assert "left-pad" in found
    assert _merged(told) == _merged(reads)  # the same ranges, in the same order
    disk = {path: 1000 + fs.ino(path) for path in candidates}
    metadata = {disk[f"{site}/pkg-1.0.dist-info/{n}"] for n in ("METADATA", "INSTALLER", "RECORD")}
    metadata.add(disk["/opt/web/node_modules/left-pad/package.json"])
    hashed = {disk[f"{site}/{rel}"] for rel in files}
    kinds = [(kind, d) for kind, d in events.log]
    first_meta_read = next(i for i, (k, d) in enumerate(kinds) if k == "read" and d in metadata)
    assert {d for k, d in kinds[:first_meta_read] if k == "told"} == metadata
    first_hash_read = next(i for i, (k, d) in enumerate(kinds) if k == "read" and d in hashed)
    told_before = {d for k, d in kinds[:first_hash_read] if k == "told"}
    assert hashed <= told_before  # all three told before the first is hashed


def test_metadata_not_read_is_not_told() -> None:
    # Told and never read is a request paid for nothing: a node_modules holds many a
    # package.json that is not a package's own (tests, nested node_modules), and an
    # .egg-info without installed-files.txt is not read at all.
    reads: Log = []
    told: Log = []
    fs = _ToldFs(1, reads, told)
    site = "/usr/lib/python3/site-packages"
    fs.add_file(f"{site}/old-1.0.egg-info/PKG-INFO", b"Name: old\nVersion: 1.0\n")  # no listing
    fs.add_file(f"{site}/kept-2.0.egg-info/PKG-INFO", b"Name: kept\nVersion: 2.0\n")
    fs.add_file(f"{site}/kept-2.0.egg-info/installed-files.txt", b"../kept.py\n")
    fs.add_file(f"{site}/kept.py", b"x = 1\n")
    nm = "/opt/web/node_modules"
    fs.add_file(f"{nm}/a/package.json", b'{"name": "a"}')
    fs.add_file(f"{nm}/a/test/fixture/package.json", b'{"name": "fixture"}')  # not a package
    fs.add_file(f"{nm}/a/node_modules/b/package.json", b'{"name": "b"}')  # nested: part of a
    src = SystemSource.from_fs(fs)
    candidates = [path.decode() for path, *_ in src.walk()]
    reads.clear()
    told.clear()
    found = sorted(p.name for p in find_language_packages(src, candidates))
    assert found == ["a", "kept"]
    assert _merged(told) == _merged(reads)  # the same ranges, in the same order
    listing = 1000 + fs.ino(f"{site}/kept-2.0.egg-info/installed-files.txt")
    assert [d for d, _, _ in reads].count(listing) == 1  # read once, not again for the files
