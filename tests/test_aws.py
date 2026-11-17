"""EBS snapshots as disks, without AWS: a fake "ebs" client serves golden
images block by block (as ListSnapshotBlocks / GetSnapshotBlock would),
and the EC2 calls go through botocore's Stubber."""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import io
import json
import random
import threading
from pathlib import Path

import boto3
import botocore.waiter
import pytest
from botocore.exceptions import ClientError, IncompleteReadError
from botocore.stub import ANY, Stubber
from conftest import GOLDEN_DIR

from diskread import BytesDevice, DiskReadError, FileDevice
from ec2_byhand import cli
from ec2_byhand.aws.ebs import (
    FETCH_ATTEMPTS,
    READ_AHEAD_BLOCKS,
    READ_AHEAD_THREADS,
    EbsSnapshotDevice,
)
from ec2_byhand.aws.snapshots import (
    TAG_KEY,
    AwsSourceError,
    Disk,
    delete_snapshots,
    describe_instance,
    image_disks,
    snapshot_instance,
)
from ec2_byhand.packages import read_packages
from ec2_byhand.packages.verify import verify_packages

BLOCK = 512 * 1024
CURRENT = GOLDEN_DIR / "verify-al2023.img"
BASELINE = GOLDEN_DIR / "verify-al2023-before.img"


class _ValidationException(Exception):
    pass


class FakeEbs:
    """The two EBS direct API reads, served from local images.

    Like the real service, only blocks holding data are listed (the others
    read as zeros), and every block comes with its SHA-256."""

    class exceptions:
        ValidationException = _ValidationException

    def __init__(self, images: dict[str, Path | bytes], page: int = 10000) -> None:
        self._devs = {}
        for snap, src in images.items():
            dev = BytesDevice(src) if isinstance(src, bytes) else FileDevice(src)
            self._devs[snap] = dev
        self.page = page
        self._read_lock = threading.Lock()
        self.gets: list[tuple[str, int]] = []
        self.generation = 0  # bumped to expire every token handed out
        self.corrupt: set[tuple[str, int]] = set()

    def _data_blocks(self, snap: str) -> list[int]:
        dev = self._devs[snap]
        return [
            i
            for i in range(-(-dev.size // BLOCK))
            if dev.read_at(i * BLOCK, min(BLOCK, dev.size - i * BLOCK)).strip(b"\0")
        ]

    def list_snapshot_blocks(self, SnapshotId, MaxResults, NextToken=None, StartingBlockIndex=None):
        dev = self._devs[SnapshotId]
        blocks = self._data_blocks(SnapshotId)
        start = int(NextToken or 0)
        chunk = blocks[start : start + min(MaxResults, self.page)]
        resp = {
            "Blocks": [
                {"BlockIndex": i, "BlockToken": f"{SnapshotId}/{i}/{self.generation}"}
                for i in chunk
            ],
            "ExpiryTime": datetime.datetime(2030, 1, 1),
            "VolumeSize": -(-dev.size // (1 << 30)),
            "BlockSize": BLOCK,
        }
        if start + len(chunk) < len(blocks):
            resp["NextToken"] = str(start + len(chunk))
        return resp

    def get_snapshot_block(self, SnapshotId, BlockIndex, BlockToken):
        if BlockToken != f"{SnapshotId}/{BlockIndex}/{self.generation}":
            raise _ValidationException("invalid or expired block token")
        self.gets.append((SnapshotId, BlockIndex))
        dev = self._devs[SnapshotId]
        off = BlockIndex * BLOCK
        with self._read_lock:  # a FileDevice seeks, and the device reads from several threads
            data = dev.read_at(off, min(BLOCK, dev.size - off)).ljust(BLOCK, b"\0")
        checksum = base64.b64encode(hashlib.sha256(data).digest()).decode()
        if (SnapshotId, BlockIndex) in self.corrupt:
            data = b"\1" + data[1:]
        return {
            "DataLength": BLOCK,
            "BlockData": io.BytesIO(data),
            "Checksum": checksum,
            "ChecksumAlgorithm": "SHA256",
        }


def _image(seed: int = 1) -> bytes:
    rnd = random.Random(seed)
    img = bytearray(1 << 30)  # 1 GiB volume, data in a few blocks only
    for i in (0, 1, 7, 2047):
        img[i * BLOCK : (i + 1) * BLOCK] = rnd.randbytes(BLOCK)
    return bytes(img)


def test_reads_match_the_image_and_skip_empty_blocks() -> None:
    img = _image()
    fake = FakeEbs({"snap-1": img}, page=2)  # several ListSnapshotBlocks pages
    dev = EbsSnapshotDevice(fake, "snap-1", cache_blocks=2)
    assert dev.size == len(img)
    assert dev.stats.list_requests == 2
    rnd = random.Random(7)
    for _ in range(200):
        off = rnd.randrange(0, len(img) - 3 * BLOCK)
        n = rnd.randrange(1, 3 * BLOCK)
        assert dev.read_at(off, n) == img[off : off + n]
    assert dev.read_at(len(img) - 10, 10) == img[-10:]
    assert {i for _, i in fake.gets} <= {0, 1, 7, 2047}  # zero blocks are never requested


def test_cache_avoids_repeat_requests() -> None:
    fake = FakeEbs({"snap-1": _image()})
    dev = EbsSnapshotDevice(fake, "snap-1")
    for _ in range(10):
        dev.read_at(100, 4096)
        dev.read_at(BLOCK + 5, 100)
    assert fake.gets == [("snap-1", 0), ("snap-1", 1)]


def test_checksum_mismatch_and_expired_tokens() -> None:
    fake = FakeEbs({"snap-1": _image()})
    dev = EbsSnapshotDevice(fake, "snap-1")
    fake.generation += 1  # every token expires
    assert dev.read_at(0, 4) == _image()[:4]  # listed again, then read
    assert dev.stats.list_requests == 2
    fake.corrupt.add(("snap-1", 7))
    with pytest.raises(DiskReadError, match="SHA-256"):
        dev.read_at(7 * BLOCK, 4)
    assert fake.gets.count(("snap-1", 7)) == FETCH_ATTEMPTS  # asked again before giving up


class _DroppedStream:
    """A block's data on a connection that drops before the end."""

    def read(self) -> bytes:
        raise IncompleteReadError(actual_bytes=100, expected_bytes=BLOCK)


@pytest.mark.parametrize("failure", ["dropped-connection", "bad-checksum"])
def test_a_block_that_arrives_broken_is_asked_for_again(failure: str) -> None:
    fake = FakeEbs({"snap-1": _image()})
    get = fake.get_snapshot_block
    broken = [True]  # the first transfer only

    def flaky(**kwargs):
        resp = get(**kwargs)
        if broken.pop() if broken else False:
            if failure == "dropped-connection":
                resp["BlockData"] = _DroppedStream()
            else:
                resp["Checksum"] = "not the checksum"
        return resp

    fake.get_snapshot_block = flaky
    dev = EbsSnapshotDevice(fake, "snap-1")
    assert dev.read_at(7 * BLOCK, 4) == _image()[7 * BLOCK : 7 * BLOCK + 4]
    assert fake.gets == [("snap-1", 7)] * 2
    assert dev.stats.block_requests == 2  # the broken one was billed too


def test_a_connection_that_keeps_dropping_ends_the_read() -> None:
    fake = FakeEbs({"snap-1": _image()})
    fake.get_snapshot_block = lambda **kwargs: {"BlockData": _DroppedStream()}
    dev = EbsSnapshotDevice(fake, "snap-1")
    with pytest.raises(IncompleteReadError):
        dev.read_at(0, 4)


# --- fetching ahead ---------------------------------------------------------

DATA_BLOCKS = range(0, 400, 2)  # every other block of the first 200 MiB holds data


def _busy_image() -> bytes:
    rnd = random.Random(3)
    img = bytearray(1 << 30)
    for i in DATA_BLOCKS:
        img[i * BLOCK : (i + 1) * BLOCK] = rnd.randbytes(BLOCK)
    return bytes(img)


def _files(seed: int = 5, count: int = 300) -> list[tuple[int, int]]:
    """Ranges read one after another, as file contents are: most small, some spanning
    blocks, some sharing a block with a file read long before."""
    rnd = random.Random(seed)
    out = []
    for _ in range(count):
        offset = rnd.randrange(0, 410 * BLOCK)
        out.append((offset, rnd.choice([100, 4096, 70_000, 3 * BLOCK])))
    return out


def _read_ahead(dev: EbsSnapshotDevice, files: list[tuple[int, int]]) -> list[bytes]:
    for offset, length in files:
        dev.will_read(offset, length)
    return [dev.read_at(offset, length) for offset, length in files]


@pytest.mark.parametrize("cache_blocks", [512, 8])
def test_fetching_ahead_asks_for_no_more_than_one_by_one(cache_blocks: int) -> None:
    img, files = _busy_image(), _files()
    one_by_one, ahead = FakeEbs({"snap-1": img}), FakeEbs({"snap-1": img})
    dev1 = EbsSnapshotDevice(one_by_one, "snap-1", cache_blocks=cache_blocks, threads=0)
    dev2 = EbsSnapshotDevice(ahead, "snap-1", cache_blocks=cache_blocks)
    expected = [img[offset : offset + length] for offset, length in files]
    assert [dev1.read_at(offset, length) for offset, length in files] == expected
    assert _read_ahead(dev2, files) == expected
    assert dev2.stats.block_requests == len(ahead.gets)
    if cache_blocks == 512:  # all fits: the very same requests
        assert sorted(ahead.gets) == sorted(one_by_one.gets)
        assert dev2.stats == dev1.stats
    else:  # a block read again soon is not dropped from the small cache in between
        assert len(ahead.gets) <= len(one_by_one.gets)


def test_blocks_fetched_ahead_are_kept_until_read() -> None:
    fake = FakeEbs({"snap-1": _busy_image()})
    dev = EbsSnapshotDevice(fake, "snap-1", cache_blocks=2)
    files = [(i * BLOCK, BLOCK) for i in DATA_BLOCKS[:50]]
    _read_ahead(dev, files)
    assert sorted(fake.gets) == [("snap-1", i) for i in DATA_BLOCKS[:50]]  # each once


def test_a_cached_block_told_again_is_not_dropped_before_it_is_read() -> None:
    # Seen on Ubuntu 24.04: a block read once and told again further on (a small file
    # sharing it) fell out of the cache before the read-ahead reached it.
    fake = FakeEbs({"snap-1": _busy_image()})
    dev = EbsSnapshotDevice(fake, "snap-1", cache_blocks=4)
    shared = DATA_BLOCKS[0]
    dev.read_at(shared * BLOCK, 10)  # now in the cache
    later = DATA_BLOCKS[1 : READ_AHEAD_BLOCKS + 20]  # more than the read-ahead and the cache
    files = [(i * BLOCK, BLOCK) for i in later] + [(shared * BLOCK + 100, 10)]
    _read_ahead(dev, files)
    assert fake.gets.count(("snap-1", shared)) == 1


def test_blocks_left_unread_are_not_fetched_again() -> None:
    img = _busy_image()
    fake = FakeEbs({"snap-1": img})
    dev = EbsSnapshotDevice(fake, "snap-1")
    first, second = (0, 20 * BLOCK), (100 * BLOCK, 20 * BLOCK)
    dev.will_read(*first)
    dev.will_read(*second)
    assert dev.read_at(0, 10) == img[:10]  # the first given up after one block
    assert dev.read_at(*second) == img[100 * BLOCK : 120 * BLOCK]
    assert dev.read_at(*first) == img[: 20 * BLOCK]
    assert sorted(fake.gets) == [("snap-1", i) for i in range(0, 120, 2) if i < 20 or i >= 100]


def test_errors_while_fetching_ahead() -> None:
    img = _busy_image()
    fake = FakeEbs({"snap-1": img})
    dev = EbsSnapshotDevice(fake, "snap-1")
    fake.generation += 1  # every token expires, under all the threads at once
    fake.corrupt.add(("snap-1", 40))
    files = [(i * BLOCK, BLOCK) for i in DATA_BLOCKS[:60]]
    for f in files:
        dev.will_read(*f)
    for offset, length in files:
        if offset == 40 * BLOCK:
            with pytest.raises(DiskReadError, match="SHA-256"):
                dev.read_at(offset, length)
        else:
            assert dev.read_at(offset, length) == img[offset : offset + length]
    assert dev.stats.list_requests == 2  # listed again once, not by every thread
    assert fake.gets.count(("snap-1", 40)) == FETCH_ATTEMPTS
    assert len(fake.gets) == 59 + FETCH_ATTEMPTS
    assert dev.stats.block_requests == len(fake.gets)
    with pytest.raises(DiskReadError, match="SHA-256"):  # not remembered: asked for again
        dev.read_at(40 * BLOCK, 1)
    assert fake.gets.count(("snap-1", 40)) == 2 * FETCH_ATTEMPTS


def test_a_dropped_connection_while_fetching_ahead() -> None:
    img = _busy_image()
    fake = FakeEbs({"snap-1": img})
    get = fake.get_snapshot_block
    dropped: set[int] = set()

    def flaky(**kwargs):
        resp = get(**kwargs)
        if kwargs["BlockIndex"] % 10 == 0 and kwargs["BlockIndex"] not in dropped:
            dropped.add(kwargs["BlockIndex"])
            resp["BlockData"] = _DroppedStream()
        return resp

    fake.get_snapshot_block = flaky
    dev = EbsSnapshotDevice(fake, "snap-1")
    assert _read_ahead(dev, [(0, 100 * BLOCK)]) == [img[: 100 * BLOCK]]
    assert len(fake.gets) == 50 + len(dropped) == dev.stats.block_requests


def test_close_stops_fetching_ahead() -> None:
    img = _busy_image()
    fake = FakeEbs({"snap-1": img})
    dev = EbsSnapshotDevice(fake, "snap-1")
    dev.will_read(0, 400 * BLOCK)  # 200 blocks with data
    dev.close()
    fetched = len(fake.gets)
    assert fetched <= READ_AHEAD_BLOCKS
    assert dev.read_at(398 * BLOCK, 10) == img[398 * BLOCK : 398 * BLOCK + 10]  # still readable
    assert len(fake.gets) == fetched + 1


def test_package_check_fetches_ahead_what_it_reads_one_by_one() -> None:
    _need_images()
    results, stats = [], []
    for threads in (0, READ_AHEAD_THREADS):
        dev = EbsSnapshotDevice(FakeEbs({"snap-now": CURRENT}), "snap-now", threads=threads)
        snap = cli.open_disks({"/dev/xvda": dev}, "current")
        db = read_packages(snap.source)
        assert db is not None
        results.append(verify_packages(snap.source, db))
        stats.append(dev.stats)
        dev.close()
    assert results[0] == results[1]
    assert stats[0] == stats[1]


# --- EC2: which snapshots -------------------------------------------------


@pytest.fixture
def ec2():
    client = boto3.client(
        "ec2", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x"
    )
    with Stubber(client) as stub:
        yield client, stub
        stub.assert_no_pending_responses()


def _instance_response(volumes: dict[str, str]) -> dict:
    return {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-0abc",
                        "ImageId": "ami-0base",
                        "RootDeviceName": "/dev/xvda",
                        "BlockDeviceMappings": [
                            {"DeviceName": d, "Ebs": {"VolumeId": v}} for d, v in volumes.items()
                        ],
                    }
                ]
            }
        ]
    }


def test_instance_snapshots_and_ami(ec2) -> None:
    client, stub = ec2
    stub.add_response(
        "describe_instances",
        _instance_response({"/dev/xvda": "vol-1", "/dev/xvdf": "vol-2"}),
        {"InstanceIds": ["i-0abc"]},
    )
    stub.add_response(
        "create_snapshots",
        {
            "Snapshots": [
                {"SnapshotId": "snap-b", "VolumeId": "vol-2"},
                {"SnapshotId": "snap-a", "VolumeId": "vol-1"},
            ]
        },
        {
            "InstanceSpecification": {"InstanceId": "i-0abc", "ExcludeBootVolume": False},
            "Description": "ec2-byhand: i-0abc",
            "TagSpecifications": [
                {"ResourceType": "snapshot", "Tags": [{"Key": TAG_KEY, "Value": "i-0abc"}]}
            ],
        },
    )
    stub.add_response(
        "describe_images",
        {
            "Images": [
                {
                    "ImageId": "ami-0base",
                    "BlockDeviceMappings": [
                        {"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": "snap-ami"}},
                        {"DeviceName": "/dev/sdb", "VirtualName": "ephemeral0"},
                    ],
                }
            ]
        },
        {"ImageIds": ["ami-0base"]},
    )

    inst = describe_instance(client, "i-0abc")
    assert inst.image_id == "ami-0base"
    assert inst.volumes == {"/dev/xvda": "vol-1", "/dev/xvdf": "vol-2"}
    assert snapshot_instance(client, inst) == [
        Disk("/dev/xvda", "snap-a", "vol-1"),
        Disk("/dev/xvdf", "snap-b", "vol-2"),
    ]
    assert image_disks(client, "ami-0base") == [Disk("/dev/xvda", "snap-ami")]


def test_deregistered_ami_is_explained(ec2) -> None:
    client, stub = ec2
    stub.add_client_error(
        "describe_images", "InvalidAMIID.NotFound", expected_params={"ImageIds": ["ami-gone"]}
    )
    with pytest.raises(AwsSourceError, match="--baseline-snapshot"):
        image_disks(client, "ami-gone")


# --- the whole command, end to end -----------------------------------------


def _need_images() -> None:
    if not BASELINE.exists():
        pytest.skip(
            "no golden data; run: wsl -u root -- bash tools/golden/build_verify.sh tests/golden/out"
        )


def test_analyze_instance_matches_image_files(ec2, monkeypatch, tmp_path: Path) -> None:
    _need_images()
    client, stub = ec2
    stub.add_response(
        "describe_instances",
        _instance_response({"/dev/xvda": "vol-1"}),
        {"InstanceIds": ["i-0abc"]},
    )
    # The baseline is resolved and opened before the snapshots are created,
    # so a bad baseline cannot waste the minutes a snapshot wait takes.
    stub.add_response(
        "describe_images",
        {
            "Images": [
                {
                    "ImageId": "ami-0base",
                    "BlockDeviceMappings": [
                        {"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": "snap-ami"}}
                    ],
                }
            ]
        },
        {"ImageIds": ["ami-0base"]},
    )
    stub.add_response(
        "create_snapshots", {"Snapshots": [{"SnapshotId": "snap-now", "VolumeId": "vol-1"}]}
    )
    stub.add_response(
        "describe_snapshots",
        {"Snapshots": [{"SnapshotId": "snap-now", "State": "pending"}]},
        {"SnapshotIds": ["snap-now"]},
    )
    stub.add_response(
        "describe_snapshots",
        {"Snapshots": [{"SnapshotId": "snap-now", "State": "completed"}]},
        {"SnapshotIds": ["snap-now"]},
    )
    stub.add_response(
        "delete_snapshot", {}, {"SnapshotId": "snap-now"}
    )  # made by the run, so removed
    fake = FakeEbs({"snap-now": CURRENT, "snap-ami": BASELINE})
    monkeypatch.setattr(cli, "make_aws_clients", lambda region, profile: (client, fake))
    # The pause between looks at the snapshot (the time module is botocore's and ours).
    monkeypatch.setattr(botocore.waiter.time, "sleep", lambda s: None)

    out_aws, out_files = tmp_path / "aws", tmp_path / "files"
    assert cli.main(["--instance-id", "i-0abc", "-o", str(out_aws), "-q"]) == 0
    assert (
        cli.main(
            [
                "--current-image",
                str(CURRENT),
                "--baseline-image",
                str(BASELINE),
                "-o",
                str(out_files),
                "-q",
            ]
        )
        == 0
    )
    a = json.loads((out_aws / "manifest.json").read_text(encoding="utf-8"))
    f = json.loads((out_files / "manifest.json").read_text(encoding="utf-8"))
    assert a["current"]["label"] == "i-0abc /dev/xvda=snap-now"
    assert a["baseline"]["label"] == "ami-0base /dev/xvda=snap-ami"
    for key in (
        "hand_placed",
        "modified_package_files",
        "deleted",
        "packages",
        "services",
        "summary",
        "warnings",
    ):
        assert a[key] == f[key], key
    assert (out_aws / "after.tar.gz").read_bytes() == (out_files / "after.tar.gz").read_bytes()
    requested = len(fake.gets) * BLOCK
    assert requested < (CURRENT.stat().st_size + BASELINE.stat().st_size)  # not a full copy


def test_snapshots_are_deleted_when_the_run_fails(ec2, monkeypatch, tmp_path: Path) -> None:
    client, stub = ec2
    stub.add_response(
        "describe_instances",
        _instance_response({"/dev/xvda": "vol-1"}),
        {"InstanceIds": ["i-0abc"]},
    )
    stub.add_response(
        "create_snapshots", {"Snapshots": [{"SnapshotId": "snap-now", "VolumeId": "vol-1"}]}
    )
    stub.add_client_error(
        "describe_snapshots", "UnauthorizedOperation", expected_params={"SnapshotIds": ["snap-now"]}
    )
    stub.add_response("delete_snapshot", {}, {"SnapshotId": "snap-now"})
    monkeypatch.setattr(cli, "make_aws_clients", lambda region, profile: (client, FakeEbs({})))
    args = ["--instance-id", "i-0abc", "--no-baseline", "-o", str(tmp_path / "o"), "-q"]
    assert cli.main(args) == 1


def test_bad_baseline_fails_before_snapshots_are_made(ec2, monkeypatch, tmp_path: Path) -> None:
    # No create_snapshots is stubbed: the deregistered AMI must end the run
    # before any snapshot is created (and before the minutes waiting on one).
    client, stub = ec2
    stub.add_response(
        "describe_instances",
        _instance_response({"/dev/xvda": "vol-1"}),
        {"InstanceIds": ["i-0abc"]},
    )
    stub.add_client_error(
        "describe_images", "InvalidAMIID.NotFound", expected_params={"ImageIds": ["ami-0base"]}
    )
    monkeypatch.setattr(cli, "make_aws_clients", lambda region, profile: (client, FakeEbs({})))
    assert cli.main(["--instance-id", "i-0abc", "-o", str(tmp_path / "o"), "-q"]) == 2


class DeniedEbs(FakeEbs):
    """An EBS client refusing ListSnapshotBlocks with `code` and `message`."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__({})
        self._error = {"Error": {"Code": code, "Message": message}}

    def list_snapshot_blocks(self, SnapshotId, MaxResults, NextToken=None, StartingBlockIndex=None):
        raise ClientError(self._error, "ListSnapshotBlocks")


def _image_response(image_id: str, snapshot: str, state: str | None = None) -> dict:
    image: dict = {
        "ImageId": image_id,
        "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": snapshot}}],
    }
    if state:
        image["State"] = state
    return {"Images": [image]}


def test_unreadable_baseline_snapshot_is_explained(
    ec2, monkeypatch, tmp_path: Path, capsys
) -> None:
    client, stub = ec2
    stub.add_response(
        "describe_instances",
        _instance_response({"/dev/xvda": "vol-1"}),
        {"InstanceIds": ["i-0abc"]},
    )
    stub.add_response(
        "describe_images", _image_response("ami-0base", "snap-ami"), {"ImageIds": ["ami-0base"]}
    )
    ebs = DeniedEbs("AccessDeniedException", "not authorized")
    monkeypatch.setattr(cli, "make_aws_clients", lambda region, profile: (client, ebs))
    argv = ["--instance-id", "i-0abc", "-o", str(tmp_path / "o"), "-q"]
    assert cli.main(argv) == 2
    err = capsys.readouterr().err
    assert "snap-ami" in err
    assert "IAM policy" in err
    assert "copy-image" in err
    assert "--baseline-ami" in err  # a running server cannot be launched again from a copy
    assert "--no-baseline" in err
    assert "launch" not in err
    lines = err.splitlines()
    assert lines[0].startswith("ec2-byhand: error: baseline: cannot read the blocks of snap-ami")
    assert lines[1:] == []


class PublicAmiEbs(FakeEbs):
    """Golden images as snapshots, refusing those in `public` as AWS does the snapshots
    behind a public AMI (what it answered on 2026-11-13 for the public AL2023 AMI)."""

    def __init__(self, images: dict[str, Path | bytes], public: set[str]) -> None:
        super().__init__(images)
        self._public = public

    def list_snapshot_blocks(self, SnapshotId, MaxResults, NextToken=None, StartingBlockIndex=None):
        if SnapshotId in self._public:
            error = {"Code": "ValidationException", "Message": "Public snapshots are not supported"}
            raise ClientError({"Error": error}, "ListSnapshotBlocks")
        return super().list_snapshot_blocks(SnapshotId, MaxResults, NextToken, StartingBlockIndex)


def _copy_params(image_id: str = "ami-0base") -> dict:
    tags = [{"Key": TAG_KEY, "Value": image_id}]
    return {
        "SourceImageId": image_id,
        "SourceRegion": "us-east-1",
        "Name": ANY,
        "Description": ANY,
        "TagSpecifications": [
            {"ResourceType": "image", "Tags": tags},
            {"ResourceType": "snapshot", "Tags": tags},
        ],
    }


def _stub_public_instance(stub: Stubber) -> None:
    """The instance, launched from a public AMI."""
    stub.add_response(
        "describe_instances",
        _instance_response({"/dev/xvda": "vol-1"}),
        {"InstanceIds": ["i-0abc"]},
    )
    stub.add_response(
        "describe_images", _image_response("ami-0base", "snap-ami"), {"ImageIds": ["ami-0base"]}
    )


def test_a_public_ami_is_copied_while_the_snapshots_are_taken(
    ec2, monkeypatch, tmp_path: Path, capsys
) -> None:
    _need_images()
    client, stub = ec2
    _stub_public_instance(stub)
    # The copy is started before the snapshots, so that it is made while they are.
    stub.add_response("copy_image", {"ImageId": "ami-0copy"}, _copy_params())
    stub.add_response(
        "create_snapshots", {"Snapshots": [{"SnapshotId": "snap-now", "VolumeId": "vol-1"}]}
    )
    stub.add_response(
        "describe_snapshots",
        {"Snapshots": [{"SnapshotId": "snap-now", "State": "completed"}]},
        {"SnapshotIds": ["snap-now"]},
    )
    for state in ("pending", "available"):
        stub.add_response(
            "describe_images",
            _image_response("ami-0copy", "snap-copy", state),
            {"ImageIds": ["ami-0copy"]},
        )
    stub.add_response(
        "describe_images", _image_response("ami-0copy", "snap-copy"), {"ImageIds": ["ami-0copy"]}
    )
    # Both deleted at the end: the snapshot, then the copy with its snapshot.
    stub.add_response("delete_snapshot", {}, {"SnapshotId": "snap-now"})
    stub.add_response(
        "deregister_image",
        {
            "Return": True,
            "DeleteSnapshotResults": [{"SnapshotId": "snap-copy", "ReturnCode": "success"}],
        },
        {"ImageId": "ami-0copy", "DeleteAssociatedSnapshots": True},
    )
    fake = PublicAmiEbs(
        {"snap-now": CURRENT, "snap-ami": BASELINE, "snap-copy": BASELINE}, {"snap-ami"}
    )
    monkeypatch.setattr(cli, "make_aws_clients", lambda region, profile: (client, fake))
    monkeypatch.setattr(botocore.waiter.time, "sleep", lambda s: None)  # the pause between looks

    out_aws, out_files = tmp_path / "aws", tmp_path / "files"
    assert cli.main(["--instance-id", "i-0abc", "-o", str(out_aws)]) == 0
    captured = capsys.readouterr()
    assert "copying it into this account as ami-0copy (deleted at the end)" in captured.err
    assert "AMI copies made:        ami-0copy (deleted)" in captured.out
    assert "snapshots made:         snap-now (deleted)" in captured.out
    argv = ["--current-image", str(CURRENT), "--baseline-image", str(BASELINE), "-o"]
    assert cli.main([*argv, str(out_files), "-q"]) == 0
    a = json.loads((out_aws / "manifest.json").read_text(encoding="utf-8"))
    f = json.loads((out_files / "manifest.json").read_text(encoding="utf-8"))
    assert a["baseline"]["label"] == "ami-0base (copied as ami-0copy) /dev/xvda=snap-copy"
    for key in ("hand_placed", "modified_package_files", "deleted", "packages", "summary"):
        assert a[key] == f[key], key
    assert not [g for g in fake.gets if g[0] == "snap-ami"]


@pytest.mark.parametrize(
    ("code", "message", "command"),
    [
        # What AWS answered on 2026-11-13 for a RHEL AMI: it cannot be copied at all.
        ("InvalidRequest", "You do not have permission to access the storage of this ami", False),
        # The IAM policy does not allow it: the user may still copy it by hand.
        ("UnauthorizedOperation", "You are not authorized to perform this operation.", True),
    ],
)
def test_a_public_ami_that_cannot_be_copied_is_explained(
    ec2, monkeypatch, tmp_path: Path, capsys, code: str, message: str, command: bool
) -> None:
    client, stub = ec2
    _stub_public_instance(stub)
    stub.add_client_error("copy_image", code, message, expected_params=_copy_params())
    # Nothing else: no snapshot is taken for a run that cannot have its baseline.
    ebs = PublicAmiEbs({}, {"snap-ami"})
    monkeypatch.setattr(cli, "make_aws_clients", lambda region, profile: (client, ebs))
    argv = ["--instance-id", "i-0abc", "-o", str(tmp_path / "o"), "-q", "--profile", "my work"]
    assert cli.main(argv) == 2
    lines = capsys.readouterr().err.splitlines()
    assert lines[0].startswith("ec2-byhand: error: baseline: ami-0base is a public AMI")
    assert f"({code}: {message})" in lines[0]
    assert "--no-baseline" in lines[0]
    # The command to copy it, on a line of its own: this AMI, this run's region and profile.
    expected = (
        "    aws ec2 copy-image --profile 'my work' --region us-east-1 --source-region us-east-1 "
        "--source-image-id ami-0base --name ec2-byhand-baseline"
    )
    assert lines[1:] == ([expected] if command else [])


@pytest.mark.parametrize("keep", [False, True])
def test_the_copy_is_deleted_when_the_run_is_stopped(
    ec2, monkeypatch, tmp_path: Path, capsys, keep: bool
) -> None:
    _need_images()
    client, stub = ec2
    _stub_public_instance(stub)
    stub.add_response("copy_image", {"ImageId": "ami-0copy"}, _copy_params())
    stub.add_response(
        "create_snapshots", {"Snapshots": [{"SnapshotId": "snap-now", "VolumeId": "vol-1"}]}
    )
    stub.add_response(
        "describe_snapshots",
        {"Snapshots": [{"SnapshotId": "snap-now", "State": "completed"}]},
        {"SnapshotIds": ["snap-now"]},
    )
    stub.add_response(
        "describe_images",
        _image_response("ami-0copy", "snap-copy", "pending"),
        {"ImageIds": ["ami-0copy"]},
    )
    if not keep:
        stub.add_response("delete_snapshot", {}, {"SnapshotId": "snap-now"})
        stub.add_response(
            "deregister_image",
            {"Return": True, "DeleteSnapshotResults": []},
            {"ImageId": "ami-0copy", "DeleteAssociatedSnapshots": True},
        )

    def ctrl_c(seconds: float) -> None:
        raise KeyboardInterrupt

    ebs = PublicAmiEbs({"snap-now": CURRENT}, {"snap-ami"})
    monkeypatch.setattr(cli, "make_aws_clients", lambda region, profile: (client, ebs))
    monkeypatch.setattr(botocore.waiter.time, "sleep", ctrl_c)  # stopped waiting for the copy
    argv = ["--instance-id", "i-0abc", "-o", str(tmp_path / "o"), "-q"]
    assert cli.main([*argv, "--keep-snapshots"] if keep else argv) == 130
    err = capsys.readouterr().err
    if keep:
        assert "keeping the AMI copies: ami-0copy (--baseline-ami takes them" in err
    else:
        assert "keeping" not in err


def test_public_baseline_snapshot_given_by_id_has_no_ami_to_copy(
    ec2, monkeypatch, tmp_path: Path, capsys
) -> None:
    client, _stub = ec2
    ebs = DeniedEbs("ValidationException", "Public snapshots are not supported")
    monkeypatch.setattr(cli, "make_aws_clients", lambda region, profile: (client, ebs))
    argv = ["--current-snapshot", "snap-a", "--baseline-snapshot", "snap-b", "-o"]
    assert cli.main([*argv, str(tmp_path / "o"), "-q"]) == 2
    err = capsys.readouterr().err
    # The current side is read first and fails the same way: nothing to copy is named.
    assert "public snapshot" in err
    assert "--source-image-id" not in err


def test_one_failed_delete_does_not_leave_the_rest_behind(ec2) -> None:
    client, stub = ec2
    stub.add_client_error(
        "delete_snapshot", "RequestLimitExceeded", expected_params={"SnapshotId": "snap-a"}
    )
    stub.add_response("delete_snapshot", {}, {"SnapshotId": "snap-b"})  # still attempted
    failed = delete_snapshots(client, [Disk("/dev/xvda", "snap-a"), Disk("/dev/xvdf", "snap-b")])
    assert [d.snapshot_id for d, _ in failed] == ["snap-a"]
    assert "RequestLimitExceeded" in failed[0][1]


def _run_that_made(client, *snapshot_ids: str) -> cli._Aws:
    """The AWS side of a run (--quiet) that made these snapshots."""
    args = argparse.Namespace(region=None, profile=None, quiet=True, keep_snapshots=False)
    aws = cli._Aws(args)
    aws._clients = (client, None)
    aws.created = [Disk(f"/dev/xvd{'afg'[i]}", s) for i, s in enumerate(snapshot_ids)]
    return aws


def test_cleanup_remembers_what_it_could_not_delete(ec2, capsys) -> None:
    client, stub = ec2
    stub.add_client_error(
        "delete_snapshot", "UnauthorizedOperation", expected_params={"SnapshotId": "snap-a"}
    )
    stub.add_response("delete_snapshot", {}, {"SnapshotId": "snap-b"})
    aws = _run_that_made(client, "snap-a", "snap-b")
    aws.cleanup()
    assert aws.not_deleted == ["snap-a"]
    assert "could not delete snap-a" in capsys.readouterr().err  # even with --quiet


def test_cleanup_stopped_half_way_says_which_snapshots_are_left(capsys) -> None:
    # Ctrl+C a second time, while the snapshots are being deleted: nothing else would
    # tell which of them still cost money.
    deleted = []

    class Ec2:
        def delete_snapshot(self, SnapshotId: str) -> None:
            if SnapshotId == "snap-b":
                raise KeyboardInterrupt
            deleted.append(SnapshotId)

    aws = _run_that_made(Ec2(), "snap-a", "snap-b", "snap-c")
    with pytest.raises(KeyboardInterrupt):
        aws.cleanup()
    assert deleted == ["snap-a"]
    err = capsys.readouterr().err
    assert "still there, delete them by hand: snap-b snap-c" in err


def test_a_snapshot_that_could_not_be_deleted_is_not_called_deleted(
    ec2, monkeypatch, tmp_path: Path, capsys
) -> None:
    _need_images()
    client, stub = ec2
    stub.add_response(
        "describe_instances",
        _instance_response({"/dev/xvda": "vol-1"}),
        {"InstanceIds": ["i-0abc"]},
    )
    stub.add_response(
        "create_snapshots", {"Snapshots": [{"SnapshotId": "snap-now", "VolumeId": "vol-1"}]}
    )
    stub.add_response(
        "describe_snapshots",
        {"Snapshots": [{"SnapshotId": "snap-now", "State": "completed"}]},
        {"SnapshotIds": ["snap-now"]},
    )
    stub.add_client_error(
        "delete_snapshot", "UnauthorizedOperation", expected_params={"SnapshotId": "snap-now"}
    )
    fake = FakeEbs({"snap-now": CURRENT})
    monkeypatch.setattr(cli, "make_aws_clients", lambda region, profile: (client, fake))
    args = ["--instance-id", "i-0abc", "--no-baseline", "--no-archives", "-o", str(tmp_path / "o")]
    assert cli.main(args) == 0
    out = capsys.readouterr().out
    assert "snap-now (NOT deleted: delete them by hand)" in out
    assert "(deleted)" not in out


@pytest.mark.parametrize("value", ["0", "129", "many"])
def test_parallel_must_be_a_count_in_range(value: str, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--current-image", "x.img", "--no-baseline", "-o", "out", "--parallel", value])
    assert exc.value.code == 2
    assert "--parallel" in capsys.readouterr().err


@pytest.mark.parametrize("parallel", [None, "3"])
def test_parallel_reaches_every_snapshot(parallel, monkeypatch, tmp_path: Path) -> None:
    _need_images()  # before the fake snapshots are made of them
    seen: list[int] = []
    real = EbsSnapshotDevice.__init__

    def init(self, *args, **kwargs):
        seen.append(kwargs.get("threads", READ_AHEAD_THREADS))
        real(self, *args, **kwargs)

    monkeypatch.setattr(EbsSnapshotDevice, "__init__", init)
    ebs = FakeEbs({"snap-now": CURRENT, "snap-ami": BASELINE})
    monkeypatch.setattr(cli, "make_aws_clients", lambda region, profile: (None, ebs))
    args = ["--current-snapshot", "snap-now", "--baseline-snapshot", "snap-ami"]
    args += ["-o", str(tmp_path / "o"), "-q", "--no-archives"]
    args += ["--parallel", parallel] if parallel else []
    assert cli.main(args) == 0
    assert seen == [int(parallel) if parallel else READ_AHEAD_THREADS] * 2
