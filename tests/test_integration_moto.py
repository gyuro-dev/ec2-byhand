"""The command against moto's EBS direct API: the real boto3 client, with requests
serialised and responses streamed as against AWS, but no account. What FakeEbs
in test_aws.py cannot show: that the ebs client is made and used the way
botocore expects, end to end.

Needs the `integration` dependency group (`uv sync --group integration`);
skipped without it. moto's snapshots have 512-byte blocks (EBS has 512 KiB),
so a golden image goes up one small block at a time and the test takes a
while, which is why it is not part of the default run.

What moto does not reproduce, and so stays for a real account: block tokens
that expire, ListSnapshotBlocks pages, throttling and latency, encrypted
snapshots, and snapshots behind an AMI that cannot be read."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any

import boto3
import pytest
from conftest import GOLDEN_DIR

from ec2_byhand import cli
from ec2_byhand import manifest as manifest_io

pytest.importorskip("moto")
from moto import mock_aws

IMAGE = GOLDEN_DIR / "ext4-default.img"


def _upload(ebs: Any, image: Path) -> str:
    """The image as a completed snapshot: every block that holds data, with its SHA-256."""
    data = image.read_bytes()
    started = ebs.start_snapshot(
        VolumeSize=-(-len(data) // (1 << 30)), Description="ec2-byhand integration test"
    )
    snapshot_id, block_size = started["SnapshotId"], started["BlockSize"]
    written = 0
    for index in range(-(-len(data) // block_size)):
        block = data[index * block_size : (index + 1) * block_size].ljust(block_size, b"\0")
        if not block.strip(b"\0"):
            continue  # never written: read back as zeros, as on EBS
        ebs.put_snapshot_block(
            SnapshotId=snapshot_id,
            BlockIndex=index,
            BlockData=block,
            DataLength=block_size,
            Checksum=base64.b64encode(hashlib.sha256(block).digest()).decode(),
            ChecksumAlgorithm="SHA256",
        )
        written += 1
    ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=written)
    return snapshot_id


def _comparable(manifest: dict[str, Any]) -> dict[str, Any]:
    """The manifest without what names the input or the moment."""
    manifest = dict(manifest)
    manifest.pop("generated_at")
    manifest["current"] = {k: v for k, v in manifest["current"].items() if k != "label"}
    return manifest


@pytest.mark.integration
def test_the_command_reads_a_snapshot_through_boto3(tmp_path: Path, monkeypatch, capsys) -> None:
    if not IMAGE.exists():
        pytest.skip(
            "no golden images; run: wsl -u root -- bash tools/golden/build_fs.sh tests/golden/out"
        )
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")  # moto fakes the credentials
    from_image, from_aws = tmp_path / "image", tmp_path / "aws"
    assert cli.main(["--current-image", str(IMAGE), "--no-baseline", "-o", str(from_image)]) == 0
    capsys.readouterr()
    with mock_aws():
        snapshot_id = _upload(boto3.client("ebs"), IMAGE)
        args = ["--current-snapshot", snapshot_id, "--no-baseline", "-o", str(from_aws)]
        assert cli.main(args) == 0
    out = capsys.readouterr().out
    assert "EBS direct API:" in out
    assert "GetSnapshotBlock" in out
    aws = manifest_io.read(from_aws / "manifest.json")
    assert aws["current"]["label"] == f"disk0={snapshot_id}"
    assert _comparable(aws) == _comparable(manifest_io.read(from_image / "manifest.json"))
    assert (from_aws / "after.tar.gz").read_bytes() == (from_image / "after.tar.gz").read_bytes()
