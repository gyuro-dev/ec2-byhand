"""--upload: the outputs to S3, against moto's S3 (the real boto3 client, no account)."""

from __future__ import annotations

from pathlib import Path

import boto3
import pytest
from conftest import GOLDEN_DIR
from memfs import MemFs

from diskread.source import SystemSource
from ec2_byhand import cli
from ec2_byhand.analyze import Snapshot
from ec2_byhand.aws import upload
from ec2_byhand.aws.upload import S3Place, UploadError, bucket_client, upload_outputs

pytest.importorskip("moto")
from moto import mock_aws

BUCKET = "ec2-byhand-test-bucket"


@pytest.fixture
def s3(monkeypatch: pytest.MonkeyPatch):
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_DEFAULT_REGION": "ap-northeast-1",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with mock_aws():
        client = boto3.client("s3", region_name="ap-northeast-1")
        client.create_bucket(
            Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": "ap-northeast-1"}
        )
        yield client


def test_s3_place() -> None:
    place = S3Place.parse("s3://my-bucket/servers/prod/")
    assert place == S3Place("my-bucket", "servers/prod")
    assert place.run_prefix("i-0123", "2026-11-14T12:00:05+00:00") == (
        "servers/prod/i-0123/20261114T120005Z"
    )
    assert S3Place.parse("s3://my-bucket").run_prefix(
        "snap-1 snap-2", "2026-11-14T12:00:05+00:00"
    ) == ("snap-1_snap-2/20261114T120005Z")
    for bad in ("my-bucket/x", "s3://", "s3://UPPER", "https://my-bucket"):
        with pytest.raises(ValueError, match="not"):
            S3Place.parse(bad)


def _outputs(tmp_path: Path) -> Path:
    out = tmp_path / "out"
    (out / "patches" / "etc").mkdir(parents=True)
    (out / "manifest.json").write_text("{}", encoding="utf-8")
    (out / "report.txt").write_text("ec2-byhand report\n", encoding="utf-8")
    (out / "after.tar.gz").write_bytes(b"\x1f\x8b" + bytes(6 << 20))  # 6 MiB: two parts below
    (out / "patches" / "etc" / "app.conf.diff").write_text("--- a\n+++ b\n", encoding="utf-8")
    return out


def test_every_file_goes_up_encrypted_the_manifest_last(
    s3, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(upload, "PART_BYTES", 5 << 20)  # S3's smallest part
    keys = upload_outputs(s3, _outputs(tmp_path), S3Place(BUCKET, "runs"), "runs/i-1/T")
    assert keys == [
        "runs/i-1/T/after.tar.gz",
        "runs/i-1/T/patches/etc/app.conf.diff",
        "runs/i-1/T/report.txt",
        "runs/i-1/T/manifest.json",
    ]
    for key in keys:
        head = s3.head_object(Bucket=BUCKET, Key=key)
        assert head["ServerSideEncryption"] == "aws:kms"
    tar = s3.head_object(Bucket=BUCKET, Key="runs/i-1/T/after.tar.gz")
    assert tar["ContentLength"] == 2 + (6 << 20)
    assert "-" in tar["ETag"]  # a multipart upload
    assert tar["ContentType"] == "application/gzip"
    report = s3.head_object(Bucket=BUCKET, Key="runs/i-1/T/report.txt")
    assert report["ContentType"] == "text/plain; charset=utf-8"


def test_only_the_runs_own_files_go_up(s3, tmp_path: Path) -> None:
    # With --force the output directory may be one that holds other things (-o .).
    out = _outputs(tmp_path)
    (out / ".env").write_text("SECRET=1", encoding="utf-8")
    (out / "notes.txt").write_text("mine", encoding="utf-8")
    (out / ".git").mkdir()
    (out / ".git" / "config").write_text("[core]", encoding="utf-8")
    (out / "patches" / "etc" / "not-a-patch.txt").write_text("mine", encoding="utf-8")
    keys = upload_outputs(s3, out, S3Place(BUCKET, "runs"), "runs/i-1/T")
    assert keys == [
        "runs/i-1/T/after.tar.gz",
        "runs/i-1/T/patches/etc/app.conf.diff",
        "runs/i-1/T/report.txt",
        "runs/i-1/T/manifest.json",
    ]


def test_a_missing_bucket_is_told_before_the_run(s3) -> None:
    with pytest.raises(UploadError, match="no such bucket"):
        bucket_client(boto3.Session(region_name="ap-northeast-1"), "no-such-bucket-here")


def test_the_command_uploads_its_outputs(
    s3, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A server in memory, so that this runs wherever moto is, golden images or not.
    fs = MemFs()
    fs.add_file("/etc/app.conf", b"x=1\n")
    server = Snapshot("i-0abc", SystemSource.from_fs(fs))
    monkeypatch.setattr(cli, "_sides", lambda args, aws, stack: (server, None))
    rc = cli.main(
        [
            "--current-image",
            "unused.img",
            "-o",
            str(tmp_path / "out"),
            "--upload",
            f"s3://{BUCKET}/runs",
        ]
    )
    assert rc == 0
    listed = s3.list_objects_v2(Bucket=BUCKET, Prefix="runs/")["Contents"]
    names = {o["Key"].split("/", 3)[3] for o in listed}
    assert {"manifest.json", "report.txt", "after.tar.gz"} <= names
    assert "uploaded:               s3://" in capsys.readouterr().out


def test_kms_key_id_needs_upload(tmp_path: Path) -> None:
    image = GOLDEN_DIR / "verify-al2023.img"
    rc = cli.main(["--current-image", str(image), "-o", str(tmp_path / "o"), "--kms-key-id", "k"])
    assert rc == 2
