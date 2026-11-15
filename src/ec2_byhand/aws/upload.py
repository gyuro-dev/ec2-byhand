"""Upload a run's outputs to S3: --upload s3://bucket/prefix.

Each run goes to its own place, s3://bucket/prefix/<label>/<generated_at>/ (the label
is the instance id, the snapshot or --label; the time is the manifest's, in UTC), so
an earlier run is never overwritten. Every object is encrypted with SSE-KMS (the
aws/s3 key unless --kms-key-id names another) and carries a SHA-256 checksum that S3
checks on arrival; large files go up in parts, several at a time. manifest.json goes
last: when it is there, the rest is too. Only the files the run wrote go up
(ec2_byhand.archive.output_files), whatever else the output directory holds.

The bucket is looked at before the analysis starts (HeadBucket), so a wrong name or a
missing permission costs seconds, not the run, and the client is made for the
bucket's own region.

実行の出力を S3 に上げる（--upload s3://bucket/prefix）。実行ごとに
s3://bucket/prefix/<ラベル>/<generated_at>/ に置くので（ラベルはインスタンス ID・スナップ
ショット・--label、時刻は manifest のもので UTC）、前の実行を上書きしない。どのオブジェクトも
SSE-KMS（--kms-key-id が無ければ aws/s3 の鍵）で暗号化し、S3 が受け取るときに確かめる SHA-256
のチェックサムを付ける。大きなファイルは分割して並列に上げる。manifest.json は最後に上げる:
それがあれば残りもそろっている。上げるのは実行が書いたファイルだけ
（ec2_byhand.archive.output_files）で、出力先にあるほかのものは上げない。
バケットは解析を始める前に見る（HeadBucket）ので、名前の誤りや
権限の不足は実行全体ではなく数秒で分かる。クライアントはバケットのリージョンで作る。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ec2_byhand.archive import output_files
from ec2_byhand.messages import msg

PART_BYTES = 64 << 20
CONCURRENCY = 8
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
_LABEL_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
CONTENT_TYPES = {
    ".json": "application/json",
    ".gz": "application/gzip",
    ".diff": "text/x-diff",
    ".txt": "text/plain; charset=utf-8",
}


class UploadError(Exception):
    """The outputs could not be uploaded (they stay in the output directory).

    出力を上げられなかった（出力ディレクトリには残っている）。
    """


@dataclass(frozen=True)
class S3Place:
    """Where --upload points: a bucket and a key prefix (may be empty).

    --upload の行き先: バケットとキーの前置き（空でもよい）。
    """

    bucket: str
    prefix: str

    @classmethod
    def parse(cls, text: str) -> S3Place:
        """s3://bucket[/prefix] -> S3Place; ValueError otherwise.

        s3://bucket[/prefix] を S3Place に。形が違えば ValueError。
        """
        if not text.startswith("s3://"):
            raise ValueError(msg("not_an_s3_url", text=text))
        bucket, _, prefix = text[len("s3://") :].partition("/")
        if not _BUCKET.fullmatch(bucket):
            raise ValueError(msg("not_a_bucket_name", bucket=bucket))
        return cls(bucket, prefix.strip("/"))

    def run_prefix(self, label: str, generated_at: str) -> str:
        """The key prefix of one run: <prefix>/<label>/<time>, the time as 20261114T120000Z.

        1 回の実行のキーの前置き: <prefix>/<ラベル>/<時刻>（時刻は 20261114T120000Z の形）。
        """
        stamp = re.sub(r"[-:]", "", generated_at.replace("+00:00", "Z"))
        parts = [self.prefix, _LABEL_UNSAFE.sub("_", label).strip("_") or "run", stamp]
        return "/".join(p for p in parts if p)


def bucket_client(session: Any, bucket: str) -> Any:
    """An S3 client for the bucket's own region, having checked the bucket is there and
    reachable (HeadBucket, which needs s3:ListBucket on it).

    バケットのリージョンの S3 クライアント。バケットがあって届くことを先に確かめる（HeadBucket。
    そのバケットへの s3:ListBucket が要る）。
    """
    from botocore.config import Config
    from botocore.exceptions import ClientError

    config = Config(retries={"mode": "adaptive", "max_attempts": 10})
    s3 = session.client("s3", config=config)
    try:
        response = s3.head_bucket(Bucket=bucket)
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code", "")
        headers = err.response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
        region = headers.get("x-amz-bucket-region")
        if code in ("301", "PermanentRedirect") and region:
            return session.client("s3", region_name=region, config=config)
        if code in ("404", "NoSuchBucket", "NotFound"):
            raise UploadError(msg("no_such_bucket", bucket=bucket)) from err
        if code in ("403", "AccessDenied", "Forbidden"):
            raise UploadError(msg("bucket_access_denied", bucket=bucket)) from err
        raise UploadError(msg("bucket_unreachable", bucket=bucket, error=err)) from err
    region = response.get("ResponseMetadata", {}).get("HTTPHeaders", {}).get("x-amz-bucket-region")
    if region and region != s3.meta.region_name:
        return session.client("s3", region_name=region, config=config)
    return s3


def upload_outputs(
    s3: Any, outdir: Path, place: S3Place, run_prefix: str, kms_key_id: str | None = None
) -> list[str]:
    """Upload the run's files in `outdir` (archive.output_files, nothing else that is
    there) below `run_prefix`, manifest.json last; returns the keys in the order uploaded.

    `outdir` にある実行のファイル（archive.output_files。そこにあるほかのものは上げない）を
    `run_prefix` の下に上げ（manifest.json は最後）、上げた順のキーを返す。
    """
    from boto3.exceptions import S3UploadFailedError
    from boto3.s3.transfer import TransferConfig
    from botocore.exceptions import BotoCoreError, ClientError

    # Only what the run wrote: with --force the directory may hold other files too.
    files = sorted(output_files(outdir))
    files.sort(key=lambda p: p.name == "manifest.json" and p.parent == outdir)
    transfer = TransferConfig(
        multipart_threshold=PART_BYTES, multipart_chunksize=PART_BYTES, max_concurrency=CONCURRENCY
    )
    done = []
    for path in files:
        key = f"{run_prefix}/{path.relative_to(outdir).as_posix()}"
        extra = {
            "ServerSideEncryption": "aws:kms",
            "ChecksumAlgorithm": "SHA256",
            "ContentType": CONTENT_TYPES.get(path.suffix, "application/octet-stream"),
        }
        if kms_key_id:
            extra["SSEKMSKeyId"] = kms_key_id
        try:
            s3.upload_file(str(path), place.bucket, key, ExtraArgs=extra, Config=transfer)
        except (BotoCoreError, ClientError, S3UploadFailedError) as err:
            raise UploadError(
                msg("upload_file_failed", name=path.name, bucket=place.bucket, key=key, error=err)
            ) from err
        done.append(key)
    return done
