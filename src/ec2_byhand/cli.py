"""ec2-byhand command line.

    ec2-byhand --instance-id i-0123... -o DIR
    ec2-byhand --current-snapshot snap-... [--baseline-snapshot snap-... | --baseline-ami ami-...]
             -o DIR
    ec2-byhand --current-image IMG [IMG ...] [--baseline-image IMG [IMG ...]] -o DIR

The server now is --instance-id, --current-snapshot or --current-image; the
AMI it started from (the baseline) is --baseline-ami, --baseline-snapshot or
--baseline-image. Each side is one or more disks (one per EBS volume): EBS
snapshots read through the EBS direct APIs, or raw image files. With several
disks, partitions, LVM and the root's /etc/fstab put them together; with a
single filesystem and no usable fstab, that filesystem is the root.

--instance-id snapshots every EBS volume of the instance (CreateSnapshots,
crash-consistent across volumes), compares with the AMI it was launched
from, and deletes the snapshots it made afterwards (--keep-snapshots keeps
them).

A run writes to --output: manifest.json (the data), report.txt (the same for a person
to read), after.tar.gz, before.tar.gz and patches/; and prints a summary. What it says
to its user comes from ec2_byhand.messages, in English or Japanese.

ec2-byhand のコマンドライン。「今のサーバー」は --instance-id / --current-snapshot /
--current-image、「起動元の AMI（ベースライン）」は --baseline-ami / --baseline-snapshot /
--baseline-image で指定する。各側は 1 つ以上のディスク（EBS ボリュームごとに 1 つ）: EBS direct
APIs 越しに読むスナップショットか、生のイメージファイル。複数ディスクはパーティション・LVM・
ルートの /etc/fstab で組み上げ、ファイルシステムが 1 つで使える fstab が無ければそれをルートに
する。--instance-id は全 EBS ボリュームをスナップショットして起動元 AMI と比較し、作ったスナッ
プショットは後で消す（--keep-snapshots で残す）。実行は --output に manifest.json（データ）、
report.txt（人が読む一覧）、after.tar.gz・before.tar.gz・patches/ を書き、まとめを表示する。
利用者に見せる文言は ec2_byhand.messages から取る（英語か日本語）。
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import re
import shlex
import signal
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from diskread import FileDevice
from diskread.blockdev import BlockDevice
from diskread.errors import DiskReadError
from diskread.source import SystemSource
from diskread.system import Volume, assemble, scan
from ec2_byhand import __version__
from ec2_byhand import manifest as manifest_io
from ec2_byhand import report as report_io
from ec2_byhand.analyze import ReadPlan, Snapshot, analyze
from ec2_byhand.archive import ArchiveOptions, output_files, printable, write_outputs
from ec2_byhand.aws import MAX_THREADS, READ_AHEAD_THREADS
from ec2_byhand.aws.devices import BY_ID, EBS_NAMES, ebs_device_volume
from ec2_byhand.messages import language, language_from_environment, msg, row, wrap
from ec2_byhand.noise import NoiseFilter
from ec2_byhand.sensitive import Sensitive

if TYPE_CHECKING:
    from ec2_byhand.aws.ebs import EbsSnapshotDevice
    from ec2_byhand.aws.snapshots import Disk

_SIZE = re.compile(r"(\d+(?:\.\d+)?)\s*([kKmMgGtT]?)i?[bB]?\Z")
_UNITS = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}
PROGRESS_SECONDS = 30  # how often a long read over the EBS direct APIs says how far it got
WAIT_PROGRESS_SECONDS = 300  # how often a long wait for the snapshots says how far they are
WARNINGS_SHOWN = 3  # of one code, in the summary; the manifest has them all
# Larger files are not read unless asked for: what a migration wants is small, and a
# database or a dump would otherwise take hours of reads and fill the output.
DEFAULT_MAX_FILE_SIZE = 1 << 30
MUCH_TO_READ = 1 << 30  # from here on, the plan says how to leave data out


class UsageError(Exception):
    """Wrong input or arguments; printed as one line, exit code 2. `command`, when
    given, is a command to run next, printed after it on a line of its own.

    入力や引数の誤り。1 行で表示して終了コード 2。`command` があれば、次に実行する
    コマンドで、そのあとに 1 行で表示する。
    """

    def __init__(self, message: str, command: str = "") -> None:
        super().__init__(message)
        self.command = command


def parse_size(text: str) -> int:
    """A size argument like "500K", "100M" or "2G" as bytes.

    「500K」「100M」「2G」のようなサイズ引数をバイト数にする。
    """
    m = _SIZE.match(text.strip())
    if not m:
        raise argparse.ArgumentTypeError(msg("not_a_size", text=text))
    return int(float(m.group(1)) * _UNITS[m.group(2).lower()])


def size_limit(text: str) -> int | None:
    """A --max-file-size argument: a size as parse_size reads it, or "none" for no limit.

    --max-file-size の引数: parse_size が読むサイズ、または上限なしを表す「none」。
    """
    return None if text.strip().lower() == "none" else parse_size(text)


def size_text(size: int) -> str:
    """A byte count as people write it: "17 bytes", "300 MiB", "5.2 GiB".

    バイト数を人が書く形にする（「17 bytes」「300 MiB」「5.2 GiB」）。
    """
    for unit, step in (("TiB", 1 << 40), ("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if size >= step:
            return f"{size / step:.1f}".removesuffix(".0") + f" {unit}"
    return msg("one_byte") if size == 1 else msg("bytes", size=size)


def path_glob(text: str) -> str:
    """An --exclude / --include pattern, refused when it could never match: patterns
    are compared with whole absolute paths, so "*.bak" or "opt/app/**" would silently
    do nothing.

    --exclude / --include のパターン。絶対に一致しないものは拒否する: パターンは絶対パス全体と比
    べるので、「*.bak」や「opt/app/**」は何も言わずに空振りしてしまう。
    """
    if not text.startswith(("/", "**")) or text.endswith("/"):
        raise argparse.ArgumentTypeError(msg("not_a_path_glob", text=text))
    return text


def open_snapshot(
    stack: ExitStack, images: list[str], label: str, verify_checksums: bool = False
) -> Snapshot:
    """Open local image files as one side of the comparison.

    ローカルのイメージファイル群を比較の片側として開く。
    """
    disks: dict[str, BlockDevice] = {}
    for i, image in enumerate(images):
        if not Path(image).is_file():
            raise UsageError(msg("no_such_image", label=label, image=image))
        disks[f"disk{i}"] = stack.enter_context(FileDevice(image))
    return open_disks(disks, label, verify_checksums)


def open_disks(
    disks: dict[str, BlockDevice],
    label: str,
    verify_checksums: bool = False,
    serials: dict[str, str] | None = None,
    find_serials: Callable[[], dict[str, str]] | None = None,
    attached: dict[str, str] | None = None,
) -> Snapshot:
    """Assemble the opened disks into a Snapshot; a single filesystem is enough.
    `serials` gives disks' serial numbers by name (see diskread.system.scan);
    `find_serials` is asked for them the first time an fstab line names a volume in a
    way only its serial number answers and nothing matches: by its id
    (/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol...), or, with `attached`, by
    the device name the instance has it under (/dev/xvdf). `attached` gives those
    names by serial number (see ec2_byhand.aws.devices).

    開いたディスク群を Snapshot に組み上げる。ファイルシステム 1 つだけでもよい。`serials` はディ
    スク名ごとのシリアル番号（diskread.system.scan 参照）。`find_serials` は、fstab の指定が
    シリアル番号でしか引けず、どれにも当たらなかったとき、最初の 1 回だけ尋ねる: ボリューム ID
    の名前（/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol...）か、`attached` があるときは
    インスタンスでのデバイス名（/dev/xvdf）。`attached` はそのデバイス名をシリアル番号で引く表
    （ec2_byhand.aws.devices 参照）。
    """
    volumes = scan(disks, verify_checksums, serials)
    asked = False

    def resolve(spec: str, found: list[Volume]) -> Volume | None:
        nonlocal asked
        volume = ebs_device_volume(spec, found, attached)
        by_serial = spec.startswith(BY_ID) or (bool(attached) and spec.startswith(EBS_NAMES))
        if volume is None and find_serials is not None and not asked and by_serial:
            asked = True
            for disk, serial in find_serials().items():
                for v in found:
                    if v.serial is None and (v.name == disk or v.name.startswith(disk + "p")):
                        v.serial = serial
            volume = ebs_device_volume(spec, found, attached)
        return volume

    try:
        system = assemble(volumes, resolve_device=resolve)
        return Snapshot(label, SystemSource.from_system(system), system)
    except DiskReadError as err:
        with_fs = [v.fs for v in volumes if v.fs is not None]
        if len(with_fs) == 1:  # e.g. one filesystem image without an fstab
            return Snapshot(label, SystemSource.from_fs(with_fs[0]))
        found = ", ".join(
            f"{v.name} ({v.fs_type or v.error or msg('no_filesystem')})" for v in volumes
        ) or msg("no_volumes")
        raise UsageError(msg("cannot_assemble", label=label, error=err, found=found)) from err


def _warning_line(w: dict[str, Any]) -> str:
    """One warning for the summary: its code, where it happened, and the message."""
    where = [str(w[k]) for k in ("snapshot", "mountpoint", "spec", "volume", "path") if w.get(k)]
    place = f" ({' '.join(where)})" if where else ""
    return printable(msg("warning", code=w["code"], place=place, message=w.get("message", "")))


def _warning_lines(warnings: list[dict[str, Any]]) -> list[str]:
    """The warnings for the summary: the first few of each code, then how many more of
    it the manifest holds. Read errors can run to thousands, and one line each would
    push the numbers, and the warnings that change their meaning, off the screen."""
    lines = []
    seen: Counter[str] = Counter()
    for w in warnings:
        seen[w["code"]] += 1
        if seen[w["code"]] <= WARNINGS_SHOWN:
            lines.append(_warning_line(w))
    lines += [
        printable(msg("warnings_more", code=code, count=count - WARNINGS_SHOWN))
        for code, count in seen.items()
        if count > WARNINGS_SHOWN
    ]
    return lines


def _plan_lines(plan: ReadPlan, max_file_size: int | None, snapshots_made: bool) -> list[str]:
    """What there is to read, said before reading it: one line, and when it is much,
    the largest files and how to leave them out. This is the moment to stop a run
    that is about to read a database. With `snapshots_made` (--instance-id), stopping
    also costs the snapshots, which the hint says."""
    first = msg("plan", size=size_text(plan.size), files=plan.files)
    if plan.over_limit and max_file_size is not None:
        first += msg("plan_over_limit", count=plan.over_limit, limit=size_text(max_file_size))
    if plan.size < MUCH_TO_READ:
        return [first]
    largest = [f"  {size_text(size):>10}  {printable(path)}" for path, size in plan.largest]
    hint = msg("plan_hint")
    if snapshots_made:
        hint += msg("plan_hint_snapshots")
    return [first + msg("plan_largest"), *largest, hint]


def _summary_lines(m: dict[str, Any], outdir: Path) -> list[str]:
    """The human-readable summary of an analyze run: printed at its end, and the head
    of report.txt, which lists the paths behind its numbers."""
    s = m["summary"]

    def sides_with(code: str) -> set[str]:
        return {w["snapshot"] for w in m["warnings"] if w["code"] == code}

    # Numbers a damaged package database changes the meaning of say so where they stand.
    unreadable_db, damaged_db = (
        sides_with("package-db-unreadable"),
        sides_with("package-db-damaged"),
    )
    incomplete_db = unreadable_db | damaged_db
    with_package_files = msg("may_include_package_files")
    if s["modified_package_files"] is None:
        modified = msg("unknown")
    else:
        modified = str(s["modified_package_files"])
    no_baseline = m["baseline"] is None
    if s["modified_package_files_since_baseline"] is not None:
        modified += msg("since_baseline", count=s["modified_package_files_since_baseline"])
    elif no_baseline and s["modified_package_files"]:
        modified += msg("modified_without_baseline")
    if s["packages_installed"] is None:
        packages = msg("unknown")
    else:
        packages = msg("packages_installed", count=s["packages_installed"])
    if m["packages"]["changes"] is not None:
        packages += (
            f", +{s['packages_added']} -{s['packages_removed']} "
            f"^{s['packages_upgraded']} v{s['packages_downgraded']}"
        )
    elif "baseline" in unreadable_db:
        packages += msg("package_changes_unknown")
    if damaged_db:
        packages += msg("package_entries_unreadable")
    lines = [
        row("manifest", str(outdir / "manifest.json")),
        row("report", str(outdir / report_io.NAME)),
        row("baseline", msg("baseline_none") if no_baseline else m["baseline"]["label"]),
    ]
    span = s.get("changed_between")
    if span:
        first, last = (t[:16].replace("T", " ") for t in span)  # to the minute, in UTC
        lines.append(row("changed_between", msg("changed_between", first=first, last=last)))
    lines += [
        row(
            "hand_placed",
            str(s["hand_placed"])
            + (msg("ami_files_too") if no_baseline else "")
            + (with_package_files if "current" in incomplete_db else ""),
        ),
        row("modified_package_files", modified),
        row(
            "deleted",
            msg("deleted_unknown")
            if s["deleted"] is None
            else str(s["deleted"]) + (with_package_files if "baseline" in incomplete_db else ""),
        ),
        row("packages", packages),
    ]
    if m.get("snaps") is not None:  # snapd on either side: what changed of its snaps
        lines.append(row("snaps", str(s["snaps"])))
    edited = s["language_package_files_edited_after_install"]
    lines += [
        row(
            "language_packages",
            str(s["language_packages"])
            + (msg("edited_after_install", count=edited) if edited else ""),
        ),
        row("package_scripts", msg("count_files", count=s["files_from_package_scripts"])),
    ]
    if s.get("files_from_cloud_init") is not None:  # cloud-init ran: what it wrote at boot
        lines.append(row("cloud_init", msg("count_files", count=s["files_from_cloud_init"])))
    by_package = s.get("services_by_package")
    lines += [
        row("alternatives", str(s["alternatives"])),
        row(
            "services",
            str(s["services"])
            + (msg("services_by_package", count=by_package) if by_package else ""),
        ),
    ]
    c = m.get("containers")
    if c is not None:  # a container engine on either side: what changed of it
        counts = {kind: len(c[kind]) for kind in ("images", "containers", "volumes")}
        lines.append(row("containers", msg("containers", **counts)))
    lines.append(row("noise", str(s["noise"])))
    if s["files_over_max_file_size"]:
        of_packages = s["package_files_over_max_file_size"]
        over = msg(
            "not_read", count=s["files_over_max_file_size"], limit=size_text(m["max_file_size"])
        )
        if of_packages:
            over += msg("not_read_package_files", count=of_packages)
        lines.append(row("not_read", over + msg("not_read_hint")))
    if s.get("files_with_secrets"):
        lines.append(row("secrets", msg("secrets", count=s["files_with_secrets"])))
    if s["package_files_to_review"]:
        lines.append(row("to_review", msg("to_review", count=s["package_files_to_review"])))
    if "archives" in m:
        a = m["archives"]
        lines.append(row("after", msg("count_entries", count=a["after"]["entries"])))
        if a["before"]:
            lines.append(row("before", msg("count_entries", count=a["before"]["entries"])))
        lines.append(
            row("patches", msg("patches_none") if no_baseline else str(a["patches"]["files"]))
        )
        if a["skipped"]:
            lines.append(row("skipped", msg("skipped", count=len(a["skipped"]))))
        if a.get("masked"):
            lines.append(row("masked", msg("masked", count=len(a["masked"]))))
    return lines + _warning_lines(m["warnings"])


def _say(message: str) -> None:
    """One line on stderr. A stderr that is gone (the terminal closed, the SSH session
    lost) must not stop what the line was about: deleting the snapshots."""
    with contextlib.suppress(OSError, ValueError):
        print(f"ec2-byhand: {message}", file=sys.stderr, flush=True)


def _progress(args: argparse.Namespace, message: str) -> None:
    """One line of progress on stderr (silent with --quiet): AWS runs spend
    minutes in snapshot waits and block reads with nothing else to show."""
    if not args.quiet:
        _say(message)


def parallel_count(text: str) -> int:
    """A --parallel argument: how many blocks to fetch at once, from 1 to MAX_THREADS.

    --parallel の引数: 同時に取るブロックの数（1〜MAX_THREADS）。
    """
    try:
        n = int(text)
    except ValueError:
        n = 0
    if not 1 <= n <= MAX_THREADS:
        raise argparse.ArgumentTypeError(msg("not_a_parallel_count", max=MAX_THREADS, text=text))
    return n


def s3_place(text: str) -> Any:
    """--upload's argument: s3://bucket[/prefix].

    --upload の引数: s3://bucket[/prefix]。
    """
    from ec2_byhand.aws.upload import S3Place

    try:
        return S3Place.parse(text)
    except ValueError as err:
        raise argparse.ArgumentTypeError(str(err)) from err


def make_s3_client(region: str | None, profile: str | None, bucket: str) -> Any:
    """An S3 client for the bucket's region, the bucket checked. Replaced by tests.

    バケットのリージョンの S3 クライアント（バケットを確かめてから）。テストが差し替える。
    """
    import boto3

    from ec2_byhand.aws.upload import bucket_client

    return bucket_client(boto3.Session(profile_name=profile, region_name=region), bucket)


def make_aws_clients(region: str | None, profile: str | None) -> tuple[Any, Any]:
    """(ec2, ebs) boto3 clients. A separate function so tests can replace it.

    (ec2, ebs) の boto3 クライアント。テストが差し替えられるように別関数にしてある。
    """
    import boto3
    from botocore.config import Config

    session = boto3.Session(profile_name=profile, region_name=region)
    config = Config(retries={"mode": "adaptive", "max_attempts": 10})
    # A connection for each thread that fetches blocks ahead, or they wait for one. Made
    # only as needed, so the most --parallel allows costs nothing when fewer are used.
    ebs_config = config.merge(Config(max_pool_connections=MAX_THREADS))
    return session.client("ec2", config=config), session.client("ebs", config=ebs_config)


class _PublicImage(Exception):
    """The baseline AMI is public: the EBS direct APIs do not read its snapshots."""

    def __init__(self, image_id: str) -> None:
        super().__init__(image_id)
        self.image_id = image_id


@dataclass(frozen=True)
class _Copying:
    """A baseline still being copied into the account: `copy` of the public AMI `image_id`."""

    image_id: str
    copy: str


class _Aws:
    """The AWS side of one run: clients made on first use, snapshots and AMI copies it made."""

    def __init__(self, args: argparse.Namespace) -> None:
        self._args = args
        self._clients: tuple[Any, Any] | None = None
        self.created: list[Disk] = []  # the snapshots --instance-id made
        self.not_deleted: list[str] = []  # of those, the ids cleanup could not delete
        self.copies: list[str] = []  # the AMI copies made of a public baseline AMI
        self.copies_not_deleted: list[str] = []  # of those, the ids cleanup could not delete
        self._copy_snapshots: dict[str, int] = {}  # how many snapshots each copy has
        # --instance-id: the device name of each of its volumes, by serial number. It
        # names the disks of snapshots given by id too, when they are of these volumes
        # (a backup as the baseline), so that an fstab's /dev/xvdf finds them.
        self.attached: dict[str, str] = {}
        self.devices: list[EbsSnapshotDevice] = []
        self._last_report = time.monotonic()

    @property
    def clients(self) -> tuple[Any, Any]:
        """The (ec2, ebs) clients, made on first use."""
        if self._clients is None:
            self._clients = make_aws_clients(self._args.region, self._args.profile)
        return self._clients

    def _report_reads(self) -> None:
        """Say how far the block reads got, at most every PROGRESS_SECONDS."""
        now = time.monotonic()
        if now - self._last_report < PROGRESS_SECONDS:
            return
        self._last_report = now
        reads = sum(d.stats.block_requests for d in self.devices)
        mib = sum(d.stats.block_bytes for d in self.devices) / (1 << 20)
        _progress(self._args, msg("read_so_far", reads=reads, mib=mib))

    def report_wait(self, progress: dict[str, str], copy: bool = False) -> None:
        """Say how far the snapshots (or the AMI `copy`) waited for are, at most every
        WAIT_PROGRESS_SECONDS: the first snapshot of a large volume takes hours."""
        now = time.monotonic()
        if now - self._last_report < WAIT_PROGRESS_SECONDS:
            return
        self._last_report = now
        each = ", ".join(f"{snapshot} {done}".strip() for snapshot, done in progress.items())
        if copy:
            _progress(self._args, msg("copy_progress", progress=each))
        else:
            _progress(self._args, msg("snapshots_progress", progress=each))

    def start_copy(self, image_id: str, snapshots: int) -> _Copying:
        """Start copying the public AMI `image_id`, which has `snapshots` snapshots, into
        this account (the EBS direct APIs read the copy's snapshots, not its own); the
        copy is deleted when the run ends."""
        from botocore.exceptions import ClientError

        from ec2_byhand.aws.snapshots import AwsSourceError, copy_image

        try:
            copy = copy_image(self.clients[0], image_id)
        except ClientError as err:
            error = err.response.get("Error", {})
            code = error.get("Code", "")
            # Missing permissions: the user may still copy it by hand. Otherwise the AMI
            # is one that cannot be copied at all (Red Hat's RHEL AMIs, on 2026-11-13).
            denied = code in ("UnauthorizedOperation", "AccessDenied", "AccessDeniedException")
            raise AwsSourceError(
                msg(
                    "cannot_copy_ami",
                    image=image_id,
                    code=code,
                    why=error.get("Message", ""),
                    next_step=msg("copy_ami_denied" if denied else "copy_ami_refused"),
                ),
                self._copy_image_command(image_id) if denied else "",
            ) from err
        self.copies.append(copy)
        self._copy_snapshots[copy] = snapshots
        _progress(self._args, msg("copying_ami", image=image_id, copy=copy))
        return _Copying(image_id, copy)

    def open_copy(self, copying: _Copying, verify: bool) -> Snapshot:
        """Wait for the AMI copy to be available, then open its snapshots as the baseline."""
        from ec2_byhand.aws.snapshots import image_disks, wait_for_image

        _progress(self._args, msg("waiting_for_copy", copy=copying.copy))
        wait_for_image(
            self.clients[0], copying.copy, lambda done: self.report_wait(done, copy=True)
        )
        baseline = self.open(image_disks(self.clients[0], copying.copy), "baseline", verify)
        # The manifest's data: in English whatever the language of the messages.
        baseline.label = f"{copying.image_id} (copied as {copying.copy}) {baseline.label}"
        return baseline

    def _copy_image_command(self, image_id: str) -> str:
        """The AWS CLI command that copies `image_id` into this account, for the same
        region and profile as this run."""
        region = self.clients[0].meta.region_name
        profile = f" --profile {shlex.quote(self._args.profile)}" if self._args.profile else ""
        return (
            f"aws ec2 copy-image{profile} --region {region} --source-region {region} "
            f"--source-image-id {image_id} --name ec2-byhand-baseline"
        )

    def open(
        self, disks: list[Disk], label: str, verify: bool, image_id: str | None = None
    ) -> Snapshot:
        """Open EBS snapshots as one side of the comparison. `image_id` is the AMI they
        are of, when they came from one: an error can then say how to copy it."""
        from botocore.exceptions import ClientError

        from ec2_byhand.aws.ebs import EbsSnapshotDevice
        from ec2_byhand.aws.snapshots import AwsSourceError

        snapshots = " ".join(d.snapshot_id for d in disks)
        _progress(self._args, msg("reading_snapshots", label=label, snapshots=snapshots))
        devices: dict[str, BlockDevice] = {}
        opened = len(self.devices)
        for d in disks:
            try:
                dev = EbsSnapshotDevice(
                    self.clients[1],
                    d.snapshot_id,
                    on_fetch=self._report_reads,
                    threads=self._args.parallel,
                )
            except ClientError as err:
                error = err.response.get("Error", {})
                code = error.get("Code", "")
                # What AWS answered on 2026-11-13 for the snapshot behind a public AMI.
                public = (
                    code == "ValidationException" and "public" in error.get("Message", "").lower()
                )
                if not public and code not in (
                    "AccessDeniedException",
                    "UnauthorizedOperation",
                    "ResourceNotFoundException",
                ):
                    raise
                if label == "baseline" and public and image_id:
                    del self.devices[opened:]  # the copy is read instead
                    raise _PublicImage(image_id) from err
                next_step = msg("blocks_next_step") if label == "baseline" else ""
                raise AwsSourceError(
                    msg(
                        "cannot_read_blocks",
                        label=label,
                        snapshot=d.snapshot_id,
                        code=code,
                        reason=msg("blocks_public" if public else "blocks_denied"),
                        next_step=next_step,
                    )
                ) from err
            self.devices.append(dev)
            devices[d.device] = dev
        # On EBS the NVMe serial number is the volume id, without its dash.
        serials = {d.device: d.volume_id.replace("-", "") for d in disks if d.volume_id}
        unknown = [d for d in disks if not d.volume_id]

        def find_serials() -> dict[str, str]:
            """For snapshots given by id: the volumes they came from (DescribeSnapshots)."""
            from botocore.exceptions import BotoCoreError, ClientError

            from ec2_byhand.aws.snapshots import snapshot_volumes

            try:
                by_snapshot = snapshot_volumes(self.clients[0], [d.snapshot_id for d in unknown])
            except (BotoCoreError, ClientError) as err:
                _progress(self._args, msg("cannot_tell_volumes", label=label, error=err))
                return {}
            return {
                d.device: by_snapshot[d.snapshot_id].replace("-", "")
                for d in unknown
                if d.snapshot_id in by_snapshot
            }

        snap = open_disks(
            devices, label, verify, serials, find_serials if unknown else None, self.attached
        )
        snap.label = " ".join(f"{d.device}={d.snapshot_id}" for d in disks)
        return snap

    def close(self) -> None:
        """Stop the block reads still fetched ahead (after an error or Ctrl+C), before
        the snapshots they read may be deleted."""
        for dev in self.devices:
            dev.close()

    def cleanup(self) -> None:
        """Delete the snapshots and AMI copies this run made, unless asked to keep them,
        saying which: after an error or Ctrl+C nothing else tells whether they still
        cost money."""
        try:
            self._cleanup_snapshots()
        finally:
            self._cleanup_copies()

    def _cleanup_copies(self) -> None:
        """Deregister the AMI copies this run made, with their snapshots."""
        from ec2_byhand.aws.snapshots import delete_image

        if not self.copies:
            return
        ids = " ".join(self.copies)
        if self._args.keep_snapshots:
            _say(msg("keeping_copies", ids=ids))  # even with --quiet: they cost money
            return
        _progress(self._args, msg("deleting_copies", ids=ids))
        left = list(self.copies)
        try:
            for copy in self.copies:
                for why in delete_image(self.clients[0], copy, self._copy_snapshots[copy]):
                    _say(msg("could_not_delete", snapshot=copy, why=why))
                    if copy not in self.copies_not_deleted:
                        self.copies_not_deleted.append(copy)
                left.remove(copy)
        except BaseException:  # Ctrl+C again, or the session lost, while deleting
            _say(msg("copies_left", ids=" ".join(left)))
            raise
        if not self.copies_not_deleted:
            _progress(self._args, msg("copies_deleted"))

    def _cleanup_snapshots(self) -> None:
        """Delete the snapshots --instance-id made."""
        from ec2_byhand.aws.snapshots import delete_snapshots

        if not self.created:
            return
        ids = " ".join(d.snapshot_id for d in self.created)
        if self._args.keep_snapshots:
            # Even with --quiet: they cost money until deleted, and with --label nothing
            # else names them.
            _say(msg("keeping_snapshots", ids=ids))
            return
        _progress(self._args, msg("deleting_snapshots", ids=ids))
        left = [d.snapshot_id for d in self.created]
        try:
            for d in self.created:  # one at a time, to know which are left if stopped
                for _, why in delete_snapshots(self.clients[0], [d]):
                    # Even with --quiet: a leaked snapshot costs money.
                    _say(msg("could_not_delete", snapshot=d.snapshot_id, why=why))
                    self.not_deleted.append(d.snapshot_id)
                left.remove(d.snapshot_id)
        except BaseException:  # Ctrl+C again, or the session lost, while deleting
            _say(msg("snapshots_left", ids=" ".join(left)))
            raise
        if not self.not_deleted:
            _progress(self._args, msg("snapshots_deleted"))


def _baseline_side(
    args: argparse.Namespace, aws: _Aws, stack: ExitStack, image_id: str | None, verify: bool
) -> Snapshot | _Copying | None:
    """Open the baseline side, whichever way the arguments (or the AMI) name it. A public
    AMI is copied into the account first: the copy started is returned, for the caller
    to wait for (with --instance-id, while the current snapshots are taken)."""
    from ec2_byhand.aws.snapshots import Disk, image_disks

    if args.no_baseline:
        return None
    if args.baseline_image:
        baseline = open_snapshot(stack, args.baseline_image, "baseline", verify)
        baseline.label = " ".join(args.baseline_image)
        return baseline
    if args.baseline_snapshot:
        return aws.open(
            [Disk(f"disk{i}", s) for i, s in enumerate(args.baseline_snapshot)], "baseline", verify
        )
    if image_id:
        disks = image_disks(aws.clients[0], image_id)
        try:
            baseline = aws.open(disks, "baseline", verify, image_id)
        except _PublicImage:
            return aws.start_copy(image_id, len(disks))
        baseline.label = f"{image_id} {baseline.label}"
        return baseline
    return None


def _sides(
    args: argparse.Namespace, aws: _Aws, stack: ExitStack
) -> tuple[Snapshot, Snapshot | None]:
    """Open the current and baseline sides, whichever way the arguments name them."""
    from ec2_byhand.aws.snapshots import (
        Disk,
        describe_instance,
        snapshot_instance,
        wait_for_snapshots,
    )

    verify = args.verify_checksums
    image_id = args.baseline_ami
    if args.current_image:
        current = open_snapshot(stack, args.current_image, "current", verify)
        current.label = " ".join(args.current_image)
        baseline = _baseline_side(args, aws, stack, image_id, verify)
    elif args.instance_id:
        inst = describe_instance(aws.clients[0], args.instance_id)
        image_id = image_id or inst.image_id
        aws.attached = {volume.replace("-", ""): dev for dev, volume in inst.volumes.items()}
        # The baseline is opened first: a deregistered AMI or unreadable
        # baseline snapshots must fail here, not after minutes were spent
        # creating and waiting for the current snapshots.
        baseline = _baseline_side(args, aws, stack, image_id, verify)
        _progress(args, msg("creating_snapshots", instance=args.instance_id))
        aws.created = snapshot_instance(aws.clients[0], inst)
        _progress(args, msg("waiting_for_snapshots", count=len(aws.created)))
        wait_for_snapshots(aws.clients[0], aws.created, aws.report_wait)
        current = aws.open(aws.created, "current", verify)
        current.label = f"{args.instance_id} {current.label}"
    else:
        current = aws.open(
            [Disk(f"disk{i}", s) for i, s in enumerate(args.current_snapshot)], "current", verify
        )
        baseline = _baseline_side(args, aws, stack, image_id, verify)
    current.label = args.label or current.label
    if isinstance(baseline, _Copying):
        baseline = aws.open_copy(baseline, verify)
    return current, baseline


def _clear_previous_run(outdir: Path) -> None:
    """Remove what an earlier run left in `outdir`, so that with --force nothing
    stale passes for this run's result. Its manifest.json is what shows the
    directory is ours; a directory without one, and other files, are left alone."""
    try:
        manifest_io.read(outdir / "manifest.json")
    except (OSError, ValueError):
        return
    for path in output_files(outdir):
        path.unlink()
    patches = outdir / "patches"
    below = [p for p in patches.rglob("*") if p.is_dir()]
    for d in sorted([patches, *below], key=lambda p: len(p.parts), reverse=True):
        if d.is_dir() and not any(d.iterdir()):
            d.rmdir()


def run(args: argparse.Namespace) -> int:
    """Open both sides, analyze, write the outputs; returns the exit code.

    両側を開いて解析し、出力を書く。終了コードを返す。
    """
    from ec2_byhand.aws.snapshots import AwsSourceError

    outdir = Path(args.output)
    if outdir.exists() and not outdir.is_dir():
        raise UsageError(msg("output_not_a_directory", path=outdir))
    if outdir.is_dir() and any(outdir.iterdir()) and not args.force:
        raise UsageError(msg("output_not_empty", path=outdir))
    noise = NoiseFilter(excludes=tuple(args.exclude), includes=tuple(args.include))
    sensitive = Sensitive(tuple(args.sensitive))
    if args.kms_key_id and not args.upload:
        raise UsageError(msg("kms_key_without_upload"))
    s3 = None
    if args.upload:  # looked at now: a wrong bucket must not cost the whole run
        from ec2_byhand.aws.upload import UploadError

        try:
            s3 = make_s3_client(args.region, args.profile, args.upload.bucket)
        except UploadError as err:
            raise UsageError(str(err)) from err
    aws = _Aws(args)
    with ExitStack() as stack:
        # The outputs hold copies of files that may be root-only on the server: owner-only here.
        stack.callback(os.umask, os.umask(0o077))
        stack.callback(aws.cleanup)
        stack.callback(aws.close)  # first: callbacks run last-in first-out
        try:
            current, baseline = _sides(args, aws, stack)
        except AwsSourceError as err:
            raise UsageError(str(err), err.command) from err
        if aws.devices:
            _progress(args, msg("analyzing"))

        def say_plan(plan: ReadPlan) -> None:
            for line in _plan_lines(plan, args.max_file_size, bool(aws.created)):
                _progress(args, line)

        m = analyze(
            current,
            baseline,
            noise,
            args.max_file_size,
            before_reading=say_plan,
            sensitive=sensitive,
        )
        outdir.mkdir(parents=True, exist_ok=True)
        _clear_previous_run(outdir)
        if not args.no_archives:
            opts = ArchiveOptions(
                include_sensitive=args.include_sensitive,
                max_file_size=args.max_file_size,
                sensitive=sensitive,
            )
            m["archives"] = write_outputs(
                m, current.source, baseline.source if baseline else None, outdir, opts
            )
        manifest_io.write(m, outdir / "manifest.json")
        summary = _summary_lines(m, outdir)
        report_io.write(m, summary, outdir / report_io.NAME)
    if not args.quiet:
        print("\n".join(summary))
        if aws.devices:
            reads = sum(d.stats.block_requests for d in aws.devices)
            mib = sum(d.stats.block_bytes for d in aws.devices) / (1 << 20)
            print(row("ebs_direct_api", f"{reads} GetSnapshotBlock ({mib:.0f} MiB)"))
        # What became of each snapshot made, as it is: one that could not be deleted
        # costs money until someone deletes it.
        done = msg("kept") if args.keep_snapshots else msg("deleted")
        for left, fate in ((False, done), (True, msg("not_deleted"))):
            made = [
                d.snapshot_id for d in aws.created if (d.snapshot_id in aws.not_deleted) == left
            ]
            if made:
                print(row("snapshots_made", msg("snapshots_made", ids=" ".join(made), fate=fate)))
            copies = [c for c in aws.copies if (c in aws.copies_not_deleted) == left]
            if copies:
                print(row("copies_made", msg("snapshots_made", ids=" ".join(copies), fate=fate)))
    if s3 is not None:
        return _upload(args, s3, m, outdir)
    return 0


def _upload(args: argparse.Namespace, s3: Any, m: dict[str, Any], outdir: Path) -> int:
    """Upload the outputs (--upload); 1 if that failed, the outputs staying in `outdir`."""
    from ec2_byhand.aws.upload import UploadError, upload_outputs

    place = args.upload
    prefix = place.run_prefix(m["current"]["label"], m["generated_at"])
    _progress(args, msg("uploading", bucket=place.bucket, prefix=prefix))
    try:
        keys = upload_outputs(s3, outdir, place, prefix, args.kms_key_id)
    except UploadError as err:
        _say(msg("upload_failed", error=err, outdir=outdir))
        return 1
    if not args.quiet:
        uploaded = msg("uploaded_to", bucket=place.bucket, prefix=prefix, count=len(keys))
        print(row("uploaded", uploaded))
    return 0


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Help whose lines break where a terminal needs them to: argparse counts
    characters, and a line of Japanese is twice as wide as it counts."""

    def _split_lines(self, text: str, width: int) -> list[str]:
        return super()._split_lines(text, width) if text.isascii() else wrap(text, width)


def build_parser() -> argparse.ArgumentParser:
    """The argparse parser for the ec2-byhand command, its help in the language now.

    ec2-byhand コマンドの argparse パーサー。ヘルプは今の言語で書く。
    """
    p = argparse.ArgumentParser(
        prog="ec2-byhand",
        description=msg("help_description"),
        epilog=msg("help_epilog"),
        formatter_class=_HelpFormatter,
        add_help=False,
    )
    # --help and --version in a group made here, where their help can be in the
    # language now; made first, it stands where argparse's own "options" would.
    options = p.add_argument_group(msg("help_group_options"))
    options.add_argument("-h", "--help", action="help", help=msg("help_help"))
    options.add_argument(
        "--version", action="version", version=f"ec2-byhand {__version__}", help=msg("help_version")
    )
    now = p.add_argument_group(msg("help_group_now"))
    cur = now.add_mutually_exclusive_group(required=True)
    cur.add_argument("--instance-id", metavar="ID", help=msg("help_instance_id"))
    cur.add_argument(
        "--current-snapshot", nargs="+", metavar="SNAP", help=msg("help_current_snapshot")
    )
    cur.add_argument("--current-image", nargs="+", metavar="IMG", help=msg("help_current_image"))
    ami = p.add_argument_group(msg("help_group_baseline"))
    base = ami.add_mutually_exclusive_group()
    base.add_argument("--baseline-ami", metavar="AMI", help=msg("help_baseline_ami"))
    base.add_argument(
        "--baseline-snapshot", nargs="+", metavar="SNAP", help=msg("help_baseline_snapshot")
    )
    base.add_argument("--baseline-image", nargs="+", metavar="IMG", help=msg("help_baseline_image"))
    base.add_argument("--no-baseline", action="store_true", help=msg("help_no_baseline"))
    what = p.add_argument_group(msg("help_group_what"))
    what.add_argument(
        "--exclude",
        action="append",
        default=[],
        type=path_glob,
        metavar="GLOB",
        help=msg("help_exclude"),
    )
    what.add_argument(
        "--include",
        action="append",
        default=[],
        type=path_glob,
        metavar="GLOB",
        help=msg("help_include"),
    )
    what.add_argument("--verify-checksums", action="store_true", help=msg("help_verify_checksums"))
    out = p.add_argument_group(msg("help_group_output"))
    out.add_argument("--output", "-o", required=True, metavar="DIR", help=msg("help_output"))
    out.add_argument(
        "--max-file-size",
        type=size_limit,
        default=DEFAULT_MAX_FILE_SIZE,
        metavar="SIZE",
        help=msg("help_max_file_size"),
    )
    out.add_argument("--include-sensitive", action="store_true", help=msg("help_include_sensitive"))
    out.add_argument(
        "--sensitive",
        action="append",
        default=[],
        type=path_glob,
        metavar="GLOB",
        help=msg("help_sensitive"),
    )
    out.add_argument("--no-archives", action="store_true", help=msg("help_no_archives"))
    out.add_argument("--upload", type=s3_place, metavar="S3URL", help=msg("help_upload"))
    out.add_argument("--kms-key-id", metavar="KEY", help=msg("help_kms_key_id"))
    out.add_argument("--label", help=msg("help_label"))
    out.add_argument("--force", action="store_true", help=msg("help_force"))
    out.add_argument("--quiet", "-q", action="store_true", help=msg("help_quiet"))
    aws = p.add_argument_group(msg("help_group_aws"))
    aws.add_argument("--region", help=msg("help_region"))
    aws.add_argument("--profile", help=msg("help_profile"))
    aws.add_argument("--keep-snapshots", action="store_true", help=msg("help_keep_snapshots"))
    aws.add_argument(
        "--parallel",
        type=parallel_count,
        default=READ_AHEAD_THREADS,
        metavar="N",
        help=msg("help_parallel", default=READ_AHEAD_THREADS),
    )
    return p


@contextlib.contextmanager
def _ending_like_ctrl_c() -> Iterator[None]:
    """Inside this, SIGTERM, SIGHUP (the terminal closed, the SSH or CloudShell session
    lost) and SIGBREAK end the run as Ctrl+C does. Left alone they kill the process on
    the spot, and the snapshots it made stay, costing money, with nothing said."""

    def stop(signum: int, frame: object) -> None:
        raise KeyboardInterrupt

    before = {}
    if threading.current_thread() is threading.main_thread():  # only there can signals be set
        for name in ("SIGTERM", "SIGHUP", "SIGBREAK"):  # each OS has its own of these
            number = getattr(signal, name, None)
            if number is not None:
                before[number] = signal.signal(number, stop)
    try:
        yield
    finally:
        for number, handler in before.items():
            signal.signal(number, signal.SIG_DFL if handler is None else handler)


def _escape_what_stdout_cannot_write() -> None:
    """Have stdout write a character its encoding lacks as an escape, as stderr does,
    instead of failing: a redirected stdout has the locale's encoding (cp932 on a
    Japanese Windows), and a path of the analyzed disk may hold anything."""
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(errors="backslashreplace")


def main(argv: list[str] | None = None) -> int:
    """Entry point: run in the language the environment asks for (see
    ec2_byhand.messages), turning known errors into exit codes.

    エントリポイント: 環境が求める言語（ec2_byhand.messages 参照）で実行し、既知のエラーを終了コード
    にする。
    """
    _escape_what_stdout_cannot_write()
    with language(language_from_environment()), _ending_like_ctrl_c():
        args = build_parser().parse_args(argv)
        try:
            return run(args)
        # Said with _say: after SIGHUP there is no stderr left, and the exit code must
        # still say what happened.
        except KeyboardInterrupt:  # the snapshots were dealt with on the way out of run()
            _say(msg("interrupted"))
            return 130
        except UsageError as err:
            _say(msg("error", error=printable(str(err))))
            if err.command:
                # Without the program's name in front: the line is there to be copied.
                with contextlib.suppress(OSError, ValueError):
                    print(f"    {printable(err.command)}", file=sys.stderr, flush=True)
            return 2
        except DiskReadError as err:
            _say(msg("cannot_read_disks", error=printable(str(err))))
            return 1
        except OSError as err:  # an image that cannot be opened, a full disk, no permission...
            _say(msg("error", error=printable(str(err))))
            return 1
        except Exception as err:  # AWS: no credentials, access denied, throttling...
            from botocore.exceptions import BotoCoreError, ClientError

            if isinstance(err, (BotoCoreError, ClientError)):
                _say(msg("aws_error", error=printable(str(err))))
                return 1
            raise


if __name__ == "__main__":
    sys.exit(main())
