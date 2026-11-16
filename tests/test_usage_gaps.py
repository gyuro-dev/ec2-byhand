"""What a real migration runs into: large files, excluded trees, dpkg hand work,
an app's own node_modules, files the noise rules used to swallow, and the CLI's
messages. Each test names the gap it closes."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import io
import json
import signal
import sqlite3
import struct
import tarfile
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from memfs import MemFs

from diskread import BytesDevice, DiskReadError
from diskread.fs import FileType, Stat
from diskread.source import SystemSource
from diskread.system import Mount, System, Volume, assemble
from ec2_byhand import __version__, cli
from ec2_byhand.analyze import ReadPlan, Snapshot, analyze
from ec2_byhand.archive import ArchiveOptions, write_outputs
from ec2_byhand.aws import ebs, snapshots
from ec2_byhand.aws.devices import ebs_device_volume
from ec2_byhand.aws.ebs import EbsStats
from ec2_byhand.aws.snapshots import Disk
from ec2_byhand.langpkgs import find_language_packages
from ec2_byhand.noise import NoiseFilter
from ec2_byhand.packages import read_packages
from ec2_byhand.packages.history import ZoneChange, parse_apt_history, read_history, zone_from
from ec2_byhand.packages.model import Package, PackageDB, PackageFile
from ec2_byhand.packages.verify import (
    RPMFILE_GHOST,
    VERIFY_DIGEST,
    VERIFY_SIZE,
    ReadLimits,
    verify_packages,
)
from ec2_byhand.sensitive import is_sensitive

BIG = 1000


def _snap(fs: MemFs) -> Snapshot:
    return Snapshot("test", SystemSource.from_fs(fs))


def _items(m: dict, key: str = "hand_placed") -> dict[str, dict]:
    return {i["path"]: i for i in m[key]}


def _tar_names(path: Path) -> set[str]:
    with tarfile.open(path) as tar:
        return set(tar.getnames())


# --- large files -----------------------------------------------------------------------


def test_a_file_over_the_limit_is_never_read() -> None:
    fs = MemFs()
    fs.add_file("/opt/dump.sql", bytes(BIG + 1))
    fs.add_file("/opt/small.conf", b"x")
    item = _items(analyze(_snap(fs), max_file_size=BIG))
    assert "sha256" not in item["/opt/dump.sql"]
    assert item["/opt/dump.sql"]["hash_skipped"] == "too-large"
    assert "sha256" in item["/opt/small.conf"]
    assert fs.opened == [fs.ino("/opt/small.conf")]


def test_a_large_file_is_judged_by_size_and_mtime_against_the_baseline() -> None:
    before, after = MemFs(), MemFs()
    for fs, stamp in ((before, 1), (after, 1)):
        fs.add_file("/opt/same", bytes(BIG + 1), mtime_ns=stamp)
    before.add_file("/opt/touched", bytes(BIG + 1), mtime_ns=1)
    after.add_file("/opt/touched", bytes(BIG + 1), mtime_ns=2)
    before.add_file("/opt/grown", bytes(BIG + 1))
    after.add_file("/opt/grown", bytes(BIG + 2))
    item = _items(analyze(_snap(after), _snap(before), max_file_size=BIG))
    assert set(item) == {"/opt/touched", "/opt/grown"}
    assert item["/opt/touched"]["changed"] == ["mtime"]
    assert item["/opt/grown"]["changed"] == ["sha256", "size"]
    assert not before.opened
    assert not after.opened


def test_a_changed_file_is_read_once_and_a_resized_one_not_on_the_baseline() -> None:
    before, after = MemFs(), MemFs()
    before.add_file("/opt/edited", b"aaa")
    after.add_file("/opt/edited", b"bbb")
    before.add_file("/opt/resized", b"short")
    after.add_file("/opt/resized", b"much longer")
    item = _items(analyze(_snap(after), _snap(before)))
    assert item["/opt/edited"]["changed"] == ["sha256"]
    assert sorted(after.opened) == sorted([after.ino("/opt/edited"), after.ino("/opt/resized")])
    assert before.opened == [before.ino("/opt/edited")]


# --- --exclude keeps the walk out ------------------------------------------------------


def _with_cache() -> MemFs:
    fs = MemFs()
    fs.add_file("/opt/cache/a/b", b"x")
    fs.add_file("/opt/keep", b"x")
    return fs


def test_an_excluded_directory_is_not_walked() -> None:
    fs = _with_cache()
    m = analyze(_snap(fs), noise=NoiseFilter(excludes=("/opt/cache/**",)))
    assert fs.ino("/opt/cache") not in fs.listed
    assert set(_items(m)) == {"/", "/opt", "/opt/keep"}
    assert m["noise"]["by_rule"]["user-exclude"] == 1


def test_a_pattern_that_may_be_included_back_is_still_walked() -> None:
    fs = _with_cache()
    noise = NoiseFilter(excludes=("/opt/cache/**",), includes=("/opt/cache/a/**",))
    m = analyze(_snap(fs), noise=noise)
    assert "/opt/cache/a/b" in _items(m)


def test_a_file_pattern_does_not_stop_the_walk() -> None:
    assert not NoiseFilter(excludes=("**/*.bak",)).prunes("/opt/x.bak")


class _HalfWritten(MemFs):
    """Some inodes cannot be read, like one caught half-written in a dirty snapshot."""

    def __init__(self) -> None:
        super().__init__()
        self.bad: set[int] = set()

    def stat(self, ino: int) -> Stat:
        if ino in self.bad:
            raise DiskReadError(f"unknown file type in mode 0o0 (inode {ino})")
        return super().stat(ino)


def test_an_unreadable_path_a_rule_hides_is_counted_not_warned() -> None:
    # Seen on RHEL 9: /var/lib/rsyslog/imjournal.state, rewritten every few seconds.
    fs = _HalfWritten()
    fs.add_file("/var/lib/rsyslog/imjournal.state", b"x")
    fs.add_file("/opt/app/conf", b"x")
    readable = analyze(_snap(fs))["noise"]["by_rule"]
    fs.bad = {fs.ino("/var/lib/rsyslog/imjournal.state"), fs.ino("/opt/app/conf")}
    m = analyze(_snap(fs))
    assert [w["path"] for w in m["warnings"] if w["code"] == "read-error"] == ["/opt/app/conf"]
    assert m["noise"]["by_rule"] == readable  # counted under its rule, as if it had been read


# --- dpkg: what dpkg --verify cannot see ---------------------------------------------------


def _dpkg_db(fs: MemFs, packages: dict[str, tuple[str, dict[str, bytes | None]]]) -> None:
    """name -> (version, path -> content whose md5 is recorded, or None for none recorded)."""
    status = ""
    for name, (version, files) in packages.items():
        status += (
            f"Package: {name}\nStatus: install ok installed\n"
            f"Version: {version}\nArchitecture: amd64\n\n"
        )
        fs.add_file(f"/var/lib/dpkg/info/{name}:amd64.list", "\n".join(files).encode() + b"\n")
        sums = "".join(
            f"{hashlib.md5(data).hexdigest()}  {path.lstrip('/')}\n"
            for path, data in files.items()
            if data is not None
        )
        fs.add_file(f"/var/lib/dpkg/info/{name}:amd64.md5sums", sums.encode())
    fs.add_file("/var/lib/dpkg/status", status.encode())


def _dpkg_sides(version_now: str = "1.0") -> tuple[MemFs, MemFs]:
    """The same package on both sides, then the hand work on the current one."""
    listed: dict[str, bytes | None] = {
        "/srv/app": None,
        "/usr/bin/run": b"run",
        "/usr/lib/app.so": None,
        "/usr/share/app/data": None,
    }
    before, after = MemFs(), MemFs()
    _dpkg_db(before, {"app": ("1.0", listed)})
    _dpkg_db(after, {"app": (version_now, listed)})
    before.add_dir("/srv/app")
    after.add_dir("/srv/app", mode=0o777)
    before.add_file("/usr/bin/run", b"run")
    after.add_file("/usr/bin/run", b"run", mode=0o4755)
    before.add_link("/usr/lib/app.so", "app.so.1")
    after.add_link("/usr/lib/app.so", "/opt/patched.so")
    before.add_file("/usr/share/app/data", b"old")
    after.add_file("/usr/share/app/data", b"new")
    return before, after


def test_dpkg_changes_only_the_baseline_can_show() -> None:
    before, after = _dpkg_sides()
    item = _items(analyze(_snap(after), _snap(before)), "modified_package_files")
    assert item["/srv/app"]["problems"] == ["mode"]
    assert item["/usr/bin/run"]["problems"] == ["mode"]
    assert item["/usr/lib/app.so"]["problems"] == ["link"]
    assert item["/usr/share/app/data"]["problems"] == ["content-since-baseline"]
    assert all(i["since_baseline"] for i in item.values())


def test_a_file_the_ami_already_changed_is_compared_with_the_ami() -> None:
    # Seen on AL2023: the AMI ships an sshd_config that differs from its package, so
    # "content" is a problem on both sides, and a line appended by hand hid behind it.
    listed: dict[str, bytes | None] = {"/etc/edited": b"pkg", "/etc/kept": b"pkg"}
    before, after = MemFs(), MemFs()
    for fs in (before, after):
        _dpkg_db(fs, {"app": ("1.0", listed)})
        fs.add_file("/etc/kept", b"ami")
    before.add_file("/etc/edited", b"ami")
    after.add_file("/etc/edited", b"ami + hand")
    item = _items(analyze(_snap(after), _snap(before)), "modified_package_files")
    assert item["/etc/edited"]["since_baseline"] is True
    assert item["/etc/kept"]["since_baseline"] is False


def test_a_package_directory_under_run_is_never_missing() -> None:
    # Seen on AL2023: lvm2 lists /run/lvm, which only the tmpfs of a running system holds.
    listed: dict[str, bytes | None] = {"/run/app": None, "/etc/app.conf": None}
    before, after = MemFs(), MemFs()
    _dpkg_db(before, {"other": ("1", {})})
    _dpkg_db(after, {"app": ("1.0", listed)})
    m = analyze(_snap(after), _snap(before))
    assert [i["path"] for i in m["modified_package_files"]] == ["/etc/app.conf"]
    assert m["noise"]["by_rule"]["runtime"] == 1


def test_a_package_upgraded_since_the_baseline_is_not_compared() -> None:
    before, after = _dpkg_sides(version_now="2.0")
    assert not analyze(_snap(after), _snap(before))["modified_package_files"]


def test_a_directory_many_packages_list_is_reported_once() -> None:
    before, after = MemFs(), MemFs()
    listed: dict[str, bytes | None] = {"/srv/app": None}
    for fs in (before, after):
        _dpkg_db(fs, {"a": ("1", listed), "b": ("1", listed)})
    before.add_dir("/srv/app")
    after.add_dir("/srv/app", mode=0o777)
    m = analyze(_snap(after), _snap(before))
    assert [i["path"] for i in m["modified_package_files"]] == ["/srv/app"]


# --- an app's own node_modules -------------------------------------------------------------


def test_local_node_modules_is_grouped_not_listed_file_by_file() -> None:
    fs = MemFs()
    top = "/opt/app/node_modules"
    fs.add_file("/opt/app/package.json", b"{}")
    fs.add_file(f"{top}/express/package.json", b'{"name": "express", "version": "4.0.0"}')
    fs.add_file(f"{top}/express/index.js", b"//")
    fs.add_file(f"{top}/express/node_modules/dep/package.json", b'{"name": "dep"}')
    fs.add_file(f"{top}/@scope/lib/package.json", b'{"name": "@scope/lib", "version": "1.0.0"}')
    fs.add_link(f"{top}/.bin/express", "../express/index.js")
    fs.add_file(f"{top}/.package-lock.json", b"{}")
    m = analyze(_snap(fs))
    assert {p["name"]: p["location"] for p in m["language_packages"]} == {
        "express": top,
        "@scope/lib": top,
    }
    assert set(_items(m)) == {"/", "/opt", "/opt/app", "/opt/app/package.json"}


def test_a_stray_file_in_node_modules_stays_hand_placed() -> None:
    fs = MemFs()
    fs.add_file("/opt/app/node_modules/x/package.json", b'{"name": "x"}')
    fs.add_file("/opt/app/node_modules/NOTES.txt", b"remember this")
    assert "/opt/app/node_modules/NOTES.txt" in _items(analyze(_snap(fs)))


# --- what the noise rules used to swallow ------------------------------------------------


def test_a_certificate_put_by_hand_is_not_noise_but_generated_links_are() -> None:
    fs = MemFs()
    fs.add_file("/etc/ssl/certs/server.crt", b"cert")
    fs.add_link("/etc/ssl/certs/Mozilla_Root.pem", "/usr/share/ca-certificates/root.crt")
    fs.add_file("/etc/ssl/certs/ca-certificates.crt", b"bundle")
    m = analyze(_snap(fs))
    found = _items(m)
    assert "/etc/ssl/certs/server.crt" in found
    assert "/etc/ssl/certs/Mozilla_Root.pem" not in found
    assert "/etc/ssl/certs/ca-certificates.crt" not in found
    assert m["noise"]["by_rule"]["ca-links"] == 1


def test_a_log_directory_made_by_hand_is_kept_but_its_logs_are_not() -> None:
    before, after = MemFs(), MemFs()
    before.add_dir("/var/log")
    after.add_file("/var/log/myapp/app.log", b"line")
    after.add_file("/var/log/journal/abc/system.journal", b"x")
    outdir_item = _items(analyze(_snap(after), _snap(before)))
    assert set(outdir_item) == {"/var/log/myapp"}
    assert outdir_item["/var/log/myapp"]["type"] == str(FileType.DIR)


def test_excluding_a_log_directory_hides_the_directory_too() -> None:
    fs = MemFs()
    fs.add_file("/var/log/vendor/app.log", b"line")
    m = analyze(_snap(fs), noise=NoiseFilter(excludes=("/var/log/vendor/**",)))
    assert "/var/log/vendor" not in _items(m)


# --- archives ---------------------------------------------------------------------------------


def test_files_from_a_package_run_are_archived(tmp_path: Path) -> None:
    before, after = MemFs(), MemFs()
    before.add_file("/etc/app.conf", b"old\n")
    after.add_file("/etc/app.conf", b"new\n")
    after.add_file("/etc/app.d/generated", b"x")
    manifest = {
        "hand_placed": [],
        "modified_package_files": [],
        "deleted": [],
        "package_scripts": [
            {
                "files": [
                    {"path": "/etc/app.conf", "status": "modified"},
                    {"path": "/etc/app.d/generated", "status": "added"},
                ]
            }
        ],
    }
    result = write_outputs(manifest, _snap(after).source, _snap(before).source, tmp_path)
    assert _tar_names(tmp_path / "after.tar.gz") == {"etc/app.conf", "etc/app.d/generated"}
    assert _tar_names(tmp_path / "before.tar.gz") == {"etc/app.conf"}
    assert result["patches"]["files"] == 1


def test_a_package_file_the_baseline_already_had_is_not_archived(tmp_path: Path) -> None:
    # Seen on AL2023: /boot's initramfs differs in mode from its package in the AMI
    # itself (28 MB in after.tar.gz). Without a baseline it is archived: hand work or not
    # cannot be told.
    before, after = MemFs(), MemFs()
    for fs in (before, after):
        fs.add_file("/boot/initramfs.img", b"ami")
    before.add_file("/etc/app.conf", b"old\n")
    after.add_file("/etc/app.conf", b"new\n")
    entry = {"package": "app", "problems": ["mode"], "config": False}
    manifest = {
        "hand_placed": [],
        "modified_package_files": [
            {**entry, "path": "/boot/initramfs.img", "since_baseline": False},
            {**entry, "path": "/etc/app.conf", "since_baseline": True},
        ],
        "deleted": [],
    }
    write_outputs(manifest, _snap(after).source, _snap(before).source, tmp_path / "with")
    assert _tar_names(tmp_path / "with" / "after.tar.gz") == {"etc/app.conf"}
    assert _tar_names(tmp_path / "with" / "before.tar.gz") == {"etc/app.conf"}

    for m in manifest["modified_package_files"]:
        m["since_baseline"] = None
    write_outputs(manifest, _snap(after).source, None, tmp_path / "without")
    assert _tar_names(tmp_path / "without" / "after.tar.gz") == {
        "boot/initramfs.img",
        "etc/app.conf",
    }


@pytest.mark.parametrize(
    ("old", "new", "reason"),
    [
        ("設定\n".encode("euc-jp"), "変更\n".encode("euc-jp"), "patch-not-utf8"),
        (b"a\n" * (1 << 20), b"b\n" * (1 << 20), "patch-too-large"),
    ],
    ids=["euc-jp", "over-1-mib"],
)
def test_a_missing_patch_says_why(tmp_path: Path, old: bytes, new: bytes, reason: str) -> None:
    before, after = MemFs(), MemFs()
    before.add_file("/etc/app.conf", old)
    after.add_file("/etc/app.conf", new)
    manifest = {
        "hand_placed": [{"path": "/etc/app.conf", "status": "modified"}],
        "modified_package_files": [],
        "deleted": [],
    }
    result = write_outputs(manifest, _snap(after).source, _snap(before).source, tmp_path)
    assert result["skipped"] == [{"archive": "patches", "path": "/etc/app.conf", "reason": reason}]


def test_a_binary_file_needs_no_reason(tmp_path: Path) -> None:
    before, after = MemFs(), MemFs()
    before.add_file("/opt/app.bin", b"\0old")
    after.add_file("/opt/app.bin", b"\0new")
    manifest = {
        "hand_placed": [{"path": "/opt/app.bin", "status": "modified"}],
        "modified_package_files": [],
        "deleted": [],
    }
    result = write_outputs(manifest, _snap(after).source, _snap(before).source, tmp_path)
    assert result["skipped"] == []


@pytest.mark.parametrize("name", [".env.example", ".env.sample", ".env.template", ".env.dist"])
def test_env_templates_are_not_secrets(name: str) -> None:
    assert not is_sensitive(f"/opt/app/{name}")


@pytest.mark.parametrize("name", [".env", ".env.production", ".env.local"])
def test_real_env_files_still_are(name: str) -> None:
    assert is_sensitive(f"/opt/app/{name}")


# --- services and versions in the manifest ----------------------------------------------------


def test_unchanged_services_are_counted_not_listed() -> None:
    before, after = MemFs(), MemFs()
    wants = "/etc/systemd/system/multi-user.target.wants"
    for fs in (before, after):
        fs.add_link(f"{wants}/sshd.service", "/usr/lib/systemd/system/sshd.service")
    after.add_link(f"{wants}/myapp.service", "/etc/systemd/system/myapp.service")
    m = analyze(_snap(after), _snap(before))
    assert [s["unit"] for s in m["services"]] == ["myapp.service"]
    assert m["summary"]["services"] == 1
    assert m["summary"]["services_unchanged_since_baseline"] == 1


def test_manifest_says_which_version_made_it() -> None:
    assert analyze(_snap(MemFs()))["tool"] == {"name": "ec2-byhand", "version": __version__}


# --- volumes -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("spec", "index"),
    [
        ("/dev/xvdf", 0),
        ("/dev/sdf", 0),
        ("/dev/xvda1", 1),
        ("/dev/sda1", 1),
        ("/dev/xvdp1", 2),
        ("/dev/sdb", None),
        ("/dev/xvda2", None),
        ("/dev/nvme1n1p1", None),
    ],
)
def test_sd_and_xvd_names_resolve_to_the_disk_the_api_named(spec: str, index: int | None) -> None:
    dev = BytesDevice(bytes(512))
    vols = [Volume("/dev/sdf", dev), Volume("/dev/sda1p1", dev), Volume("/dev/xvdpp1", dev)]
    assert ebs_device_volume(spec, vols) is (None if index is None else vols[index])


def test_a_filesystem_nothing_mounts_is_a_warning() -> None:
    root_fs, data_fs = MemFs(), MemFs()
    dev = BytesDevice(bytes(512))
    root = Volume("/dev/xvda", dev, fs_type="xfs", fs=root_fs)
    data = Volume("/dev/xvdf", dev, fs_type="xfs", fs=data_fs)
    swap = Volume("/dev/xvdg", dev)  # no filesystem at all: nothing to say
    mount = Mount(b"/", root, None, root_fs)
    system = System(volumes=[root, data, swap], root=root, mounts=[mount])
    m = analyze(Snapshot("test", SystemSource.from_system(system), system))
    (warning,) = [w for w in m["warnings"] if w["code"] == "unmounted-volume"]
    assert warning["volume"] == "/dev/xvdf"
    assert warning["snapshot"] == "current"


# --- the command line ------------------------------------------------------------------------


def test_summary_says_where_a_warning_happened(tmp_path: Path, monkeypatch, capsys) -> None:
    fs = MemFs()
    dev = BytesDevice(bytes(512))
    root = Volume("/dev/xvda", dev, fs_type="xfs", fs=fs)
    data = Volume("/dev/xvdf", dev, fs_type="ext4", fs=MemFs())
    system = System([root, data], root, [Mount(b"/", root, None, fs)])
    monkeypatch.setattr(
        cli,
        "_sides",
        lambda args, aws, stack: (Snapshot("x", SystemSource.from_system(system), system), None),
    )
    assert cli.main(["--current-image", "unused", "-o", str(tmp_path / "o"), "--no-archives"]) == 0
    out = capsys.readouterr().out
    assert "warning: unmounted-volume (current /dev/xvdf): holds a ext4 filesystem" in out
    assert "language packages:" in out
    assert "services:" in out


def test_version_option(capsys) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"ec2-byhand {__version__}"


@pytest.mark.parametrize("flag", ["--exclude", "--include"])
@pytest.mark.parametrize("pattern", ["*.bak", "opt/app/**", "/opt/app/"])
def test_a_pattern_that_could_never_match_is_refused(flag: str, pattern: str, capsys) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--current-image", "x", "-o", "o", f"{flag}={pattern}"])
    assert exit_info.value.code == 2
    assert "/opt/app/**" in capsys.readouterr().err


class _Ec2:
    def __init__(self) -> None:
        self.deleted: list[str] = []

    def delete_snapshot(self, **kwargs: str) -> None:
        self.deleted.append(kwargs["SnapshotId"])


def test_ctrl_c_says_what_happened_to_the_snapshots(tmp_path: Path, monkeypatch, capsys) -> None:
    ec2 = _Ec2()
    monkeypatch.setattr(cli, "make_aws_clients", lambda region, profile: (ec2, None))

    def sides(args, aws, stack):
        aws.created = [Disk("/dev/xvda", "snap-made")]
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_sides", sides)
    assert cli.main(["--current-image", "unused", "-o", str(tmp_path / "o")]) == 130
    err = capsys.readouterr().err
    assert ec2.deleted == ["snap-made"]
    assert "snap-made" in err
    assert "snapshots deleted" in err
    assert err.rstrip().endswith("interrupted")


def test_sigterm_ends_the_run_as_ctrl_c_does(tmp_path: Path, monkeypatch, capsys) -> None:
    # Killed on the spot, the run would leave its snapshots behind, costing money.
    ec2 = _Ec2()
    monkeypatch.setattr(cli, "make_aws_clients", lambda region, profile: (ec2, None))
    before = signal.getsignal(signal.SIGTERM)

    def sides(args, aws, stack):
        aws.created = [Disk("/dev/xvda", "snap-made")]
        signal.raise_signal(signal.SIGTERM)
        raise AssertionError("the signal did not end the run")

    monkeypatch.setattr(cli, "_sides", sides)
    assert cli.main(["--current-image", "unused", "-o", str(tmp_path / "o")]) == 130
    assert ec2.deleted == ["snap-made"]
    assert "snapshots deleted" in capsys.readouterr().err
    assert signal.getsignal(signal.SIGTERM) is before  # the run leaves no handler behind


def test_snapshots_are_deleted_though_stderr_is_gone(tmp_path: Path, monkeypatch) -> None:
    # After SIGHUP the terminal is gone: saying what is deleted fails, deleting must not.
    class Gone:
        def write(self, text: str) -> int:
            raise OSError(5, "Input/output error")

        def flush(self) -> None:
            raise OSError(5, "Input/output error")

    ec2 = _Ec2()
    aws = cli._Aws(SimpleNamespace(quiet=False, keep_snapshots=False, region=None, profile=None))
    aws._clients = (ec2, None)
    aws.created = [Disk("/dev/xvda", "snap-made")]
    monkeypatch.setattr(cli.sys, "stderr", Gone())
    aws.cleanup()
    assert ec2.deleted == ["snap-made"]


def test_kept_snapshots_are_named_even_when_quiet(tmp_path: Path, monkeypatch, capsys) -> None:
    # They cost money until deleted, and with --label nothing else says which they are.
    def sides(args, aws, stack):
        aws.created = [Disk("/dev/xvda", "snap-kept")]
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_sides", sides)
    args = ["--current-image", "unused", "-o", str(tmp_path / "o"), "--keep-snapshots", "-q"]
    assert cli.main(args) == 130
    assert "keeping snapshots: snap-kept" in capsys.readouterr().err


def test_the_wait_for_snapshots_has_no_limit_and_says_how_far_they_are(monkeypatch) -> None:
    states = [("pending", "0%")] * 1500 + [("pending", "99%"), ("completed", "100%")]
    looks: list[dict[str, str]] = []
    slept: list[float] = []

    def describe_snapshots(SnapshotIds: list[str]) -> dict:  # noqa: N803
        state, progress = states[len(slept)]
        return {"Snapshots": [{"SnapshotId": "snap-1", "State": state, "Progress": progress}]}

    monkeypatch.setattr(snapshots.time, "sleep", slept.append)
    ec2 = SimpleNamespace(describe_snapshots=describe_snapshots)
    snapshots.wait_for_snapshots(ec2, [Disk("/dev/xvda", "snap-1")], looks.append)
    assert len(slept) == 1501  # over two hours of looks
    assert looks[-1] == {"snap-1": "99%"}
    # Often enough that the reads start soon after the snapshots are done.
    assert set(slept) == {5}

    def failed(SnapshotIds: list[str]) -> dict:  # noqa: N803
        return {"Snapshots": [{"SnapshotId": "snap-1", "State": "error", "StateMessage": "x"}]}

    with pytest.raises(snapshots.AwsSourceError, match="snap-1 failed: x"):
        snapshots.wait_for_snapshots(SimpleNamespace(describe_snapshots=failed), [Disk("d", "s")])


def test_a_long_wait_reports_every_few_minutes(monkeypatch, capsys) -> None:
    clock = [1000.0]
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    aws = cli._Aws(SimpleNamespace(quiet=False, region=None, profile=None))
    for _ in range(41):  # ten minutes of looks
        aws.report_wait({"snap-1": "37%", "snap-2": ""})
        clock[0] += 15
    err = capsys.readouterr().err
    assert err.count("snapshots so far: snap-1 37%, snap-2\n") == 2


def test_many_warnings_of_one_kind_do_not_bury_the_summary() -> None:
    def warning(code: str, path: str) -> dict:
        return {"code": code, "snapshot": "current", "path": path, "message": "bad block"}

    warnings = [{"code": "no-baseline", "message": "no baseline snapshot"}]
    warnings += [warning("read-error", f"/srv/{n}") for n in range(1234)]
    warnings += [warning("content-not-verified", "/usr/bin/big")]
    assert cli._warning_lines(warnings) == [
        "warning: no-baseline: no baseline snapshot",
        "warning: read-error (current /srv/0): bad block",
        "warning: read-error (current /srv/1): bad block",
        "warning: read-error (current /srv/2): bad block",
        "warning: content-not-verified (current /usr/bin/big): bad block",
        'warning: read-error: 1231 more (see "warnings" in the manifest)',
    ]
    assert len(cli._warning_lines(warnings[:4])) == 4  # three of a kind: all shown


def test_stdout_that_cannot_write_a_character_escapes_it(monkeypatch) -> None:
    # A redirected stdout on a Japanese Windows is cp932, and has no "é"; Japanese
    # messages on an ASCII stdout are the same case the other way round.
    raw = io.BytesIO()
    monkeypatch.setattr(cli.sys, "stdout", io.TextIOWrapper(raw, encoding="cp932"))
    cli._escape_what_stdout_cannot_write()
    print("warning: read-error (current /opt/caf\u00e9.conf): x", file=cli.sys.stdout, flush=True)
    assert raw.getvalue().rstrip() == rb"warning: read-error (current /opt/caf\xe9.conf): x"

    raw = io.BytesIO()
    monkeypatch.setattr(cli.sys, "stdout", io.TextIOWrapper(raw, encoding="ascii"))
    monkeypatch.setenv("EC2_BYHAND_LANG", "ja")
    with pytest.raises(SystemExit) as exit_:
        cli.main(["--help"])
    assert exit_.value.code == 0
    cli.sys.stdout.flush()
    assert rb"\u73fe\u5728\u306e\u30b5\u30fc\u30d0\u30fc" in raw.getvalue()  # 現在のサーバー


def test_keep_snapshots_names_them_when_the_run_is_cut_short(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    def sides(args, aws, stack):
        aws.created = [Disk("/dev/xvda", "snap-kept")]
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_sides", sides)
    args = ["--current-image", "unused", "-o", str(tmp_path / "o"), "--keep-snapshots"]
    assert cli.main(args) == 130
    assert "keeping snapshots: snap-kept" in capsys.readouterr().err


def test_long_reads_report_progress(monkeypatch, capsys) -> None:
    aws = cli._Aws(SimpleNamespace(quiet=False, region=None, profile=None))
    aws.devices = [SimpleNamespace(stats=EbsStats(block_requests=3, block_bytes=3 << 20))]
    aws._report_reads()  # too soon: nothing to say yet
    assert capsys.readouterr().err == ""
    monkeypatch.setattr(cli, "PROGRESS_SECONDS", 0)
    aws._report_reads()
    assert "read 3 blocks (3 MiB) so far" in capsys.readouterr().err


def test_manifest_reports_the_cap_end_to_end(tmp_path: Path, monkeypatch) -> None:
    fs = MemFs()
    fs.add_file("/opt/dump.sql", bytes(2048))
    monkeypatch.setattr(cli, "_sides", lambda args, aws, stack: (_snap(fs), None))
    args = ["--current-image", "unused", "-o", str(tmp_path / "o"), "-q", "--max-file-size", "1K"]
    assert cli.main(args) == 0
    m = json.loads((tmp_path / "o" / "manifest.json").read_text(encoding="utf-8"))
    assert _items(m)["/opt/dump.sql"]["hash_skipped"] == "too-large"
    assert m["archives"]["skipped"][0]["reason"] == "too-large"
    assert not fs.opened


# --- fstab entries that name a volume by id, or only by a boot-time number ---------------------


def _nvme_system(fstab: str, *others: Volume) -> System:
    """A root volume holding this fstab, plus other volumes, assembled as a run would."""
    fs = MemFs()
    fs.add_file("/etc/fstab", fstab.encode())
    root = Volume(
        "/dev/xvda", BytesDevice(bytes(512)), fs_type="xfs", fs=fs, partition=1, label="x"
    )
    return assemble([root, *others], resolve_device=ebs_device_volume)


def _volume(name: str, fs_type: str = "xfs", partition: int | None = None, **kw) -> Volume:
    return Volume(
        name, BytesDevice(bytes(512)), fs_type=fs_type, fs=MemFs(), partition=partition, **kw
    )


def test_by_id_names_the_volume_whatever_the_other_disks_hold() -> None:
    one, two = _volume("/dev/sdf", serial="vol0aaa"), _volume("/dev/sdg", serial="vol0bbb")
    part = _volume("/dev/sdhp1", partition=1, serial="vol0ccc")
    by_id = "/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store"
    system = _nvme_system(
        f"LABEL=x / xfs defaults 0 0\n"
        f"{by_id}_vol0bbb /data xfs defaults 0 0\n"
        f"{by_id}_vol0ccc_1-part1 /logs xfs defaults 0 0\n",
        one,
        two,
        part,
    )
    assert {m.mountpoint: m.volume for m in system.mounts if m.mountpoint != b"/"} == {
        b"/data": two,
        b"/logs": part,
    }
    assert not system.inferred


def test_by_id_picks_the_partition_it_names() -> None:
    first = _volume("/dev/sdfp1", partition=1, serial="vol0aaa")
    second = _volume("/dev/sdfp2", partition=2, serial="vol0aaa")
    by_id = "/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol0aaa"
    assert ebs_device_volume(f"{by_id}-part2", [first, second]) is second
    assert ebs_device_volume(by_id, [first, second]) is None  # the whole disk has no filesystem


def test_the_only_volume_that_fits_is_mounted_and_the_guess_reported() -> None:
    data = _volume("/dev/sdf")
    system = _nvme_system(
        "/dev/nvme0n1p1 / xfs defaults 0 0\n/dev/nvme1n1 /data xfs defaults 0 0\n", data
    )
    assert [m.mountpoint for m in system.mounts] == [b"/", b"/data"]
    assert [v for _, v in system.inferred] == [data]  # the root line is no guess
    assert not system.unresolved


def test_a_filesystem_type_and_partition_can_tell_volumes_apart() -> None:
    xfs, ext4, part = (
        _volume("/dev/sdf"),
        _volume("/dev/sdg", "ext4"),
        _volume("/dev/sdhp1", partition=1),
    )
    system = _nvme_system(
        "LABEL=x / xfs defaults 0 0\n"
        "/dev/nvme1n1 /a xfs defaults 0 0\n"
        "/dev/nvme2n1 /b ext3 defaults 0 0\n"
        "/dev/nvme3n1p1 /c xfs defaults 0 0\n",
        xfs,
        ext4,
        part,
    )
    assert {m.mountpoint: m.volume for m in system.mounts if m.mountpoint != b"/"} == {
        b"/a": xfs,
        b"/b": ext4,
        b"/c": part,
    }


def test_two_volumes_that_fit_are_not_guessed_between() -> None:
    system = _nvme_system(
        "LABEL=x / xfs defaults 0 0\n/dev/nvme1n1 /a xfs defaults 0 0\n",
        _volume("/dev/sdf"),
        _volume("/dev/sdg"),
    )
    assert [m.mountpoint for m in system.mounts] == [b"/"]
    ((entry, reason),) = system.unresolved
    assert entry.mountpoint == "/a"
    assert "2 volumes fit" in reason


def test_two_entries_after_one_volume_get_nothing() -> None:
    system = _nvme_system(
        "LABEL=x / xfs defaults 0 0\n"
        "/dev/nvme1n1 /a xfs defaults 0 0\n"
        "/dev/nvme2n1 /b xfs defaults 0 0\n",
        _volume("/dev/sdf"),
    )
    assert [m.mountpoint for m in system.mounts] == [b"/"]
    assert [e.mountpoint for e, _ in system.unresolved] == ["/a", "/b"]


def test_an_nvme_entry_with_nothing_left_is_unresolved_in_fstab_order() -> None:
    system = _nvme_system(
        "/dev/nvme1n1 /a xfs defaults 0 0\nUUID=gone /b xfs defaults 0 0\n"
        "/dev/nvme2n1 /c ext4 defaults 0 0\n"
    )
    assert [e.mountpoint for e, _ in system.unresolved] == ["/a", "/b", "/c"]
    assert {r for _, r in system.unresolved} == {"device not found among the scanned volumes"}


def test_a_run_gives_scan_the_volume_ids_as_serial_numbers(monkeypatch) -> None:
    seen: dict[str, str] = {}

    def fake_open_disks(devices, label, verify, serials, find_serials=None, attached=None):
        seen.update(serials)
        return _snap(MemFs())

    monkeypatch.setattr(cli, "open_disks", fake_open_disks)
    monkeypatch.setattr(cli, "make_aws_clients", lambda region, profile: (None, None))
    monkeypatch.setattr(ebs, "EbsSnapshotDevice", lambda *args, **kwargs: SimpleNamespace())
    aws = cli._Aws(SimpleNamespace(quiet=True, region=None, profile=None, parallel=1))
    disks = [Disk("/dev/xvdf", "snap-1", "vol-0abc"), Disk("disk1", "snap-2")]
    aws.open(disks, "current", False)
    assert seen == {"/dev/xvdf": "vol0abc"}


def test_a_run_understands_ec2_device_names_in_fstab(monkeypatch) -> None:
    fs = MemFs()
    fs.add_file("/etc/fstab", b"LABEL=x / xfs defaults 0 0\n/dev/xvdf /data xfs defaults 0 0\n")
    root = Volume("/dev/sda1", BytesDevice(bytes(512)), fs_type="xfs", fs=fs, label="x")
    data = _volume("/dev/sdf")
    monkeypatch.setattr(cli, "scan", lambda disks, verify, serials: [root, data])
    snapshot = cli.open_disks({}, "current")
    assert sorted(snapshot.source.mounts) == [b"/", b"/data"]


def test_by_id_for_snapshots_given_by_id_asks_for_their_volumes(monkeypatch) -> None:
    # --current-snapshot: no volume ids are known until DescribeSnapshots is asked, and it
    # is asked only when fstab names a volume by its id.
    by_id = "/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol0aaa"
    asked: list[int] = []

    def find_serials() -> dict[str, str]:
        asked.append(1)
        return {"disk1": "vol0aaa"}

    for fstab, mounts, times in (
        (f"LABEL=x / xfs defaults 0 0\n{by_id} /data xfs defaults 0 0\n", [b"/", b"/data"], 1),
        ("LABEL=x / xfs defaults 0 0\n", [b"/"], 0),
    ):
        fs = MemFs()
        fs.add_file("/etc/fstab", fstab.encode())
        root = Volume("disk0", BytesDevice(bytes(512)), fs_type="xfs", fs=fs, label="x")
        monkeypatch.setattr(cli, "scan", lambda *a, root=root: [root, _volume("disk1")])
        asked.clear()
        snapshot = cli.open_disks({}, "current", find_serials=find_serials)
        assert sorted(snapshot.source.mounts) == mounts
        assert len(asked) == times


def test_a_backup_given_by_id_gets_the_device_names_of_the_instance(monkeypatch) -> None:
    # --instance-id i-... --baseline-snapshot snap-root snap-data: the baseline's disks are
    # "disk0" and "disk1", and fstab says /dev/xvdf. Unmounted there but mounted on the
    # current side, everything on the data volume would come out as added.
    attached = {"vol0root": "/dev/xvda", "vol0data": "/dev/sdf"}
    asked: list[int] = []

    def find_serials() -> dict[str, str]:
        asked.append(1)
        return {"disk0": "vol0root", "disk1": "vol0data"}

    fs = MemFs()
    fs.add_file("/etc/fstab", b"LABEL=x / xfs defaults 0 0\n/dev/xvdf1 /data xfs defaults 0 0\n")
    root = Volume("disk0", BytesDevice(bytes(512)), fs_type="xfs", fs=fs, label="x")
    data = _volume("disk1p1", partition=1)
    monkeypatch.setattr(cli, "scan", lambda *a: [root, data, _volume("disk2")])
    snapshot = cli.open_disks({}, "baseline", find_serials=find_serials, attached=attached)
    assert snapshot.source.mounts[b"/data"] is data.fs
    assert len(asked) == 1
    # Without the instance's names there is nothing to ask DescribeSnapshots for.
    asked.clear()
    data.serial = None
    snapshot = cli.open_disks({}, "baseline", find_serials=find_serials)
    assert sorted(snapshot.source.mounts) == [b"/"]
    assert not asked


def test_the_instance_tells_which_volume_a_device_name_is() -> None:
    whole = _volume("disk1", serial="vol0aaa")
    first = _volume("disk2p1", partition=1, serial="vol0bbb")
    other = _volume("disk3", serial="vol0ccc")  # of a volume the instance no longer has
    attached = {"vol0aaa": "/dev/sdf", "vol0bbb": "/dev/xvdg"}
    volumes = [whole, first, other]
    assert ebs_device_volume("/dev/xvdf", volumes, attached) is whole
    assert ebs_device_volume("/dev/sdg1", volumes, attached) is first
    assert ebs_device_volume("/dev/sdg", volumes, attached) is None
    assert ebs_device_volume("/dev/sdh", volumes, attached) is None
    assert ebs_device_volume("/dev/xvdf", volumes) is None


def test_the_volumes_of_snapshots_given_by_id_come_from_describe_snapshots(monkeypatch) -> None:
    found: dict[str, str] = {}

    def fake_open_disks(devices, label, verify, serials, find_serials=None, attached=None):
        found.update(find_serials())
        return _snap(MemFs())

    ec2 = SimpleNamespace(
        describe_snapshots=lambda **kwargs: {
            "Snapshots": [
                {"SnapshotId": "snap-1", "VolumeId": "vol-0aaa"},
                {"SnapshotId": "snap-2", "VolumeId": "vol-ffffffff"},  # a copy: no volume
            ]
        }
    )
    monkeypatch.setattr(cli, "open_disks", fake_open_disks)
    monkeypatch.setattr(cli, "make_aws_clients", lambda region, profile: (ec2, None))
    monkeypatch.setattr(ebs, "EbsSnapshotDevice", lambda *args, **kwargs: SimpleNamespace())
    aws = cli._Aws(SimpleNamespace(quiet=True, region=None, profile=None, parallel=1))
    aws.open([Disk("disk0", "snap-1"), Disk("disk1", "snap-2")], "current", False)
    assert found == {"disk0": "vol0aaa"}


def test_the_guess_is_a_warning_in_the_manifest() -> None:
    system = _nvme_system(
        "LABEL=x / xfs defaults 0 0\n/dev/nvme1n1 /data xfs defaults 0 0\n", _volume("/dev/sdf")
    )
    m = analyze(Snapshot("test", SystemSource.from_system(system), system))
    (warning,) = [w for w in m["warnings"] if w["code"] == "inferred-mount"]
    assert warning["mountpoint"] == "/data"
    assert warning["spec"] == "/dev/nvme1n1"
    assert warning["volume"] == "/dev/sdf"
    assert not [w for w in m["warnings"] if w["code"] == "unmounted-volume"]


# --- npm: edits suspected from the times ------------------------------------------------------

_MINUTE = 60 * 10**9


def _npm_app(lockfile: bool = True) -> MemFs:
    """A package extracted at minute 0, its install ending (lockfile) at minute 1."""
    fs = MemFs()
    top = "/opt/app/node_modules"
    if lockfile:
        fs.add_file(f"{top}/.package-lock.json", b"{}", mtime_ns=_MINUTE)
    fs.add_file(f"{top}/x/package.json", b'{"name": "x"}')
    fs.add_file(f"{top}/x/index.js", b"//", mtime_ns=1)
    return fs


def test_a_file_much_newer_than_the_install_is_listed_and_archived(tmp_path: Path) -> None:
    fs = _npm_app()
    fs.add_file("/opt/app/node_modules/x/patched.js", b"// fix", mtime_ns=60 * _MINUTE)
    m = analyze(_snap(fs))
    (pkg,) = m["language_packages"]
    assert pkg["edited_after_install"] == ["/opt/app/node_modules/x/patched.js"]
    assert pkg["modified"] == []  # suspected, not proven
    assert m["summary"]["language_package_files_edited_after_install"] == 1
    write_outputs(m, _snap(fs).source, None, tmp_path)
    assert _tar_names(tmp_path / "after.tar.gz") >= {"opt/app/node_modules/x/patched.js"}


def test_a_copied_tree_or_a_build_is_not_an_edit() -> None:
    fs = _npm_app()  # within the margin: `cp -r`, or what an install script built
    fs.add_file("/opt/app/node_modules/x/build/out.node", b"x", mtime_ns=5 * _MINUTE)
    assert analyze(_snap(fs))["language_packages"][0]["edited_after_install"] == []


def test_a_global_package_is_measured_from_its_package_json() -> None:
    fs = _npm_app(lockfile=False)
    fs.add_file("/opt/app/node_modules/x/patched.js", b"// fix", mtime_ns=60 * _MINUTE)
    (pkg,) = analyze(_snap(fs))["language_packages"]
    assert pkg["edited_after_install"] == ["/opt/app/node_modules/x/patched.js"]


def test_an_edited_package_json_shows_when_a_lockfile_is_there() -> None:
    fs = _npm_app()
    fs.add_file("/opt/app/node_modules/x/package.json", b'{"name": "x"}', mtime_ns=60 * _MINUTE)
    (pkg,) = analyze(_snap(fs))["language_packages"]
    assert pkg["edited_after_install"] == ["/opt/app/node_modules/x/package.json"]


def test_a_new_edit_counts_as_a_change_against_the_baseline() -> None:
    before, after = _npm_app(), _npm_app()
    after.add_file("/opt/app/node_modules/x/patched.js", b"// fix", mtime_ns=60 * _MINUTE)
    (pkg,) = analyze(_snap(after), _snap(before))["language_packages"]
    assert pkg["status"] == "changed"


def test_hand_work_inside_what_a_rule_hides_is_not_noise() -> None:
    noise = NoiseFilter()
    # cloud-init's own state is noise; a script put there for it to run at boot is not.
    assert noise.match("/var/lib/cloud/instances/i-0abc/user-data.txt") == "generated"
    assert noise.match("/var/lib/cloud/scripts/per-boot", FileType.DIR) == "generated"
    assert noise.match("/var/lib/cloud/scripts/per-boot/10-mount.sh", FileType.REG) is None
    assert noise.match("/var/lib/cloud/scripts/per-instance/lib/helper.sh") is None
    # systemd's state is noise; `loginctl enable-linger deploy` is a setting.
    assert noise.match("/var/lib/systemd/random-seed") == "generated"
    assert noise.match("/var/lib/systemd/linger", FileType.DIR) == "generated"
    assert noise.match("/var/lib/systemd/linger/deploy", FileType.REG) is None

    fs = MemFs()
    fs.add_file("/var/lib/cloud/scripts/per-boot/10-mount.sh", b"#!/bin/sh\nmount /data\n")
    fs.add_file("/var/lib/cloud/data/status.json", b"{}")
    fs.add_file("/var/lib/systemd/linger/deploy", b"")
    m = analyze(_snap(fs))
    assert sorted(path for path, item in _items(m).items() if item["type"] == "reg") == [
        "/var/lib/cloud/scripts/per-boot/10-mount.sh",
        "/var/lib/systemd/linger/deploy",
    ]


def test_state_that_services_and_docker_build_keep_is_noise() -> None:
    # Seen on real instances (2026-11-15) among the hand-placed paths, though nobody
    # put them there: fwupd's refresh timer and `docker build` did.
    noise = NoiseFilter()
    assert noise.match("/var/lib/fwupd/metadata/lvfs/firmware.xml.zst") == "generated"
    assert noise.match("/var/lib/fwupd/pki/secret.key") == "generated"
    assert noise.match("/etc/fwupd/fwupd.conf") is None  # its configuration is not
    assert noise.match("/root/.docker/buildx/activity/default") == "container"
    assert noise.match("/home/alice/.docker/buildx", FileType.DIR) == "container"
    assert noise.match("/root/.docker/config.json") is None  # a user's own settings
    assert noise.match("/root/.docker", FileType.DIR) is None


def test_apt_history_from_before_a_change_of_the_time_zone() -> None:
    # apt logs local time without the zone. After `timedatectl set-timezone Asia/Tokyo`
    # the earlier stamps, written in UTC, were read as Tokyo time, nine hours early:
    # what apt's scripts made then looked like hand work (seen on Ubuntu 24.04, 2026-11-15).
    tokyo = timezone(timedelta(hours=9))
    log = (
        "Start-Date: 2026-11-15  01:00:00\nCommandline: apt-get install nginx\n"
        "Install: nginx:amd64 (1.24)\nEnd-Date: 2026-11-15  01:00:30\n\n"
        "Start-Date: 2026-11-15  11:30:00\nCommandline: apt-get install jq\n"
        "Install: jq:amd64 (1.7)\nEnd-Date: 2026-11-15  11:30:10\n"
    )

    def utc(hour: int, minute: int, second: int = 0) -> int:
        return int(datetime(2026, 11, 15, hour, minute, second, tzinfo=UTC).timestamp())

    changed = ZoneChange(UTC, utc(2, 0))  # set to Tokyo at 02:00 UTC = 11:00 in Tokyo
    before, after = parse_apt_history(log, zone=tokyo, change=changed)
    assert (before.begin, before.end) == (utc(1, 0), utc(1, 0, 30))  # written in UTC
    assert (after.begin, after.end) == (utc(2, 30), utc(2, 30, 10))  # written in Tokyo time
    wrong, _ = parse_apt_history(log, zone=tokyo)
    assert wrong.begin == utc(1, 0) - 9 * 3600  # what it was read as


def test_a_run_reads_apt_history_in_the_zone_of_then() -> None:
    def server(zone: bytes, changed_at: int) -> MemFs:
        fs = MemFs()
        fs.add_file("/var/lib/dpkg/status", b"")
        fs.add_file("/etc/localtime", zone, ctime_ns=changed_at * 10**9)
        fs.add_file(
            "/var/log/apt/history.log",
            b"Start-Date: 2026-11-15  01:00:00\nCommandline: apt-get install nginx\n"
            b"Install: nginx:amd64 (1.24)\nEnd-Date: 2026-11-15  01:00:30\n",
        )
        return fs

    made = int(datetime(2026, 11, 15, 1, 0, 10, tzinfo=UTC).timestamp())  # inside the run
    # A zoneinfo file as /etc/localtime holds it: one type (JST, +9:00), no transitions.
    block = b"TZif2" + bytes(15) + struct.pack(">6l", 0, 0, 0, 0, 1, 4)
    block += struct.pack(">lBB", 9 * 3600, 0, 0) + b"JST\0"
    tokyo = block + block + b"\nJST-9\n"
    assert zone_from(tokyo).utcoffset(None) == timedelta(hours=9)
    before, after = server(b"", 0), server(tokyo, made + 3600)
    after.add_file("/var/lib/nginx/made-by-postinst", b"x", mtime_ns=made * 10**9)
    m = analyze(_snap(after), _snap(before))
    (group,) = m["package_scripts"]
    assert [f["path"] for f in group["files"]] == ["/var/lib/nginx/made-by-postinst"]
    assert "/var/lib/nginx/made-by-postinst" not in _items(m)
    # The same zone on both sides: nothing to reinterpret, the stamp is Tokyo time.
    same = analyze(_snap(after), _snap(server(tokyo, 0)))
    assert same["package_scripts"] == []


def test_a_pip_package_installed_with_target_is_one_package() -> None:
    # pip install --target /opt/app/vendor: no site-packages in the path, but a RECORD
    # (seen on real instances, 2026-11-15: every file came out as hand-placed).
    fs = MemFs()
    data = b"def read(): pass\n"
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    vendor = "/opt/app/vendor"
    record = (
        f"iniconfig/__init__.py,sha256={digest},{len(data)}\n"
        "iniconfig-2.0.0.dist-info/METADATA,,\niniconfig-2.0.0.dist-info/RECORD,,\n"
    )
    fs.add_file(f"{vendor}/iniconfig/__init__.py", data)
    fs.add_file(
        f"{vendor}/iniconfig-2.0.0.dist-info/METADATA", b"Name: iniconfig\nVersion: 2.0.0\n"
    )
    fs.add_file(f"{vendor}/iniconfig-2.0.0.dist-info/RECORD", record.encode())
    fs.add_file(f"{vendor}/mine.py", b"# put here by hand\n")
    # A directory that only looks like one: no RECORD, so nothing says what belongs to it.
    fs.add_file("/opt/app/notes.dist-info/README", b"not a package\n")
    m = analyze(_snap(fs))
    (pkg,) = m["language_packages"]
    assert (pkg["name"], pkg["version"], pkg["location"]) == ("iniconfig", "2.0.0", vendor)
    assert pkg["modified"] == []
    items = _items(m)
    assert f"{vendor}/iniconfig/__init__.py" not in items
    assert f"{vendor}/mine.py" in items  # what is not in the RECORD stays hand work
    assert "/opt/app/notes.dist-info/README" in items


def test_the_commands_npm_links_go_with_their_package() -> None:
    # npm install -g cowsay: /usr/local/bin/cowsay -> ../lib/node_modules/cowsay/cli.js
    # (seen on real instances, 2026-11-15: the links were listed as hand-placed).
    fs = MemFs()
    top = "/usr/local/lib/node_modules/cowsay"
    fs.add_file(f"{top}/package.json", b'{"name": "cowsay", "version": "1.6.0"}')
    fs.add_file(f"{top}/cli.js", b"#!/usr/bin/env node\n")
    fs.add_link("/usr/local/bin/cowsay", "../lib/node_modules/cowsay/cli.js")
    fs.add_link("/usr/local/bin/cowthink", "../lib/node_modules/cowsay/cli.js")
    fs.add_link("/usr/local/bin/mine", "/opt/app/run.sh")  # a link someone made
    fs.add_link("/usr/local/share/cowsay", "../lib/node_modules/cowsay/cli.js")  # not in bin
    # AL2023: the link goes through /usr/lib/node_modules, itself a link (alternatives).
    fs.add_link("/usr/lib/node_modules", "/usr/local/lib/node_modules")
    fs.add_link("/usr/bin/cowsay", "../lib/node_modules/cowsay/cli.js")
    m = analyze(_snap(fs))
    assert [p["name"] for p in m["language_packages"]] == ["cowsay"]
    links = sorted(path for path, item in _items(m).items() if item["type"] == "lnk")
    assert links == ["/usr/lib/node_modules", "/usr/local/bin/mine", "/usr/local/share/cowsay"]


# --- memory: what is kept for every path of both sides (measured 2026-11-15) -------------------


def test_a_stat_has_no_dictionary_of_its_own() -> None:
    # One is kept for every path walked, on both sides: 300,000 files a side took 1.6 GB.
    fs = MemFs()
    fs.add_file("/opt/x", b"data")
    st = fs.stat(fs.ino("/opt/x"))
    assert not hasattr(st, "__dict__")
    assert st.type is FileType.REG
    assert st.type is FileType.REG  # worked out once, then kept
    assert dataclasses.replace(st, mode=0o040755).type is FileType.DIR  # not the old memo
    assert st == dataclasses.replace(st)


def test_files_are_told_and_hashed_a_batch_at_a_time(monkeypatch) -> None:
    # Told all at once, every file to hash was an open file kept until read: with a
    # million files that was most of the memory of a run.
    from ec2_byhand import analyze as analysis

    monkeypatch.setattr(analysis, "HASH_BATCH", 4)
    before, after = MemFs(), MemFs()
    for fs in (before, after):
        for n in range(30):
            fs.add_file(f"/opt/data/f{n:02d}", b"same %d" % n)
    after.add_file("/opt/data/f07", b"other 7")
    held: list[int] = []
    real = analysis._Hasher.sha256

    def sha256(self, fs, ino):
        held.append(len(self._opened))
        return real(self, fs, ino)

    monkeypatch.setattr(analysis._Hasher, "sha256", sha256)
    m = analyze(_snap(after), _snap(before))
    assert [h["path"] for h in m["hand_placed"]] == ["/opt/data/f07"]
    assert max(held) <= 4
    assert len(after.opened) == len(set(after.opened)) == 30  # still each file once


def test_a_resolv_conf_that_says_it_was_generated_is_noise() -> None:
    # Amazon Linux 2: the AMI has none, dhclient writes one at every boot (seen on a
    # fresh instance, 2026-11-15: listed as added).
    generated, by_hand = MemFs(), MemFs()
    text = b"options timeout:2 attempts:5\nnameserver 10.0.0.2\n"
    generated.add_file("/etc/resolv.conf", b"; generated by /usr/sbin/dhclient-script\n" + text)
    by_hand.add_file("/etc/resolv.conf", b"# our resolvers\nnameserver 10.1.1.1\n")
    m = analyze(_snap(generated), _snap(MemFs()))
    assert "/etc/resolv.conf" not in _items(m)
    assert m["noise"]["by_rule"]["generated"] == 1
    assert "/etc/resolv.conf" in _items(analyze(_snap(by_hand), _snap(MemFs())))


def test_npm_cache_is_noise() -> None:
    fs = MemFs()
    fs.add_file("/root/.npm/_cacache/index-v5/aa/bb", b"x")
    fs.add_file("/home/app/.npm/_logs/debug.log", b"x")
    fs.add_file("/root/.npmrc", b"registry=x")
    found = _items(analyze(_snap(fs)))
    assert not [p for p in found if ".npm/" in p]
    assert "/root/.npmrc" in found


# --- dpkg without a baseline: say so, and list what is worth a look -----------------------------


def _dpkg_server() -> MemFs:
    fs = MemFs()
    listed: dict[str, bytes | None] = {
        "/usr/bin/sudo": b"sudo",
        "/usr/bin/plain": b"plain",
        "/usr/bin/wall": b"wall",
        "/etc/cron.d": None,
        "/usr/lib/app.so": None,
        "/var/mail": None,
    }
    _dpkg_db(fs, {"app": ("1.0", listed)})
    fs.add_file("/usr/bin/sudo", b"sudo", mode=0o4755)
    fs.add_file("/usr/bin/plain", b"plain", mode=0o755)
    fs.add_file("/usr/bin/wall", b"wall", mode=0o2755)
    fs.add_dir("/etc/cron.d", mode=0o777)
    fs.add_link("/usr/lib/app.so", "app.so.1")  # 0777 means nothing on a link
    fs.add_dir("/var/mail", mode=0o2775)  # setgid on a directory is ordinary
    fs.add_file("/opt/hand/run", b"x", mode=0o4755)  # not a package file
    return fs


def test_dpkg_without_a_baseline_warns_and_lists_files_to_review() -> None:
    m = analyze(_snap(_dpkg_server()))
    assert [w["code"] for w in m["warnings"] if w["code"].startswith("dpkg")] == [
        "dpkg-metadata-unverified"
    ]
    assert {i["path"]: i["reasons"] for i in m["package_files_to_review"]} == {
        "/etc/cron.d": ["world-writable"],
        "/usr/bin/sudo": ["setuid"],
        "/usr/bin/wall": ["setgid"],
    }
    item = _items(m, "package_files_to_review")["/usr/bin/sudo"]
    assert item["package"] == "app"
    assert item["mode"] == "4755"
    assert m["summary"]["package_files_to_review"] == 3


def test_a_package_file_changed_since_the_first_boot_is_listed_for_review() -> None:
    # Seen on Ubuntu 24.04: chmod / chown on package files after launch, no baseline. Its
    # install time is no reference (building the AMI touched half the files after it);
    # the first boot is, from cloud-init's log. Files a package run changed are left out.
    boot = int(datetime(2026, 11, 14, 13, 58, 39, tzinfo=UTC).timestamp()) * 10**9
    fs = _dpkg_server()
    fs.add_dir("/var/lib/cloud/instance")
    fs.add_file(
        "/var/log/cloud-init.log",
        b"2026-11-14 13:58:39,000 - util.py[DEBUG]: Cloud-init v. 24.1 running 'init-local'\n",
    )
    fs.add_file(
        "/var/log/apt/history.log",
        b"Start-Date: 2026-11-14  14:10:00\nCommandline: apt-get install -y app\n"
        b"Upgrade: app:amd64 (1.0, 1.0)\nEnd-Date: 2026-11-14  14:10:20\n",
    )
    fs.add_file("/usr/bin/plain", b"plain", mode=0o755, ctime_ns=boot + 33 * 10**9)  # by hand
    fs.add_file("/usr/bin/wall", b"wall", mode=0o2755, ctime_ns=boot - 10**9)  # before boot
    fs.add_file(
        "/usr/bin/sudo", b"sudo", mode=0o4755, ctime_ns=boot + 690 * 10**9
    )  # in the apt run
    m = analyze(_snap(fs))
    reasons = {i["path"]: i["reasons"] for i in m["package_files_to_review"]}
    assert reasons["/usr/bin/plain"] == ["changed-since-boot"]
    assert reasons["/usr/bin/wall"] == ["setgid"]
    assert reasons["/usr/bin/sudo"] == ["setuid"]
    assert reasons["/etc/cron.d"] == ["world-writable"]  # a directory: never by its ctime


def test_without_cloud_inits_log_nothing_is_called_changed_since_boot() -> None:
    fs = _dpkg_server()
    fs.add_file("/usr/bin/plain", b"plain", mode=0o755, ctime_ns=10**18)
    m = analyze(_snap(fs))
    assert "/usr/bin/plain" not in {i["path"] for i in m["package_files_to_review"]}


def test_a_baseline_makes_the_review_list_unnecessary() -> None:
    m = analyze(_snap(_dpkg_server()), _snap(_dpkg_server()))
    assert m["package_files_to_review"] == []
    assert not [w for w in m["warnings"] if w["code"] == "dpkg-metadata-unverified"]


@pytest.mark.parametrize("before", [None, "0.9"])
def test_packages_new_since_the_baseline_are_listed_for_review(before: str | None) -> None:
    # Seen on Ubuntu: apt install tree, then chmod 4755 /usr/bin/tree. The baseline has no
    # copy of a file of a package added (or upgraded) since, and dpkg records no mode.
    base = MemFs()
    _dpkg_db(base, {"other": ("1", {}), **({"app": (before, {})} if before else {})})
    m = analyze(_snap(_dpkg_server()), _snap(base))
    assert {i["path"] for i in m["package_files_to_review"]} == {
        "/etc/cron.d",
        "/usr/bin/sudo",
        "/usr/bin/wall",
    }
    assert not [w for w in m["warnings"] if w["code"] == "dpkg-metadata-unverified"]


def test_rpm_records_modes_so_it_needs_no_such_warning() -> None:
    m = analyze(_snap(MemFs()))
    assert not [w for w in m["warnings"] if w["code"] == "dpkg-metadata-unverified"]
    assert m["package_files_to_review"] == []


def test_summary_mentions_files_to_review_only_when_there_are_some(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    fs = _dpkg_server()
    monkeypatch.setattr(cli, "_sides", lambda args, aws, stack: (_snap(fs), None))
    args = ["--current-image", "unused", "-o", str(tmp_path / "o"), "--no-archives"]
    assert cli.main(args) == 0
    assert "to review:              3 package files" in capsys.readouterr().out
    monkeypatch.setattr(cli, "_sides", lambda args, aws, stack: (_snap(MemFs()), None))
    assert cli.main([*args, "--force"]) == 0
    assert "to review" not in capsys.readouterr().out


# --- package verification reads as little as it can, in disk order ------------------------------

_CONTENT_ONLY = VERIFY_DIGEST | VERIFY_SIZE  # no owners: MemFs has no /etc/passwd


def _recorded(path: str, data: bytes, **kw) -> PackageFile:
    return PackageFile(
        path=path,
        digest=hashlib.sha256(data).hexdigest(),
        digest_algo="sha256",
        size=len(data),
        verify=_CONTENT_ONLY,
        **kw,
    )


def _ghost(path: str) -> PackageFile:
    return PackageFile(path=path, flags=RPMFILE_GHOST, verify=0)


def _rpm_db(*groups: tuple[PackageFile, ...]) -> PackageDB:
    packages = tuple(
        Package(
            manager="rpm",
            name=f"pkg{i}",
            arch="x86_64",
            epoch=None,
            version="1",
            release="1",
            files=files,
        )
        for i, files in enumerate(groups)
    )
    return PackageDB("rpm", "rpm-sqlite", "/var/lib/rpm", packages)


def _paths(problems: list) -> dict[str, set[str]]:
    return {x.path: set(x.problems) for x in problems}


def test_contents_are_read_in_inode_order_not_package_order() -> None:
    fs = MemFs()
    names = ["/a", "/b", "/c", "/d"]
    for name in names:
        fs.add_file(name, name.encode())
    db = _rpm_db(*[(_recorded(n, n.encode()),) for n in reversed(names)])
    assert verify_packages(SystemSource.from_fs(fs), db) == []
    assert fs.opened == sorted(fs.opened)
    assert len(fs.opened) == 4


def test_a_file_two_packages_list_is_read_once() -> None:
    fs = MemFs()
    fs.add_file("/shared", b"x")
    listed = _recorded("/shared", b"x")
    assert verify_packages(SystemSource.from_fs(fs), _rpm_db((listed,), (listed,))) == []
    assert fs.opened == [fs.ino("/shared")]


def test_a_problem_found_by_reading_is_still_reported() -> None:
    fs = MemFs()
    fs.add_file("/edited", b"new")
    problems = verify_packages(SystemSource.from_fs(fs), _rpm_db((_recorded("/edited", b"old"),)))
    assert _paths(problems) == {"/edited": {"content"}}


def test_a_size_that_differs_from_the_package_needs_no_read() -> None:
    fs = MemFs()
    fs.add_file("/grown", b"much longer now")
    problems = verify_packages(SystemSource.from_fs(fs), _rpm_db((_recorded("/grown", b"x"),)))
    assert _paths(problems) == {"/grown": {"content", "size"}}
    assert not fs.opened


def test_a_ghost_that_changed_size_needs_no_read_on_either_side() -> None:
    before, after = MemFs(), MemFs()
    before.add_file("/var/lib/db", b"small")
    after.add_file("/var/lib/db", b"much larger")
    src, base = SystemSource.from_fs(after), SystemSource.from_fs(before)
    problems = verify_packages(src, _rpm_db((_ghost("/var/lib/db"),)), base)
    assert _paths(problems) == {"/var/lib/db": {"content-since-baseline"}}
    assert not before.opened
    assert not after.opened


def test_a_ghost_of_the_same_size_is_compared_with_the_baseline() -> None:
    before, after = MemFs(), MemFs()
    before.add_file("/var/lib/db", b"old")
    after.add_file("/var/lib/db", b"new")
    src, base = SystemSource.from_fs(after), SystemSource.from_fs(before)
    problems = verify_packages(src, _rpm_db((_ghost("/var/lib/db"),)), base)
    assert _paths(problems) == {"/var/lib/db": {"content-since-baseline"}}


def test_a_ghost_that_became_a_link_is_compared_with_the_baseline() -> None:
    # timedatectl set-timezone: /etc/localtime, a %ghost of systemd, from a file to a link.
    # rpm records nothing of a ghost's target, so only the baseline can tell (seen on a
    # real AL2023 instance, 2026-11-15: the change was reported nowhere).
    before, after, same = MemFs(), MemFs(), MemFs()
    before.add_file("/etc/localtime", b"TZif2 UTC")
    after.add_link("/etc/localtime", "../usr/share/zoneinfo/Asia/Tokyo")
    same.add_link("/etc/localtime", "../usr/share/zoneinfo/Asia/Tokyo")
    db = _rpm_db((_ghost("/etc/localtime"), _ghost("/etc/new-link")))
    src = SystemSource.from_fs(after)
    problems = verify_packages(src, db, SystemSource.from_fs(before), base_db=db)
    assert _paths(problems) == {"/etc/localtime": {"link"}}
    assert verify_packages(src, db, SystemSource.from_fs(same), base_db=db) == []
    assert verify_packages(src, db) == []  # no baseline: nothing to compare a ghost with
    after.add_link("/etc/new-link", "elsewhere")
    src = SystemSource.from_fs(after)
    problems = verify_packages(src, db, SystemSource.from_fs(same), base_db=db)
    assert _paths(problems) == {"/etc/new-link": {"created-since-baseline"}}
    # A package installed since the baseline made its links itself (alternatives' pip3).
    assert verify_packages(src, db, SystemSource.from_fs(same), base_db=_rpm_db()) == []


def test_an_acl_or_a_capability_alone_is_a_change() -> None:
    # setfacl, setcap and setfattr leave type, mode, owner and content as they were
    # (seen on a real AL2023 instance, 2026-11-15: such a change was reported nowhere).
    before, after = MemFs(), MemFs()
    for fs in (before, after):
        fs.add_file("/opt/app/server", b"binary")
        fs.add_file("/opt/app/data.txt", b"data")
        fs.add_file("/opt/app/same.txt", b"same")
        for path in ("/opt/app/server", "/opt/app/data.txt", "/opt/app/same.txt"):
            fs.set_xattr(path, "security.selinux", b"system_u:object_r:usr_t:s0")
    after.set_xattr("/opt/app/server", "security.capability", b"\x01\x00\x00\x02")
    after.set_xattr("/opt/app/data.txt", "system.posix_acl_access", b"acl")
    after.set_xattr("/opt/app/data.txt", "trusted.SGI_ACL_FILE", b"xfs's raw copy")
    # A chcon is a change too, told on its own: `xattrs` names settings, not the label.
    after.set_xattr("/opt/app/same.txt", "security.selinux", b"system_u:object_r:etc_t:s0\0")
    after.add_file("/opt/app/new", b"new")
    after.set_xattr("/opt/app/new", "user.note", b"x")
    items = _items(analyze(_snap(after), _snap(before)))
    assert items["/opt/app/server"]["changed"] == ["xattrs"]
    assert items["/opt/app/server"]["xattrs"] == ["security.capability"]
    assert items["/opt/app/data.txt"]["changed"] == ["xattrs"]
    assert items["/opt/app/data.txt"]["xattrs"] == ["system.posix_acl_access"]
    assert items["/opt/app/new"]["xattrs"] == ["user.note"]
    assert items["/opt/app/same.txt"]["changed"] == ["selinux"]
    assert items["/opt/app/same.txt"]["selinux"] == "system_u:object_r:etc_t:s0"
    assert "xattrs" not in items["/opt/app/same.txt"]
    assert "selinux" not in items["/opt/app/server"]  # its label is as it was


def test_labels_on_one_side_only_are_not_a_change_of_every_path() -> None:
    # SELinux switched on since the baseline, or a baseline built without it: every path
    # gains a label, and none of them was touched for that.
    before, after = MemFs(), MemFs()
    for fs in (before, after):
        fs.add_file("/opt/app/data.txt", b"data")
    after.set_xattr("/opt/app/data.txt", "security.selinux", b"system_u:object_r:usr_t:s0")
    assert "/opt/app/data.txt" not in _items(analyze(_snap(after), _snap(before)))
    assert "/opt/app/data.txt" not in _items(analyze(_snap(before), _snap(after)))


def test_the_mode_fwupd_gives_its_own_configuration_is_not_hand_work() -> None:
    # Seen on Ubuntu 24.04 (2026-11-15): fwupd makes /etc/fwupd/fwupd.conf 0640 when it
    # starts, and that came out as a package file changed since the baseline.
    def server(mode: int, other: int = 0o644) -> MemFs:
        fs = MemFs()
        status = (
            b"Package: fwupd\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.9\n"
        )
        fs.add_file("/var/lib/dpkg/status", status)
        fs.add_file("/var/lib/dpkg/info/fwupd.list", b"/etc/fwupd/fwupd.conf\n/etc/fwupd/x.conf\n")
        fs.add_file("/etc/fwupd/fwupd.conf", b"[fwupd]\n", mode=mode)
        fs.add_file("/etc/fwupd/x.conf", b"[x]\n", mode=other)
        return fs

    m = analyze(_snap(server(0o640)), _snap(server(0o644)))
    assert m["modified_package_files"] == []
    assert m["noise"]["by_rule"]["service-made"] == 1
    # Another mode, or another file: someone did that.
    m = analyze(_snap(server(0o600, 0o640)), _snap(server(0o644)))
    assert {x["path"]: x["problems"] for x in m["modified_package_files"]} == {
        "/etc/fwupd/fwupd.conf": ["mode"],
        "/etc/fwupd/x.conf": ["mode"],
    }


def test_a_file_over_the_limit_is_not_read_and_not_called_changed() -> None:
    before, after = MemFs(), MemFs()
    before.add_file("/var/lib/db", b"o" * 100)
    after.add_file("/var/lib/db", b"n" * 100)
    after.add_file("/usr/lib/big.so", b"n" * 100)
    src, base = SystemSource.from_fs(after), SystemSource.from_fs(before)
    db = _rpm_db((_ghost("/var/lib/db"), _recorded("/usr/lib/big.so", b"o" * 100)))
    limits = ReadLimits(max_file_size=10)
    assert verify_packages(src, db, base, limits=limits) == []
    assert limits.too_large == {"/var/lib/db", "/usr/lib/big.so"}
    assert not before.opened
    assert not after.opened


def test_a_path_the_limits_skip_is_not_read_or_listed_as_too_large() -> None:
    fs = MemFs()
    fs.add_file("/hidden", b"new")
    limits = ReadLimits(skip=lambda path: path == "/hidden")
    db = _rpm_db((_recorded("/hidden", b"old"),))
    assert verify_packages(SystemSource.from_fs(fs), db, limits=limits) == []
    assert not fs.opened
    assert limits.too_large == set()


def test_noise_is_not_read_to_verify_a_package() -> None:
    fs = MemFs()
    listed: dict[str, bytes | None] = {"/var/log/app.log": b"recorded", "/usr/bin/run": b"run"}
    _dpkg_db(fs, {"app": ("1.0", listed)})
    fs.add_file("/var/log/app.log", b"grown since")
    fs.add_file("/usr/bin/run", b"run")
    analyze(_snap(fs))
    assert fs.ino("/var/log/app.log") not in fs.opened
    assert fs.ino("/usr/bin/run") in fs.opened


def test_what_the_limit_left_unverified_is_a_warning() -> None:
    fs = MemFs()
    listed: dict[str, bytes | None] = {"/usr/lib/big.so": b"x" * 2000}
    _dpkg_db(fs, {"app": ("1.0", listed)})
    fs.add_file("/usr/lib/big.so", b"y" * 2000)
    site = "/opt/venv/lib/python3.12/site-packages"
    fs.add_file(f"{site}/torch/huge.so", b"z" * 2000)
    record = "torch/huge.so,sha256=abc,2000\ntorch-1.0.dist-info/RECORD,,\n"
    fs.add_file(f"{site}/torch-1.0.dist-info/RECORD", record.encode())
    m = analyze(_snap(fs), max_file_size=BIG)
    (warning,) = [w for w in m["warnings"] if w["code"] == "content-not-verified"]
    assert warning["entries"] == [f"{site}/torch/huge.so", "/usr/lib/big.so"]
    assert "2 package files" in warning["message"]
    assert fs.ino("/usr/lib/big.so") not in fs.opened
    assert fs.ino(f"{site}/torch/huge.so") not in fs.opened
    assert not m["modified_package_files"]
    assert m["language_packages"][0]["modified"] == []


def test_no_limit_no_warning() -> None:
    assert not [w for w in analyze(_snap(MemFs()))["warnings"] if "verified" in w["code"]]


def _pip_site(fs: MemFs, data: bytes, record_size: int) -> str:
    site = "/opt/venv/lib/python3.12/site-packages"
    fs.add_file(f"{site}/demo/a.so", data)
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    record = f"demo/a.so,sha256={digest},{record_size}\n"
    fs.add_file(f"{site}/demo-1.0.dist-info/RECORD", record.encode())
    return f"{site}/demo/a.so"


def test_pip_size_that_differs_from_record_needs_no_read() -> None:
    fs = MemFs()
    path = _pip_site(fs, b"edited", record_size=3)
    (pkg,) = analyze(_snap(fs))["language_packages"]
    assert pkg["modified"] == [path]
    assert fs.ino(path) not in fs.opened


def test_pip_file_is_still_read_when_nothing_rules_it_out() -> None:
    fs = MemFs()
    path = _pip_site(fs, b"intact", record_size=6)
    (pkg,) = find_language_packages(
        SystemSource.from_fs(fs),
        [
            "/opt/venv/lib/python3.12/site-packages/demo-1.0.dist-info",
        ],
    )
    assert pkg.modified == []
    assert fs.ino(path) in fs.opened


def test_pip_file_over_the_limit_is_unverified_not_modified() -> None:
    fs = MemFs()
    path = _pip_site(fs, b"x" * 100, record_size=100)
    (pkg,) = find_language_packages(
        SystemSource.from_fs(fs),
        ["/opt/venv/lib/python3.12/site-packages/demo-1.0.dist-info"],
        max_file_size=10,
    )
    assert pkg.unverified == [path]
    assert pkg.modified == []
    assert fs.ino(path) not in fs.opened


# --- what a review of the whole tool found ---------------------------------------------------


def test_a_package_apt_removed_is_gone_though_its_conffiles_remain() -> None:
    def status(state: str) -> bytes:
        return (
            "Package: nginx\nStatus: " + state + "\nVersion: 1.24\nArchitecture: amd64\n\n"
            "Package: curl\nStatus: install ok installed\nVersion: 8.5\nArchitecture: amd64\n\n"
        ).encode()

    before, after = MemFs(), MemFs()
    before.add_file("/var/lib/dpkg/status", status("install ok installed"))
    after.add_file("/var/lib/dpkg/status", status("deinstall ok config-files"))  # apt remove
    m = analyze(_snap(after), _snap(before))
    assert [p["name"] for p in m["packages"]["installed"]] == ["curl"]
    assert [(c["kind"], c["name"]) for c in m["packages"]["changes"]] == [("removed", "nginx")]


def test_a_deleted_log_directory_or_certificate_is_reported() -> None:
    before, after = MemFs(), MemFs()
    before.add_dir("/var/log/myapp")  # the app does not start without it
    before.add_file("/var/log/old.log", b"line")  # a log file: noise, gone or not
    before.add_file("/etc/ssl/certs/server.crt", b"cert")
    before.add_link("/etc/ssl/certs/Mozilla_Root.pem", "/usr/share/ca-certificates/root.crt")
    after.add_dir("/var/log")
    after.add_dir("/etc/ssl/certs")
    deleted = {d["path"]: d["type"] for d in analyze(_snap(after), _snap(before))["deleted"]}
    assert deleted == {"/var/log/myapp": "dir", "/etc/ssl/certs/server.crt": "reg"}


def test_a_missing_log_directory_of_a_package_is_reported() -> None:
    listed: dict[str, bytes | None] = {"/var/log/app": None, "/var/log/app/app.log": None}
    before, after = MemFs(), MemFs()
    for fs in (before, after):
        _dpkg_db(fs, {"app": ("1.0", listed)})
    before.add_file("/var/log/app/app.log", b"line")
    after.add_dir("/var/log")
    m = analyze(_snap(after), _snap(before))
    missing = _items(m, "modified_package_files")
    assert {path: i["problems"] for path, i in missing.items()} == {"/var/log/app": ["missing"]}
    assert m["noise"]["by_rule"]["logs"] == 1  # the log file itself


def _tzif(utc_offset: int, name: str) -> bytes:
    """A zoneinfo file for a zone that has always been at one offset."""
    counts = struct.pack(">6l", 0, 0, 0, 0, 1, len(name) + 1)
    ttinfo = struct.pack(">lBB", utc_offset, 0, 0)
    return b"TZif" + bytes(16) + counts + ttinfo + name.encode() + b"\0"


@pytest.mark.parametrize(
    ("localtime", "utc_hour"),
    [(_tzif(9 * 3600, "JST"), 3), (None, 12), (b"not a zoneinfo file", 12)],
    ids=["tokyo", "no-localtime", "damaged-localtime"],
)
def test_apt_history_is_read_in_the_servers_time_zone(
    localtime: bytes | None, utc_hour: int
) -> None:
    fs = MemFs()
    fs.add_file(
        "/var/log/apt/history.log",
        b"Start-Date: 2026-10-24  12:00:01\nCommandline: apt-get install -y nginx\n"
        b"Install: nginx:amd64 (1.24.0-2ubuntu7)\nEnd-Date: 2026-10-24  12:00:09\n",
    )
    if localtime is not None:
        fs.add_file("/usr/share/zoneinfo/Asia/Tokyo", localtime)
        fs.add_link("/etc/localtime", "/usr/share/zoneinfo/Asia/Tokyo")
    (t,) = read_history(SystemSource.from_fs(fs))
    assert t.begin == int(datetime(2026, 10, 24, utc_hour, 0, 1, tzinfo=UTC).timestamp())
    assert t.end is not None
    assert t.end - t.begin == 8


def _swap_file(size: int = 64 * 1024) -> bytes:
    data = bytearray(b"paged-out memory with a password in it ".ljust(size, b"."))
    data[4086:4096] = b"SWAPSPACE2"  # what mkswap writes at the end of the first page
    return bytes(data)


def test_a_swap_file_is_listed_but_never_hashed_or_archived(tmp_path: Path) -> None:
    fs = MemFs()
    fs.add_file("/swapfile", _swap_file(), mode=0o600)
    fs.add_file("/opt/data.bin", bytes(64 * 1024))  # as large, but not swap
    m = analyze(_snap(fs))
    item = _items(m)
    assert item["/swapfile"]["hash_skipped"] == "swap"
    assert "sha256" not in item["/swapfile"]
    assert "sha256" in item["/opt/data.bin"]
    result = write_outputs(m, _snap(fs).source, None, tmp_path)
    assert "swapfile" not in _tar_names(tmp_path / "after.tar.gz")
    assert {"archive": "after", "path": "/swapfile", "reason": "swap"} in result["skipped"]


def test_a_swap_file_the_baseline_also_had_is_not_compared_by_content() -> None:
    before, after = MemFs(), MemFs()
    before.add_file("/swapfile", _swap_file())
    after.add_file("/swapfile", _swap_file().replace(b"password", b"PASSWORD"))  # pages moved
    assert "/swapfile" not in _items(analyze(_snap(after), _snap(before)))


def test_a_file_over_the_limit_gets_no_patch_and_is_not_read_for_one(tmp_path: Path) -> None:
    before, after = MemFs(), MemFs()
    before.add_file("/etc/big.conf", b"a\n" * BIG, mtime_ns=1)
    after.add_file("/etc/big.conf", b"b\n" * BIG, mtime_ns=2)
    m = analyze(_snap(after), _snap(before), max_file_size=BIG)
    opts = ArchiveOptions(max_file_size=BIG)
    result = write_outputs(m, _snap(after).source, _snap(before).source, tmp_path, opts)
    assert result["patches"]["files"] == 0
    assert {s["reason"] for s in result["skipped"]} == {"too-large"}  # said by the archives
    assert not before.opened
    assert not after.opened


def test_an_empty_rpm_database_does_not_hide_the_dpkg_one(tmp_path: Path) -> None:
    con = sqlite3.connect(tmp_path / "rpmdb.sqlite")  # what running rpm once on Debian leaves
    con.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB)")
    con.commit()
    con.close()
    fs = MemFs()
    _dpkg_db(fs, {"app": ("1.0", {"/usr/bin/run": b"run"})})
    fs.add_file("/var/lib/rpm/rpmdb.sqlite", (tmp_path / "rpmdb.sqlite").read_bytes())
    db = read_packages(SystemSource.from_fs(fs))
    assert db is not None
    assert (db.manager, [p.name for p in db.packages]) == ("dpkg", ["app"])


def test_an_unreadable_rpm_database_is_not_passed_over_for_an_empty_dpkg_one() -> None:
    fs = MemFs()
    fs.add_file("/var/lib/rpm/rpmdb.sqlite", b"not a database")
    fs.add_file("/var/lib/dpkg/status", b"")
    with pytest.raises(DiskReadError, match=r"rpmdb\.sqlite"):
        read_packages(SystemSource.from_fs(fs))


def test_without_a_baseline_what_the_image_holds_under_dev_is_noise() -> None:
    fs = MemFs()
    fs.add_file("/dev/console", b"")
    fs.add_file("/run/lock/x", b"")
    m = analyze(_snap(fs))
    assert not [p for p in _items(m) if p.startswith(("/dev", "/run"))]
    assert m["noise"]["by_rule"]["mountpoints"] == 5  # /dev, /run and what is below them


def test_with_a_baseline_a_file_hidden_under_a_mountpoint_is_shown() -> None:
    before, after = MemFs(), MemFs()
    for fs in (before, after):
        fs.add_file("/dev/console", b"")  # the image build left it: same on both sides
    after.add_file("/dev/.hidden/payload", b"x")  # under devtmpfs while the server runs
    after.add_file("/tmp/scratch", b"x")  # still noise: /tmp is written all the time
    m = analyze(_snap(after), _snap(before))
    assert set(_items(m)) == {"/dev/.hidden", "/dev/.hidden/payload"}
    assert "mountpoints" not in m["noise"]["rules"]


def test_npm_file_times_come_from_the_walk_when_it_has_them() -> None:
    fs = _npm_app()
    src = SystemSource.from_fs(fs)
    stats = {p.decode(): st for p, _fs, _ino, st in src.walk()}
    # The walk's word is taken: a time only it knows shows in the result.
    patched = "/opt/app/node_modules/x/index.js"
    stats[patched] = dataclasses.replace(stats[patched], mtime_ns=60 * _MINUTE)
    (pkg,) = find_language_packages(src, stats, stats=stats)
    assert pkg.edited_after_install == [patched]


# --- the size limit is on unless lifted, and a run says what it will read ----------------------

GIB = 1 << 30


def _big_file(size: int) -> BytesDevice:
    """A file of `size` zero bytes that takes no memory to hold."""

    class Zeros:
        def __init__(self) -> None:
            self.size = size

        def read_at(self, offset: int, length: int) -> bytes:
            return bytes(length)

    return Zeros()  # type: ignore[return-value]


class _BigFs(MemFs):
    """MemFs whose files can be given any size without holding their bytes."""

    def __init__(self) -> None:
        super().__init__()
        self.sizes: dict[int, int] = {}

    def add_big(self, path: str, size: int) -> None:
        self.add_file(path, b"")
        self.sizes[self.ino(path)] = size

    def stat(self, ino: int):
        st = super().stat(ino)
        return dataclasses.replace(st, size=self.sizes[ino]) if ino in self.sizes else st

    def open(self, ino: int):
        if ino in self.sizes:
            self.opened.append(ino)
            return _big_file(self.sizes[ino])
        return super().open(ino)


def _run_cli(monkeypatch, fs: MemFs, out: Path, *options: str) -> dict:
    monkeypatch.setattr(cli, "_sides", lambda args, aws, stack: (_snap(fs), None))
    assert cli.main(["--current-image", "unused", "-o", str(out), "--no-archives", *options]) == 0
    return json.loads((out / "manifest.json").read_text(encoding="utf-8"))


def test_a_file_over_one_gib_is_not_read_unless_the_limit_is_lifted(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    fs = _BigFs()
    fs.add_big("/var/lib/mysql/ibdata1", GIB + 1)
    fs.add_file("/etc/app.conf", b"x")
    m = _run_cli(monkeypatch, fs, tmp_path / "default")
    assert _items(m)["/var/lib/mysql/ibdata1"]["hash_skipped"] == "too-large"
    assert m["max_file_size"] == GIB
    assert m["summary"]["files_over_max_file_size"] == 1
    assert fs.ino("/var/lib/mysql/ibdata1") not in fs.opened
    out = capsys.readouterr()
    assert "not read:               1 files over 1 GiB (--max-file-size none reads them)" in out.out
    assert "will read up to 1 byte in 1 files that no package owns; 1 over 1 GiB left unread" in (
        out.err
    )


def test_max_file_size_none_reads_every_file(tmp_path: Path, monkeypatch, capsys) -> None:
    assert cli.size_limit("none") is None
    assert cli.size_limit("2G") == 2 * GIB
    fs = MemFs()
    fs.add_file("/etc/app.conf", b"x")
    m = _run_cli(monkeypatch, fs, tmp_path / "o", "--max-file-size", "none")
    assert m["max_file_size"] is None
    assert m["summary"]["files_over_max_file_size"] is None
    assert "not read" not in capsys.readouterr().out


def test_package_files_over_the_limit_count_as_not_read() -> None:
    fs = MemFs()
    _dpkg_db(fs, {"app": ("1.0", {"/usr/lib/big.so": b"x" * 2000})})
    fs.add_file("/usr/lib/big.so", b"y" * 2000)
    fs.add_file("/opt/dump.sql", bytes(BIG + 1))
    fs.add_file("/var/log/huge.log", bytes(BIG + 1))  # noise: not something left unread
    summary = analyze(_snap(fs), max_file_size=BIG)["summary"]
    assert summary["files_over_max_file_size"] == 2
    assert summary["package_files_over_max_file_size"] == 1


def test_summary_says_how_many_of_the_unread_files_are_package_files(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    fs = MemFs()
    _dpkg_db(fs, {"app": ("1.0", {"/usr/lib/big.so": b"x" * 2000})})
    fs.add_file("/usr/lib/big.so", b"y" * 2000)
    fs.add_file("/opt/dump.sql", bytes(2000))
    _run_cli(monkeypatch, fs, tmp_path / "o", "--max-file-size", "1K")
    out = capsys.readouterr().out
    assert "not read:               2 files over 1 KiB, 1 of them package files (" in out


def test_a_run_says_how_much_there_is_to_read_before_reading_it() -> None:
    fs = MemFs()
    fs.add_file("/opt/a", b"a" * 300)
    fs.add_file("/opt/b", b"b" * 200)
    fs.add_file("/opt/c", b"c" * 100)
    fs.add_file("/opt/d", b"d" * 50)
    fs.add_file("/opt/dump.sql", bytes(BIG + 1))
    fs.add_file("/var/log/app.log", b"noise")
    opened_when_told: list[int] = []
    plans: list[ReadPlan] = []

    def before_reading(plan: ReadPlan) -> None:
        opened_when_told.extend(fs.opened)
        plans.append(plan)

    analyze(_snap(fs), max_file_size=BIG, before_reading=before_reading)
    assert plans == [ReadPlan(4, 650, (("/opt/a", 300), ("/opt/b", 200), ("/opt/c", 100)), 1)]
    assert opened_when_told == []  # said before anything was read
    assert fs.opened  # and then it was read


def test_much_to_read_names_the_largest_files_and_the_way_out() -> None:
    small = ReadPlan(142, 2 << 20, (("/opt/a", 1 << 20),), 0)
    assert cli._plan_lines(small, GIB, False) == [
        "will read up to 2 MiB in 142 files that no package owns"
    ]
    much = ReadPlan(
        3, 5 * GIB + (GIB // 5), (("/var/lib/mysql/ib\x1bdata1", GIB), ("/opt/x", 300 << 20)), 2
    )
    hint = "to leave data out: Ctrl+C, then run again with --exclude 'DIR/**'"
    first = "will read up to 5.2 GiB in 3 files that no package owns; 2 over 1 GiB left unread"
    assert cli._plan_lines(much, GIB, False) == [
        first + "; the largest:",
        "       1 GiB  /var/lib/mysql/ib\\x1bdata1",
        "     300 MiB  /opt/x",
        hint,
    ]
    # With --instance-id, stopping also throws away the snapshots just made.
    assert cli._plan_lines(much, GIB, True)[-1] == hint + (
        " (this also deletes the snapshots just made; "
        "--keep-snapshots keeps them for --current-snapshot)"
    )


def test_the_plan_opens_only_the_largest_files() -> None:
    fs = _npm_app()
    for i in range(10):  # never read: the files of an npm package
        fs.add_file(f"/opt/app/node_modules/x/lib/{i}.bin", bytes(64 * 1024))
    fs.add_file("/opt/hand.bin", bytes(64 * 1024))
    fs.add_file("/swapfile", _swap_file())
    opened_at_plan: list[int] = []
    plans: list[ReadPlan] = []

    def before_reading(plan: ReadPlan) -> None:
        opened_at_plan.extend(fs.opened)
        plans.append(plan)

    analyze(_snap(fs), before_reading=before_reading)
    (plan,) = plans
    assert len(opened_at_plan) <= 4  # the largest three, and the swap file looked at and passed
    assert "/swapfile" not in [path for path, _ in plan.largest]
    assert len(plan.largest) == 3


def test_a_hashed_file_is_opened_once() -> None:
    fs = MemFs()
    fs.add_file("/opt/hand.bin", bytes(64 * 1024))  # large enough to be looked at for swap
    item = _items(analyze(_snap(fs)))["/opt/hand.bin"]
    assert "sha256" in item
    assert fs.opened == [fs.ino("/opt/hand.bin")]


def test_an_unreadable_database_beside_a_usable_one_is_still_reported() -> None:
    fs = MemFs()
    _dpkg_db(fs, {"app": ("1.0", {"/usr/bin/run": b"run"})})
    fs.add_file("/var/lib/rpm/rpmdb.sqlite", b"not a database")
    db = read_packages(SystemSource.from_fs(fs))
    assert db is not None
    assert db.manager == "dpkg"
    (note,) = db.damaged
    assert "rpmdb.sqlite" in note
    assert note.endswith("(the dpkg database was used instead)")
    (warning,) = [w for w in analyze(_snap(fs))["warnings"] if w["code"].startswith("package-db")]
    assert warning["code"] == "package-db-damaged"


def test_sizes_are_written_as_people_write_them() -> None:
    assert [
        cli.size_text(n) for n in (1, 17, 1 << 10, 1536, 300 << 20, GIB, 5 * GIB + GIB // 5)
    ] == [
        "1 byte",
        "17 bytes",
        "1 KiB",
        "1.5 KiB",
        "300 MiB",
        "1 GiB",
        "5.2 GiB",
    ]


def test_a_swap_file_is_opened_once_to_archive_it_or_not(tmp_path: Path) -> None:
    fs = MemFs()
    fs.add_file("/swapfile", _swap_file())
    fs.add_file("/opt/data.bin", bytes(64 * 1024))
    manifest = {
        "hand_placed": [
            {"path": "/swapfile", "status": "added"},
            {"path": "/opt/data.bin", "status": "added"},
        ],
        "modified_package_files": [],
        "deleted": [],
    }
    write_outputs(manifest, _snap(fs).source, None, tmp_path)
    assert sorted(fs.opened) == sorted([fs.ino("/swapfile"), fs.ino("/opt/data.bin")])


def test_items_carry_their_ctime_and_the_summary_the_span() -> None:
    # The ctime, not the mtime, tells when a change was made: `touch` can set the mtime.
    day = int(datetime(2026, 11, 14, tzinfo=UTC).timestamp()) * 10**9
    before, after = MemFs(), MemFs()
    after.add_file("/etc/a.conf", b"a", mtime_ns=0, ctime_ns=day + 3600 * 10**9)
    after.add_file("/etc/b.conf", b"b", mtime_ns=0, ctime_ns=day + 7200 * 10**9)
    after.add_dir("/etc", ctime_ns=day + 7200 * 10**9)
    m = analyze(_snap(after), _snap(before))
    item = _items(m)["/etc/a.conf"]
    assert item["ctime"] == "2026-11-14T01:00:00+00:00"
    assert item["mtime"] == "1970-01-01T00:00:00+00:00"
    assert m["summary"]["changed_between"] == [
        "2026-11-14T01:00:00+00:00",
        "2026-11-14T02:00:00+00:00",
    ]
    assert analyze(_snap(MemFs()), _snap(MemFs()))["summary"]["changed_between"] is None
