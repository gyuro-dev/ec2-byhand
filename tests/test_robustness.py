"""What a damaged, odd or hostile snapshot must not be able to do: abort the run
with a traceback, corrupt the outputs, write outside the output directory, or
slip a secret past the sensitive filter."""

from __future__ import annotations

import contextlib
import dataclasses
import gzip
import json
import os
import random
import shutil
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PureWindowsPath
from typing import Any

import pytest
from botocore.exceptions import EndpointConnectionError
from conftest import GOLDEN_DIR
from memfs import MemFs

from diskread import BytesDevice, DiskReadError, FileDevice
from diskread.fs import FileType, lookup, walk
from diskread.fs.detect import open_fs
from diskread.fs.xfs import Xfs
from diskread.partition import read_partition_table
from diskread.source import SystemSource
from diskread.system import scan
from ec2_byhand import cli
from ec2_byhand.analyze import Snapshot, _warnings, analyze
from ec2_byhand.archive import (
    ArchiveOptions,
    _patch_name,
    _read_text,
    _TarWriter,
    write_outputs,
)
from ec2_byhand.aws.snapshots import Disk, delete_snapshots
from ec2_byhand.langpkgs import find_alternatives, find_language_packages
from ec2_byhand.noise import DpkgPathExcludes, NoiseFilter
from ec2_byhand.packages.history import read_history
from ec2_byhand.packages.rpmdb import read_bdb, read_sqlite
from ec2_byhand.sensitive import is_sensitive

MIB = 1 << 20
SITE = "/usr/local/lib/python3.12/site-packages"


class _BadBlockDevice:
    """A file whose bytes can be read only up to a bad block."""

    def __init__(self, data: bytes, bad_from: int) -> None:
        self._dev = BytesDevice(data)
        self._bad_from = bad_from

    @property
    def size(self) -> int:
        return self._dev.size

    def read_at(self, offset: int, length: int) -> bytes:
        if offset + length > self._bad_from:
            raise DiskReadError(f"bad block at {self._bad_from}")
        return self._dev.read_at(offset, length)


class _DamagedFs(MemFs):
    """MemFs where chosen files fail to read and chosen directories fail to list."""

    def __init__(self) -> None:
        super().__init__()
        self.bad_files: set[int] = set()
        self.bad_dirs: set[int] = set()

    def spoil_file(self, path: str) -> None:
        self.bad_files.add(lookup(self, path))

    def spoil_dir(self, path: str) -> None:
        self.bad_dirs.add(lookup(self, path))

    def open(self, ino: int) -> BytesDevice:
        if ino in self.bad_files:
            raise DiskReadError(f"inode {ino}: unreadable")
        return super().open(ino)

    def listdir(self, ino: int) -> list[tuple[bytes, int]]:
        if ino in self.bad_dirs:
            raise DiskReadError(f"directory {ino}: unreadable")
        return super().listdir(ino)


def _snapshot(fs: MemFs) -> Snapshot:
    return Snapshot("test", SystemSource.from_fs(fs))


def _manifest_for(hand_modified: list[str]) -> dict[str, Any]:
    return {
        "hand_placed": [{"path": p, "status": "modified"} for p in hand_modified],
        "modified_package_files": [],
        "deleted": [],
    }


# --- the tar stays readable, whatever fails while writing it ------------------


def test_read_error_midway_leaves_the_tar_readable(tmp_path: Path) -> None:
    payload = b"x" * (3 * MIB)

    class Fs(MemFs):
        def open(self, ino: int):
            if ino == lookup(self, "/b"):
                return _BadBlockDevice(payload, 2 * MIB)
            return super().open(ino)

    fs = Fs()
    fs.add_file("/a", b"A" * 100)
    fs.add_file("/b", payload)
    fs.add_file("/c", b"C" * 100)
    src = SystemSource.from_fs(fs)
    w = _TarWriter(tmp_path / "t.tar.gz", "after", ArchiveOptions())
    for p in ("/a", "/b", "/c"):
        w.add(src, p)
    w.close()
    with tarfile.open(tmp_path / "t.tar.gz") as tar:
        assert tar.getnames() == ["a", "c"]
        assert tar.extractfile("c").read() == b"C" * 100
    assert w.stats.entries == 2
    assert [(s["path"], s["reason"]) for s in w.stats.skipped] == [("/b", "read-error")]


def test_file_shorter_than_its_stat_is_a_read_error(tmp_path: Path) -> None:
    class Fs(MemFs):
        def open(self, ino: int):
            return BytesDevice(super().open(ino).read_at(0, 1))

    fs = Fs()
    fs.add_file("/short", b"12345")
    w = _TarWriter(tmp_path / "t.tar.gz", "after", ArchiveOptions())
    w.add(SystemSource.from_fs(fs), "/short")
    w.close()
    assert w.stats.skipped[0]["reason"] == "read-error"
    with tarfile.open(tmp_path / "t.tar.gz") as tar:
        assert tar.getnames() == []


# --- patch names --------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/..\\..\\..\\evil",
        "/C:\\Windows\\evil",
        "/C:evil",
        "/etc/..\\..\\..\\evil",
        "/.. /.. /evil",
        "/etc/a:b",
        "/etc/x\ny",
        "/etc/bad-\udcff",
    ],
)
def test_patch_name_stays_inside_the_patches_dir_on_windows(path: str) -> None:
    target = PureWindowsPath("out", "patches", _patch_name(path))
    assert target.parts[:2] == ("out", "patches")
    assert ".." not in target.parts
    assert all(part.strip(" .") for part in target.parts)
    assert not set(_patch_name(path)) & set('<>:"\\|?*\n')
    _patch_name(path).encode("utf-8")  # no surrogates left: must be a valid file name


def test_patch_names_of_different_paths_differ() -> None:
    names = [_patch_name(p) for p in ("/a:b", "/a%3Ab", "/a_b", "/a\\b", "/a/b", "/x\udcff", "/x")]
    assert len(set(names)) == len(names)


def test_ordinary_patch_names_are_unchanged() -> None:
    assert _patch_name("/etc/my.conf") == "etc/my.conf.diff"
    assert _patch_name("/opt/日本語/a b.txt") == "opt/日本語/a b.txt.diff"


def test_patch_that_cannot_be_written_is_listed_not_fatal(tmp_path: Path) -> None:
    # /etc/x's patch is the file etc/x.diff; /etc/x.diff/y's needs it to be a directory.
    before, after = MemFs(), MemFs()
    for fs, text in ((before, b"old\n"), (after, b"new\n")):
        fs.add_file("/etc/x", text)
        fs.add_file("/etc/x.diff/y", text)
    result = write_outputs(
        _manifest_for(["/etc/x", "/etc/x.diff/y"]),
        SystemSource.from_fs(after),
        SystemSource.from_fs(before),
        tmp_path,
    )
    assert result["patches"]["files"] == 1
    assert [(s["archive"], s["path"]) for s in result["skipped"]] == [("patches", "/etc/x.diff/y")]


def test_a_path_cannot_forge_a_patch_header_line(tmp_path: Path) -> None:
    before, after = MemFs(), MemFs()
    path = "/etc/x\n+++ b/etc/passwd"
    for fs, text in ((before, b"old\n"), (after, b"new\n")):
        fs.add_file(path, text)
    write_outputs(
        _manifest_for([path]), SystemSource.from_fs(after), SystemSource.from_fs(before), tmp_path
    )
    (patch,) = (tmp_path / "patches").rglob("*.diff")
    assert "+++ b/etc/passwd" not in patch.read_text(encoding="utf-8").split("\n")


# --- patch contents -----------------------------------------------------------


def _patch_bytes(tmp_path: Path, old: bytes, new: bytes) -> bytes:
    before, after = MemFs(), MemFs()
    before.add_file("/etc/f", old)
    after.add_file("/etc/f", new)
    write_outputs(
        _manifest_for(["/etc/f"]),
        SystemSource.from_fs(after),
        SystemSource.from_fs(before),
        tmp_path,
    )
    return (tmp_path / "patches" / "etc" / "f.diff").read_bytes()


def test_last_line_without_newline_is_marked(tmp_path: Path) -> None:
    assert _patch_bytes(tmp_path, b"a", b"a\nb\n") == (
        b"--- a/etc/f\n+++ b/etc/f\n@@ -1 +1,2 @@\n-a\n\\ No newline at end of file\n+a\n+b\n"
    )


def test_patch_lines_keep_lf_on_every_platform(tmp_path: Path) -> None:
    assert b"\r" not in _patch_bytes(tmp_path, b"one\n", b"two\n")


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (b"a", b"a\nb\n"),
        (b"a\nb\n", b"a"),
        (b"a", b"b"),
        (b"one\ftwo\nkeep\nthree\n", b"one\ftwo\nkeep\nTHREE\n"),
        ("nel\u0085here\nkeep\nend\n".encode(), "nel\u0085here\nkeep\nEND\n".encode()),
        ("ls\u2028here\nkeep\nend\n".encode(), "ls\u2028here\nkeep\nEND\n".encode()),
        (b"crlf\r\nkeep\r\nend\r\n", b"crlf\r\nkeep\r\nEND\r\n"),
    ],
)
def test_patches_apply_with_patch_1(tmp_path: Path, old: bytes, new: bytes) -> None:
    if shutil.which("patch") is None:
        pytest.skip("patch(1) is not installed")
    diff = _patch_bytes(tmp_path, old, new)
    work = tmp_path / "work"
    (work / "etc").mkdir(parents=True)
    (work / "etc" / "f").write_bytes(old)
    (tmp_path / "p.diff").write_bytes(diff)
    subprocess.run(
        ["patch", "--binary", "-s", "-p1", "-i", str(tmp_path / "p.diff")], cwd=work, check=True
    )
    assert (work / "etc" / "f").read_bytes() == new


# --- owner-only outputs, and --force ------------------------------------------


def _fake_sides(monkeypatch, current: MemFs, baseline: MemFs | None = None) -> None:
    def sides(args, aws, stack):
        return _snapshot(current), _snapshot(baseline) if baseline else None

    monkeypatch.setattr(cli, "_sides", sides)


def _run(out: Path, *extra: str) -> int:
    return cli.main(["--current-image", "unused", "-o", str(out), "-q", *extra])


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_outputs_are_owner_only(tmp_path: Path, monkeypatch) -> None:
    before, after = MemFs(), MemFs()
    before.add_file("/opt/app.conf", b"old\n")
    after.add_file("/opt/app.conf", b"new\n")
    _fake_sides(monkeypatch, after, before)
    previous = os.umask(0o022)
    try:
        assert _run(tmp_path / "out") == 0
        assert os.umask(0o022) == 0o022  # the process umask is put back
    finally:
        os.umask(previous)
    made = list((tmp_path / "out").rglob("*"))
    assert {p.name for p in made} >= {"manifest.json", "after.tar.gz", "before.tar.gz", "patches"}
    assert all(p.stat().st_mode & 0o077 == 0 for p in made), [
        (p.name, oct(p.stat().st_mode)) for p in made
    ]


def test_force_leaves_nothing_of_the_previous_run(tmp_path: Path, monkeypatch) -> None:
    out = tmp_path / "out"
    (out / "patches" / "etc").mkdir(parents=True)
    (out / "manifest.json").write_text('{"schema": "ec2-byhand/manifest/v1"}', encoding="utf-8")
    (out / "before.tar.gz").write_bytes(b"stale")
    (out / "after.tar.gz").write_bytes(b"stale")
    (out / "patches" / "etc" / "old.diff").write_text("stale", encoding="utf-8")
    (out / "report.txt").write_text("stale", encoding="utf-8")
    (out / "notes.txt").write_text("mine", encoding="utf-8")
    fs = MemFs()
    fs.add_file("/opt/x", b"data")
    _fake_sides(monkeypatch, fs)
    assert _run(out, "--force", "--no-archives") == 0
    assert sorted(p.name for p in out.iterdir()) == ["manifest.json", "notes.txt", "report.txt"]
    assert (out / "report.txt").read_text(encoding="utf-8").startswith("ec2-byhand ")
    assert json.loads((out / "manifest.json").read_text(encoding="utf-8"))["schema"]


def test_force_does_not_touch_a_directory_that_is_not_a_previous_run(
    tmp_path: Path, monkeypatch
) -> None:
    out = tmp_path / "out"
    (out / "patches").mkdir(parents=True)
    (out / "patches" / "mine.diff").write_text("keep", encoding="utf-8")
    (out / "before.tar.gz").write_bytes(b"keep")
    _fake_sides(monkeypatch, MemFs())
    assert _run(out, "--force", "--no-archives") == 0
    assert (out / "patches" / "mine.diff").read_text(encoding="utf-8") == "keep"
    assert (out / "before.tar.gz").read_bytes() == b"keep"


def test_os_error_is_a_message_not_a_traceback(tmp_path: Path, monkeypatch, capsys) -> None:
    def sides(args, aws, stack):
        raise PermissionError(13, "Permission denied", "/images/disk.img")

    monkeypatch.setattr(cli, "_sides", sides)
    assert _run(tmp_path / "out") == 1
    assert "Permission denied" in capsys.readouterr().err


def test_terminal_control_characters_in_warnings_are_escaped(tmp_path, monkeypatch, capsys) -> None:
    fs = _DamagedFs()
    fs.add_file("/var/lib/dpkg/status", b"")
    fs.add_file("/var/lib/dnf/history.sqlite", b"not a database")
    _fake_sides(monkeypatch, fs)
    original = cli.analyze

    def analyze_with_warning(*args, **kwargs):
        m = original(*args, **kwargs)
        m["warnings"].append({"code": "x", "message": "evil\x1b[2Jname\udcff"})
        return m

    monkeypatch.setattr(cli, "analyze", analyze_with_warning)
    assert cli.main(["--current-image", "unused", "-o", str(tmp_path / "o")]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "evil\\x1b[2Jname" in out


# --- damage in auxiliary data only costs that data ----------------------------


def test_unreadable_package_history_is_a_warning() -> None:
    fs = MemFs()
    fs.add_file("/var/lib/dpkg/status", b"")
    fs.add_file("/var/lib/dnf/history.sqlite", b"not a database at all, just garbage bytes")
    m = analyze(_snapshot(fs))
    assert [w["code"] for w in m["warnings"] if "history" in w["code"]] == [
        "package-history-unreadable"
    ]
    assert m["packages"]["history"] == []


def test_unreadable_baseline_history_is_a_warning() -> None:
    cur, base = MemFs(), MemFs()
    cur.add_file("/var/lib/dpkg/status", b"")
    base.add_file("/var/lib/dpkg/status", b"")
    base.add_file("/var/lib/dnf/history.sqlite", b"not a database at all, just garbage bytes")
    m = analyze(_snapshot(cur), _snapshot(base))
    (w,) = [w for w in m["warnings"] if w["code"] == "package-history-unreadable"]
    assert w["snapshot"] == "baseline"


GARBAGE = b"\x00\xff garbage, not a package database \x01" * 50
RPMDB_PATHS = ("/var/lib/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/rpmdb.sqlite")
DPKG_STATUS = "/var/lib/dpkg/status"
BDB_PAGE = 512
INSTALLED_A = b"Package: a\nVersion: 1\nStatus: install ok installed\nArchitecture: all\n\n"


def _rpm_header(name: str) -> bytes:
    """The smallest header that makes a package."""
    index, data = b"", b""
    for tag, value in ((1000, name), (1001, "1"), (1002, "1")):
        index += struct.pack(">IIII", tag, 6, len(data), 1)
        data += value.encode() + b"\0"
    return struct.pack(">II", 3, len(data)) + index + data


def _rpmdb_with_header(*values: object) -> bytes:
    """A well-formed rpmdb.sqlite whose rows hold `values` as the package headers."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "rpmdb.sqlite"
        con = sqlite3.connect(path)
        con.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob)")
        con.executemany("INSERT INTO Packages (blob) VALUES (?)", [(v,) for v in values])
        con.commit()
        con.close()
        return path.read_bytes()


def _codes(m: dict[str, Any]) -> list[str]:
    return [w["code"] for w in m["warnings"]]


@pytest.mark.parametrize(
    ("path", "content"),
    [
        pytest.param(RPMDB_PATHS[0], b"rpmdb\n", id="rpmdb-placeholder"),
        pytest.param(RPMDB_PATHS[1], GARBAGE, id="rpmdb-garbage"),
        pytest.param(RPMDB_PATHS[0], b"", id="rpmdb-empty"),
        pytest.param(RPMDB_PATHS[0], _rpmdb_with_header(None), id="rpmdb-null-header"),
        pytest.param(RPMDB_PATHS[0], _rpmdb_with_header("text"), id="rpmdb-text-header"),
        pytest.param(RPMDB_PATHS[0], _rpmdb_with_header(-1), id="rpmdb-negative-header"),
        pytest.param(RPMDB_PATHS[0], _rpmdb_with_header(b"\xff" * 64), id="rpmdb-bad-header"),
        pytest.param("/var/lib/rpm/Packages", GARBAGE, id="berkeley-db-garbage"),
        pytest.param(DPKG_STATUS, GARBAGE, id="dpkg-garbage"),
        pytest.param(DPKG_STATUS, b"\0" * 4096, id="dpkg-all-zeros"),
        pytest.param(DPKG_STATUS, INSTALLED_A + b"\0" * 4096, id="dpkg-zeros-after-the-text"),
        pytest.param(DPKG_STATUS, b"not: a status file\n", id="dpkg-no-package-entries"),
    ],
)
def test_damaged_package_db_is_a_warning_not_the_end_of_the_run(path, content) -> None:
    fs = MemFs()
    fs.add_file(path, content)
    fs.add_file("/opt/app", b"x")
    m = analyze(_snapshot(fs))
    # It leads the list, and "no database found" would be untrue.
    assert _codes(m)[0] == "package-db-unreadable"
    assert "no-package-db" not in _codes(m)
    assert m["warnings"][0]["snapshot"] == "current"
    assert "every file counts as unowned" in m["warnings"][0]["message"]
    assert m["current"]["package_db"] is None
    # The analysis went on, and unknown is not reported as zero.
    assert "/opt/app" in [h["path"] for h in m["hand_placed"]]
    assert m["modified_package_files"] == []
    assert m["summary"]["modified_package_files"] is None
    assert m["summary"]["packages_installed"] is None


@pytest.mark.parametrize("path", [RPMDB_PATHS[0], "/var/lib/rpm/Packages", DPKG_STATUS])
def test_package_db_on_bad_blocks_is_a_warning(path: str) -> None:
    fs = _DamagedFs()
    fs.add_file(path, b"x")
    fs.spoil_file(path)
    m = analyze(_snapshot(fs))
    assert _codes(m)[0] == "package-db-unreadable"
    assert "no-package-db" not in _codes(m)


def test_directory_above_the_package_db_on_bad_blocks_is_a_warning() -> None:
    fs = _DamagedFs()
    fs.add_file(DPKG_STATUS, INSTALLED_A)
    fs.spoil_dir("/var/lib/dpkg")
    m = analyze(_snapshot(fs))
    assert "package-db-unreadable" in _codes(m)


@pytest.mark.parametrize(
    "status",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"\n\n", id="blank"),
        pytest.param(
            b"Package: a\nStatus: purge ok not-installed\n\n",
            id="only-packages-no-longer-installed",
        ),
    ],
)
def test_status_without_installed_packages_is_not_damage(status: bytes) -> None:
    fs = MemFs()
    fs.add_file(DPKG_STATUS, status)
    m = analyze(_snapshot(fs))
    assert "package-db-unreadable" not in _codes(m)
    assert m["current"]["package_db"]["packages"] == 0
    assert m["summary"]["packages_installed"] == 0


def test_no_package_db_still_means_there_is_none() -> None:
    fs = MemFs()
    fs.add_file("/opt/app", b"x")
    m = analyze(_snapshot(fs))
    assert "no-package-db" in _codes(m)
    assert "package-db-unreadable" not in _codes(m)
    assert m["summary"]["packages_installed"] == 0


def _dpkg_fs(*files: str) -> MemFs:
    """A readable dpkg system where package "a" owns `files`, each of which exists."""
    fs = MemFs()
    fs.add_file(DPKG_STATUS, INSTALLED_A)
    fs.add_file("/var/lib/dpkg/info/a.list", "".join(f"{f}\n" for f in files).encode())
    for f in files:
        fs.add_file(f, b"x")
    return fs


def test_damaged_baseline_db_is_a_warning_about_the_baseline() -> None:
    # Only the current side's lack of a database has a warning of its own,
    # so this one must not depend on that.
    cur = _dpkg_fs("/usr/bin/a")
    base = _dpkg_fs("/usr/bin/a", "/usr/bin/gone")
    base.add_file(DPKG_STATUS, GARBAGE)
    m = analyze(_snapshot(cur), _snapshot(base))
    (w,) = [w for w in m["warnings"] if w["code"] == "package-db-unreadable"]
    assert w["snapshot"] == "baseline"
    assert "no-package-db" not in _codes(m)
    assert m["baseline"]["package_db"] is None
    assert m["current"]["package_db"]["packages"] == 1
    # The current side is known, the comparison is not.
    assert m["summary"]["packages_installed"] == 1
    assert m["packages"]["changes"] is None
    assert m["summary"]["modified_package_files_since_baseline"] is None
    # What the warning says: a package file gone from the baseline looks hand-placed.
    assert "/usr/bin/gone" in [d["path"] for d in m["deleted"]]


def test_damaged_current_db_with_a_baseline_lists_only_what_changed() -> None:
    cur = _dpkg_fs("/usr/bin/a", "/usr/bin/same")
    base = _dpkg_fs("/usr/bin/a", "/usr/bin/same")
    cur.add_file("/usr/bin/a", b"changed")
    cur.add_file(DPKG_STATUS, GARBAGE)
    m = analyze(_snapshot(cur), _snapshot(base))
    assert _codes(m)[0] == "package-db-unreadable"
    assert m["warnings"][0]["snapshot"] == "current"
    paths = [h["path"] for h in m["hand_placed"]]
    assert "/usr/bin/a" in paths
    assert "/usr/bin/same" not in paths
    assert m["packages"]["changes"] is None
    assert m["summary"]["modified_package_files_since_baseline"] is None


def test_both_damaged_dbs_are_reported() -> None:
    cur, base = MemFs(), MemFs()
    cur.add_file(DPKG_STATUS, GARBAGE)
    base.add_file(RPMDB_PATHS[0], GARBAGE)
    m = analyze(_snapshot(cur), _snapshot(base))
    assert [w["snapshot"] for w in m["warnings"] if w["code"] == "package-db-unreadable"] == [
        "current",
        "baseline",
    ]


def test_history_is_still_read_when_the_package_db_is_damaged() -> None:
    log = b"Start-Date: 2026-01-01  00:00:00\nCommandline: apt install x\n"
    cur, base = MemFs(), MemFs()
    cur.add_file(DPKG_STATUS, INSTALLED_A)
    cur.add_file("/var/log/apt/history.log", log)
    base.add_file(DPKG_STATUS, GARBAGE)
    base.add_file("/var/log/apt/history.log", log)
    m = analyze(_snapshot(cur), _snapshot(base))
    # Without the baseline's history this run would count as new.
    assert [t["since_baseline"] for t in m["packages"]["history"]] == [False]

    cur.add_file(DPKG_STATUS, GARBAGE)
    m = analyze(_snapshot(cur))
    assert [t["cmdline"] for t in m["packages"]["history"]] == ["apt install x"]


def _names(m: dict[str, Any]) -> list[str]:
    return [p["name"] for p in m["packages"]["installed"]]


def _damage(m: dict[str, Any]) -> dict[str, Any]:
    (w,) = [w for w in m["warnings"] if w["code"] == "package-db-damaged"]
    return w


def _bdb_page(*items: bytes) -> bytes:
    """A hash page holding raw items: each is its kind byte and what follows."""
    page = bytearray(BDB_PAGE)
    page[25] = 13
    struct.pack_into("<H", page, 20, len(items))
    end = BDB_PAGE
    for i, item in enumerate(items):
        end -= len(item)
        page[end : end + len(item)] = item
        struct.pack_into("<H", page, 26 + 2 * i, end)
    return bytes(page)


def _bdb(*pages: bytes) -> bytes:
    meta = bytearray(BDB_PAGE)
    struct.pack_into("<I", meta, 12, 0x061561)
    struct.pack_into("<I", meta, 20, BDB_PAGE)
    struct.pack_into("<I", meta, 32, len(pages))
    return bytes(meta) + b"".join(pages)


def _bdb_inline(key: int, value: bytes) -> list[bytes]:
    return [b"\x01" + struct.pack("<I", key), b"\x01" + value]


def test_bad_rpm_headers_cost_only_those_packages() -> None:
    fs = MemFs()
    db = _rpmdb_with_header(_rpm_header("a"), None, b"\xff" * 64, _rpm_header("b"))
    fs.add_file(RPMDB_PATHS[0], db)
    m = analyze(_snapshot(fs))
    assert _names(m) == ["a", "b"]
    assert m["summary"]["packages_installed"] == 2
    assert m["current"]["package_db"]["packages"] == 2
    w = _damage(m)
    assert w["snapshot"] == "current"
    assert [e.split(":")[0] for e in w["entries"]] == [
        "rpmdb.sqlite header 2",
        "rpmdb.sqlite header 3",
    ]
    assert "entries that could not be read: 2" in w["message"]
    assert _codes(m)[0] == "package-db-damaged"
    assert "package-db-unreadable" not in _codes(m)
    assert "no-package-db" not in _codes(m)


def _ruin_sqlite_page(db: bytes, n: int) -> bytes:
    """`db` with its page `n` (from 0) overwritten; 0xFF is no valid SQLite page or pointer."""
    size = int.from_bytes(db[16:18], "big")
    return db[: n * size] + b"\xff" * size + db[(n + 1) * size :]


def test_bad_sqlite_overflow_page_costs_only_that_package() -> None:
    # As in real rpmdbs, the headers are larger than a page. A scan reading them all
    # would stop at the first bad page, losing every package after it.
    filler = {name: name.encode() * 20000 for name in "abc"}
    db = _rpmdb_with_header(*(_rpm_header(name) + filler[name] for name in "abc"))
    size = int.from_bytes(db[16:18], "big")
    overflow_page = db.index(b"b" * (size - 8)) // size
    fs = MemFs()
    fs.add_file(RPMDB_PATHS[0], _ruin_sqlite_page(db, overflow_page))
    m = analyze(_snapshot(fs))
    assert _names(m) == ["a", "c"]
    (entry,) = _damage(m)["entries"]
    assert entry.startswith("rpmdb.sqlite header 2")


def test_bad_sqlite_table_page_costs_the_rows_after_it() -> None:
    names = [f"p{i}" for i in range(1000)]
    db = _rpmdb_with_header(*(_rpm_header(name) for name in names))
    last_page = len(db) // int.from_bytes(db[16:18], "big") - 1
    fs = MemFs()
    fs.add_file(RPMDB_PATHS[0], _ruin_sqlite_page(db, last_page))
    m = analyze(_snapshot(fs))
    assert 0 < len(_names(m)) < len(names)
    (entry,) = _damage(m)["entries"]
    assert entry.startswith("rpmdb.sqlite after header")


def test_bad_berkeley_db_records_cost_only_those_packages() -> None:
    broken_chain = b"\x03\0\0\0" + struct.pack("<II", 99, 100)
    db = _bdb(
        _bdb_page(
            *_bdb_inline(1, _rpm_header("a")),
            *_bdb_inline(2, b"\xff" * 64),  # a bad header
            b"\x01" + struct.pack("<I", 3),
            broken_chain,  # a record that cannot even be fetched
        ),
    )
    fs = MemFs()
    fs.add_file("/var/lib/rpm/Packages", db)
    m = analyze(_snapshot(fs))
    assert _names(m) == ["a"]
    assert len(_damage(m)["entries"]) == 2


def test_bad_berkeley_db_page_costs_only_that_page() -> None:
    bad = bytearray(_bdb_page())
    struct.pack_into("<H", bad, 20, 0xFFFF)  # far more entries than the page can hold
    db = _bdb(bytes(bad), _bdb_page(*_bdb_inline(1, _rpm_header("a"))))
    fs = MemFs()
    fs.add_file("/var/lib/rpm/Packages", db)
    m = analyze(_snapshot(fs))
    assert _names(m) == ["a"]
    assert _damage(m)["entries"][0].startswith("Berkeley DB page 1")


def test_readers_raise_without_on_damage() -> None:
    with pytest.raises(DiskReadError):
        read_sqlite(_rpmdb_with_header(_rpm_header("a"), None), None)
    with pytest.raises(DiskReadError):
        read_bdb(_bdb(_bdb_page(*_bdb_inline(1, b"\xff" * 64))))


def _two_dpkg_packages() -> _DamagedFs:
    fs = _DamagedFs()
    stanza = "Package: {0}\nVersion: 1\nStatus: install ok installed\nArchitecture: all\n\n"
    fs.add_file(DPKG_STATUS, (stanza.format("a") + stanza.format("b")).encode())
    for name in "ab":
        fs.add_file(f"/usr/bin/{name}", b"x")
        fs.add_file(f"/var/lib/dpkg/info/{name}.list", f"/usr/bin/{name}\n".encode())
    return fs


def test_unreadable_dpkg_file_list_costs_only_that_package() -> None:
    fs = _two_dpkg_packages()
    fs.spoil_file("/var/lib/dpkg/info/a.list")
    m = analyze(_snapshot(fs))
    # The package itself is known from status; only its files are not.
    assert _names(m) == ["a", "b"]
    paths = [h["path"] for h in m["hand_placed"]]
    assert "/usr/bin/a" in paths
    assert "/usr/bin/b" not in paths
    (entry,) = _damage(m)["entries"]
    assert entry.startswith("dpkg info/a.list")


def test_unreadable_dpkg_md5sums_keeps_the_files_owned() -> None:
    fs = _two_dpkg_packages()
    fs.add_file("/var/lib/dpkg/info/a.md5sums", b"x")
    fs.spoil_file("/var/lib/dpkg/info/a.md5sums")
    m = analyze(_snapshot(fs))
    assert "/usr/bin/a" not in [h["path"] for h in m["hand_placed"]]
    (entry,) = _damage(m)["entries"]
    assert entry.startswith("dpkg info/a.md5sums")


def test_unreadable_dpkg_info_directory_keeps_the_package_list() -> None:
    fs = _two_dpkg_packages()
    fs.spoil_dir("/var/lib/dpkg/info")
    m = analyze(_snapshot(fs))
    assert _names(m) == ["a", "b"]
    assert "/usr/bin/a" in [h["path"] for h in m["hand_placed"]]
    assert "package-db-damaged" in _codes(m)


def test_damaged_package_can_look_removed_or_added_and_the_warning_says_so() -> None:
    whole = MemFs()
    whole.add_file(RPMDB_PATHS[0], _rpmdb_with_header(_rpm_header("a"), _rpm_header("b")))
    part = MemFs()
    part.add_file(RPMDB_PATHS[0], _rpmdb_with_header(_rpm_header("a"), None))

    m = analyze(_snapshot(part), _snapshot(whole))
    assert [(c["kind"], c["name"]) for c in m["packages"]["changes"]] == [("removed", "b")]
    assert _damage(m)["snapshot"] == "current"
    assert "show them as removed" in _damage(m)["message"]

    m = analyze(_snapshot(whole), _snapshot(part))
    assert [(c["kind"], c["name"]) for c in m["packages"]["changes"]] == [("added", "b")]
    assert _damage(m)["snapshot"] == "baseline"
    assert "show them as added" in _damage(m)["message"]


@pytest.mark.parametrize("epoch", ["\u00b2", "9" * 5000, "x"])
def test_unusable_dpkg_epoch_is_not_damage(epoch: str) -> None:
    fs = MemFs()
    status = f"Package: a\nVersion: {epoch}:1\nStatus: install ok installed\n"
    fs.add_file(DPKG_STATUS, status.encode())
    m = analyze(_snapshot(fs))
    assert _names(m) == ["a"]
    assert "package-db-damaged" not in _codes(m)
    assert "package-db-unreadable" not in _codes(m)


def test_summary_marks_a_partly_damaged_db(tmp_path, monkeypatch, capsys) -> None:
    fs = MemFs()
    fs.add_file(RPMDB_PATHS[0], _rpmdb_with_header(_rpm_header("a"), None))
    _fake_sides(monkeypatch, fs)
    assert cli.main(["--current-image", "unused", "-o", str(tmp_path / "o")]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert "packages:               1 installed (some entries unreadable)" in lines
    assert next(x for x in lines if x.startswith("hand-placed:")).endswith(
        "(may include package files)"
    )
    assert any(
        x.startswith("warning: package-db-damaged (current): entries that could not be read: 1")
        for x in lines
    )
    manifest = json.loads((tmp_path / "o" / "manifest.json").read_text("utf-8"))
    assert manifest["summary"]["packages_installed"] == 1


def test_summary_shows_what_a_damaged_current_db_makes_unknown(
    tmp_path, monkeypatch, capsys
) -> None:
    fs = MemFs()
    fs.add_file(DPKG_STATUS, GARBAGE)
    fs.add_file("/opt/app", b"x")
    _fake_sides(monkeypatch, fs)
    assert cli.main(["--current-image", "unused", "-o", str(tmp_path / "o")]) == 0
    out = capsys.readouterr().out
    assert "modified package files: unknown" in out
    assert "packages:               unknown" in out
    assert "(may include package files)" in out.split("deleted:")[0]
    assert "warning: package-db-unreadable (current): dpkg status: damaged" in out
    manifest = json.loads((tmp_path / "o" / "manifest.json").read_text("utf-8"))
    assert manifest["summary"]["packages_installed"] is None


def test_summary_shows_what_a_damaged_baseline_db_makes_unknown(
    tmp_path, monkeypatch, capsys
) -> None:
    cur, base = _dpkg_fs("/usr/bin/a"), MemFs()
    base.add_file(DPKG_STATUS, GARBAGE)
    _fake_sides(monkeypatch, cur, base)
    assert cli.main(["--current-image", "unused", "-o", str(tmp_path / "o")]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert "packages:               1 installed (changes since baseline unknown)" in lines
    assert next(x for x in lines if x.startswith("deleted:")).endswith(
        "(may include package files)"
    )
    assert not next(x for x in lines if x.startswith("hand-placed:")).endswith("package files)")


def test_unreadable_auxiliary_files_do_not_abort_the_analysis() -> None:
    fs = _DamagedFs()
    aux = [
        "/etc/os-release",
        "/etc/passwd",
        "/etc/group",
        "/etc/dpkg/dpkg.cfg",
        "/etc/dpkg/dpkg.cfg.d/x",
        "/var/lib/alternatives/python",
        f"{SITE}/demo-1.0.dist-info/METADATA",
        f"{SITE}/old.egg-info/installed-files.txt",
        "/usr/lib/node_modules/n/package.json",
    ]
    for path in aux:
        fs.add_file(path, b"x")
        fs.spoil_file(path)
    fs.add_file("/var/lib/dpkg/status", b"")
    m = analyze(_snapshot(fs))
    assert m["current"]["os"] == {}


def test_unreadable_directories_of_auxiliary_data_do_not_abort_the_analysis() -> None:
    fs = _DamagedFs()
    fs.add_file("/var/lib/dpkg/status", b"")
    for path in ("/etc/dpkg/dpkg.cfg.d/x", "/var/lib/alternatives/python", "/opt/keep"):
        fs.add_file(path, b"x")
    fs.spoil_dir("/etc/dpkg/dpkg.cfg.d")
    fs.spoil_dir("/var/lib/alternatives")
    m = analyze(_snapshot(fs))
    assert "/opt/keep" in {h["path"] for h in m["hand_placed"]}
    assert find_alternatives(_snapshot(fs).source) == []


def test_unreadable_file_in_a_pip_package_counts_as_modified() -> None:
    fs = _DamagedFs()
    fs.add_file(f"{SITE}/demo/a.py", b"data")
    fs.spoil_file(f"{SITE}/demo/a.py")
    fs.add_file(f"{SITE}/demo-1.0.dist-info/RECORD", b"demo/a.py,sha256=abc,4\n")
    src = SystemSource.from_fs(fs)
    (pkg,) = find_language_packages(src, [p.decode() for p, *_ in src.walk()])
    assert pkg.modified == [f"{SITE}/demo/a.py"]


def test_text_reader_treats_a_damaged_path_as_no_text() -> None:
    fs = _DamagedFs()
    fs.add_file("/opt/d/f", b"data\n")
    fs.spoil_dir("/opt/d")
    assert _read_text(SystemSource.from_fs(fs), "/opt/d/f") == (None, None)


def test_patch_step_survives_a_damaged_baseline_path(tmp_path: Path) -> None:
    before, after = _DamagedFs(), MemFs()
    for fs in (before, after):
        fs.add_file("/opt/d/f", b"data\n")
    before.spoil_dir("/opt/d")
    result = write_outputs(
        _manifest_for(["/opt/d/f"]),
        SystemSource.from_fs(after),
        SystemSource.from_fs(before),
        tmp_path,
    )
    assert result["patches"]["files"] == 0
    assert result["skipped"][0]["reason"] == "read-error"


def test_unreadable_xfs_log_warns_instead_of_aborting() -> None:
    class BadLog(Xfs):
        def __init__(self) -> None:
            pass

        @property
        def log_state(self):
            raise DiskReadError("XFS log has no valid record header")

    src = SystemSource({b"/": BadLog()})
    assert [w["code"] for w in _warnings(Snapshot("x", src), "current")] == ["dirty-snapshot"]


# --- odd but legal language package metadata ----------------------------------


@pytest.mark.parametrize(
    "text", [b"[]", b'"just a string"', b"3", b"null", b"not json", b'{"name": 1, "version": 2}']
)
def test_npm_package_json_of_any_shape(text: bytes) -> None:
    fs = MemFs()
    fs.add_file("/usr/lib/node_modules/x/package.json", text)
    m = analyze(_snapshot(fs))
    (item,) = m["language_packages"]
    assert item["name"] == "x"
    assert item["version"] is None


def test_pip_metadata_that_is_not_utf8_or_not_csv() -> None:
    fs = MemFs()
    fs.add_file(f"{SITE}/demo-1.0.dist-info/INSTALLER", b"pip\xff\n")
    fs.add_file(f"{SITE}/demo-1.0.dist-info/RECORD", b"x" * (200 * 1024) + b",,\n")
    src = SystemSource.from_fs(fs)
    (pkg,) = find_language_packages(src, [p.decode() for p, *_ in src.walk()])
    assert pkg.name == "demo"


# --- corrupt metadata inside the readers --------------------------------------


class _RecordingDevice:
    """Remembers which byte ranges were read: that is where the metadata is."""

    def __init__(self, dev: FileDevice) -> None:
        self._dev = dev
        self.ranges: set[tuple[int, int]] = set()

    @property
    def size(self) -> int:
        return self._dev.size

    def read_at(self, offset: int, length: int) -> bytes:
        self.ranges.add((offset, length))
        return self._dev.read_at(offset, length)


class _CorruptedDevice:
    """A device with a few bytes overwritten."""

    def __init__(self, dev: FileDevice, patches: dict[int, int]) -> None:
        self._dev = dev
        self._patches = patches

    @property
    def size(self) -> int:
        return self._dev.size

    def read_at(self, offset: int, length: int) -> bytes:
        data = self._dev.read_at(offset, length)
        hits = [o for o in self._patches if offset <= o < offset + length]
        if not hits:
            return data
        out = bytearray(data)
        for o in hits:
            out[o - offset] = self._patches[o]
        return bytes(out)


def _read_all_metadata(dev: Any) -> None:
    """Open and walk the filesystem the way analyze does; only DiskReadError may come out."""
    fs = open_fs(dev)
    for _path, ino, st in walk(fs, lambda path, err: None):
        try:
            fs.xattrs(ino)
            if st.type is FileType.LNK:
                fs.readlink(ino)
            elif st.type is FileType.REG:
                content = fs.open(ino)
                content.read_at(0, min(content.size, 4096))
        except DiskReadError:
            pass


def corrupt_and_read(path: Path, rounds: int) -> None:
    """Overwrite a few random bytes of what a clean read touches, and read it all again."""
    with FileDevice(path) as dev:
        recording = _RecordingDevice(dev)
        _read_all_metadata(recording)
        spans = sorted(r for r in recording.ranges if 0 < r[1] <= 65536)
        rnd = random.Random(path.name)
        for _ in range(rounds):
            patches = {}
            for _ in range(rnd.randrange(1, 40)):
                off, n = rnd.choice(spans)
                patches[off + rnd.randrange(n)] = rnd.choice((0, 1, 0x7F, 0xFF, rnd.randrange(256)))
            with contextlib.suppress(DiskReadError):
                _read_all_metadata(_CorruptedDevice(dev, patches))


@pytest.mark.parametrize(
    "image",
    ["ext4-inline", "ext4-ea-inode", "ext4-noextents-1k", "xfs-latest", "xfs-v4", "vfat-fat12"],
)
def test_corrupt_metadata_only_ever_raises_disk_read_error(image: str) -> None:
    path = GOLDEN_DIR / f"{image}.img"
    if not path.exists():
        pytest.skip("no golden images; run tools/golden/build_fs.sh")
    corrupt_and_read(path, rounds=6)


def test_partition_past_the_end_of_the_disk_is_recorded_not_raised() -> None:
    sector = bytearray(1 << 20)
    struct.pack_into("<BBBBBBBBII", sector, 0x1BE, 0, 0, 0, 0, 0x83, 0, 0, 0, 2048, 1 << 31)
    sector[0x1FE:0x200] = b"\x55\xaa"
    (volume,) = scan({"disk0": BytesDevice(sector)})
    assert volume.name == "disk0p1"
    assert volume.fs is None
    assert "out of range" in (volume.error or "")


def test_unusable_lvm_metadata_is_recorded_not_raised(monkeypatch) -> None:
    import diskread.system as system

    def broken(devices, unreadable=None):
        raise DiskReadError("metadata text CRC mismatch")

    monkeypatch.setattr(system, "read_label", lambda dev: object())
    monkeypatch.setattr(system, "find_volume_groups", broken)
    volumes = scan({"disk0": BytesDevice(bytes(1 << 20))})
    assert [v.error for v in volumes] == ["metadata text CRC mismatch"]


def test_truncated_berkeley_db_is_a_disk_read_error() -> None:
    pagesize = 512
    db = bytearray(pagesize * 2)
    struct.pack_into("<I", db, 12, 0x061561)
    struct.pack_into("<I", db, 20, pagesize)
    struct.pack_into("<I", db, 32, 1)
    db[pagesize + 25] = 13  # a hash page...
    struct.pack_into("<H", db, pagesize + 20, 0xFFFF)  # ...claiming far too many entries
    with pytest.raises(DiskReadError):
        read_bdb(bytes(db))


class _Files:
    """Just enough of a source for the history readers."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self._files = files

    def read(self, path: str) -> bytes | None:
        return self._files.get(path)

    def listdir(self, path: str) -> list[str] | None:
        prefix = path + "/"
        names = [p[len(prefix) :] for p in self._files if p.startswith(prefix)]
        return names or None


def test_corrupt_rotated_apt_log_is_skipped() -> None:
    good = b"Start-Date: 2026-01-01  00:00:00\nCommandline: apt install x\n"
    packed = bytearray(gzip.compress(b"some text " * 1000))
    packed[20:40] = b"\xff" * 20  # corrupts the deflate stream, not the gzip header
    src = _Files({"/var/log/apt/history.log": good, "/var/log/apt/history.log.1.gz": bytes(packed)})
    assert [t.cmdline for t in read_history(src)] == ["apt install x"]


def test_views_in_a_database_from_the_disk_cannot_call_unsafe_functions(tmp_path: Path) -> None:
    # A snapshot's database is data, not code. trusted_schema=OFF makes SQLite
    # refuse non-innocuous functions used from its schema.
    path = tmp_path / "rpmdb.sqlite"
    con = sqlite3.connect(path)
    con.execute("CREATE VIEW Packages AS SELECT 1 AS hnum, load_extension('evil') AS blob")
    con.commit()
    con.close()
    with pytest.raises(DiskReadError, match="unsafe use"):
        read_sqlite(path.read_bytes(), None)


# --- vfat mount options -------------------------------------------------------


def test_vfat_accepts_user_names_in_uid_and_gid() -> None:
    path = GOLDEN_DIR / "vfat-fat12.img"
    if not path.exists():
        pytest.skip("no golden images; run tools/golden/build_vfat.sh")
    from diskread.fs.fat import Vfat

    with FileDevice(path) as dev:
        fs = Vfat(dev, "uid=ec2-user,gid=wheel,umask=oops,fmask=0077,time_offset=x,codepage=none")
        st = fs.stat(fs.root_ino)
        assert (st.uid, st.gid) == (0, 0)
        assert fs.listdir(fs.root_ino)


# --- snapshots ----------------------------------------------------------------


def test_network_failure_while_deleting_does_not_leave_the_rest_behind() -> None:
    attempted = []

    class Ec2:
        def delete_snapshot(self, **kwargs: str) -> None:
            attempted.append(kwargs["SnapshotId"])
            if kwargs["SnapshotId"] == "snap-a":
                raise EndpointConnectionError(endpoint_url="https://ec2.example")

    failed = delete_snapshots(Ec2(), [Disk("/dev/a", "snap-a"), Disk("/dev/b", "snap-b")])
    assert attempted == ["snap-a", "snap-b"]
    assert [d.snapshot_id for d, _ in failed] == ["snap-a"]
    assert "ec2.example" in failed[0][1]


# --- globs --------------------------------------------------------------------


def test_newlines_in_a_path_do_not_defeat_the_globs() -> None:
    assert is_sensitive("/home/a\nb/.ssh/id_rsa")
    assert is_sensitive("/opt/x\ny/.env")
    noise = NoiseFilter(excludes=("/opt/scratch/**",))
    assert noise.match("/tmp/a\nb") == "runtime"
    assert noise.match("/opt/scratch/a\nb/c") == "user-exclude"
    assert noise.match("/home/u\nv/x/__pycache__/y") == "generated"


@pytest.mark.parametrize(
    "path",
    [
        "/srv/app/.env.production",
        "/etc/krb5.keytab",
        "/home/u/.npmrc",
        "/home/u/.pypirc",
        "/root/.vault-token",
        "/root/.mysql_history",
        "/root/.psql_history",
        "/etc/ipsec.secrets",
        "/etc/wireguard/wg0.conf",
        "/etc/NetworkManager/system-connections/office.nmconnection",
        "/var/lib/amazon/ssm/Vault/Store/EC2RegistrationKey",
        "/var/lib/snapd/device/private-keys-v1/WwmCuACHfiU6Stg04toPR",
        "/var/lib/ubuntu-advantage/private/machine-token.json",
    ],
)
def test_more_secret_paths_are_flagged(path: str) -> None:
    assert is_sensitive(path)


@pytest.mark.parametrize(
    ("path", "file_type", "rule"),
    [
        # Seen on real EC2 instances (2026-11-13).
        ("/var/log/amazon/ssm/audits", FileType.DIR, "agents"),  # not shadowed by "logs"
        ("/var/lib/amazon/ssm/ipc/health", FileType.SOCK, "agents"),
        ("/root/snap", FileType.DIR, "agents"),
        ("/var/spool/postfix/private/anvil", FileType.SOCK, "runtime"),
        ("/var/lib/snapd/device/private-keys-v1/k", FileType.REG, "generated"),
        ("/var/log/myapp", FileType.DIR, None),  # a directory someone made stays visible
        ("/root/snap/other-app", FileType.DIR, None),
        ("/var/lib/snapd/snaps/tool_1.snap", FileType.REG, None),  # a snap installed by hand
    ],
)
def test_service_state_seen_on_ec2_is_noise(path: str, file_type: FileType, rule) -> None:
    assert NoiseFilter().match(path, file_type) == rule


def test_ordinary_paths_are_not_flagged() -> None:
    assert not is_sensitive("/etc/hosts")
    assert not is_sensitive("/opt/app/environment.py")
    assert not is_sensitive("/etc/wireguard")


# --- smaller things -----------------------------------------------------------


def test_deleted_directories_are_counted_whatever_their_neighbours_are_called() -> None:
    # "-" sorts before "/", so a plain sort puts /a-b between /a and /a/c.
    base = MemFs()
    base.add_file("/gone/c", b"1")
    base.add_file("/gone-too/d", b"2")
    m = analyze(_snapshot(MemFs()), _snapshot(base))
    assert m["deleted"] == [
        {"path": "/gone", "type": "dir", "entries_below": 1},
        {"path": "/gone-too", "type": "dir", "entries_below": 1},
    ]


def test_gone_wants_directory_is_reported_under_services_only() -> None:
    base, cur = MemFs(), MemFs()
    cur.add_file("/etc/systemd/system/kept.service", b"")
    base.add_file("/etc/systemd/system/kept.service", b"")
    base.add_link("/etc/systemd/system/multi-user.target.wants/x.service", "/opt/x.service")
    m = analyze(_snapshot(cur), _snapshot(base))
    assert m["deleted"] == []
    assert [s["status"] for s in m["services"]] == ["removed"]


def test_dpkg_cfg_is_read_after_its_fragments() -> None:
    fs = MemFs()
    fs.add_file("/etc/dpkg/dpkg.cfg.d/a", b"path-include=/usr/share/doc/keep/*\n")
    fs.add_file("/etc/dpkg/dpkg.cfg", b"path-exclude=/usr/share/doc/*\n")
    excludes = DpkgPathExcludes.from_source(SystemSource.from_fs(fs))
    assert excludes.excluded("/usr/share/doc/keep/README")  # dpkg.cfg comes last, so it wins


def test_unsupported_rpm_digest_is_unreadable_not_a_crash() -> None:
    from ec2_byhand.packages.model import Package, PackageDB, PackageFile
    from ec2_byhand.packages.verify import verify_packages

    fs = MemFs()
    fs.add_file("/usr/bin/x", b"data")
    pkg = Package(
        manager="rpm",
        name="x",
        arch="x86_64",
        epoch=None,
        version="1",
        release="1",
        files=(PackageFile(path="/usr/bin/x", digest="ab", digest_algo="3", mode=0o100644),),
    )
    db = PackageDB("rpm", "rpm-sqlite", "/x", (pkg,))
    (problem,) = verify_packages(SystemSource.from_fs(fs), db)
    assert "unreadable" in problem.problems
    assert "3" in (problem.error or "")


def test_read_chunks_covers_the_device_in_order() -> None:
    from diskread.blockdev import read_chunks

    data = bytes(range(256)) * 10
    assert b"".join(read_chunks(BytesDevice(data), 100)) == data
    assert list(read_chunks(BytesDevice(b""))) == []


def test_printable_escapes_only_what_a_terminal_would_act_on() -> None:
    from ec2_byhand.archive import printable

    assert printable("/opt/日本語/a b.txt") == "/opt/日本語/a b.txt"
    assert printable("a\x1b[2Jb\nc") == "a\\x1b[2Jb\\nc"
    printable("bad-\udcff").encode("utf-8")


def test_huge_file_is_not_read_into_memory() -> None:
    class Sparse:
        size = 1 << 60

        def read_at(self, offset: int, length: int) -> bytes:
            raise AssertionError("must be refused before reading")

    class Fs(MemFs):
        def stat(self, ino: int):
            st = super().stat(ino)
            return dataclasses.replace(st, size=Sparse.size) if ino == self.huge else st

        def open(self, ino: int):
            return Sparse() if ino == self.huge else super().open(ino)

    fs = Fs()
    fs.add_file("/etc/os-release", b"")
    fs.huge = lookup(fs, "/etc/os-release")
    with pytest.raises(DiskReadError, match="too large"):
        SystemSource.from_fs(fs).read("/etc/os-release")
    assert _snapshot(fs).source.try_read("/etc/os-release") is None


def test_dividing_by_a_size_that_reads_as_zero_is_damage_not_a_crash() -> None:
    from diskread.errors import malformed_as_disk_read_error

    @malformed_as_disk_read_error
    def descriptors_per_block(block_size: int, desc_size: int) -> int:
        return 32 // (block_size // desc_size)

    with pytest.raises(DiskReadError, match="malformed on-disk data"):
        descriptors_per_block(4096, 8192)


def test_ext4_group_descriptor_larger_than_a_block_is_refused() -> None:
    from diskread.fs.ext4.superblock import INCOMPAT_64BIT, parse_superblock

    path = GOLDEN_DIR / "ext4-default.img"
    if not path.exists():
        pytest.skip("no golden images; run tools/golden/build_fs.sh")
    with FileDevice(path) as dev:
        raw = bytearray(dev.read_at(1024, 1024))
    incompat = struct.unpack_from("<I", raw, 0x60)[0]
    struct.pack_into("<I", raw, 0x60, incompat | INCOMPAT_64BIT)
    for desc_size in (8192, 2048):  # a power of two, as required, but more than the kernel takes
        struct.pack_into("<H", raw, 0xFE, desc_size)
        with pytest.raises(DiskReadError, match="group descriptor size"):
            parse_superblock(bytes(raw))
    struct.pack_into("<H", raw, 0xFE, 64)
    assert parse_superblock(bytes(raw)).desc_size == 64


class _CountingDevice:
    """A device that notes how many bytes each read asked for."""

    def __init__(self, data: bytes) -> None:
        self._dev = BytesDevice(data)
        self.reads: list[int] = []

    @property
    def size(self) -> int:
        return self._dev.size

    def read_at(self, offset: int, length: int) -> bytes:
        self.reads.append(length)
        return self._dev.read_at(offset, length)


def test_only_the_fat_entries_in_use_are_read() -> None:
    from diskread.fs.fat.bpb import BootSector, Fat

    boot = BootSector(
        fat_type=16,
        bytes_per_sector=512,
        cluster_size=512,
        fat_offset=512,
        fat_bytes=64 * MIB,  # what a damaged boot sector claims the table takes
        root_dir_offset=0,
        root_dir_bytes=0,
        data_offset=0,
        cluster_count=100,
        root_cluster=0,
        volume_id=0,
        label="",
    )
    dev = _CountingDevice(bytes(128 * MIB))
    fat = Fat(dev, boot)
    assert dev.reads == [(100 + 2) * 2]  # 16 bits for each cluster and the two reserved
    assert fat.next(101) == 0  # the last cluster's entry is within what was read


def test_fat_with_more_clusters_than_an_entry_can_name_is_refused() -> None:
    from diskread.fs.fat.bpb import parse_boot_sector

    sector = bytearray(512)
    sector[0:3] = b"\xeb\x58\x90"
    struct.pack_into("<HBHB", sector, 0x0B, 512, 1, 32, 2)  # one sector per cluster
    sector[0x15] = 0xF8
    struct.pack_into("<I", sector, 0x20, 0xFFFFFFFF)  # total sectors
    struct.pack_into("<I", sector, 0x24, 1)  # sectors per FAT
    sector[0x1FE:0x200] = b"\x55\xaa"
    with pytest.raises(DiskReadError, match="bad FAT geometry"):
        parse_boot_sector(bytes(sector))


def test_ext4_extent_node_naming_one_child_twice_is_refused() -> None:
    from diskread.fs.ext4.blockmap import EXTENT_MAGIC, extent_runs

    leaf = struct.pack("<HHHHI", EXTENT_MAGIC, 0, 340, 0, 0).ljust(4096, b"\0")
    root = struct.pack("<HHHHI", EXTENT_MAGIC, 2, 4, 1, 0)
    root += struct.pack("<IIHH", 0, 7, 0, 0) + struct.pack("<IIHH", 100, 7, 0, 0)
    reads: list[int] = []

    def read_block(block: int) -> bytes:
        reads.append(block)
        return leaf

    with pytest.raises(DiskReadError, match="reached twice"):
        extent_runs(root.ljust(60, b"\0"), read_block, ino=12)
    assert reads == [7]


def test_xfs_bmap_node_naming_one_child_twice_is_refused() -> None:
    from diskread.fs.xfs.bmap import BMAP_MAGIC, fork_runs
    from diskread.fs.xfs.inode import FMT_BTREE, Fork
    from diskread.fs.xfs.superblock import Superblock

    sb = Superblock(
        block_size=4096,
        blocklog=12,
        dblocks=1000,
        agblocks=1000,
        agcount=1,
        agblklog=10,
        inode_size=512,
        inopblog=3,
        dir_block_size=4096,
        root_ino=128,
        log_start=0,
        log_blocks=0,
        incompat=0,
        ro_compat=0,
        uuid="",
        version=4,
        features2=0,
        label="",
    )
    # The root in the inode: level 1, two records, then keys and pointers (both to block 7).
    maxrecs = (100 - 4) // 16
    root = bytearray(100)
    struct.pack_into(">HH", root, 0, 1, 2)
    struct.pack_into(">QQ", root, 4 + maxrecs * 8, 7, 7)
    leaf = (BMAP_MAGIC + struct.pack(">HH", 0, 0)).ljust(4096, b"\0")
    reads: list[int] = []

    def read_block(linear: int) -> bytes:
        reads.append(linear)
        return leaf

    with pytest.raises(DiskReadError, match="reached twice"):
        fork_runs(Fork(FMT_BTREE, 0, bytes(root)), sb, read_block, ino=131)
    assert reads == [7]


def test_a_chain_of_empty_ebrs_ends() -> None:
    from diskread.partition.mbr import MAX_LOGICAL

    def sector(slot: int, ptype: int, start: int, count: int) -> bytearray:
        s = bytearray(512)
        s[0x1BE + 16 * slot + 4] = ptype
        struct.pack_into("<II", s, 0x1BE + 16 * slot + 8, start, count)
        s[0x1FE:0x200] = b"\x55\xaa"
        return s

    links = 4 * MAX_LOGICAL
    disk = bytearray(sector(0, 0x05, 1, links))  # the extended partition, from LBA 1
    for i in range(links):  # each EBR holds no partition and names the next one
        disk += sector(1, 0x05, i + 1, 1)
    dev = _CountingDevice(bytes(disk))
    with pytest.raises(DiskReadError, match="EBR chain"):
        read_partition_table(dev)
    assert len(dev.reads) <= MAX_LOGICAL + 2  # LBA 0 (looked at twice at most) and the EBRs


def test_a_symlink_loop_is_an_error_not_a_hang() -> None:
    fs = MemFs()
    fs.add_link("/a", "b")
    fs.add_link("/b", "a")
    with pytest.raises(DiskReadError, match="symbolic links"):
        SystemSource.from_fs(fs).read("/a")


def test_dot_dot_after_a_symlink_climbs_from_where_the_link_leads() -> None:
    fs = MemFs()
    fs.add_file("/srv/app/conf", b"x")
    fs.add_file("/srv/other", b"o")
    fs.add_link("/opt/app", "/srv/app")
    src = SystemSource.from_fs(fs)
    assert src.read("/opt/app/../other") == b"o"  # as the kernel: /opt/app is /srv/app
    assert src.realpath("/opt/app/conf") == "/srv/app/conf"
    assert src.read("/opt/app/./conf/../conf") == b"x"
    assert src.read("/opt/app/missing/../conf") is None  # a step into nothing stays nothing
