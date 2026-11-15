from __future__ import annotations

from pathlib import Path

import pytest
from conftest import GOLDEN_DIR

from ec2_byhand.packages import diff_packages, read_packages
from ec2_byhand.packages.dpkg import parse_stanzas, status_abbrev
from ec2_byhand.packages.vercmp import dpkg_compare, parse_rpm_evr, rpm_evr_compare

CASES = sorted(p for p in GOLDEN_DIR.glob("pkgdb-*") if (p / "before").is_dir())


class LocalSource:
    """A golden snapshot directory seen as the package paths of a system."""

    def __init__(self, root: Path) -> None:
        self.root = root

    PREFIXES = (
        ("/var/lib/rpm/", "rpm/"),
        ("/var/lib/dpkg/", "dpkg/"),
        ("/var/lib/dnf/", "dnf/"),
        ("/var/lib/yum/history/", "yum/"),
        ("/var/log/apt/", "apt/"),
    )

    def listdir(self, path: str) -> list[str] | None:
        for prefix, local in self.PREFIXES:
            if (path + "/").startswith(prefix):
                d = self.root / local
                return sorted(p.name.replace("", ":") for p in d.iterdir()) if d.is_dir() else None
        return None

    def read(self, path: str) -> bytes | None:
        for prefix, local in self.PREFIXES:
            if path.startswith(prefix):
                rel = local + path[len(prefix) :]
                # WSL stores ":" (as in "libc6:amd64.list") on a Windows drive as U+F03A.
                for name in (rel, rel.replace(":", "")):
                    f = self.root / name
                    if f.is_file():
                        return f.read_bytes()
                return None
        return None


def _tsv(path: Path) -> list[list[str]]:
    return [
        line.split("\t")
        for line in path.read_text(encoding="utf-8", errors="surrogateescape").splitlines()
        if line
    ]


def _skip_without(cases: list[Path]) -> None:
    if not cases:
        pytest.skip(
            "no golden data; run: wsl -u root -- bash tools/golden/build_pkgdb.sh tests/golden/out"
        )


@pytest.mark.parametrize(
    "case",
    [c / s for c in CASES for s in ("before", "after")] or [None],
    ids=(lambda p: f"{p.parent.name}-{p.name}") if CASES else None,
)
def test_packages_match_package_manager(case: Path | None) -> None:
    _skip_without(CASES)
    assert case is not None
    db = read_packages(LocalSource(case))
    assert db is not None
    expected = _tsv(case / "expected.tsv")

    if db.manager == "rpm":
        assert db.format == (
            "rpm-sqlite" if (case / "rpm" / "rpmdb.sqlite").exists() else "rpm-bdb"
        )
        got = sorted(
            (
                p.name,
                str(p.epoch or 0),
                p.version,
                p.release,
                p.arch or "(none)",
                str(p.install_time),
            )
            for p in db.packages
        )
        assert got == sorted(tuple(e) for e in expected)

        want_files = sorted(
            (n, a, path, digest, int(mode), int(flags) & 1 == 1, int(size))
            for n, a, path, digest, mode, flags, size in _tsv(case / "files.tsv")
        )
        got_files = sorted(
            (p.name, p.arch or "(none)", f.path, f.digest or "", f.mode, f.is_config, f.size)
            for p in db.packages
            for f in p.files
        )
        assert got_files == want_files
    else:
        got = sorted((p.name, p.arch, p.version, p.status) for p in db.packages)
        assert got == sorted((n, a, v, s) for n, a, v, s in expected)
        # dpkg-query -L also prints diversion notes ("diverted by ..."); keep paths only.
        want_files = sorted(tuple(r) for r in _tsv(case / "files.tsv") if r[2].startswith("/"))
        got_files = sorted((p.name, p.arch, f.path) for p in db.packages for f in p.files)
        assert got_files == want_files


@pytest.mark.parametrize("case", CASES or [None], ids=(lambda p: p.name) if CASES else None)
def test_diff_matches_scenario(case: Path | None) -> None:
    _skip_without(CASES)
    assert case is not None
    before = read_packages(LocalSource(case / "before"))
    after = read_packages(LocalSource(case / "after"))
    assert before is not None
    assert after is not None
    scenario = dict(line.split("=", 1) for line in (case / "scenario.txt").read_text().splitlines())
    changes = diff_packages(before, after)
    kinds = {(c.kind, c.name) for c in changes}

    if scenario["upgraded"]:
        assert ("upgraded", scenario["upgraded"]) in kinds
    if scenario["downgraded"]:
        assert ("downgraded", scenario["downgraded"]) in kinds
    assert ("removed", scenario["removed"]) in kinds
    assert ("added", scenario["added"]) in kinds

    # Every change is a real difference in what the package manager reports,
    # and every such difference is reported.
    def evrs(snapshot: str) -> set[tuple[str, ...]]:
        rows = _tsv(case / snapshot / "expected.tsv")
        return {tuple(r[:5]) if before.manager == "rpm" else tuple(r[:3]) for r in rows}

    changed_names = {r[0] for r in evrs("before") ^ evrs("after")}
    assert {c.name for c in changes} == changed_names
    assert all(k in ("added", "removed", "upgraded", "downgraded") for k, _ in kinds)


def test_version_compare_matches_rpm_and_dpkg() -> None:
    vdir = GOLDEN_DIR / "vercmp"
    if not (vdir / "rpm.tsv").exists():
        pytest.skip("no golden data; run tools/golden/build_vercmp.sh")
    for name, cmp in (
        ("rpm", lambda a, b: rpm_evr_compare(parse_rpm_evr(a), parse_rpm_evr(b))),
        ("dpkg", dpkg_compare),
    ):
        rows = _tsv(vdir / f"{name}.tsv")
        bad = [(a, b, r) for a, b, r in rows if cmp(a, b) != int(r)]
        assert len(rows) > 1000
        assert not bad, f"{name}: {bad[:5]}"


def test_dpkg_status_parsing() -> None:
    st = parse_stanzas(
        "Package: a\nStatus: install ok installed\nConffiles:\n"
        " /etc/a abc\n /etc/b def\n\nPackage: b\n"
    )
    assert st[0]["Conffiles"] == "\n/etc/a abc\n/etc/b def"
    assert status_abbrev("install ok installed") == "ii "
    assert status_abbrev("deinstall ok config-files") == "rc "
    assert status_abbrev("install reinstreq half-installed") == "iHR"


def test_source_follows_symlinks_on_one_filesystem() -> None:
    from diskread import FileDevice
    from diskread.fs.ext4 import Ext4
    from diskread.source import SystemSource

    path = GOLDEN_DIR / "ext4-default.img"
    if not path.exists():
        pytest.skip("no golden images; run tools/golden/build_fs.sh")
    with FileDevice(path) as dev:
        src = SystemSource.from_fs(Ext4(dev))
        assert src.read("/link-short") == b"hello\n"  # relative symlink
        assert src.read("/d0/d1/../../small.txt") == b"hello\n"
        assert src.read("/etc/app/app.conf").startswith(b"listen=")
        assert src.read("/link-dangling") is None
        assert src.read("/link-long") is None  # absolute target that does not exist
        assert src.read("/etc") is None  # a directory is not a file


def test_source_crosses_mounts() -> None:
    from contextlib import ExitStack

    from diskread import FileDevice
    from diskread.source import SystemSource
    from diskread.system import assemble, scan

    a, b = GOLDEN_DIR / "system-a.img", GOLDEN_DIR / "system-b.img"
    if not a.exists():
        pytest.skip("no golden images; run tools/golden/build_system.sh")
    with ExitStack() as stack:
        system = assemble(
            scan(
                {
                    "diskA": stack.enter_context(FileDevice(a)),
                    "diskB": stack.enter_context(FileDevice(b)),
                }
            )
        )
        src = SystemSource.from_system(system)
        assert src.read("/var/lib/rpm/rpmdb.sqlite") == b"rpmdb\n"  # on the /var volume
        assert src.read("/var/SHADOWED") is None  # hidden by the /var mount
        assert src.read("/boot/efi/EFI/amzn/grub.cfg").startswith(b"configfile")  # nested vfat
        assert src.read("/etc/hostname") == b"server01\n"


def test_sqlite_rpmdb_applies_wal(tmp_path: Path) -> None:
    """A snapshot taken mid-transaction holds recent rows only in the WAL."""
    import shutil
    import sqlite3

    from ec2_byhand.packages.rpmdb import read_sqlite

    src = GOLDEN_DIR / "pkgdb-al2023" / "after" / "rpm" / "rpmdb.sqlite"
    if not src.exists():
        pytest.skip("no golden data; run tools/golden/build_pkgdb.sh")
    db = tmp_path / "rpmdb.sqlite"
    shutil.copy(src, db)
    con = sqlite3.connect(db)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
    hnum, _name = next(
        (h, n)
        for h, n in (
            (h, read_sqlite_name(b)) for h, b in con.execute("SELECT hnum, blob FROM Packages")
        )
        if n == "jq"
    )
    con.execute("DELETE FROM Packages WHERE hnum = ?", (hnum,))
    con.commit()
    main, wal = (
        db.read_bytes(),
        (tmp_path / "rpmdb.sqlite-wal").read_bytes(),
    )  # copied while still open
    con.close()

    assert wal, "the change should sit in the WAL"
    assert "jq" in {p.name for p in read_sqlite(main, None)}  # main file alone: stale
    assert "jq" not in {p.name for p in read_sqlite(main, wal)}  # with the WAL: current


def read_sqlite_name(blob: bytes) -> str:
    from ec2_byhand.packages.rpmheader import package_from_header

    return package_from_header(bytes(blob)).name


@pytest.mark.parametrize(
    "case",
    [c for c in CASES if (c / "after" / "history.json").exists()] or [None],
    ids=(lambda p: p.name) if CASES else None,
)
def test_history_matches_package_manager_api(case: Path | None) -> None:
    import json

    from ec2_byhand.packages.history import read_history

    _skip_without(CASES)
    assert case is not None
    expected = json.loads((case / "after" / "history.json").read_text())
    got = [
        {
            "id": t.id,
            "begin": t.begin,
            "end": t.end,
            "cmdline": t.cmdline,
            "packages": sorted(
                (
                    {"name": i.name, "arch": i.arch, "evr": i.evr, "action": i.action}
                    for i in t.items
                ),
                key=lambda p: (p["name"], p["action"]),
            ),
        }
        for t in read_history(LocalSource(case / "after"))
    ]
    assert got == expected


def test_apt_history_records_the_scenario() -> None:
    from ec2_byhand.packages.history import read_history

    case = GOLDEN_DIR / "pkgdb-ubuntu2404"
    if not (case / "after" / "apt").is_dir():
        pytest.skip("no golden data; run tools/golden/build_pkgdb.sh")
    s = dict(line.split("=", 1) for line in (case / "scenario.txt").read_text().splitlines())
    before = {r[0]: r[2] for r in _tsv(case / "before" / "expected.tsv")}
    after = {r[0]: r[2] for r in _tsv(case / "after" / "expected.tsv")}
    items = [(t.cmdline, i) for t in read_history(LocalSource(case / "after")) for i in t.items]
    acts = {(i.action, i.name, i.evr, i.old_evr) for _, i in items}
    assert ("Upgrade", s["upgraded"], after[s["upgraded"]], before[s["upgraded"]]) in acts
    assert ("Downgrade", s["downgraded"], after[s["downgraded"]], before[s["downgraded"]]) in acts
    assert any(i.action == "Remove" and i.name == s["removed"] for _, i in items)
    install = next(cmd for cmd, i in items if i.action == "Install" and i.name == s["added"])
    assert install.startswith("apt-get install")
    assert s["added"] in install


def test_parse_apt_history_stanza() -> None:
    from ec2_byhand.packages.history import parse_apt_history

    (t,) = parse_apt_history(
        "Start-Date: 2026-10-24  12:00:01\nCommandline: apt-get install -y nginx\n"
        "Install: nginx:amd64 (1.24.0-2ubuntu7), libgd3:amd64 (2.3.3-9ubuntu5, automatic)\n"
        "Upgrade: tzdata:all (2024a-2ubuntu1, 2026e-0ubuntu0.24.04.1)\n"
        "End-Date: 2026-10-24  12:00:09\n"
    )
    assert t.cmdline == "apt-get install -y nginx"
    assert t.end - t.begin == 8
    assert [(i.action, i.name, i.arch, i.evr, i.old_evr) for i in t.items] == [
        ("Install", "nginx", "amd64", "1.24.0-2ubuntu7", None),
        ("Install", "libgd3", "amd64", "2.3.3-9ubuntu5", None),
        ("Upgrade", "tzdata", "all", "2026e-0ubuntu0.24.04.1", "2024a-2ubuntu1"),
    ]


def test_dnf_history_applies_wal(tmp_path: Path) -> None:
    """A snapshot taken mid-transaction holds the newest history only in the WAL."""
    import shutil
    import sqlite3

    from ec2_byhand.packages.history import read_history

    src = GOLDEN_DIR / "pkgdb-al2023" / "after" / "dnf" / "history.sqlite"
    if not src.exists():
        pytest.skip("no golden data; run tools/golden/build_pkgdb.sh")
    (tmp_path / "dnf").mkdir()
    db = tmp_path / "dnf" / "history.sqlite"
    shutil.copy(src, db)
    con = sqlite3.connect(db)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute(
        "UPDATE trans SET cmdline = 'install hand-typed-command' "
        "WHERE id = (SELECT max(id) FROM trans)"
    )
    con.commit()
    wal = (tmp_path / "dnf" / "history.sqlite-wal").read_bytes()  # copied while still open
    main = db.read_bytes()
    con.close()

    snap = tmp_path / "snap"
    (snap / "dnf").mkdir(parents=True)
    (snap / "dnf" / "history.sqlite").write_bytes(main)
    assert (
        read_history(LocalSource(snap))[-1].cmdline != "install hand-typed-command"
    )  # main file alone: stale
    (snap / "dnf" / "history.sqlite-wal").write_bytes(wal)
    assert (
        read_history(LocalSource(snap))[-1].cmdline == "install hand-typed-command"
    )  # with the WAL
