"""verify_packages / unowned_paths against rpm -Va, dpkg --verify and the
unowned list computed in a chroot of the same tree (build_verify.sh)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from conftest import GOLDEN_DIR
from memfs import MemFs

from diskread import FileDevice
from diskread.fs.ext4 import Ext4
from diskread.source import SystemSource
from ec2_byhand.packages import read_packages
from ec2_byhand.packages.model import Package, PackageDB, PackageFile
from ec2_byhand.packages.verify import (
    RPMFILE_GHOST,
    VERIFY_ALL,
    VERIFY_DIGEST,
    VERIFY_MTIME,
    VERIFY_SIZE,
    unowned_paths,
    verify_packages,
)

CASES = sorted(p for p in GOLDEN_DIR.glob("verify-*") if p.is_dir() and (p / "verify.txt").exists())
# rpm -V letters we reproduce; T (mtime), D (device), P (capabilities) are not checked.
RPM_CODES = {"S": "size", "M": "mode", "5": "content", "L": "link", "U": "user", "G": "group"}
LINE = re.compile(r"^(\S+) +(?:[cdglra] +)?(/.*)$")


def _truth(case: Path) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for line in (
        (case / "verify.txt").read_text(encoding="utf-8", errors="surrogateescape").splitlines()
    ):
        m = LINE.match(line)
        assert m, line
        codes, path = m.groups()
        kinds = (
            {"missing"} if codes == "missing" else {RPM_CODES[c] for c in codes if c in RPM_CODES}
        )
        if kinds:
            out.setdefault(path, set()).update(kinds)
    return out


@pytest.fixture(scope="module", params=CASES or [None], ids=(lambda p: p.name) if CASES else None)
def opened(request):
    case = request.param
    if case is None:
        pytest.skip(
            "no golden data; run: wsl -u root -- bash tools/golden/build_verify.sh tests/golden/out"
        )
    dev = FileDevice(GOLDEN_DIR / f"{case.name}.img")
    src = SystemSource.from_fs(Ext4(dev))
    db = read_packages(src)
    assert db is not None
    yield case, src, db
    dev.close()


def test_verify_matches_package_manager(opened) -> None:
    case, src, db = opened
    ours: dict[str, set[str]] = {}
    for p in verify_packages(src, db):
        ours.setdefault(p.path, set()).update(p.problems)
    truth = _truth(case)
    diffs = [
        f"{path}: expected {sorted(truth.get(path, ()))}, got {sorted(ours.get(path, ()))}"
        for path in sorted(set(truth) | set(ours))
        if truth.get(path) != ours.get(path)
    ]
    assert not diffs, "\n".join(diffs[:30])


def test_scenario_is_found(opened) -> None:
    case, src, db = opened
    s = dict(line.split("=", 1) for line in (case / "scenario.txt").read_text().splitlines())
    found = {}
    for p in verify_packages(src, db):
        found.setdefault(p.path, set()).update(p.problems)
    assert "content" in found[s["config"]]
    assert "content" in found[s["edited"]]
    assert found[s["deleted"]] == {"missing"}
    assert s["touched"] not in found  # mtime only
    if s["kind"] == "rpm":
        assert found[s["chmodded"]] == {"mode"}
        assert found[s["chowned"]] == {"user", "group"}
        assert found[s["relinked"]] == {"link"}


def test_unowned_matches_chroot(opened) -> None:
    case, src, db = opened
    truth = (
        (case / "unowned.txt").read_text(encoding="utf-8", errors="surrogateescape").splitlines()
    )
    ours = sorted(p for p, _ in unowned_paths(src, db))
    missing, extra = sorted(set(truth) - set(ours)), sorted(set(ours) - set(truth))
    assert not missing, f"missing {missing[:10]}"
    assert not extra, f"extra {extra[:10]}"
    for hand_placed in (
        "/opt/myapp/bin/run.sh",
        "/usr/local/bin/tool",
        "/usr/local/bin/tool-link",
        "/etc/myapp.conf",
        "/srv/data",
    ):
        assert hand_placed in ours


def test_files_rpm_does_not_check_are_compared_with_the_baseline() -> None:
    # /etc/passwd is %verify(not md5 size mtime) and /etc/hostname %ghost:
    # rpm -V never looks at their content, so useradd or a hand edit only
    # shows against the baseline.
    def tree(passwd: bytes, hostname: bytes | None) -> SystemSource:
        fs = MemFs()
        fs.add_file("/etc/passwd", passwd)
        fs.add_file("/etc/group", b"root:x:0:\n")
        fs.add_file("/etc/os-release", b"ID=amzn\n")
        if hostname is not None:
            fs.add_file("/etc/hostname", hostname)
        return SystemSource.from_fs(fs)

    not_md5 = VERIFY_ALL & ~(VERIFY_DIGEST | VERIFY_SIZE | VERIFY_MTIME)
    files = (
        PackageFile(
            "/etc/passwd", mode=0o100644, verify=not_md5, is_config=True, user="root", group="root"
        ),
        PackageFile(
            "/etc/group", mode=0o100644, verify=not_md5, is_config=True, user="root", group="root"
        ),
        PackageFile("/etc/hostname", mode=0o100644, flags=RPMFILE_GHOST, user="root", group="root"),
        PackageFile("/etc/os-release", mode=0o100644, verify=not_md5, user="root", group="root"),
    )
    db = PackageDB(
        "rpm",
        "rpm-sqlite",
        "/var/lib/rpm",
        (Package("rpm", "setup", "noarch", None, "2.13", "1", files=files),),
    )
    base = tree(b"root:x:0:0::/root:/bin/bash\n", None)
    now = tree(
        b"root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n", b"web1\n"
    )

    def problems(src, baseline=None) -> dict[str, set[str]]:
        return {p.path: set(p.problems) for p in verify_packages(src, db, baseline)}

    assert problems(now) == {}  # what rpm -V says
    assert problems(now, base) == {
        "/etc/passwd": {"content-since-baseline"},
        "/etc/hostname": {"created-since-baseline"},
    }
    assert problems(base, base) == {}


def test_only_paths_limits_what_is_read() -> None:
    # The baseline side is verified only for the paths the current side
    # flagged; nothing else may be looked at (each read costs an API call).
    fs = MemFs()
    fs.add_file("/etc/a.conf", b"edited\n")
    fs.add_file("/etc/b.conf", b"edited\n")
    src = SystemSource.from_fs(fs)
    files = tuple(
        PackageFile(p, digest="0" * 64, digest_algo="sha256", mode=0o100644, verify=VERIFY_DIGEST)
        for p in ("/etc/a.conf", "/etc/b.conf", "/etc/gone.conf")
    )
    pkg = Package("rpm", "p", "noarch", None, "1", "1", files=files)
    db = PackageDB("rpm", "rpm-sqlite", "/var/lib/rpm", (pkg,))
    assert {p.path for p in verify_packages(src, db)} == {
        "/etc/a.conf",
        "/etc/b.conf",
        "/etc/gone.conf",
    }
    only = verify_packages(src, db, only_paths={"/etc/a.conf"})
    assert {p.path for p in only} == {"/etc/a.conf"}
