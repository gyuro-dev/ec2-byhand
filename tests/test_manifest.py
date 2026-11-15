"""End-to-end: the manifest of a hand-modified server against its baseline
(build_verify.sh) must report exactly the hand work the scenario did."""

from __future__ import annotations

import json
from contextlib import ExitStack
from pathlib import Path

import pytest
from conftest import GOLDEN_DIR

from diskread import FileDevice
from diskread.fs.ext4 import Ext4
from diskread.source import SystemSource
from ec2_byhand import manifest
from ec2_byhand.analyze import Snapshot, analyze, path_fields
from ec2_byhand.noise import DpkgPathExcludes, NoiseFilter, glob_to_regex

CASES = sorted(p.name.removeprefix("verify-") for p in GOLDEN_DIR.glob("verify-*") if p.is_dir())
CASES = [c for c in CASES if (GOLDEN_DIR / f"verify-{c}-before.img").exists()]

# Not hand work, but in two of the golden trees all the same: verify_chroot.sh ran in a
# chroot with nothing mounted on /dev, so its "2> /dev/null" made a regular file there.
# With a baseline that is reported, as a file hidden under a mountpoint should be.
GOLDEN_BUILD_LEFTOVERS = {"/dev/null"}

HAND_PLACED = {
    "/etc/myapp.conf",
    "/etc/systemd/system/myapp.service",
    "/opt/myapp",
    "/opt/myapp/bin",
    "/opt/myapp/bin/run.sh",
    "/opt/myapp/bin/server",
    "/opt/myapp/conf",
    "/opt/myapp/conf/app.yml",
    "/srv/data",
    "/usr/local/bin/tool",
    "/usr/local/bin/tool-link",
    "/var/www",
    "/var/www/html",
    "/var/www/html/index.html",
    "/root/.ssh",
    "/root/.ssh/id_rsa",
}


def _snapshot(stack: ExitStack, image: Path, label: str) -> Snapshot:
    return Snapshot(label, SystemSource.from_fs(Ext4(stack.enter_context(FileDevice(image)))))


@pytest.fixture(scope="module", params=CASES or [None])
def with_baseline(request):
    case = request.param
    if case is None:
        pytest.skip(
            "no golden data; run: wsl -u root -- bash tools/golden/build_verify.sh tests/golden/out"
        )
    with ExitStack() as stack:
        cur = _snapshot(stack, GOLDEN_DIR / f"verify-{case}.img", case)
        base = _snapshot(stack, GOLDEN_DIR / f"verify-{case}-before.img", f"{case}-before")
        m = analyze(cur, base)
    scenario = dict(
        line.split("=", 1)
        for line in (GOLDEN_DIR / f"verify-{case}" / "scenario.txt").read_text().splitlines()
    )
    return case, m, scenario


def test_hand_placed_is_exactly_the_hand_work(with_baseline) -> None:
    _, m, _ = with_baseline
    # Files a package run wrote in its first or last second cannot be told
    # from hand work done right before or after it, so they stay here, but
    # only with a near_transaction hint.
    planted = {
        h["path"]: h["status"]
        for h in m["hand_placed"]
        if "near_transaction" not in h and h["path"] not in GOLDEN_BUILD_LEFTOVERS
    }
    assert planted == {**dict.fromkeys(HAND_PLACED, "added"), "/opt/legacy/change.txt": "modified"}
    assert not any("near_transaction" in h for h in m["hand_placed"] if h["path"] in HAND_PLACED)
    change = next(h for h in m["hand_placed"] if h["path"] == "/opt/legacy/change.txt")
    assert change["changed"] == ["sha256"]  # "version 1" -> "version 2": same size
    link = next(h for h in m["hand_placed"] if h["path"] == "/usr/local/bin/tool-link")
    assert link["type"] == "lnk"
    assert link["target"] == "tool"
    server = next(h for h in m["hand_placed"] if h["path"] == "/opt/myapp/bin/server")
    assert len(server["sha256"]) == 64
    assert server["size"] == 50000


def test_modified_package_files_since_baseline(with_baseline) -> None:
    _, m, s = with_baseline
    since = {x["path"]: x["problems"] for x in m["modified_package_files"] if x["since_baseline"]}
    expected = {
        s["config"]: ["content"],
        s["edited"]: ["content"],
        s["deleted"]: ["missing"],
        # rpm records these; for dpkg they come from comparing with the baseline.
        s["chmodded"]: ["mode"],
        s["chowned"]: ["group", "user"],
        s["relinked"]: ["link"],
    }
    if s["kind"] == "rpm":
        expected[s["config"]] = expected[s["edited"]] = ["content", "size"]
    assert since == expected
    config = next(x for x in m["modified_package_files"] if x["path"] == s["config"])
    assert config["config"] is True


def test_deleted_packages_services(with_baseline) -> None:
    _, m, _ = with_baseline
    assert m["deleted"] == [{"path": "/opt/legacy/remove.txt", "type": "reg"}]
    changes = {(c["kind"], c["name"]) for c in m["packages"]["changes"]}
    assert ("added", "tree") in changes
    tree = next(c for c in m["packages"]["changes"] if c["name"] == "tree")
    # which command did it
    assert "install" in tree["via"]["cmdline"]
    assert "tree" in tree["via"]["cmdline"]
    recent = [t for t in m["packages"]["history"] if t["since_baseline"]]
    assert any("tree" in (t["cmdline"] or "") for t in recent)
    # Installing python3-pip can also upgrade dependencies (Ubuntu's updates
    # pocket); every change must be traced to the command that made it.
    assert all(kind in ("added", "upgraded") for kind, _ in changes)
    assert all("via" in c for c in m["packages"]["changes"])
    svc = {s["unit"]: s["status"] for s in m["services"]}
    assert svc["myapp.service"] == "added"
    assert "legacy.service" not in svc  # unchanged since the baseline: counted, not listed
    assert m["summary"]["services_unchanged_since_baseline"] >= 1
    assert not [w for w in m["warnings"] if w["code"] not in ("unresolved-mount",)]


def test_noise_and_summary(with_baseline) -> None:
    case, m, _ = with_baseline
    by_rule = m["noise"]["by_rule"]
    assert by_rule.get("package-manager", 0) > 0
    if case.startswith("ubuntu"):
        assert by_rule["dpkg-path-exclude"] > 1000  # docs the minimal image never installed
    s = m["summary"]
    near = sum(1 for h in m["hand_placed"] if "near_transaction" in h)
    leftovers = sum(1 for h in m["hand_placed"] if h["path"] in GOLDEN_BUILD_LEFTOVERS)
    assert s["hand_placed"] == len(HAND_PLACED) + 1 + near + leftovers
    assert s["deleted"] == 1
    assert s["packages_added"] >= 1
    # The manifest is valid JSON that reads back.
    assert json.loads(manifest.dumps(m))["schema"] == "ec2-byhand/manifest/v1"


def test_without_baseline_reports_everything_unowned() -> None:
    if not CASES:
        pytest.skip("no golden data; run tools/golden/build_verify.sh")
    with ExitStack() as stack:
        m = analyze(_snapshot(stack, GOLDEN_DIR / f"verify-{CASES[0]}.img", CASES[0]))
    got = {h["path"] for h in m["hand_placed"]}
    assert got >= HAND_PLACED
    assert "/opt/legacy/keep.txt" in got  # cannot tell it predates the server without a baseline
    assert {h["status"] for h in m["hand_placed"]} == {"present"}
    assert any(w["code"] == "no-baseline" for w in m["warnings"])
    assert m["packages"]["changes"] is None
    assert all(x["since_baseline"] is None for x in m["modified_package_files"])


def test_glob_rules() -> None:
    r = glob_to_regex
    assert r("/var/log/**").match("/var/log")
    assert r("/var/log/**").match("/var/log/a/b")
    assert not r("/var/log/**").match("/var/logs")
    assert r("/home/*/.bash_history").match("/home/ec2-user/.bash_history")
    assert not r("/home/*/.bash_history").match("/home/a/b/.bash_history")
    assert r("**/__pycache__/**").match("/usr/lib/python3/x/__pycache__/y.pyc")
    f = NoiseFilter(excludes=("/opt/scratch/**",), includes=("/var/log/myapp/**",))
    assert f.match("/var/log/messages") == "logs"
    assert f.match("/var/log/myapp/app.log") is None  # include wins
    assert f.match("/opt/scratch/x") == "user-exclude"
    assert f.match("/opt/myapp/run.sh") is None


def test_dpkg_path_exclude_last_match_wins() -> None:
    d = DpkgPathExcludes([(False, "/usr/share/doc/*"), (True, "/usr/share/doc/*/copyright")])
    assert d.excluded("/usr/share/doc/bash/README.gz")
    assert not d.excluded("/usr/share/doc/bash/copyright")
    assert not d.excluded("/usr/bin/bash")


def test_non_utf8_paths_round_trip() -> None:
    f = path_fields("/bad-\udcff")
    assert f == {"path": "/bad-\\xff", "path_hex": b"/bad-\xff".hex()}
    assert path_fields("/日本語") == {"path": "/日本語"}


def test_iso_time_before_1970() -> None:
    from ec2_byhand.analyze import iso_time

    assert iso_time(0) == "1970-01-01T00:00:00+00:00"
    assert iso_time(-(2**31) * 10**9) == "1901-12-13T20:45:52+00:00"
    assert iso_time(4102444800_123456789) == "2100-01-01T00:00:00.123456+00:00"


def test_language_packages_and_alternatives(with_baseline) -> None:
    _, m, s = with_baseline
    site = s["site"]
    pkgs = {p["name"].lower(): p for p in m["language_packages"]}
    assert {"requests", "urllib3", "idna", "certifi", "charset-normalizer"} <= set(pkgs)
    req = pkgs["requests"]
    assert (req["ecosystem"], req["status"], req["installer"]) == ("pypi", "added", "pip")
    assert req["modified"] == [f"{site}/requests/__version__.py"]  # hand patch inside a pip package
    assert req["missing"] == [f"{site}/requests/help.py"]
    assert not any(
        h["path"].startswith(site) for h in m["hand_placed"]
    )  # grouped, not listed file by file
    alts = {a["name"]: a for a in m["alternatives"]}
    assert alts["myeditor"] == {
        "status": "added",
        "name": "myeditor",
        "mode": "manual",
        "link": "/usr/local/bin/myeditor",
        "current": "/usr/bin/cat",
    }
    assert not any(
        h["path"] in ("/usr/local/bin/myeditor", "/etc/alternatives/myeditor")
        for h in m["hand_placed"]
    )


def test_install_script_output_is_attributed(with_baseline) -> None:
    case, m, _ = with_baseline
    attributed = {
        f["path"]: g["transaction"]["cmdline"] for g in m["package_scripts"] for f in g["files"]
    }
    hinted = {
        h["path"]: h["near_transaction"]["cmdline"]
        for h in m["hand_placed"]
        if "near_transaction" in h
    }
    if case.startswith("ubuntu"):
        # readline-common's postinst does `cp -p`: mtime is from 2024, only ctime tells.
        assert "python3-pip" in attributed["/etc/inputrc"]
        assert "/etc/timezone" in attributed
    if case.startswith("el8"):
        # Written in the run's first or last second: kept, but pointed at the run.
        module = "/etc/dnf/modules.d/python36.module"
        assert "python3-pip" in (attributed.get(module) or hinted[module])
    assert all("install" in cmd for cmd in hinted.values())
