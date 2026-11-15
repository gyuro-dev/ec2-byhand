"""Snaps from snapd's state: the snaps section, the files that come with a snap, and
the units snapd writes.

As on Ubuntu 24.04 (2026-11-14): the AMI comes with amazon-ssm-agent, core22 and snapd
(seeded); `snap install hello-world` brought hello-world and its base, core."""

from __future__ import annotations

import json

from memfs import MemFs

from diskread.source import SystemSource
from ec2_byhand.analyze import Snapshot, analyze
from ec2_byhand.snaps import read_snaps

S = "/etc/systemd/system"
SEED = b"""snaps:
  -
    name: core22
    channel: stable
    file: core22_2987.snap
  -
    name: amazon-ssm-agent
    channel: latest/stable
    classic: true
    file: amazon-ssm-agent_13349.snap
"""


def _state(snaps: dict[str, tuple[str, str]], changes: dict | None = None) -> bytes:
    """name -> (type, revision)."""
    return json.dumps(
        {
            "data": {
                "snaps": {
                    name: {
                        "type": kind,
                        "current": rev,
                        "channel": "latest/stable",
                        "sequence": [{"name": name, "revision": rev}],
                    }
                    for name, (kind, rev) in snaps.items()
                }
            },
            "changes": changes or {},
        }
    ).encode()


def _add_snap(fs: MemFs, name: str, rev: str, *, service: str | None = None) -> None:
    unit = name.replace("-", "\\x2d")
    fs.add_file(f"/var/lib/snapd/snaps/{name}_{rev}.snap", b"hsqs")
    fs.add_dir(f"/snap/{name}/{rev}")
    fs.add_link(f"/snap/{name}/current", rev)
    fs.add_dir(f"/var/snap/{name}/{rev}")
    fs.add_dir(f"/var/snap/{name}/common")
    fs.add_link(f"/var/snap/{name}/current", rev)
    mount = f"{S}/snap-{unit}-{rev}.mount"
    fs.add_file(mount, b"[Mount]\nWhat=/var/lib/snapd/snaps/x.snap\n")
    fs.add_link(f"{S}/snapd.mounts.target.wants/snap-{unit}-{rev}.mount", mount)
    if service:
        fs.add_file(f"{S}/snap.{name}.{service}.service", b"[Service]\n")
        fs.add_link(
            f"{S}/multi-user.target.wants/snap.{name}.{service}.service",
            f"{S}/snap.{name}.{service}.service",
        )


AMI = {
    "amazon-ssm-agent": ("app", "13349"),
    "core22": ("base", "2987"),
    "snapd": ("snapd", "28332"),
}
INSTALL = {
    "3": {
        "kind": "install-snap",
        "summary": 'Install "hello-world" snap',
        "spawn-time": "2026-11-14T11:53:32Z",
        "data": {"snap-names": ["hello-world"]},
    }
}


def _sides() -> tuple[MemFs, MemFs]:
    before, after = MemFs(), MemFs()
    before.add_file("/var/lib/snapd/state.json", _state(AMI))
    after.add_file(
        "/var/lib/snapd/state.json",
        _state({**AMI, "core": ("os", "17292"), "hello-world": ("app", "29")}, INSTALL),
    )
    for fs in (before, after):
        fs.add_file("/var/lib/snapd/seed/seed.yaml", SEED)
        _add_snap(fs, "amazon-ssm-agent", "13349", service="amazon-ssm-agent")
        _add_snap(fs, "core22", "2987")
    _add_snap(after, "core", "17292")
    _add_snap(after, "hello-world", "29")
    after.add_file("/var/snap/hello-world/common/config.yaml", b"greeting: hi\n")  # by hand
    after.add_file("/var/lib/snapd/seccomp/bpf/snap.hello-world.sh.bin2", b"\0")
    return before, after


def test_read_snaps() -> None:
    _, after = _sides()
    snaps, error = read_snaps(SystemSource.from_fs(after))
    assert error is None
    assert snaps is not None
    by = {s.name: s for s in snaps}
    assert by["amazon-ssm-agent"].seeded
    assert not by["hello-world"].seeded
    assert by["hello-world"].via == {
        "kind": "install-snap",
        "summary": 'Install "hello-world" snap',
        "time": "2026-11-14T11:53:32Z",
    }


def test_snaps_installed_since_the_ami() -> None:
    before, after = _sides()
    m = analyze(
        Snapshot("now", SystemSource.from_fs(after)), Snapshot("ami", SystemSource.from_fs(before))
    )
    assert [(s["name"], s["status"], s["revision"]) for s in m["snaps"]] == [
        ("core", "added", "17292"),
        ("hello-world", "added", "29"),
    ]
    assert m["summary"]["snaps_unchanged_since_baseline"] == 3
    # What comes with the snaps is not hand work; what was put in their data is.
    assert [h["path"] for h in m["hand_placed"]] == ["/var/snap/hello-world/common/config.yaml"]
    assert m["summary"]["files_in_snaps"] > 0
    services = {s["path"].removeprefix(S + "/"): s for s in m["services"]}
    assert {k: (v["by_package"], v.get("snap")) for k, v in services.items()} == {
        "snapd.mounts.target.wants/snap-core-17292.mount": (True, "core"),
        "snapd.mounts.target.wants/snap-hello\\x2dworld-29.mount": (True, "hello-world"),
    }


def test_a_refreshed_snap_and_a_damaged_state() -> None:
    before, after = _sides()
    after.add_file("/var/lib/snapd/state.json", _state({**AMI, "snapd": ("snapd", "29000")}))
    m = analyze(
        Snapshot("now", SystemSource.from_fs(after)), Snapshot("ami", SystemSource.from_fs(before))
    )
    snapd = next(s for s in m["snaps"] if s["name"] == "snapd")
    assert snapd["status"] == "refreshed"
    assert snapd["from"] == {"revision": "28332", "channel": "latest/stable"}

    after.add_file("/var/lib/snapd/state.json", b'{"data": ')
    m = analyze(Snapshot("now", SystemSource.from_fs(after)))
    assert "snap-state-unreadable" in [w["code"] for w in m["warnings"]]
    assert m["snaps"] is None
    assert "/var/lib/snapd/snaps/hello-world_29.snap" in {h["path"] for h in m["hand_placed"]}


def test_without_snapd_there_is_no_snaps_section() -> None:
    fs = MemFs()
    fs.add_file("/etc/app.conf", b"x")
    m = analyze(Snapshot("now", SystemSource.from_fs(fs)))
    assert m["snaps"] is None
    assert m["summary"]["snaps"] is None
