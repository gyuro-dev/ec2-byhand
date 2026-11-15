"""Whether a package or a person made each service link (services[].by_package).

As seen on Ubuntu 24.04 and AL2023 (2026-11-14): `apt install nginx apache2` enabled
both, recorded under deb-systemd-helper-enabled, with the links made inside the apt
run; `dnf install docker` enabled docker.socket (by preset) inside the dnf run; then
`systemctl enable myapp`, `systemctl disable apache2`, `systemctl mask apt-daily.timer`
by hand, after the runs."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from memfs import MemFs

from diskread.source import SystemSource
from ec2_byhand.analyze import Snapshot, analyze

S = "/etc/systemd/system"
U = "/usr/lib/systemd/system"
DSH = "/var/lib/systemd/deb-systemd-helper-enabled"
UNITS = {
    "nginx": f"{U}/nginx.service",
    "apache2": f"{U}/apache2.service",
    "cron": f"{U}/cron.service",
    "legacy": f"{U}/legacy.service",
}


def _ns(clock: str) -> int:
    t = datetime.strptime(f"2026-11-14 {clock}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    return int(t.timestamp()) * 10**9


def _system(packages: list[str], history: bytes = b"") -> MemFs:
    """A dpkg system with these packages, each shipping one unit."""
    fs = MemFs()
    status = ""
    for name in packages:
        unit = UNITS[name]
        status += (
            f"Package: {name}\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n\n"
        )
        fs.add_file(unit, b"[Install]\nWantedBy=multi-user.target\n")
        fs.add_file(f"/var/lib/dpkg/info/{name}:amd64.list", f"{unit}\n".encode())
        md5 = hashlib.md5(b"[Install]\nWantedBy=multi-user.target\n").hexdigest()
        fs.add_file(f"/var/lib/dpkg/info/{name}:amd64.md5sums", f"{md5}  {unit[1:]}\n".encode())
    fs.add_file("/var/lib/dpkg/status", status.encode())
    if history:
        fs.add_file("/var/log/apt/history.log", history)
    return fs


def _wants(fs: MemFs, unit: str, target: str, clock: str, *, recorded: bool = False) -> None:
    fs.add_link(f"{S}/multi-user.target.wants/{unit}", target, ctime_ns=_ns(clock))
    if recorded:
        fs.add_file(f"{DSH}/multi-user.target.wants/{unit}", b"")
        fs.add_file(f"{DSH}/{unit}.dsh-also", f"{S}/multi-user.target.wants/{unit}\n".encode())


HISTORY = (
    b"Start-Date: 2026-11-14  07:36:50\nCommandline: apt-get install -y -q nginx apache2\n"
    b"Install: nginx:amd64 (1), apache2:amd64 (1)\nEnd-Date: 2026-11-14  07:37:03\n"
)


def _services(m: dict) -> dict[str, dict]:
    return {s["path"].removeprefix(S + "/"): s for s in m["services"]}


def _sides() -> tuple[MemFs, MemFs]:
    """The AMI (cron and legacy enabled), then the installs and the hand work."""
    before = _system(["cron", "legacy", "apache2"])
    after = _system(["cron", "nginx", "apache2"], HISTORY)  # legacy removed by its package
    for fs in (before, after):
        _wants(fs, "cron.service", UNITS["cron"], "04:00:00", recorded=True)
    _wants(before, "legacy.service", UNITS["legacy"], "04:00:00", recorded=True)
    _wants(before, "apache2.service", UNITS["apache2"], "04:00:00", recorded=True)
    after.add_file(f"{DSH}/multi-user.target.wants/apache2.service", b"")  # disabled: record stays
    _wants(after, "nginx.service", UNITS["nginx"], "07:36:53", recorded=True)
    after.add_file(f"{S}/myapp.service", b"[Install]\nWantedBy=multi-user.target\n")
    _wants(after, "myapp.service", f"{S}/myapp.service", "07:37:08")
    after.add_link(f"{S}/apt-daily.timer", "/dev/null", ctime_ns=_ns("07:37:07"))
    return before, after


def test_what_packages_did_and_what_was_done_by_hand() -> None:
    before, after = _sides()
    m = analyze(
        Snapshot("now", SystemSource.from_fs(after)), Snapshot("ami", SystemSource.from_fs(before))
    )
    s = _services(m)
    assert {k: (v["status"], v["by_package"]) for k, v in s.items()} == {
        "multi-user.target.wants/nginx.service": ("added", True),  # apt install
        "multi-user.target.wants/myapp.service": ("added", False),  # systemctl enable
        "apt-daily.timer": ("added", False),  # systemctl mask
        "multi-user.target.wants/apache2.service": ("removed", False),  # systemctl disable
        "multi-user.target.wants/legacy.service": ("removed", True),  # apt remove legacy
    }
    assert "apt-get install" in s["multi-user.target.wants/nginx.service"]["transaction"]["cmdline"]
    assert m["summary"]["services_by_package"] == 2


def test_enabled_by_its_package_then_disabled_is_shown() -> None:
    # Seen on Ubuntu: `apt install apache2` then `systemctl disable apache2`. No link on
    # either side, but a new server would get it enabled by the same install.
    before = _system(["cron"])
    after = _system(["cron", "apache2"], HISTORY)
    after.add_file(f"{DSH}/multi-user.target.wants/apache2.service", b"")
    after.add_file(f"{DSH}/multi-user.target.wants/gone.service", b"")  # package removed
    before.add_file(f"{DSH}/multi-user.target.wants/old.service", b"")  # already so in the AMI
    after.add_file(f"{DSH}/multi-user.target.wants/old.service", b"")
    after.add_file(f"{U}/old.service", b"")
    m = analyze(
        Snapshot("now", SystemSource.from_fs(after)), Snapshot("ami", SystemSource.from_fs(before))
    )
    assert [(s["unit"], s["status"], s["by_package"]) for s in m["services"]] == [
        ("apache2.service", "disabled", False)
    ]


def test_a_link_made_during_a_package_run_without_a_record() -> None:
    # rpm keeps no record: docker.socket enabled by preset in `dnf install` counts by its time.
    fs = _system(["nginx"], HISTORY)
    _wants(fs, "nginx.service", UNITS["nginx"], "07:36:53")
    _wants(fs, "late.service", UNITS["nginx"], "07:38:19")  # `systemctl enable` afterwards
    _wants(fs, "edge.service", UNITS["nginx"], "07:37:03")  # the run's last second
    s = _services(analyze(Snapshot("now", SystemSource.from_fs(fs))))
    assert s["multi-user.target.wants/nginx.service"]["by_package"] is True
    assert s["multi-user.target.wants/late.service"]["by_package"] is False
    edge = s["multi-user.target.wants/edge.service"]
    assert edge["by_package"] is False  # hand work right after the run cannot be ruled out
    assert (
        edge["near_transaction"]["id"]
        == s["multi-user.target.wants/nginx.service"]["transaction"]["id"]
    )


def test_an_unmask_or_a_hand_made_unit_removed_is_hand_work() -> None:
    before, after = _system(["cron"]), _system(["cron"])
    before.add_link(f"{S}/apt-daily.timer", "/dev/null")
    before.add_file(f"{S}/myapp.service", b"[Install]\nWantedBy=multi-user.target\n")
    _wants(before, "myapp.service", f"{S}/myapp.service", "04:00:00")
    m = analyze(
        Snapshot("now", SystemSource.from_fs(after)), Snapshot("ami", SystemSource.from_fs(before))
    )
    s = _services(m)
    assert s["apt-daily.timer"]["by_package"] is False
    assert s["multi-user.target.wants/myapp.service"]["by_package"] is False
