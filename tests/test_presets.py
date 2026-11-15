"""`systemctl preset` worked out from the files, and the rpm services it enabled on
install that were disabled by hand afterwards (services[].status "disabled").

As on AL2023 (2026-11-14): 90-default.preset enables docker.socket, 99-default-disable
disables the rest; `dnf install docker nginx` enabled docker.socket only, and
`systemctl disable docker.socket` took it away."""

from __future__ import annotations

import pytest
from memfs import MemFs

from diskread.source import SystemSource
from ec2_byhand import analyze as analyze_module
from ec2_byhand.analyze import Snapshot, analyze
from ec2_byhand.packages.model import Package, PackageDB, PackageFile
from ec2_byhand.presets import Presets, preset_links

U = "/usr/lib/systemd/system"
S = "/etc/systemd/system"


def _system() -> MemFs:
    fs = MemFs()
    fs.add_file(
        "/usr/lib/systemd/system-preset/90-default.preset",
        b"# comment\nenable sshd.service\nenable docker.socket\nenable getty@.service tty1\n",
    )
    fs.add_file("/usr/lib/systemd/system-preset/99-default-disable.preset", b"disable *\n")
    fs.add_file(
        f"{U}/docker.socket",
        b"[Socket]\nListenStream=/run/docker.sock\n[Install]\nWantedBy=sockets.target\n",
    )
    fs.add_file(f"{U}/docker.service", b"[Service]\n[Install]\nWantedBy=multi-user.target\n")
    fs.add_file(f"{U}/nginx.service", b"[Service]\n[Install]\nWantedBy=multi-user.target\n")
    fs.add_file(f"{U}/getty@.service", b"[Service]\n[Install]\nWantedBy=getty.target\n")
    fs.add_file(
        f"{U}/sshd.service",
        b"[Service]\n[Install]\nWantedBy=multi-user.target\nAlias=ssh.service\n",
    )
    return fs


def test_what_preset_enables() -> None:
    src = SystemSource.from_fs(_system())
    presets = Presets(src)
    assert preset_links(src, presets, f"{U}/docker.socket") == [
        f"{S}/sockets.target.wants/docker.socket"
    ]
    assert preset_links(src, presets, f"{U}/docker.service") == []  # "disable *"
    assert preset_links(src, presets, f"{U}/nginx.service") == []
    assert preset_links(src, presets, f"{U}/getty@.service") == [
        f"{S}/getty.target.wants/getty@tty1.service"
    ]
    assert preset_links(src, presets, f"{U}/sshd.service") == [
        f"{S}/multi-user.target.wants/sshd.service",
        f"{S}/ssh.service",
    ]


def test_an_earlier_preset_directory_hides_a_file_of_the_same_name() -> None:
    fs = _system()
    fs.add_file("/etc/systemd/system-preset/90-default.preset", b"enable nginx.service\n")
    src = SystemSource.from_fs(fs)
    presets = Presets(src)
    assert preset_links(src, presets, f"{U}/nginx.service") == [
        f"{S}/multi-user.target.wants/nginx.service"
    ]
    assert preset_links(src, presets, f"{U}/docker.socket") == []


def _package(name: str, *units: str) -> Package:
    files = tuple(PackageFile(f"{U}/{u}") for u in units)
    return Package("rpm", name, "x86_64", None, "1", "1", files=files)


def test_a_service_its_package_enabled_and_someone_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before, after = _system(), _system()
    ami, now = SystemSource.from_fs(before), SystemSource.from_fs(after)
    sshd = _package("openssh-server", "sshd.service")  # the AMI's: not held to presets
    docker = _package("docker", "docker.socket", "docker.service")
    nginx = _package("nginx", "nginx.service")
    dbs = {
        id(ami): PackageDB("rpm", "rpm-sqlite", "/var/lib/rpm", (sshd,)),
        id(now): PackageDB("rpm", "rpm-sqlite", "/var/lib/rpm", (sshd, docker, nginx)),
    }
    monkeypatch.setattr(analyze_module, "read_packages", lambda src: dbs[id(src)])
    m = analyze(Snapshot("now", now), Snapshot("ami", ami))
    assert [(s["unit"], s["status"], s.get("package")) for s in m["services"]] == [
        ("docker.socket", "disabled", "docker")
    ]

    after.add_link(f"{S}/sockets.target.wants/docker.socket", f"{U}/docker.socket")  # left enabled
    still = SystemSource.from_fs(after)  # a source caches what it listed
    dbs[id(still)] = dbs[id(now)]
    m = analyze(Snapshot("now", still), Snapshot("ami", ami))
    assert [s["status"] for s in m["services"]] == ["added"]
