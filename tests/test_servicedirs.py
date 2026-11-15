"""Directories systemd makes by itself: read from tmpfiles.d and units, and left out of
hand_placed (only the directories, as systemd makes them)."""

from __future__ import annotations

from memfs import MemFs

from diskread.source import SystemSource
from ec2_byhand.analyze import Snapshot, analyze
from ec2_byhand.servicedirs import service_dirs

VAR_CONF = b"""# systemd's own, as on Ubuntu 24.04
q /var 0755 - - -
L /var/run - - - - ../run
d /var/log 0755 - - -
f /var/log/wtmp 0664 root utmp -
d /var/log/private 0700 root root -
d /var/cache/private 0700 root root -
d /var/lib/private 0700 root root -
d /run/user/%U 0700 - - -
"""


def _system() -> MemFs:
    fs = MemFs()
    fs.add_file("/usr/lib/tmpfiles.d/var.conf", VAR_CONF)
    fs.add_file(
        "/usr/lib/systemd/system/chrony.service",
        b"[Unit]\nDescription=chrony\n[Service]\nLogsDirectory=chrony\n"
        b"StateDirectory=chrony\nStateDirectoryMode=0750\n[Install]\nWantedBy=multi-user.target\n",
    )
    fs.add_file(
        "/usr/lib/systemd/system/dyn.service",
        b"[Service]\nDynamicUser=yes\nStateDirectory=dyn dyn/sub\nCacheDirectory=\n",
    )
    return fs


def test_what_systemd_is_told_to_make() -> None:
    dirs = service_dirs(SystemSource.from_fs(_system()))
    assert dirs["/var/log/private"] == 0o700  # tmpfiles.d
    assert dirs["/var/log/chrony"] == 0o755  # LogsDirectory=, the default mode
    assert dirs["/var/lib/chrony"] == 0o750  # StateDirectoryMode=
    assert dirs["/var/lib/private/dyn"] == 0o755  # DynamicUser=
    assert "/var/lib/dyn/sub" in dirs
    assert "/var/lib/dyn" in dirs
    assert not [p for p in dirs if "%" in p or p.startswith("/var/cache/dyn")]
    assert "/var/log/wtmp" not in dirs  # a file, not a directory


def test_an_earlier_tmpfiles_directory_hides_a_later_file_of_the_same_name() -> None:
    fs = _system()
    fs.add_file("/etc/tmpfiles.d/var.conf", b"d /var/log/mine 0700 - - -\n")
    dirs = service_dirs(SystemSource.from_fs(fs))
    assert "/var/log/mine" in dirs
    assert "/var/log/private" not in dirs


def test_only_the_directories_as_systemd_makes_them_leave_hand_placed() -> None:
    fs = _system()
    fs.add_dir("/var/log/private", mode=0o700)
    fs.add_dir("/var/log/chrony", mode=0o755)
    fs.add_file("/var/log/chrony/measurements.log", b"x")  # logs: noise anyway
    fs.add_file(
        "/etc/systemd/system/app.service",
        b"[Service]\nStateDirectory=app\nStateDirectoryMode=0750\n",
    )
    fs.add_dir("/var/lib/app", mode=0o755)  # chmod by hand: StateDirectoryMode= is 0750
    fs.add_dir("/var/lib/private/dyn", mode=0o755)
    fs.add_link("/var/lib/dyn", "private/dyn")
    fs.add_dir("/var/log/myapp", mode=0o755)  # made by hand: nothing says so
    m = analyze(Snapshot("now", SystemSource.from_fs(fs)))
    hand = {h["path"] for h in m["hand_placed"]}
    assert "/var/log/myapp" in hand
    assert "/var/lib/app" in hand
    assert not hand & {"/var/log/private", "/var/log/chrony", "/var/lib/dyn"}
    assert m["noise"]["by_rule"]["service-directories"] >= 3
    assert "service-directories" in m["noise"]["rules"]
