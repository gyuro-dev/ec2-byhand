"""What cloud-init wrote at boot, from its log: the reader, and the cloud_init section.

The log lines follow those of AL2023 (cloud-init 22.2) and Ubuntu 24.04 (26.2) on
EC2, 2026-11-14, cut down to what is read."""

from __future__ import annotations

import gzip
import hashlib
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from memfs import MemFs

from diskread.source import SystemSource
from ec2_byhand.analyze import Snapshot, analyze
from ec2_byhand.archive import write_outputs
from ec2_byhand.cloudinit import read_cloud_init

BOOT = "2026-11-14 06:58"
PASSWD = b"root:x:0:0:root:/root:/bin/bash\nec2-user:x:1000:1000::/home/ec2-user:/bin/bash\n"


def _ns(clock: str) -> int:
    """ns since the epoch of BOOT:<clock> ("29.915" -> 06:58:29.915 UTC)."""
    seconds, _, ms = clock.partition(".")
    t = datetime.strptime(f"{BOOT}:{seconds}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    return int(t.timestamp()) * 10**9 + int(ms.ljust(9, "0"))


def _line(clock: str, message: str, where: str = "util.py[DEBUG]") -> str:
    seconds, _, ms = clock.partition(".")
    return f"{BOOT}:{seconds},{ms.ljust(3, '0')} - {where}: {message}\n"


LOG = "".join(
    [
        _line("28.978", "Cloud-init v. 22.2.2 running 'init' at Sat, 14 Nov 2026 06:58:28 +0000."),
        _line(
            "29.350",
            "Running command ['hostnamectl', 'set-hostname', 'ip-10-0-0-1'] with allowed "
            "return codes [0] (shell=False, capture=True)",
            "subp.py[DEBUG]",
        ),
        _line("29.468", "Non-persistently setting the system hostname to ip-10-0-0-1"),
        _line(
            "29.620",
            "Running module write-files (<module 'cloudinit.config.cc_write_files'>) with "
            "frequency once-per-instance",
            "modules.py[DEBUG]",
        ),
        _line("29.915", "Writing to /etc/myapp/app.conf - wb: [644] 10 bytes"),
        _line(
            "29.918", "Running module users-groups (<module ...>) with frequency once-per-instance"
        ),
        _line("30.016", "Adding user ec2-user", "__init__.py[DEBUG]"),
        _line(
            "30.016",
            "Running hidden command to protect sensitive input/output logstring: ['useradd', "
            "'ec2-user', '--comment', 'EC2 Default User', '-m']",
            "subp.py[DEBUG]",
        ),
        _line(
            "30.160", "Running command ['passwd', '-l', 'ec2-user'] with allowed return codes [0]"
        ),
        _line("30.195", "Reading from /etc/sudoers (quiet=False)"),
        _line("30.198", "Writing to /etc/sudoers.d/90-cloud-init-users - wb: [440] 128 bytes"),
        _line("30.200", "Running module ssh (<module ...>) with frequency once-per-instance"),
        _line("30.243", "Writing to /home/ec2-user/.ssh/authorized_keys - wb: [600] 95 bytes"),
        _line("30.246", "Writing to /root/.ssh/authorized_keys - wb: [600] 261 bytes"),
        "Traceback lines and other text that is not a log line are skipped\n",
        _line("30.853", "Cloud-init v. 22.2.2 running 'modules:config' at Sat, 14 Nov 2026."),
    ]
)


def _server(log: str | None = LOG) -> MemFs:
    """A server after its first boot, then some hand work at 06:58:34."""
    fs = MemFs()
    fs.add_file("/etc/passwd", PASSWD, mtime_ns=_ns("30.150"))
    fs.add_dir("/var/lib/cloud/instance")
    if log is not None:
        fs.add_file("/var/log/cloud-init.log", log.encode())
    fs.add_file("/etc/hostname", b"ip-10-0-0-1\n", mtime_ns=_ns("29.466"))
    fs.add_file(
        "/etc/myapp/app.conf", b"port=8080\n", mtime_ns=_ns("29.915"), ctime_ns=_ns("29.918")
    )
    fs.add_dir("/etc/myapp", ctime_ns=_ns("29.915"))
    fs.add_file("/etc/sudoers.d/90-cloud-init-users", b"x", mtime_ns=_ns("30.198"))
    fs.add_dir("/home/ec2-user", mode=0o700, ctime_ns=_ns("30.150"))
    for name in (".bashrc", ".bash_profile"):  # useradd -m keeps the skeleton's mtime
        fs.add_file(f"/home/ec2-user/{name}", b"# skel", mtime_ns=0, ctime_ns=_ns("30.150"))
    fs.add_dir("/home/ec2-user/.ssh", mode=0o700, ctime_ns=_ns("30.243"))
    fs.add_file("/home/ec2-user/.ssh/authorized_keys", b"ssh-ed25519 A\n", mtime_ns=_ns("30.243"))
    fs.add_file("/var/spool/mail/ec2-user", b"", mtime_ns=_ns("30.150"))
    fs.add_dir("/root/.ssh", mode=0o700, ctime_ns=_ns("30.246"))
    fs.add_file("/root/.ssh/authorized_keys", b"no-port-forwarding ...\n", mtime_ns=_ns("30.246"))
    # Hand work, from a runcmd script and later.
    fs.add_file("/etc/myapp/hand.conf", b"hand=1\n", mtime_ns=_ns("34.563"))
    fs.add_dir("/etc/myapp", ctime_ns=_ns("34.563"))  # a file added in it
    fs.add_file("/home/ec2-user/notes.txt", b"note\n", mtime_ns=_ns("34.483"))
    fs.add_dir("/home/ec2-user", mode=0o700, ctime_ns=_ns("34.483"))  # notes.txt added in it
    return fs


def _as_amazon_linux_2(log: str, hours: int = 0) -> str:
    """The same log as cloud-init 19.3 on Amazon Linux 2 writes it (seen on EC2,
    2026-11-15): "Nov 14 06:58:29 cloud-init[1725]: util.py[DEBUG]: <message>", the
    server's local time (`hours` ahead of UTC) to the second, and no year."""
    out = []
    for line in log.splitlines():
        stamp, sep, rest = line.partition(" - ")
        if not sep:
            out.append(line)
            continue
        t = datetime.strptime(stamp[:19], "%Y-%m-%d %H:%M:%S") + timedelta(hours=hours)
        month = [
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
        ][t.month - 1]
        out.append(f"{month} {t.day:2d} {t:%H:%M:%S} cloud-init[1725]: {rest}")
    return "\n".join(out) + "\n"


def test_the_log_as_amazon_linux_2_writes_it() -> None:
    # Local time to the second and no year: the first line of a stage tells both. Not
    # read, everything cloud-init made on an AL2 instance was listed as hand work.
    for hours in (0, 9, -8):
        fs = _server(_as_amazon_linux_2(LOG, hours))
        src = SystemSource.from_fs(fs)
        ci = read_cloud_init(src)
        assert ci is not None
        assert not ci.log_missing
        assert ci.first_ns == _ns("28")

        def by(path: str, ci=ci, src=src, fs=fs) -> str | None:
            return ci.written_by(path, src.stat(fs, fs.ino(path)), created=True)

        assert by("/etc/hostname") == "init", hours
        assert by("/etc/myapp/app.conf") == "write_files"
        assert by("/etc/sudoers.d/90-cloud-init-users") == "users_groups"
        assert by("/home/ec2-user/.bashrc") == "users_groups"
        assert by("/root/.ssh/authorized_keys") == "ssh"
        assert by("/etc/myapp/hand.conf") is None  # four seconds later: hand work
        assert by("/home/ec2-user/notes.txt") is None


def test_a_log_without_a_year_past_new_year() -> None:
    from ec2_byhand.cloudinit import _lines

    def at(*when: int) -> int:
        return int(datetime(*when, tzinfo=UTC).timestamp()) * 10**9

    log = (
        "Dec 31 23:59:58 cloud-init[1]: util.py[DEBUG]: Cloud-init v. 19.3 running 'init' at "
        "Thu, 31 Dec 2026 23:59:58 +0000. Up 5.1 seconds.\n"
        "Dec 31 23:59:59 cloud-init[1]: util.py[DEBUG]: Writing to /etc/a - wb: [644] 1 bytes\n"
        "Jan  1 00:00:01 cloud-init[1]: util.py[DEBUG]: Writing to /etc/b - wb: [644] 1 bytes\n"
    )
    assert [t for t, _ in _lines(log)] == [
        at(2026, 12, 31, 23, 59, 58),
        at(2026, 12, 31, 23, 59, 59),
        at(2027, 1, 1, 0, 0, 1),
    ]
    # No line that says the year: the times cannot be told, and nothing is made up.
    assert (
        _lines("Jan  1 00:00:01 cloud-init[1]: util.py[DEBUG]: Writing to /etc/b - wb: [644]\n")
        == []
    )
    fs = _server("Jan  1 00:00:01 cloud-init[1]: util.py[DEBUG]: Writing to /etc/b - wb: [644]\n")
    ci = read_cloud_init(SystemSource.from_fs(fs))
    assert ci is not None
    assert ci.log_missing


def _modules(m: dict) -> dict[str, str]:
    return {f["path"]: g["module"] for g in m["cloud_init"] for f in g["files"]}


def test_the_log_names_what_cloud_init_wrote() -> None:
    fs = _server()
    src = SystemSource.from_fs(fs)
    ci = read_cloud_init(src)
    assert ci is not None
    assert not ci.log_missing
    assert list(ci.by_home) == ["/home/ec2-user"]

    def by(path: str, *, created: bool = True) -> str | None:
        return ci.written_by(path, src.stat(fs, fs.ino(path)), created=created)

    assert by("/etc/hostname") == "init"  # hostnamectl, before the first module
    assert by("/etc/myapp/app.conf") == "write_files"  # "write-files" on AL2023
    assert by("/etc/sudoers.d/90-cloud-init-users") == "users_groups"
    assert by("/home/ec2-user/.bashrc") == "users_groups"  # useradd -m, mtime from 2020
    assert by("/var/spool/mail/ec2-user") == "users_groups"
    assert by("/home/ec2-user/.ssh") == "ssh"  # made for the file written into it
    assert by("/root/.ssh/authorized_keys") == "ssh"
    assert by("/etc/myapp") is None  # a file was added to it by hand later
    # A directory that was there already: a file made in it does not explain a new mode.
    assert by("/home/ec2-user/.ssh", created=False) is None
    assert by("/etc/sudoers.d/90-cloud-init-users", created=False) == "users_groups"
    assert by("/etc/myapp/hand.conf") is None
    assert by("/home/ec2-user/notes.txt") is None


def test_a_file_changed_after_cloud_init_stays_hand_work() -> None:
    fs = _server()
    fs.add_file(
        "/home/ec2-user/.ssh/authorized_keys", b"ssh-ed25519 A\n# by hand\n", mtime_ns=_ns("34.483")
    )
    m = analyze(Snapshot("now", SystemSource.from_fs(fs)))
    hand = {h["path"] for h in m["hand_placed"]}
    assert "/home/ec2-user/.ssh/authorized_keys" in hand
    assert "/home/ec2-user/.ssh/authorized_keys" not in _modules(m)
    assert _modules(m)["/home/ec2-user/.ssh"] == "ssh"


def test_the_cloud_init_section() -> None:
    m = analyze(Snapshot("now", SystemSource.from_fs(_server())))
    assert [g["module"] for g in m["cloud_init"]] == ["init", "write_files", "users_groups", "ssh"]
    assert _modules(m) == {
        "/etc/hostname": "init",
        "/etc/myapp/app.conf": "write_files",
        "/etc/passwd": "users_groups",
        "/etc/sudoers.d/90-cloud-init-users": "users_groups",
        "/home/ec2-user/.bash_profile": "users_groups",
        "/home/ec2-user/.bashrc": "users_groups",
        "/var/spool/mail/ec2-user": "users_groups",
        "/home/ec2-user/.ssh": "ssh",
        "/home/ec2-user/.ssh/authorized_keys": "ssh",
        "/root/.ssh": "ssh",
        "/root/.ssh/authorized_keys": "ssh",
    }
    hand = {h["path"] for h in m["hand_placed"]}
    # The home: notes.txt was put in it by hand, so it is not as useradd left it.
    assert {"/etc/myapp", "/etc/myapp/hand.conf", "/home/ec2-user", "/home/ec2-user/notes.txt"} <= (
        hand
    )
    assert not hand & set(_modules(m))
    assert m["summary"]["files_from_cloud_init"] == 11
    assert not [w for w in m["warnings"] if w["code"].startswith("cloud-init")]


def test_what_cloud_init_wrote_is_archived(tmp_path: Path) -> None:
    fs = _server()
    m = analyze(Snapshot("now", SystemSource.from_fs(fs)))
    write_outputs(m, SystemSource.from_fs(fs), None, tmp_path)
    with tarfile.open(tmp_path / "after.tar.gz") as tar:
        names = set(tar.getnames())
    assert {"etc/myapp/app.conf", "home/ec2-user/.ssh/authorized_keys"} <= names


def test_rotated_logs_are_read_oldest_first() -> None:
    lines = LOG.splitlines(keepends=True)
    fs = _server(log="".join(lines[8:]))  # from passwd -l on
    fs.add_file("/var/log/cloud-init.log.1.gz", gzip.compress("".join(lines[:8]).encode()))
    fs.add_file("/var/log/cloud-init-output.log", b"not this one")
    ci = read_cloud_init(SystemSource.from_fs(fs))
    assert ci is not None
    assert ci.logs == ["/var/log/cloud-init.log.1.gz", "/var/log/cloud-init.log"]
    assert ci.modules[:3] == ["init", "write_files", "users_groups"]
    assert "/home/ec2-user" in ci.by_home


def test_no_log_after_cloud_init_ran_is_a_warning_and_nothing_is_attributed() -> None:
    m = analyze(Snapshot("now", SystemSource.from_fs(_server(log=None))))
    codes = [w["code"] for w in m["warnings"]]
    assert [c for c in codes if c.startswith("cloud-init")] == ["cloud-init-log-missing"]
    assert m["cloud_init"] == []
    assert m["summary"]["files_from_cloud_init"] == 0
    assert "/etc/sudoers.d/90-cloud-init-users" in {h["path"] for h in m["hand_placed"]}


def test_a_package_file_cloud_init_wrote_says_so() -> None:
    # Ubuntu's apt_configure rewrites a package's sources list: it stays a modified package
    # file (its package and problems matter), marked with the module.
    fs = _server()
    owned = {"/etc/myapp/app.conf": b"port=80\n", "/etc/myapp/hand.conf": b"hand=0\n"}
    fs.add_file(
        "/var/lib/dpkg/status",
        b"Package: myapp\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n\n",
    )
    fs.add_file("/var/lib/dpkg/info/myapp:amd64.list", "\n".join(owned).encode() + b"\n")
    sums = "".join(f"{hashlib.md5(d).hexdigest()}  {p.lstrip('/')}\n" for p, d in owned.items())
    fs.add_file("/var/lib/dpkg/info/myapp:amd64.md5sums", sums.encode())
    m = analyze(Snapshot("now", SystemSource.from_fs(fs)))
    modified = {i["path"]: i for i in m["modified_package_files"]}
    assert modified["/etc/myapp/app.conf"]["cloud_init"] == "write_files"
    assert "cloud_init" not in modified["/etc/myapp/hand.conf"]
    assert "/etc/myapp/app.conf" not in _modules(m)


def test_without_cloud_init_there_is_nothing_to_say() -> None:
    fs = MemFs()
    fs.add_file("/etc/myapp.conf", b"x")
    m = analyze(Snapshot("now", SystemSource.from_fs(fs)))
    assert m["cloud_init"] == []
    assert m["summary"]["files_from_cloud_init"] is None
