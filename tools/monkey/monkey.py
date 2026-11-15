"""Smart monkey test for ec2-byhand, run as root on an AL2023 or Ubuntu test instance by
user-data (tools/monkey/run.sh writes it there). Python 3.9, as AL2023 ships it. On
Ubuntu the packages come from apt and the data volume is ext4 (XFS on AL2023).

  phase 1   a base to change: files, packages, pip, npm, Docker, users, a service;
            then (phase1_more) a volume fstab names by its device, several users with
            packages of their own, Podman
  state1    the whole tree (/, /boot/efi, /srv/data) recorded, then frozen for the baseline
  phase 2   seeded random operations on what phase 1 made, plus fixed scenarios;
            then (phase2_more) users and their homes, pip --user / venv / --target,
            Docker build and bind mount, Podman as root and rootless, an admin's
            settings, secrets, ACLs and capabilities, odd file names
  state2    recorded again; truth.json = what changed, with the package lists
Everything it writes for itself is under /var/tmp/monkey (noise for ec2-byhand).
Progress goes to /dev/console: MONKEY-FREEZE-1, MONKEY-FREEZE-2, MONKEY-DONE; the host
answers through the instance tags (IMDS): snap=N once snapshot N is taken, stage=2.
MONKEY_SEED picks the random operations; MONKEY_FREEZE=0 snapshots without fsfreeze,
as a backup of a running server would be.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import stat
import subprocess
import sys
import time
import urllib.request

W = "/var/tmp/monkey"
SEED = int(os.environ.get("MONKEY_SEED", "20261114"))
FREEZE = os.environ.get("MONKEY_FREEZE", "1") != "0"
APT = os.path.exists("/usr/bin/apt-get")  # Ubuntu (ext4) rather than AL2023 (XFS)
FS = "ext4" if APT else "xfs"
# Ubuntu 24.04's pip refuses to touch the system Python without this (PEP 668).
PIP = "pip3 install -q --no-cache-dir" + (" --break-system-packages" if APT else "")
PIP_REMOVE = "pip3 uninstall -y -q" + (" --break-system-packages" if APT else "")
DATA = "/srv/data"
EXTRA = "/srv/extra"  # a 1 GiB volume that fstab names by its device, or by its id
ROOTS = ["/", "/boot/efi", DATA]
SKIP = {"/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp"}
DIRS = [
    "/opt/monkey",
    "/opt/monkey/conf",
    "/etc/monkey.d",
    "/usr/local/monkey",
    f"{DATA}/app",
    f"{DATA}/big",
    "/home/appuser/work",
    "/var/www/site",
    "/srv/data/日本語 dir",
]


def say(msg):
    with open("/dev/console", "w") as c:
        c.write(msg + "\n")
    print(msg, flush=True)


def sh(cmd, check=True):
    print("+", cmd, flush=True)
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if r.returncode and check:
        print(r.stdout[-2000:], r.stderr[-2000:], flush=True)
        raise SystemExit(f"failed: {cmd}")
    return r.stdout


def imds(path):
    tok = (
        urllib.request.urlopen(
            urllib.request.Request(
                "http://169.254.169.254/latest/api/token",
                method="PUT",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "300"},
            ),
            timeout=5,
        )
        .read()
        .decode()
    )
    try:
        return (
            urllib.request.urlopen(
                urllib.request.Request(
                    "http://169.254.169.254/latest/meta-data/" + path,
                    headers={"X-aws-ec2-metadata-token": tok},
                ),
                timeout=5,
            )
            .read()
            .decode()
        )
    except Exception:
        return ""


def install(names):
    if APT:
        sh(f"DEBIAN_FRONTEND=noninteractive apt-get install -y -q {names}")
    else:
        sh(f"dnf install -y -q {names}")


TAG_WAIT_SECONDS = 30 * 60  # for the run on the PC to take a snapshot and set the tag


def wait_tag(key, value):
    """Wait until the instance's tag says so. Not for ever: run.sh may be gone (stopped,
    the line lost), and with the filesystems frozen the shutdown that is the last
    resort could never write, so the instance would stay and cost."""
    deadline = time.time() + TAG_WAIT_SECONDS
    while imds(f"tags/instance/{key}") != value:
        if time.time() > deadline:
            raise TimeoutError(f"tag {key}={value} did not come in {TAG_WAIT_SECONDS} s")
        time.sleep(5)


def freeze_for(n):
    """Freeze the filesystems, tell the console, wait for the snapshot, thaw. Nothing
    may be written to disk meanwhile: no print (stdout is a file). Without FREEZE the
    snapshot is taken of busy filesystems, after a sync only."""
    sys.stdout.flush()
    os.sync()
    if not FREEZE:
        with open("/dev/console", "w") as c:
            c.write(f"MONKEY-FREEZE-{n}\n")
        wait_tag("snap", str(n))
        return
    subprocess.run(f"fsfreeze -f {DATA} && fsfreeze -f /", shell=True)
    with open("/dev/console", "w") as c:
        c.write(f"MONKEY-FREEZE-{n}\n")
    try:
        wait_tag("snap", str(n))
    finally:
        subprocess.run(f"fsfreeze -u / ; fsfreeze -u {DATA}", shell=True)


def write(path, data, mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    if mode is not None:
        os.chmod(path, mode)


def big(path, mib, rnd):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        for _ in range(mib):
            f.write(rnd.randbytes(1 << 20))


# --- phase 1 -------------------------------------------------------------------------


def phase1():
    rnd = random.Random(SEED)
    dev = sh('lsblk -dpno NAME,SIZE,TYPE | awk \'$2=="100G" && $3=="disk" {print $1}\'').strip()
    sh(f"mkfs.{FS} -q {dev}")
    os.makedirs(DATA, exist_ok=True)
    uuid = sh(f"blkid -s UUID -o value {dev}").strip()
    with open("/etc/fstab", "a") as f:
        f.write(f"UUID={uuid} {DATA} {FS} defaults,nofail 0 2\n")
    sh(f"mount {DATA}")
    if APT:
        sh("apt-get update -q")
    install("jq tree python3-pip nodejs npm " + ("docker.io" if APT else "docker"))
    # Not in AL2023 as rpms: pip refuses to replace an rpm-installed package.
    sh(f"{PIP} tabulate==0.9.0 colorama==0.4.6")
    os.makedirs("/opt/webapp", exist_ok=True)
    sh("cd /opt/webapp && npm init -y >/dev/null && npm install --silent left-pad@1.3.0")
    sh("useradd -m appuser && useradd -m user1")
    sh("systemctl enable --now docker")
    sh("docker pull -q alpine:3.20 && docker volume create v1")
    sh("docker run -d --name keep -v v1:/v alpine:3.20 sh -c 'echo base > /v/base.txt; sleep 1d'")
    write(
        "/etc/systemd/system/monkey.service",
        b"[Unit]\nDescription=monkey\n[Service]\nExecStart=/bin/sleep infinity\n"
        b"[Install]\nWantedBy=multi-user.target\n",
    )
    sh("systemctl daemon-reload && systemctl enable monkey.service")
    for d in DIRS:
        os.makedirs(d, exist_ok=True)
    for i in range(600):  # small files to be changed in phase 2
        d = rnd.choice(DIRS)
        write(
            f"{d}/f{i:04d}.{rnd.choice(['txt', 'conf', 'bin', 'sh'])}",
            rnd.randbytes(rnd.choice([0, 10, 300, 4000, 70_000, 600_000])),
        )
    for i in range(4):
        big(f"{DATA}/big/base{i}.bin", 300, rnd)
    os.symlink("f0001.txt", "/opt/monkey/link-a")
    os.link(f"{DATA}/app/" + sorted(os.listdir(f"{DATA}/app"))[0], f"{DATA}/app/hardlink")
    sh("chown -R appuser:appuser /home/appuser/work")
    phase1_more()


# --- more of both phases: users, their own installs, Podman, an admin's settings ----------

S = "/opt/scenario"  # fixed scenarios live here, out of the random operations' reach
ALPINE, BUSYBOX = "docker.io/library/alpine:3.20", "docker.io/library/busybox:1.36"
SECRETS = {
    "wp-config.php": b"<?php\ndefine( 'DB_NAME', 'wp' );\n"
    b"define( 'DB_PASSWORD', 'hunter2-wp-secret' );\n"
    b"define( 'AUTH_KEY', 'put-your-unique-phrase-here-1234' );\n",
    "database.php": b"<?php\nreturn [\n  'host' => 'db.internal',\n"
    b"  'password' => 'hunter2-php-array',\n  'fallback' => env('DB_PASSWORD', ''),\n];\n",
    "context.xml": b"<Context>\n  <password>hunter2-in-xml</password>\n</Context>\n",
    "settings.ini": b"[db]\nuser = app\npassword = hunter2-in-ini\n"
    b"url = mysql://app:hunter2-in-url@db.internal/app\n",
    "prod.env": b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAPI_TOKEN=hunter2-in-env\n",
}


def as_user(user, cmd, check=False):
    """Run `cmd` as `user`, with the runtime directory rootless tools look for."""
    uid = sh(f"id -u {user}").strip()
    return sh(f"sudo -H -u {user} env XDG_RUNTIME_DIR=/run/user/{uid} sh -c '{cmd}'", check=check)


def by_id(dev):
    """The /dev/disk/by-id name of an EBS volume (the shortest of its links)."""
    d = "/dev/disk/by-id"
    names = [
        n
        for n in os.listdir(d)
        if n.startswith("nvme-Amazon_Elastic_Block_Store_vol")
        and os.path.realpath(f"{d}/{n}") == dev
    ]
    return f"{d}/{min(names, key=len)}"


def phase1_more():
    """More to change in phase 2: a volume fstab names by its device, several users,
    packages each user installed for themself, Podman, files for the fixed scenarios."""
    extra = sh('lsblk -dpno NAME,SIZE,TYPE | awk \'$2=="1G" && $3=="disk" {print $1}\'').strip()
    sh(f"mkfs.{FS} -q {extra}")
    os.makedirs(EXTRA, exist_ok=True)
    # AL2023's udev links /dev/sdg as the volume is attached; elsewhere only its id says which.
    spec = "/dev/sdg" if os.path.exists("/dev/sdg") else by_id(extra)
    with open("/etc/fstab", "a") as f:
        f.write(f"{spec} {EXTRA} {FS} defaults,nofail 0 2\n")
    sh(f"mount {EXTRA}")
    for name in ("keep.txt", "change.txt", "remove.txt"):
        write(f"{EXTRA}/{name}", f"{name} at the baseline\n".encode())
    if spec != "/dev/sdg":
        ROOTS.append(EXTRA)  # a run given snapshots by id can mount it: part of the truth
    install("acl " + ("python3-venv cron podman uidmap" if APT else "cronie"))
    if not APT:
        sh("dnf install -y -q podman", check=False)  # not in every AL2023 repository
    sh("groupadd devs")
    for user in ("alice", "bob", "carol"):
        sh(f"useradd -m -s /bin/bash {user}")
    sh("usermod -aG devs alice && useradd -r -s /sbin/nologin svc-monkey")
    as_user("alice", f"{PIP} --user termcolor==2.4.0 text-unidecode==1.3", check=True)
    as_user("bob", f"{PIP} --user toml==0.10.2", check=True)
    write("/home/alice/notes.txt", b"alice at the baseline\n")
    write("/home/bob/bin/tool.sh", b"#!/bin/sh\necho bob\n", 0o755)
    sh("chown -R alice:alice /home/alice && chown -R bob:bob /home/bob")
    for name in ("acl.txt", "xattr.txt", "label.txt", "mtime.bin", "was-file", "olddir/sub/x.txt"):
        write(f"{S}/{name}", f"{name} at the baseline\n".encode())
    if shutil.which("podman"):
        sh(f"podman pull -q {ALPINE} && podman volume create pv1", check=False)
        sh(f"podman run -d --name pkeep -v pv1:/v {ALPINE} sleep 1d", check=False)


def phase2_more(op):
    """Fixed scenarios beyond the first set: what several users, their own pip installs,
    Docker and Podman, and an admin's settings leave behind. Each is tried on its own:
    one that fails is recorded and the rest go on."""

    def attempt(kind, path, action):
        try:
            action()
            op(kind, path)
        except (Exception, SystemExit) as e:
            op("failed", path, error=f"{kind}: {type(e).__name__}: {e}")

    def run(kind, path, cmd):
        attempt(kind, path, lambda: sh(cmd))

    def put(kind, path, data, mode=None):
        attempt(kind, path, lambda: write(path, data, mode))

    def append(kind, path, text):
        def action():
            with open(path, "a") as f:
                f.write(text)

        attempt(kind, path, action)

    # --- users ---
    run("users", "dave added with groups", "groupadd ops && useradd -m -G devs,ops dave")
    run("users", "alice into docker", "usermod -aG docker alice")
    run("users", "bob's shell", "usermod -s /bin/sh bob")
    run("users", "carol locked", "passwd -l carol")
    append("home", "/home/alice/.bashrc", "alias ll='ls -l'\n")
    append("home", "/home/alice/notes.txt", "more\n")
    key = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMonkey monkey@test\n"
    put("home", "/home/alice/.ssh/authorized_keys", key, 0o600)
    run("home", "/home/alice/.ssh", "chmod 700 /home/alice/.ssh")
    attempt("home", "/home/bob/bin/tool.sh", lambda: os.remove("/home/bob/bin/tool.sh"))
    put("home", "/home/dave/app/run.sh", b"#!/bin/sh\n", 0o755)
    if os.path.exists("/root/.ssh/authorized_keys"):
        append("home", "/root/.ssh/authorized_keys", key.decode().replace("monkey@", "root@"))
    unit = "/home/alice/.config/systemd/user"
    service = b"[Service]\nExecStart=/bin/sleep infinity\n[Install]\nWantedBy=default.target\n"
    put("user-unit", f"{unit}/hello.service", service)

    def user_wants():
        os.makedirs(f"{unit}/default.target.wants", exist_ok=True)
        os.symlink(f"{unit}/hello.service", f"{unit}/default.target.wants/hello.service")

    attempt("user-unit", f"{unit}/default.target.wants/hello.service", user_wants)
    run("users", "alice lingers", "loginctl enable-linger alice && sleep 5")
    run("home", "homes owned", "chown -R alice:alice /home/alice && chown -R dave:dave /home/dave")

    # --- what each user installed for themself, a venv, a --target directory ---
    as_user("alice", f"{PIP} --user humanize==4.9.0 && {PIP_REMOVE} text-unidecode")
    op("pip-user", "alice: humanize in, text-unidecode out")
    site = as_user("alice", "python3 -m site --user-site").strip()
    append("pip-user-edit", f"{site}/termcolor/termcolor.py", "# by hand\n")
    as_user("dave", f"{PIP} --user toml==0.10.2")
    op("pip-user", "dave: toml")
    venv_pip = "/opt/venv/bin/pip install -q --no-cache-dir"
    run("venv", "/opt/venv", f"python3 -m venv /opt/venv && {venv_pip} toml==0.10.2")
    run("pip-target", f"{S}/vendor", f"{PIP} --target {S}/vendor iniconfig==2.0.0")
    run("npm-global", "cowsay", "npm install -g --silent cowsay@1.6.0")

    # --- containers ---
    put("docker-build", "/opt/build/Dockerfile", b"FROM alpine:3.20\nRUN echo built > /b.txt\n")
    run("docker-build", "monkey/app:1", "docker build -q -t monkey/app:1 /opt/build")
    run("docker", "network monkeynet", "docker network create monkeynet")
    host = f"{DATA}/app/from-container.txt"
    echo = "sh -c 'echo from a container > /host/from-container.txt'"
    run("docker-bind", host, f"docker run --rm -v {DATA}/app:/host alpine:3.20 {echo}")
    if shutil.which("podman"):
        run(
            "podman",
            "busybox pulled, pkeep removed",
            f"podman pull -q {BUSYBOX}; podman rm -f pkeep",
        )
        run(
            "podman",
            "pv2 and pfresh",
            f"podman volume create pv2 && podman run -d --name pfresh -v pv2:/w {BUSYBOX} sleep 1d",
        )
        as_user("alice", f"podman pull -q {ALPINE}")
        as_user("alice", f"podman run -d --name alice-c {ALPINE} sleep 1d")
        as_user("alice", "podman volume create alice-v")
        op("podman-rootless", "alice: alpine, alice-c, alice-v")

    # --- an admin's settings ---
    put("etc", "/etc/sudoers.d/90-alice", b"alice ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n", 0o440)
    put("etc", "/etc/cron.d/monkey", b"*/5 * * * * root /usr/local/bin/monkey-job\n")
    put("etc", "/usr/local/bin/monkey-job", b"#!/bin/sh\ndate >> /var/log/monkey-job.log\n", 0o755)
    run("crontab", "alice", "echo '0 3 * * * /home/alice/backup.sh' | crontab -u alice -")
    put("etc", "/etc/profile.d/monkey.sh", b"export MONKEY=1\n")
    put("etc", "/etc/sysctl.d/99-monkey.conf", b"vm.swappiness = 10\n")
    append("etc", "/etc/hosts", "10.0.0.10 db.internal\n")
    run("etc", "timezone", "timedatectl set-timezone Asia/Tokyo")
    run("etc", "hostname", "hostnamectl set-hostname monkey-host")
    if APT:
        put(
            "etc", "/etc/apt/sources.list.d/monkey.list", b"# deb https://example.invalid/ x main\n"
        )
    else:
        repo = b"[monkey]\nname=monkey\nbaseurl=https://example.invalid/\nenabled=0\n"
        put("etc", "/etc/yum.repos.d/monkey.repo", repo)
    dropin = "/etc/systemd/system/nginx.service.d/override.conf"
    put("systemd", dropin, b"[Service]\nLimitNOFILE=65535\n")
    timer = b"[Timer]\nOnCalendar=daily\n[Install]\nWantedBy=timers.target\n"
    put("systemd", "/etc/systemd/system/monkey.timer", timer)
    run("systemd", "timer enabled", "systemctl daemon-reload && systemctl enable monkey.timer")
    # A unit nothing has a link for yet: AL2023 has one for ctrl-alt-del.target.
    run("systemd", "debug-shell masked", "systemctl mask debug-shell.service")
    make = "dd if=/dev/zero of=/swapfile bs=1M count=64 status=none && chmod 600 /swapfile"
    run("swap", "/swapfile", f"{make} && mkswap /swapfile > /dev/null")
    append("etc", "/etc/fstab", "/swapfile none swap sw,nofail 0 0\n")
    put("cloud-script", "/var/lib/cloud/scripts/per-boot/10-monkey.sh", b"#!/bin/sh\n", 0o755)

    # --- secrets, in the forms applications keep them ---
    for name, text in SECRETS.items():
        put("secret", f"{S}/conf/{name}", text)

    # --- what a stat does not show at first sight ---
    run("acl", f"{S}/acl.txt", f"setfacl -m u:alice:rw {S}/acl.txt")
    attempt("xattr", f"{S}/xattr.txt", lambda: os.setxattr(f"{S}/xattr.txt", "user.monkey", b"1"))
    # Only where SELinux labels the files (AL2023); elsewhere it fails and is recorded so.
    run("chcon", f"{S}/label.txt", f"chcon -t httpd_sys_content_t {S}/label.txt")
    attempt("setcap", f"{S}/capbin", lambda: shutil.copy("/bin/true", f"{S}/capbin"))
    run("setcap", f"{S}/capbin", f"setcap cap_net_bind_service+ep {S}/capbin")

    def touched_back():  # content changed, size and mtime as before
        path = f"{S}/mtime.bin"
        st = os.stat(path)
        with open(path, "r+b") as f:
            f.write(b"M")
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))

    attempt("mtime-kept", f"{S}/mtime.bin", touched_back)

    def file_to_dir():
        os.remove(f"{S}/was-file")
        write(f"{S}/was-file/inside.txt", b"was a file\n")

    attempt("file-to-dir", f"{S}/was-file", file_to_dir)

    def dir_to_link():
        shutil.rmtree(f"{S}/olddir")
        write(f"{S}/newdir/y.txt", b"y\n")
        os.symlink("newdir", f"{S}/olddir")

    attempt("dir-to-link", f"{S}/olddir", dir_to_link)
    put("odd-name", f"{S}/line\nbreak.txt", b"a name with a newline\n")
    put("odd-name", os.fsdecode(S.encode() + b"/not-utf8-\xff\xfe.txt"), b"not UTF-8\n")
    put("odd-name", f"{S}/esc-\x1b[31mred.txt", b"a name with an escape sequence\n")

    # --- the volume fstab names by its device ---
    append("extra", f"{EXTRA}/change.txt", "changed since\n")
    attempt("extra", f"{EXTRA}/remove.txt", lambda: os.remove(f"{EXTRA}/remove.txt"))
    put("extra", f"{EXTRA}/new.txt", b"new since the baseline\n")


# --- the record of a tree ---------------------------------------------------------------


def xattrs(path):
    """The path's extended attributes (ACLs, capabilities, user.*) as one digest; the
    SELinux label aside, which every file has and a relabel changes."""
    try:
        names = os.listxattr(path, follow_symlinks=False)
        names = sorted(n for n in names if n != "security.selinux")
        if not names:
            return None
        h = hashlib.sha256()
        for n in names:
            h.update(n.encode() + b"=" + os.getxattr(path, n, follow_symlinks=False) + b";")
        return h.hexdigest()[:16]
    except OSError:
        return None


def record(out):
    tree = {}
    for root in ROOTS:
        rdev = os.lstat(root).st_dev
        for dirpath, dirnames, filenames in os.walk(root):
            keep = []
            for d in dirnames:
                p = os.path.join(dirpath, d)
                if p in SKIP or os.lstat(p).st_dev != rdev:
                    continue
                keep.append(d)
            dirnames[:] = keep
            for name in [*dirnames, *filenames, ""] if dirpath == root else [*dirnames, *filenames]:
                p = os.path.join(dirpath, name) if name else dirpath
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                e = {
                    "t": stat.S_IFMT(st.st_mode),
                    "m": stat.S_IMODE(st.st_mode),
                    "u": st.st_uid,
                    "g": st.st_gid,
                }
                if stat.S_ISREG(st.st_mode):
                    e["s"] = st.st_size
                    if st.st_size <= (1 << 30):
                        h = hashlib.sha256()
                        try:
                            with open(p, "rb") as f:
                                for chunk in iter(lambda: f.read(1 << 20), b""):
                                    h.update(chunk)
                            e["h"] = h.hexdigest()
                        except OSError:
                            e["h"] = "unreadable"
                    else:
                        e["mt"] = st.st_mtime_ns
                elif stat.S_ISLNK(st.st_mode):
                    e["l"] = os.readlink(p)
                elif stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
                    e["r"] = st.st_rdev
                x = xattrs(p)
                if x:
                    e["x"] = x
                try:
                    label = os.getxattr(p, "security.selinux", follow_symlinks=False)
                    e["se"] = label.rstrip(b"\0").decode("utf-8", "replace")
                except OSError:
                    pass
                tree[p] = e
    with open(out, "w") as f:
        json.dump(tree, f)
    return tree


PODMAN_LIST = (
    "podman images --format {{.Repository}}:{{.Tag}}; "
    "podman ps -a --format {{.Names}}={{.Image}}; podman volume ls -q"
)


def lists(out):
    if APT:
        query = "dpkg-query -W -f '${db:Status-Abbrev}${Package} ${Version}.${Architecture}\\n'"
        packages = [x[3:] for x in sh(query).split("\n") if x.startswith("ii ")]
    else:
        query = "rpm -qa --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n'"
        packages = sh(query).split("\n")
    data = {
        "packages": sorted(packages),
        "images": sh("docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}'", check=False),
        "containers": sh("docker ps -a --format '{{.Names}} {{.Image}} {{.ID}}'", check=False),
        "volumes": sh("docker volume ls -q", check=False),
        "pip": sh("pip3 list --format=freeze", check=False),
        "pip_alice": as_user("alice", "pip3 list --user --format=freeze"),
        "users": sh("getent passwd | cut -d: -f1,3,7", check=False),
        "groups": sh("getent group devs ops docker", check=False),
        "podman": sh(f"{PODMAN_LIST}", check=False),
        "podman_alice": as_user("alice", PODMAN_LIST),
        "crontab_alice": sh("crontab -l -u alice", check=False),
        "linger": sh("ls /var/lib/systemd/linger", check=False),
        "fstab": sh("cat /etc/fstab", check=False),
        "enabled": sh("systemctl list-unit-files --state=enabled --no-legend", check=False),
    }
    with open(out, "w") as f:
        json.dump(data, f)


# --- phase 2 ---------------------------------------------------------------------------


def phase2():
    rnd = random.Random(SEED + 1)
    ops = []

    def files():
        out = []
        for d in DIRS:
            if not os.path.isdir(d):
                continue
            for n in sorted(os.listdir(d)):
                p = f"{d}/{n}"
                if os.path.isfile(p) and not os.path.islink(p):
                    out.append(p)
        return out

    def op(kind, path, **kw):
        ops.append({"op": kind, "path": path, **kw})

    # fixed scenarios: each category at least once
    install("nginx")
    op("pkg-install", "nginx")
    sh(("apt-get remove -y -q" if APT else "dnf remove -y -q") + " jq")
    op("pkg-remove", "jq")
    sh(f"{PIP} wcwidth==0.2.13 && {PIP_REMOVE} tabulate")
    op("pip-install", "wcwidth, tabulate removed")
    col = sh("python3 -c 'import colorama, os; print(os.path.dirname(colorama.__file__))'").strip()
    with open(f"{col}/ansi.py", "a") as f:
        f.write("# edited by hand\n")
    op("pip-edit", f"{col}/ansi.py")
    sh("cd /opt/webapp && npm install --silent is-number@7.0.0")
    op("npm-install", "is-number")
    sh("docker pull -q busybox:1.36 && docker rm -f keep && docker volume create v2")
    sh("docker run --rm -v v1:/v alpine:3.20 sh -c 'echo more > /v/more.txt'")
    sh("docker run -d --name fresh -v v2:/w busybox:1.36 sleep 1d")
    op("docker", "busybox pulled, keep removed, v1 written, v2 + fresh made")
    sh("useradd -m user2 && userdel -r user1")
    op("users", "user2 added, user1 removed")
    sh("systemctl disable monkey.service && systemctl enable nginx")
    op("services", "monkey disabled, nginx enabled")
    with open("/etc/ssh/sshd_config", "a") as f:
        f.write("ClientAliveInterval 30\n")
    op("pkg-edit", "/etc/ssh/sshd_config")
    os.chmod("/usr/bin/tree", 0o4755)
    op("pkg-chmod", "/usr/bin/tree")
    if os.path.exists("/usr/share/doc/tree/README"):
        os.chown("/usr/share/doc/tree/README", 1000, 1000)
    if os.path.exists("/etc/issue.net"):
        os.remove("/etc/issue.net")
    op("pkg-delete", "/etc/issue.net")
    write("/etc/docker/daemon.json", b'{"log-driver": "json-file"}\n')
    op("create", "/etc/docker/daemon.json")
    write(f"{DATA}/big/sparse.img", b"")
    with open(f"{DATA}/big/sparse.img", "r+b") as f:
        f.seek(2 << 30)
        f.write(b"end")  # 2 GiB apparent, over --max-file-size
    op("sparse", f"{DATA}/big/sparse.img")
    with open(f"{DATA}/big/base1.bin", "r+b") as f:  # same size, one MiB changed in the middle
        f.seek(150 << 20)
        f.write(rnd.randbytes(1 << 20))
    op("big-inplace", f"{DATA}/big/base1.bin")
    os.remove(f"{DATA}/big/base2.bin")
    op("delete", f"{DATA}/big/base2.bin")
    for i in range(2):
        big(f"{DATA}/big/new{i}.bin", 200, rnd)
        op("create-big", f"{DATA}/big/new{i}.bin")
    shutil.rmtree("/var/www/site")
    op("rmtree", "/var/www/site")
    os.mkfifo("/opt/monkey/fifo")
    op("mkfifo", "/opt/monkey/fifo")
    phase2_more(op)

    # seeded random operations
    weights = {
        "create": 20,
        "append": 12,
        "overwrite-same-size": 10,
        "truncate": 5,
        "chmod": 8,
        "chown": 5,
        "rename": 8,
        "delete": 10,
        "mkdir-tree": 4,
        "symlink": 5,
        "retarget": 3,
        "hardlink": 3,
        "unicode": 3,
    }
    kinds = list(weights)
    for n in range(400):
        try:
            kind = rnd.choices(kinds, [weights[k] for k in kinds])[0]
            fl = files()
            if kind in ("create", "unicode", "mkdir-tree"):
                d = rnd.choice([d for d in DIRS if os.path.isdir(d)])
                name = f"新しい ファイル {n}.txt" if kind == "unicode" else f"n{n:04d}.dat"
                if kind == "mkdir-tree":
                    d = f"{d}/tree{n}/a/b/c"
                p = f"{d}/{name}"
                write(p, rnd.randbytes(rnd.choice([0, 1, 100, 5000, 200_000])))
                op(kind, p)
            elif not fl:
                continue
            else:
                p = rnd.choice(fl)
                if kind == "append":
                    with open(p, "ab") as f:
                        f.write(rnd.randbytes(rnd.choice([1, 50, 4096])))
                elif kind == "overwrite-same-size":
                    size = os.path.getsize(p)
                    if size == 0:
                        continue
                    with open(p, "r+b") as f:
                        f.seek(rnd.randrange(size))
                        f.write(bytes([rnd.randrange(256)]))
                elif kind == "truncate":
                    os.truncate(p, os.path.getsize(p) // 2)
                elif kind == "chmod":
                    os.chmod(p, rnd.choice([0o600, 0o755, 0o4755, 0o777, 0o2755]))
                elif kind == "chown":
                    os.chown(p, rnd.choice([0, 1000, 65534]), rnd.choice([0, 1000, 65534]))
                elif kind == "rename":
                    q = f"{os.path.dirname(p)}/renamed-{n}-{os.path.basename(p)}"
                    os.rename(p, q)
                    op(kind, p, to=q)
                    continue
                elif kind == "delete":
                    os.remove(p)
                elif kind == "symlink":
                    q = f"{os.path.dirname(p)}/sym{n}"
                    os.symlink(os.path.basename(p), q)
                    p = q
                elif kind == "retarget":
                    if os.path.islink("/opt/monkey/link-a"):
                        os.remove("/opt/monkey/link-a")
                    os.symlink(os.path.basename(p), "/opt/monkey/link-a")
                    p = "/opt/monkey/link-a"
                elif kind == "hardlink":
                    q = f"{os.path.dirname(p)}/hl{n}"
                    os.link(p, q)
                    p = q
                op(kind, p)
        except OSError as e:  # e.g. a hard link to a file another operation removed
            op("failed", "", error=f"{type(e).__name__}: {e}")
    with open(f"{W}/ops.json", "w") as f:
        json.dump(ops, f)


def diff(a, b):
    out = {"added": [], "removed": [], "changed": {}}
    for p in b.keys() - a.keys():
        out["added"].append(p)
    for p in a.keys() - b.keys():
        out["removed"].append(p)
    for p in a.keys() & b.keys():
        fields = sorted(k for k in a[p].keys() | b[p].keys() if a[p].get(k) != b[p].get(k))
        if fields:
            out["changed"][p] = fields
    out["added"].sort()
    out["removed"].sort()
    return out


def main():
    os.makedirs(W, exist_ok=True)
    say("MONKEY-START")
    phase1()
    lists(f"{W}/lists1.json")
    t1 = record(f"{W}/state1.json")
    freeze_for(1)
    wait_tag("stage", "2")
    phase2()
    lists(f"{W}/lists2.json")
    t2 = record(f"{W}/state2.json")
    with open(f"{W}/truth.json", "w") as f:
        json.dump(diff(t1, t2), f)
    say(f"MONKEY-RECORDED {len(t2)} paths")
    freeze_for(2)
    say("MONKEY-DONE")


if __name__ == "__main__":
    try:
        main()
    except SystemExit as e:
        say(f"MONKEY-FAILED {e}")
        raise
    except Exception as e:
        say(f"MONKEY-FAILED {type(e).__name__}: {e}")
        raise
