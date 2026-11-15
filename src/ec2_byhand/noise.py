"""Noise: files that change on any running system without anyone's hand work.

Rules are path globs grouped under a name, so the manifest can report how
many paths each rule hid. Glob syntax: "*" and "?" stay within one path
component, "**" spans any number of them, and "DIR/**" also matches DIR
itself. A rule may apply to some file types only: a directory someone made in
/var/log is not a log file. A rule may also apply only without a baseline:
what lies under /dev and the other mountpoints of a running system is
compared when there is something to compare it with. User --exclude
patterns add a rule that goes first; --include patterns win over every rule.

What is not here on purpose: anything a person might have changed by hand
(/etc/alternatives, /etc/hosts, crontabs under /var/spool/cron, ...).
Files a baseline AMI already had unchanged are dropped by the baseline
comparison, not by rules.

Two things stand beside the rules. NOT_NOISE names hand work inside what a rule
covers (a script put under /var/lib/cloud/scripts, a user's linger file): never
noise. And what a path alone does not tell is counted by the analysis itself
(ec2_byhand.analyze): the directories systemd makes as it is told, a resolv.conf whose
first line says a daemon generated it, the mode a service gives a file of its own.

ノイズ: 動いているシステムなら誰の手も入らず変わるファイル。規則は名前を付けたパスグロブの束で
、manifest には規則ごとに隠した件数が出る。「*」「?」はパスの 1 要素内、「**」は複数要素にまた
がり、「DIR/**」は DIR 自身にも一致する。規則は特定の種別だけに効かせることもできる（/var/log
に手で作ったディレクトリはログファイルではない）。baseline があるときは外れる規則もある（/dev
などのマウントポイントの下は、比較すれば AMI 由来かどうか分かるため）。--exclude は最優先の規
則を 1 つ足し、--include は全規則に勝つ。人が手で変えたかもしれないもの（/etc/alternatives,
/etc/hosts, /var/spool/cron ...）はわざと入れていない。規則のほかに 2 つある: NOT_NOISE は、
規則が覆う範囲の中の手作業（/var/lib/cloud/scripts に置いたスクリプト、ユーザーの linger）で、
決してノイズにしない。パスだけでは分からないもの（systemd が指示どおりに作るディレクトリ、
デーモンが生成したと先頭行で名乗る resolv.conf、サービスが自分のファイルに付ける mode）は、
解析（ec2_byhand.analyze）が数える。
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cache

from diskread.errors import DiskReadError
from diskread.fs import FileType
from diskread.source import SystemSource


@dataclass(frozen=True)
class Rule:
    """One named noise rule: a description and its path globs.

    名前の付いたノイズ規則 1 つ: 説明とパスグロブ。
    """

    name: str
    description: str
    patterns: tuple[str, ...]
    only: frozenset[FileType] | None = None  # the file types it applies to (None: all)
    # Hides what only a baseline could tell from a change: with one, the comparison
    # decides and the rule is left out (NoiseFilter.with_baseline).
    without_baseline: bool = False
    # "DIR/**" patterns among `patterns` the walk does not even enter: what is below
    # is never read (an image's layers hold tens of thousands of files).
    prune: tuple[str, ...] = ()


DEFAULT_RULES: tuple[Rule, ...] = (
    Rule(
        "package-manager",
        "package databases, metadata caches and state",
        (
            "/var/lib/rpm/**",
            "/usr/lib/sysimage/rpm/**",
            "/var/lib/dpkg/**",
            "/var/lib/dnf/**",
            "/var/lib/yum/**",
            "/var/lib/apt/**",
            "/var/cache/**",
            "/var/lib/alternatives/**",
            "/var/lib/ucf/**",
            "/etc/dnf/vars/**",
            "/etc/yum/vars/**",
        ),
    ),
    Rule("journal", "the systemd journal, created at boot", ("/var/log/journal/**",)),
    # Seen on every EC2 image (2026-11-13): the SSM Agent's registration, sockets and
    # logs, written at first boot. Its configuration is under /etc/amazon/ssm. Before
    # "logs": the first rule a path matches decides, and that one leaves directories out.
    Rule(
        "agents",
        "state and logs of the agents EC2 images run (SSM Agent)",
        (
            "/var/lib/amazon/**",
            "/var/log/amazon/**",
            "/root/snap",  # made for the SSM Agent's snap on Ubuntu; other snaps stay visible
            "/root/snap/amazon-ssm-agent/**",
        ),
    ),
    # Not directories: the /var/log/myapp someone made is what the app needs to start.
    Rule("logs", "log files", ("/var/log/**",), frozenset(FileType) - {FileType.DIR}),
    Rule(
        "runtime",
        "runtime and temporary files",
        (
            "/var/run/**",
            "/tmp/**",
            "/var/tmp/**",
            "/var/lock/**",
            # Seen on AL2 (2026-11-13): postfix's sockets, pid and lock, made when it starts.
            # Its configuration is under /etc/postfix; the spool only holds queued mail.
            "/var/spool/postfix/**",
            "/var/lib/postfix/**",
            "/var/lib/gssproxy/**",
        ),
    ),
    # On a disk these are bare mountpoints: a running system mounts tmpfs, proc and
    # sysfs over them, so nothing it writes lands here. What the image build left is
    # noise, but a file added since is not, and it cannot be seen on the running
    # server, which makes it the more worth showing. Only a baseline tells the two apart.
    Rule(
        "mountpoints",
        "what the image holds under /proc, /sys, /dev and /run, hidden on a running system "
        "(with a baseline these paths are compared like any other)",
        ("/proc/**", "/sys/**", "/dev/**", "/run/**"),
        without_baseline=True,
    ),
    Rule(
        "generated",
        "caches and files regenerated by system tools",
        (
            "/etc/ld.so.cache",
            "/etc/pki/ca-trust/extracted/**",
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/ssl/certs/java/cacerts",
            "/etc/machine-id",
            "/var/lib/dbus/machine-id",
            "/etc/mtab",
            "/etc/adjtime",
            "/etc/udev/hwdb.bin",
            "/usr/lib/udev/hwdb.bin",
            "/var/lib/systemd/**",
            "/var/lib/pam/**",
            "/usr/lib/locale/locale-archive",
            "/usr/lib/locale/locale-archive.tmpl",
            "/usr/lib64/gconv/gconv-modules.cache",
            "/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache",
            "/usr/share/info/dir",
            "/usr/share/info/dir.old",
            "/usr/lib/.build-id/**",
            "/etc/selinux/*/active/**",
            "/etc/selinux/*/policy/**",
            "/etc/selinux/*/contexts/files/*.bin",
            "/var/lib/cloud/**",
            "/etc/ssh/ssh_host_*",
            "/var/lib/sss/**",
            "/var/lib/logrotate/**",
            "/var/lib/rsyslog/**",
            "/var/lib/chrony/**",
            "/var/lib/NetworkManager/**",
            "/var/lib/dhclient/**",
            "/var/lib/private/**",
            "/var/lib/polkit-1/**",
            "/var/lib/selinux/**",
            "**/__pycache__/**",
            "**/*.pyc",
            "/etc/.updated",
            "/var/.updated",  # systemd ConditionNeedsUpdate
            "/boot/grub2/grubenv",  # boot_success, written on every boot
            "/etc/audit/audit.rules",  # built from /etc/audit/rules.d by augenrules
            # Seen on Ubuntu 24.04 (2026-11-14): multipathd's own state, written at boot.
            # Its configuration is /etc/multipath.conf and /etc/multipath/conf.d.
            "/etc/multipath",
            "/etc/multipath/bindings",
            "/etc/multipath/wwids",
            # Seen on real EC2 instances (2026-11-13), written by services as they run:
            "/.autorelabel",  # SELinux relabel request (AL2)
            "/etc/aliases.db",  # newaliases; a hand edit shows in /etc/aliases
            "/var/lib/plymouth/**",
            "/var/lib/PackageKit/**",
            "/var/lib/command-not-found/**",
            "/var/lib/dhcpcd/**",
            "/var/lib/hibinit-agent/**",
            # fwupd's own state, fetched by its refresh timer (seen on Ubuntu 24.04,
            # 2026-11-15): firmware metadata, a client key pair, pending.db. Its
            # configuration is under /etc/fwupd.
            "/var/lib/fwupd/**",
            "/var/lib/swcatalog/**",  # AppStream catalog links
            "/var/lib/udisks2/**",
            "/var/lib/update-notifier/**",
            "/var/lib/ubuntu-advantage/apt-esm/**",  # a cache; `pro attach` state stays visible
            "/var/lib/ubuntu-advantage/status.json",
            "/var/lib/ubuntu-advantage/messages/**",
            # snapd's bookkeeping, and what it derives for each snap (seen on Ubuntu 24.04,
            # 2026-11-14). The snaps themselves are under "snaps" in the manifest.
            "/var/lib/snapd/assertions/**",
            "/var/lib/snapd/device/**",
            "/var/lib/snapd/features/**",
            "/var/lib/snapd/cache/**",
            "/var/lib/snapd/state.json",
            "/var/lib/snapd/apparmor/**",
            "/var/lib/snapd/seccomp/**",
            "/var/lib/snapd/cgroup/**",
            "/var/lib/snapd/cookie/**",
            "/var/lib/snapd/inhibit/**",
            "/var/lib/snapd/sequence/**",
            "/var/lib/snapd/mount/**",
            "/var/lib/snapd/desktop/**",
            "/var/lib/snapd/snaps/partial/**",
        ),
    ),
    Rule(
        "backup-copies",
        "automatic backups written by passwd/shadow tools",
        (
            "/etc/passwd-",
            "/etc/shadow-",
            "/etc/group-",
            "/etc/gshadow-",
            "/etc/subuid-",
            "/etc/subgid-",
            "/etc/.pwd.lock",
        ),
    ),
    Rule("filesystem", "filesystem bookkeeping", ("/lost+found", "**/lost+found/**")),
    Rule(
        "shell-history",
        "per-user shell and editor history and caches",
        (
            "/root/.bash_history",
            "/home/*/.bash_history",
            "/root/.lesshst",
            "/home/*/.lesshst",
            "/root/.viminfo",
            "/home/*/.viminfo",
            "/root/.cache/**",
            "/home/*/.cache/**",
            "/root/.python_history",
            "/home/*/.python_history",
            "/root/.npm/**",
            "/home/*/.npm/**",
        ),
    ),
    # Docker's, containerd's and Podman's own state: image layers, containers, volumes.
    # Nobody edits it by hand (the configuration is under /etc/docker, /etc/containerd,
    # /etc/containers); what was done with it shows in the manifest's "containers",
    # read from the metadata (ec2_byhand.containers). The layers are not walked; the
    # volumes are, to count them. A user's rootless Podman keeps a store of its own.
    Rule(
        "container",
        "container runtime artifacts and storage (summarized under containers)",
        (
            "/.dockerenv",
            "/var/lib/docker/**",
            "/var/lib/containerd/**",
            # Podman's store and its cache (blob-info-cache-v1.sqlite), a user's too.
            "/var/lib/containers/**",
            "/root/.local/share/containers/**",
            "/home/*/.local/share/containers/**",
            "/root/.config/cni/net.d/cni.lock",  # a rootless network's lock, not its config
            "/home/*/.config/cni/net.d/cni.lock",
            # What `docker build` keeps of its builders (seen on AL2023, 2026-11-15); a
            # user's settings are ~/.docker/config.json, which stays visible.
            "/root/.docker/buildx/**",
            "/home/*/.docker/buildx/**",
        ),
        prune=(
            "/var/lib/docker/overlay2/**",
            "/var/lib/docker/image/**",
            "/var/lib/docker/containers/**",
            "/var/lib/docker/buildkit/**",
            "/var/lib/docker/network/**",
            "/var/lib/docker/plugins/**",
            "/var/lib/docker/swarm/**",
            "/var/lib/docker/tmp/**",
            "/var/lib/containerd/**",
            *(
                f"{store}/{part}/**"
                for store in (
                    "/var/lib/containers/storage",
                    "/root/.local/share/containers/storage",
                    "/home/*/.local/share/containers/storage",
                )
                for part in (
                    "overlay",
                    "overlay-images",
                    "overlay-layers",
                    "overlay-containers",
                    "vfs",
                    "vfs-images",
                    "vfs-layers",
                    "vfs-containers",
                    "libpod",
                    "networks",
                )
            ),
        ),
    ),
    # Only the links: /etc/ssl/certs is also where certificates are put by hand.
    Rule(
        "ca-links",
        "certificate links kept by update-ca-certificates",
        ("/etc/ssl/certs/*",),
        frozenset({FileType.LNK}),
    ),
)


# Hand work inside what a rule above hides: these paths are never noise. Only what is
# put into the directories, not the directories, which come with the system.
NOT_NOISE = (
    # Where an admin puts scripts for cloud-init to run: per-boot, per-instance, per-once.
    "/var/lib/cloud/scripts/*/*/**",
    # `loginctl enable-linger USER`: the user's services start at boot.
    "/var/lib/systemd/linger/*",
)


def glob_pattern(pattern: str) -> str:
    """The regex source for one path glob (anchored at both ends).

    パスグロブ 1 つ分の正規表現ソース（両端にアンカー済み）。
    """
    # (?s:...): "**" spans anything, also a newline in a file name, which is legal.
    if pattern.endswith("/**"):
        head, tail = pattern[:-3], "(?s:/.*)?"
    else:
        head, tail = pattern, ""
    out, i = [], 0
    while i < len(head):
        if head.startswith("**", i):
            out.append("(?s:.*)")
            i += 2
        elif head[i] == "*":
            out.append("[^/]*")
            i += 1
        elif head[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(head[i]))
            i += 1
    return "".join(out) + tail + r"\Z"


@cache
def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """One path glob compiled to a regex.

    パスグロブ 1 つを正規表現にコンパイルする。
    """
    return re.compile(glob_pattern(pattern))


def combine_globs(patterns: Iterable[str]) -> re.Pattern[str] | None:
    """One regex matching any of the globs (alternatives are tried in order).

    どれかのグロブに一致する 1 本の正規表現（選択肢は順に試される）。
    """
    src = "|".join(f"(?:{glob_pattern(p)})" for p in patterns)
    return re.compile(src) if src else None


_NOT_NOISE = re.compile("|".join(f"(?:{glob_pattern(p)})" for p in NOT_NOISE))


@dataclass
class NoiseFilter:
    """The default rules plus the user's --exclude / --include patterns.

    既定の規則に、利用者の --exclude / --include を重ねたもの。
    """

    rules: tuple[Rule, ...] = DEFAULT_RULES
    excludes: tuple[str, ...] = ()  # extra user patterns, reported as rule "user-exclude"
    includes: tuple[str, ...] = ()  # always kept, whatever the rules say
    # One capturing group per rule: `match` costs one regex call per path,
    # not one per pattern (this runs on every path of both snapshots).
    _groups: list[tuple[str, frozenset[FileType] | None]] = field(
        default_factory=list, init=False, repr=False, compare=False
    )
    _combined: re.Pattern[str] | None = field(default=None, init=False, repr=False, compare=False)
    _include_re: re.Pattern[str] | None = field(default=None, init=False, repr=False, compare=False)
    _prunes: list[tuple[str, re.Pattern[str]]] = field(
        default_factory=list, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        groups = [(r.name, r.patterns, r.only) for r in self.rules]
        if self.excludes:  # first: what the user asked for beats a rule limited to some types
            groups.insert(0, ("user-exclude", self.excludes, None))
        parts = []
        for name, patterns, only in groups:
            self._groups.append((name, only))
            alts = "|".join(f"(?:{glob_pattern(p)})" for p in patterns)
            parts.append(f"({alts})")
        self._combined = re.compile("|".join(parts)) if parts else None
        self._include_re = combine_globs(self.includes)
        # An --include could reach anywhere below an excluded directory: then walk it all.
        if not self.includes:
            candidates = [("user-exclude", tuple(p for p in self.excludes if p.endswith("/**")))]
            candidates += [(r.name, r.prune) for r in self.rules]
            for name, patterns in candidates:
                regex = combine_globs(patterns)
                if regex is not None:
                    self._prunes.append((name, regex))

    def with_baseline(self) -> NoiseFilter:
        """This filter for a run that compares with a baseline: without the rules that
        only stand in for one (Rule.without_baseline).

        baseline と比較する実行のためのフィルタ: baseline の代わりでしかない規則
        （Rule.without_baseline）を外したもの。
        """
        kept = tuple(r for r in self.rules if not r.without_baseline)
        return NoiseFilter(kept, self.excludes, self.includes)

    def match(self, path: str, file_type: FileType | None = None) -> str | None:
        """Name of the rule that makes `path` noise, or None. Without `file_type`
        (the path is all that is known), rules limited to some types apply too.

        `path` をノイズにする規則の名前。なければ None。`file_type` を渡さないとき（パスしか分から
        ないとき）は、種別を限定した規則も当てはまるものとする。
        """
        if self._include_re is not None and self._include_re.match(path):
            return None
        if _NOT_NOISE.match(path):
            return None
        m = self._combined.match(path) if self._combined is not None else None
        if m is None or m.lastindex is None:
            return None
        name, only = self._groups[m.lastindex - 1]
        return (
            None if file_type is not None and only is not None and file_type not in only else name
        )

    def pruned_by(self, path: str) -> str | None:
        """The rule that lets the walk stay out of `path`, or None: the user excluded it
        and everything below it ("DIR/**"), or a rule's `prune` names it, so reading that
        metadata would be wasted requests.

        walk が `path` に入らずに済む理由の規則（無ければ None）。利用者がその配下ごと除外した
        （「DIR/**」）か、規則の `prune` に当たるので、そのメタデータを読んでも無駄になる。
        """
        for name, regex in self._prunes:
            if regex.match(path) is not None:
                return name
        return None

    def prunes(self, path: str) -> bool:
        """Whether the walk can stay out of `path` (see pruned_by).

        walk が `path` に入らずに済むか（pruned_by 参照）。
        """
        return self.pruned_by(path) is not None


class DpkgPathExcludes:
    """dpkg's path-exclude / path-include filters (/etc/dpkg/dpkg.cfg.d/*).

    Minimal Ubuntu images use them to skip docs and man pages; dpkg still
    lists those files, so dpkg --verify reports them missing. Like dpkg,
    the last matching rule wins, and patterns are fnmatch globs whose "*"
    also crosses "/".

    dpkg の path-exclude / path-include フィルタ（/etc/dpkg/dpkg.cfg.d/*）。最小構成の Ubuntu
    イメージが docs や man を省くのに使っており、dpkg はそれらも一覧に持つので dpkg --verify
    では missing に見える。dpkg と同じく最後に一致した規則が勝ち、パターンは「*」が「/」もまた
    ぐ fnmatch グロブ。
    """

    def __init__(self, filters: Iterable[tuple[bool, str]]) -> None:
        self._filters = list(filters)  # (include?, pattern)

    @classmethod
    def from_source(cls, src: SystemSource) -> DpkgPathExcludes:
        """The filters read from /etc/dpkg/dpkg.cfg and dpkg.cfg.d/*.

        /etc/dpkg/dpkg.cfg と dpkg.cfg.d/* から読んだフィルタ。
        """
        filters: list[tuple[bool, str]] = []
        cfg_d = "/etc/dpkg/dpkg.cfg.d"
        try:
            fragments = src.listdir(cfg_d) or []
        except DiskReadError:
            fragments = []
        # The order dpkg reads them in: the fragments, then dpkg.cfg.
        for path in [f"{cfg_d}/{name}" for name in fragments] + ["/etc/dpkg/dpkg.cfg"]:
            data = src.try_read(path) or b""
            for line in data.decode("utf-8", "replace").splitlines():
                line = line.strip()
                for key, include in (("path-exclude", False), ("path-include", True)):
                    if line.startswith(key):
                        pattern = line[len(key) :].lstrip(" =").strip()
                        if pattern:
                            filters.append((include, pattern))
        return cls(filters)

    def excluded(self, path: str) -> bool:
        """Whether dpkg would have skipped installing `path`.

        dpkg が `path` のインストール自体を省いたはずかどうか。
        """
        result = False
        for include, pattern in self._filters:
            if fnmatch.fnmatchcase(path, pattern):
                result = not include
        return result
