"""Paths likely to hold secrets (keys, password hashes, credentials).

The manifest flags them so that later stages can leave their contents out
of archives by default. Same glob syntax as ec2_byhand.noise.

Swap files are told by their content, not their path (is_swap): they hold
memory, so they are not read at all.

秘密を含みそうなパス（鍵・パスワードハッシュ・資格情報）。manifest がフラグを立て、後段が既定
でアーカイブから中身を外せるようにする。グロブの文法は ec2_byhand.noise と同じ。スワップファイル
はパスではなく中身で見分ける（is_swap）。中身はメモリなので、一切読まない。
"""

from __future__ import annotations

from diskread.blockdev import BlockDevice, will_read
from ec2_byhand.noise import combine_globs

SENSITIVE_PATTERNS = (
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/gshadow",
    "/etc/gshadow-",
    "/etc/security/opasswd",
    "/etc/ssh/ssh_host_*_key",
    "/etc/ipsec.secrets",
    "/etc/wireguard/*.conf",
    "/etc/NetworkManager/system-connections/*",
    # The SSM Agent's private registration key, written at first boot (seen on AL2023).
    "/var/lib/amazon/ssm/Vault/**",
    # snapd's device key and Ubuntu Pro's machine token (seen on Ubuntu 24.04).
    "/var/lib/snapd/device/private-keys-v1/**",
    "/var/lib/ubuntu-advantage/private/**",
    "**/id_rsa",
    "**/id_dsa",
    "**/id_ecdsa",
    "**/id_ed25519",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/*.jks",
    "**/*.keystore",
    "**/*.keytab",
    "**/.netrc",
    "**/.npmrc",
    "**/.pypirc",
    "**/.vault-token",
    "**/.pgpass",
    "**/.my.cnf",
    "**/.aws/credentials",
    "**/.docker/config.json",
    "**/.env",
    "**/.env.*",
    "**/.bash_history",
    "**/.mysql_history",
    "**/.psql_history",
    "**/.git-credentials",
    "**/.kube/config",
)
# Templates checked into an app's repository: their purpose is to hold no secrets.
NOT_SENSITIVE_PATTERNS = (
    "**/.env.example",
    "**/.env.sample",
    "**/.env.template",
    "**/.env.dist",
)
_REGEX = combine_globs(SENSITIVE_PATTERNS)
_NOT_REGEX = combine_globs(NOT_SENSITIVE_PATTERNS)


def is_sensitive(path: str) -> bool:
    """Whether the path matches the likely-secrets list.

    パスが「秘密を含みそう」の一覧に当たるか。
    """
    if _NOT_REGEX is not None and _NOT_REGEX.match(path) is not None:
        return False
    return _REGEX is not None and _REGEX.match(path) is not None


class Sensitive:
    """The likely-secrets list, plus the user's own patterns (--sensitive GLOB, same
    syntax as --exclude). A user pattern wins over the templates (.env.example): the
    user said so.

    「秘密を含みそう」の一覧に、利用者のパターン（--sensitive GLOB。--exclude と同じ文法）を
    足したもの。利用者のパターンはテンプレート（.env.example）の除外より優先する。
    """

    def __init__(self, extra: tuple[str, ...] = ()) -> None:
        self.extra = extra
        self._extra = combine_globs(extra) if extra else None

    def match(self, path: str) -> bool:
        """Whether the path is to be treated as a secret.

        パスを秘密として扱うか。
        """
        if self._extra is not None and self._extra.match(path) is not None:
            return True
        return is_sensitive(path)


DEFAULT = Sensitive()


# mkswap writes one of these into the last 10 bytes of the first page, whatever the
# file is called; the page is 4, 16 or 64 KiB depending on the kernel that made it.
_SWAP_SIGNATURES = (b"SWAPSPACE2", b"SWAP-SPACE")
_PAGE_SIZES = (4096, 16384, 65536)
SWAP_MIN_BYTES = 10 * 4096  # mkswap refuses anything smaller: below this, no need to look


def is_swap(content: BlockDevice) -> bool:
    """Whether a file's content is a swap area (made by mkswap). What it holds is
    memory paged out of running programs, keys and passwords among it, and none
    of it is the server's configuration: it is never read or archived.

    ファイルの中身がスワップ領域（mkswap で作ったもの）かどうか。中身は動いていたプログラムのメ
    モリで、鍵やパスワードも混じり、サーバーの設定は何も無い。読まず、アーカイブにも入れない。
    """
    if content.size < SWAP_MIN_BYTES:
        return False
    # Every probe is read, a match or not: what tell_swap_check told must be read.
    tails = [content.read_at(offset, 10) for offset in _probes(content)]
    return any(tail in _SWAP_SIGNATURES for tail in tails)


def tell_swap_check(content: BlockDevice) -> None:
    """Tell the disk what is_swap will read (will_read), so that many files can be
    checked without waiting for each.

    is_swap が読む範囲をディスクに告げる（will_read）。多くのファイルを 1 つずつ待たずに
    判定できるように。
    """
    if content.size >= SWAP_MIN_BYTES:
        for offset in _probes(content):
            will_read(content, offset, 10)


def _probes(content: BlockDevice) -> list[int]:
    """Where the swap signature may be: the last 10 bytes of each possible first page."""
    return [page - 10 for page in _PAGE_SIZES if page <= content.size]
