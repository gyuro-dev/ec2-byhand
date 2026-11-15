"""Package database model shared by the rpm and dpkg readers.

rpm と dpkg のリーダーが共有する、パッケージデータベースのモデル。
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

Manager = Literal["rpm", "dpkg"]
# Told what could not be read, so that a reader can go on with the rest.
OnDamage = Callable[[str], None]


@dataclass(frozen=True)
class PackageFile:
    """One file a package installed, with what its manager recorded about it.

    パッケージが入れたファイル 1 つと、マネージャが記録している内容。
    """

    path: str
    digest: str | None = None  # hex; None for directories, symlinks or unknown
    digest_algo: str | None = None  # "md5", "sha256", ...
    mode: int | None = None  # rpm only
    size: int | None = None  # rpm only
    is_config: bool = False
    # rpm only, used to verify the file like rpm -V does:
    flags: int = 0  # RPMFILE_* (config, ghost, missingok, ...)
    state: int | None = None  # RPMFILE_STATE_*: 0 normal, 1 replaced, 2 not installed, ...
    verify: int | None = None  # RPMVERIFY_* bits to check (None: all)
    link_to: str | None = None  # symlink target
    user: str | None = None
    group: str | None = None


@dataclass(frozen=True)
class Package:
    """One installed package and its files.

    導入済みのパッケージ 1 つとそのファイル。
    """

    manager: Manager
    name: str
    arch: str | None  # None for rpm's gpg-pubkey pseudo packages
    epoch: int | None
    version: str
    release: str | None  # rpm release; for dpkg the Debian revision is part of version
    install_time: int | None = None  # seconds since the epoch (rpm only)
    status: str | None = None  # dpkg: db:Status-Abbrev, e.g. "ii "
    files: tuple[PackageFile, ...] = field(default=(), repr=False, compare=False)

    @property
    def evr(self) -> str:
        """Version as the package manager prints it.

        パッケージマネージャが表示する形の版。
        """
        if self.manager == "dpkg":
            return self.version  # already "[epoch:]upstream[-revision]"
        prefix = f"{self.epoch}:" if self.epoch else ""
        return f"{prefix}{self.version}-{self.release}"

    @property
    def key(self) -> tuple[str, str | None]:
        """The (name, arch) identity used to match packages across snapshots.

        スナップショット間でパッケージを突き合わせる (name, arch) のキー。
        """
        return self.name, self.arch


@dataclass(frozen=True)
class PackageDB:
    """Every installed package, and which manager owns the database.

    導入済みパッケージの全体と、どのマネージャの DB か。
    """

    manager: Manager
    format: str  # "rpm-sqlite", "rpm-bdb", "dpkg"
    path: str  # where the database was found
    packages: tuple[Package, ...]
    damaged: tuple[str, ...] = ()  # what could not be read: the packages are then incomplete
