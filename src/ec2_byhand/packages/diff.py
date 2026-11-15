"""Compare two package databases (e.g. the AMI's and the current one).

2 つのパッケージデータベース（AMI のものと現在のものなど）の比較。
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Literal

from ec2_byhand.packages.model import Package, PackageDB
from ec2_byhand.packages.vercmp import dpkg_compare, rpm_evr_compare

ChangeKind = Literal["added", "removed", "upgraded", "downgraded", "changed", "reinstalled"]


@dataclass(frozen=True)
class PackageChange:
    """One package-level change between the two databases.

    2 つのデータベース間のパッケージ単位の変更 1 つ。
    """

    kind: ChangeKind
    name: str
    arch: str | None
    before: Package | None
    after: Package | None


def compare_versions(a: Package, b: Package) -> int:
    """Order two versions of the same package with its manager's own rules.

    同じパッケージの 2 つの版を、そのパッケージマネージャ自身の規則で比べる。
    """
    if a.manager == "dpkg":
        return dpkg_compare(a.version, b.version)
    return rpm_evr_compare((a.epoch, a.version, a.release), (b.epoch, b.version, b.release))


def diff_packages(before: PackageDB, after: PackageDB) -> list[PackageChange]:
    """Changes keyed by (name, arch).

    One version on each side: upgraded / downgraded (by the package
    manager's own ordering), "changed" if the versions differ only in
    spelling, "reinstalled" if the version is the same but rpm's install
    time moved. Several versions side by side (kernels): each version that
    appeared is "added", each that went away "removed".

    (name, arch) ごとの変更。両側に 1 版ずつなら upgraded / downgraded（パッケージマネージャ自
    身の順序で判定）、版の表記だけが違えば「changed」、同じ版で rpm のインストール時刻が動いて
    いれば「reinstalled」。複数の版が並ぶもの（カーネルなど）は、現れた版が「added」、消えた版
    が「removed」。
    """
    if before.manager != after.manager:
        raise ValueError("cannot compare rpm and dpkg databases")
    groups: dict[tuple[str, str | None], tuple[list[Package], list[Package]]] = defaultdict(
        lambda: ([], [])
    )
    for p in before.packages:
        groups[p.key][0].append(p)
    for p in after.packages:
        groups[p.key][1].append(p)

    out: list[PackageChange] = []
    for (name, arch), (old, new) in sorted(
        groups.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")
    ):
        if len(old) == 1 and len(new) == 1:
            a, b = old[0], new[0]
            if a.evr == b.evr:
                if (
                    a.install_time is not None
                    and b.install_time is not None
                    and a.install_time != b.install_time
                ):
                    out.append(PackageChange("reinstalled", name, arch, a, b))
                continue
            c = compare_versions(a, b)
            kind: ChangeKind = "upgraded" if c < 0 else "downgraded" if c > 0 else "changed"
            out.append(PackageChange(kind, name, arch, a, b))
            continue
        old_evrs = {p.evr: p for p in old}
        new_evrs = {p.evr: p for p in new}
        out.extend(
            PackageChange("removed", name, arch, old_evrs[evr], None)
            for evr in sorted(old_evrs.keys() - new_evrs.keys())
        )
        out.extend(
            PackageChange("added", name, arch, None, new_evrs[evr])
            for evr in sorted(new_evrs.keys() - old_evrs.keys())
        )
    return out
