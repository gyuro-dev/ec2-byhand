"""Grey-zone grouping: pip / npm packages and alternatives."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from memfs import MemFs

from diskread.source import SystemSource
from ec2_byhand.langpkgs import find_alternatives, find_language_packages


def _record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _all_paths(src: SystemSource) -> list[str]:
    return [p.decode() for p, *_ in src.walk()]


def test_pip_dist_info_record_check() -> None:
    fs = MemFs()
    site = "/usr/local/lib/python3.12/site-packages"
    good, edited = b"print('ok')\n", b"VERSION = '1'\n"
    fs.add_file(f"{site}/demo/__init__.py", good)
    fs.add_file(f"{site}/demo/version.py", edited + b"# hand patch\n")
    fs.add_file(
        f"{site}/demo-1.2.dist-info/METADATA",
        b"Metadata-Version: 2.1\nName: demo\nVersion: 1.2\n\nbody\n",
    )
    fs.add_file(f"{site}/demo-1.2.dist-info/INSTALLER", b"pip\n")
    record = (
        f"demo/__init__.py,{_record_hash(good)},{len(good)}\n"
        f"demo/version.py,{_record_hash(edited)},{len(edited)}\n"
        f"demo/gone.py,{_record_hash(b'x')},1\n"
        f"demo-1.2.dist-info/RECORD,,\n"
    )
    fs.add_file(f"{site}/demo-1.2.dist-info/RECORD", record.encode())
    src = SystemSource.from_fs(fs)

    (pkg,) = find_language_packages(src, _all_paths(src))
    assert (pkg.ecosystem, pkg.name, pkg.version, pkg.installer) == ("pypi", "demo", "1.2", "pip")
    assert pkg.modified == [f"{site}/demo/version.py"]
    assert pkg.missing == [f"{site}/demo/gone.py"]
    assert f"{site}/demo/__init__.py" in pkg.files
    assert f"{site}/demo-1.2.dist-info" in pkg.files


def test_pip_egg_info_and_npm_globals() -> None:
    fs = MemFs()
    egg = "/usr/lib/python3.6/site-packages/old.egg-info"
    fs.add_file(f"{egg}/PKG-INFO", b"Name: old\nVersion: 0.9\n")
    fs.add_file(f"{egg}/installed-files.txt", b"../old/__init__.py\n../old/missing.py\n")
    fs.add_file("/usr/lib/python3.6/site-packages/old/__init__.py", b"")
    for name in ("pm2", "@aws-cdk/cli"):
        fs.add_file(
            f"/usr/local/lib/node_modules/{name}/package.json",
            json.dumps({"name": name, "version": "5.0.0"}).encode(),
        )
        fs.add_file(f"/usr/local/lib/node_modules/{name}/index.js", b"//")
        # A dependency's package.json deeper down is not a separate global package.
        fs.add_file(
            f"/usr/local/lib/node_modules/{name}/node_modules/dep/package.json", b'{"name": "dep"}'
        )
    src = SystemSource.from_fs(fs)

    found = {(p.ecosystem, p.name): p for p in find_language_packages(src, _all_paths(src))}
    assert set(found) == {("pypi", "old"), ("npm", "pm2"), ("npm", "@aws-cdk/cli")}
    assert found[("pypi", "old")].missing == ["/usr/lib/python3.6/site-packages/old/missing.py"]
    cdk = found[("npm", "@aws-cdk/cli")]
    assert cdk.version == "5.0.0"
    assert "/usr/local/lib/node_modules/@aws-cdk/cli/node_modules/dep/package.json" in cdk.files


@pytest.mark.parametrize("state_dir", ["/var/lib/alternatives", "/var/lib/dpkg/alternatives"])
def test_alternatives(state_dir: str) -> None:
    fs = MemFs()
    fs.add_file(
        f"{state_dir}/editor",
        b"manual\n/usr/bin/editor\neditor.1.gz\n/usr/share/man/man1/editor.1.gz\n\n/usr/bin/vim\n50\n",
    )
    fs.add_file(f"{state_dir}/pager", b"auto\n/usr/bin/pager\n\n/usr/bin/less\n77\n")
    fs.add_link("/etc/alternatives/editor", "/usr/bin/vim")
    fs.add_link("/etc/alternatives/pager", "/usr/bin/less")
    alts = {a.name: a for a in find_alternatives(SystemSource.from_fs(fs))}
    assert alts["editor"].mode == "manual"
    assert alts["editor"].current == "/usr/bin/vim"
    assert set(alts["editor"].links) == {
        "/usr/bin/editor",
        "/etc/alternatives/editor",
        "/usr/share/man/man1/editor.1.gz",
        "/etc/alternatives/editor.1.gz",
    }
    assert alts["pager"].mode == "auto"


def test_alternative_links_resolve_through_symlinked_dirs() -> None:
    """The state file says /lib/cpp; with /lib -> usr/lib it lives at /usr/lib/cpp."""
    from ec2_byhand.analyze import Snapshot, analyze

    fs = MemFs()
    fs.add_link("/lib", "usr/lib")
    fs.add_file("/usr/bin/cpp-13", b"")
    fs.add_link("/usr/lib/cpp", "/etc/alternatives/cpp")
    fs.add_link("/etc/alternatives/cpp", "/usr/bin/cpp-13")
    fs.add_file("/var/lib/dpkg/alternatives/cpp", b"auto\n/lib/cpp\n\n/usr/bin/cpp-13\n10\n")
    fs.add_file("/opt/hand.txt", b"mine\n")
    m = analyze(Snapshot("memfs", SystemSource.from_fs(fs)))
    paths = {h["path"] for h in m["hand_placed"]}
    assert "/opt/hand.txt" in paths
    assert "/usr/lib/cpp" not in paths
    assert "/etc/alternatives/cpp" not in paths
    assert [a["name"] for a in m["alternatives"]] == ["cpp"]
