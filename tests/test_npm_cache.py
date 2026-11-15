"""npm packages compared with their own tarballs in the system's npm cache (cacache),
found by the lockfile's integrity: exact `modified` / `missing` instead of the guess
from the times, when every tarball is there; nothing is downloaded."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile

from memfs import MemFs

from diskread.source import SystemSource
from ec2_byhand.langpkgs import find_language_packages

APP = "/opt/app"
NM = f"{APP}/node_modules"
CACHE = "/root/.npm/_cacache"


def _tgz(files: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(f"package/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


def _cache(fs: MemFs, tarball: bytes) -> str:
    """Put a tarball in the cache as cacache does; returns its integrity string."""
    digest = hashlib.sha512(tarball).digest()
    hexed = digest.hex()
    fs.add_file(f"{CACHE}/content-v2/sha512/{hexed[:2]}/{hexed[2:4]}/{hexed[4:]}", tarball)
    return "sha512-" + base64.b64encode(digest).decode()


LEFT_PAD = {"package.json": b'{"name": "left-pad", "version": "1.3.0"}', "index.js": b"pad()\n"}
IS_NUMBER = {"package.json": b'{"name": "is-number", "version": "7.0.0"}', "index.js": b"num\n"}


def _app(*, cached: bool = True) -> MemFs:
    fs = MemFs()
    lock: dict[str, dict] = {"": {"name": "app"}}
    for rel, files in (
        ("node_modules/left-pad", LEFT_PAD),
        ("node_modules/left-pad/node_modules/is-number", IS_NUMBER),  # nested
    ):
        for name, data in files.items():
            fs.add_file(f"{APP}/{rel}/{name}", data)
        tarball = _tgz(files)
        integrity = (
            _cache(fs, tarball)
            if cached
            else "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
        )
        lock[rel] = {"version": "x", "integrity": integrity}
    fs.add_file(f"{NM}/.package-lock.json", json.dumps({"packages": lock}).encode())
    return fs


def _found(fs: MemFs) -> dict[str, object]:
    src = SystemSource.from_fs(fs)
    paths = [f"{NM}/left-pad/package.json"]
    (pkg,) = find_language_packages(src, paths)
    return {"verified_by": pkg.verified_by, "modified": pkg.modified, "missing": pkg.missing}


def test_an_untouched_package_is_verified() -> None:
    assert _found(_app()) == {"verified_by": "npm-cache", "modified": [], "missing": []}


def test_an_edit_is_found_exactly_at_any_time() -> None:
    fs = _app()
    fs.add_file(f"{NM}/left-pad/index.js", b"pad() // patched\n")  # a new size
    fs.add_file(f"{NM}/left-pad/node_modules/is-number/index.js", b"NUM\n")  # the same size
    assert _found(fs)["modified"] == [
        f"{NM}/left-pad/index.js",
        f"{NM}/left-pad/node_modules/is-number/index.js",
    ]


def test_without_the_tarballs_the_times_decide() -> None:
    assert _found(_app(cached=False))["verified_by"] is None


def test_a_deleted_file_is_missing() -> None:
    fs = MemFs()
    tarball = _tgz({**LEFT_PAD, "extra.js": b"x\n"})
    integrity = _cache(fs, tarball)
    for name, data in LEFT_PAD.items():
        fs.add_file(f"{NM}/left-pad/{name}", data)
    fs.add_file(
        f"{NM}/.package-lock.json",
        json.dumps({"packages": {"node_modules/left-pad": {"integrity": integrity}}}).encode(),
    )
    assert _found(fs) == {
        "verified_by": "npm-cache",
        "modified": [],
        "missing": [f"{NM}/left-pad/extra.js"],
    }


def _index(fs: MemFs, url: str, integrity: str) -> None:
    """Record a download in cacache's index as npm does."""
    key = "make-fetch-happen:request-cache:" + url
    entry = json.dumps({"key": key, "integrity": integrity, "time": 1, "size": 1})
    hexed = hashlib.sha256(key.encode()).hexdigest()
    line = hashlib.sha1(entry.encode()).hexdigest() + "\t" + entry
    fs.add_file(f"{CACHE}/index-v5/{hexed[:2]}/{hexed[2:4]}/{hexed[4:]}", ("\n" + line).encode())


def test_a_global_package_without_a_lockfile_is_found_by_the_cache_index() -> None:
    # Seen on AL2023 with npm 10: `npm install -g` leaves no lockfile beside the package.
    glob = "/usr/lib/node_modules"
    fs = MemFs()
    for rel, files, url in (
        ("left-pad", LEFT_PAD, "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"),
        (
            "left-pad/node_modules/is-number",
            IS_NUMBER,
            "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz",
        ),
    ):
        for name, data in files.items():
            fs.add_file(f"{glob}/{rel}/{name}", data)
        _index(fs, url, _cache(fs, _tgz(files)))
    fs.add_file(f"{glob}/left-pad/index.js", b"pad() // global edit\n")
    src = SystemSource.from_fs(fs)
    (pkg,) = find_language_packages(src, [f"{glob}/left-pad/package.json"])
    assert pkg.verified_by == "npm-cache"
    assert pkg.modified == [f"{glob}/left-pad/index.js"]
