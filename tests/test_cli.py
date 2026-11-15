"""The ec2-byhand command, end to end on the build_verify.sh before/after images."""

from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path

import pytest
from conftest import GOLDEN_DIR
from memfs import MemFs

from diskread import FileDevice
from diskread.fs import lookup
from diskread.fs.ext4 import Ext4
from diskread.source import SystemSource
from diskread.system import scan
from ec2_byhand.analyze import Snapshot, analyze
from ec2_byhand.archive import ArchiveOptions, _TarWriter
from ec2_byhand.cli import main, open_disks, parse_size
from ec2_byhand.noise import NoiseFilter

CASE = "al2023"
CURRENT = GOLDEN_DIR / f"verify-{CASE}.img"
BASELINE = GOLDEN_DIR / f"verify-{CASE}-before.img"


def _need_images() -> None:
    if not BASELINE.exists():
        pytest.skip(
            "no golden data; run: wsl -u root -- bash tools/golden/build_verify.sh tests/golden/out"
        )


def _scenario() -> dict[str, str]:
    text = (GOLDEN_DIR / f"verify-{CASE}" / "scenario.txt").read_text()
    return dict(line.split("=", 1) for line in text.splitlines())


@pytest.fixture(scope="module")
def run(tmp_path_factory) -> Path:
    _need_images()
    out = tmp_path_factory.mktemp("out")
    assert (
        main(
            [
                "--current-image",
                str(CURRENT),
                "--baseline-image",
                str(BASELINE),
                "-o",
                str(out),
                "-q",
            ]
        )
        == 0
    )
    return out


def _members(path: Path) -> dict[str, tuple[tarfile.TarInfo, bytes | None]]:
    out = {}
    with tarfile.open(path, encoding="utf-8", errors="surrogateescape") as tar:
        for info in tar:
            data = tar.extractfile(info).read() if info.isreg() else None
            out["/" + info.name] = (info, data)
    return out


def test_after_archive_matches_manifest(run: Path) -> None:
    m = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    after = _members(run / "after.tar.gz")
    for h in m["hand_placed"]:
        if h.get("sensitive"):
            continue
        info, data = after[h["path"]]
        assert {"reg": info.isreg(), "dir": info.isdir(), "lnk": info.issym()}[h["type"]]
        assert f"{info.mode:04o}" == h["mode"]
        assert (info.uid, info.gid) == (h["uid"], h["gid"])
        if h["type"] == "reg":
            assert hashlib.sha256(data).hexdigest() == h["sha256"]
        if h["type"] == "lnk":
            assert info.linkname == h["target"]
    s = _scenario()
    assert after[s["config"]][1].endswith(b"# hand edit\n")
    assert after[s["edited"]][1].endswith(b"\0hand")
    assert s["deleted"] not in after  # gone: nothing to archive
    assert after[s["relinked"]][0].linkname == "/nonexistent/target"
    assert after[s["site"] + "/requests/__version__.py"][1].endswith(
        b"# hand patch\n"
    )  # edited pip file
    assert m["archives"]["after"]["entries"] == len(after)


def test_secret_is_reported_but_not_archived(run: Path) -> None:
    m = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    key = next(h for h in m["hand_placed"] if h["path"] == "/root/.ssh/id_rsa")
    assert key["sensitive"] is True
    assert "/root/.ssh/id_rsa" not in _members(run / "after.tar.gz")
    assert {"archive": "after", "path": "/root/.ssh/id_rsa", "reason": "sensitive"} in m[
        "archives"
    ]["skipped"]


def test_before_archive_and_patches(run: Path) -> None:
    before = _members(run / "before.tar.gz")
    s = _scenario()
    assert before["/opt/legacy/change.txt"][1] == b"version 1\n"
    assert before["/opt/legacy/remove.txt"][1] == b"to be removed\n"
    assert not before[s["config"]][1].endswith(b"# hand edit\n")
    assert s["deleted"] in before  # the package file as it was before someone deleted it
    assert "/opt/myapp/bin/run.sh" not in before  # added since: no earlier version

    patch = (run / "patches" / (s["config"].lstrip("/") + ".diff")).read_text(encoding="utf-8")
    assert "+# hand edit" in patch
    assert patch.startswith(f"--- a{s['config']}")
    change = (run / "patches" / "opt/legacy/change.txt.diff").read_text(encoding="utf-8")
    assert "-version 1" in change
    assert "+version 2" in change


def test_archives_are_reproducible(run: Path, tmp_path: Path) -> None:
    assert (
        main(
            [
                "--current-image",
                str(CURRENT),
                "--baseline-image",
                str(BASELINE),
                "-o",
                str(tmp_path),
                "-q",
            ]
        )
        == 0
    )
    for name in ("after.tar.gz", "before.tar.gz"):
        assert (tmp_path / name).read_bytes() == (run / name).read_bytes()


def test_options(tmp_path: Path) -> None:
    _need_images()
    out = tmp_path / "o"
    assert (
        main(
            [
                "--current-image",
                str(CURRENT),
                "--baseline-image",
                str(BASELINE),
                "-o",
                str(out),
                "-q",
                "--max-file-size",
                "10K",
                "--include-sensitive",
                "--exclude",
                "/var/www/**",
            ]
        )
        == 0
    )
    m = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    after = _members(out / "after.tar.gz")
    assert "/opt/myapp/bin/server" not in after  # 50000 bytes > 10K
    assert {"archive": "after", "path": "/opt/myapp/bin/server", "reason": "too-large"} in m[
        "archives"
    ]["skipped"]
    assert after["/root/.ssh/id_rsa"][0].mode == 0o600
    assert not any(h["path"].startswith("/var/www") for h in m["hand_placed"])
    assert m["noise"]["by_rule"]["user-exclude"] == 1  # the directory: it was not walked


@pytest.mark.parametrize("readme", ["README.md", "README.ja.md"])
def test_readme_python_example_works_on_a_real_disk(readme: str, tmp_path, monkeypatch) -> None:
    _need_images()
    text = (Path(__file__).parent.parent / readme).read_text(encoding="utf-8")
    example = text.split("```python\n", 1)[1].split("```", 1)[0]
    example = example.replace('"current.img"', repr(str(CURRENT)))
    example = example.replace('"ami.img"', repr(str(BASELINE)))
    monkeypatch.chdir(tmp_path)
    exec(example, {})
    assert json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))["hand_placed"]


def test_open_disks_reads_a_disk_with_partitions() -> None:
    image = GOLDEN_DIR / "system-a.img"
    if not image.exists():
        pytest.skip("no golden images; run tools/golden/build_system.sh")
    with FileDevice(image) as dev:
        assert b"/boot/efi" in open_disks({"disk0": dev}, "x").source.mounts


def test_without_baseline_and_errors(tmp_path: Path, capsys) -> None:
    _need_images()
    out = tmp_path / "o"
    assert main(["--current-image", str(CURRENT), "-o", str(out)]) == 0
    assert (out / "after.tar.gz").exists()
    assert not (out / "before.tar.gz").exists()
    assert "warning: no-baseline" in capsys.readouterr().out
    assert main(["--current-image", str(CURRENT), "-o", str(out), "-q"]) == 2  # not empty
    assert main(["--current-image", str(tmp_path / "nope.img"), "-o", str(tmp_path / "x")]) == 2
    assert "no such image file" in capsys.readouterr().err


def test_parse_size() -> None:
    assert parse_size("500") == 500
    assert parse_size("10K") == 10 << 10
    assert parse_size("1.5M") == int(1.5 * (1 << 20))
    assert parse_size("2GiB") == 2 << 30


def test_pax_time_keeps_nanoseconds() -> None:
    from ec2_byhand.archive import pax_time

    assert pax_time(1_600_000_000_999_999_999) == "1600000000.999999999"
    assert pax_time(-876_543_211) == "-0.876543211"
    assert pax_time(-(2**31) * 10**9) == "-2147483648.000000000"


def test_verify_checksums(run: Path, tmp_path: Path) -> None:
    out = tmp_path / "o"
    args = [
        "--current-image",
        str(CURRENT),
        "--baseline-image",
        str(BASELINE),
        "-o",
        str(out),
        "-q",
        "--no-archives",
    ]
    assert main([*args, "--verify-checksums"]) == 0
    checked = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    plain = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    assert checked["hand_placed"] == plain["hand_placed"]
    assert not [w for w in checked["warnings"] if w["code"] == "read-error"]


class _Flipped:
    """A device with one bit flipped, as on-disk corruption would leave it."""

    def __init__(self, dev, at: int) -> None:
        self._dev, self._at = dev, at
        self.size = dev.size

    def read_at(self, offset: int, length: int) -> bytes:
        data = bytearray(self._dev.read_at(offset, length))
        if offset <= self._at < offset + length:
            data[self._at - offset] ^= 0x01
        return bytes(data)


def test_checksum_mismatch_is_a_read_error() -> None:
    _need_images()
    target = _scenario()["config"]
    with FileDevice(CURRENT) as dev:
        fs = Ext4(dev)
        ino = lookup(fs, target)
        sb = fs.superblock
        group, index = divmod(ino - 1, sb.inodes_per_group)
        at = fs._groups.inode_table(group) * sb.block_size + index * sb.inode_size + 0x10  # i_mtime

        def manifest(verify: bool) -> dict:
            (vol,) = scan({"disk0": _Flipped(dev, at)}, verify)
            return analyze(Snapshot("current", SystemSource.from_fs(vol.fs)), None, NoiseFilter())

        message = f"checksum mismatch: ext4 inode {ino}"
        m = manifest(True)
        errors = [(w["path"], w["message"]) for w in m["warnings"] if w["code"] == "read-error"]
        assert errors == [(target, message)]  # from the walk; the rest of the tree is still read
        (item,) = [i for i in m["modified_package_files"] if i["path"] == target]
        assert item["problems"] == ["unreadable"]
        assert item["error"] == message
        m = manifest(False)
        assert not [w for w in m["warnings"] if w["code"] == "read-error"]
        assert not [i for i in m["modified_package_files"] if "unreadable" in i["problems"]]


def test_a_filesystem_keeps_many_inodes_as_bytes_and_few_parsed() -> None:
    # A parsed inode takes four times its bytes; kept parsed, 262,144 of them were half
    # of a run's memory. The bytes are what saves a second read of the disk.
    from diskread.fs import INODE_CACHE, PARSED_INODES

    _need_images()

    class Counting:
        def __init__(self, dev) -> None:
            self._dev, self.size, self.reads = dev, dev.size, 0

        def read_at(self, offset: int, length: int) -> bytes:
            self.reads += 1
            return self._dev.read_at(offset, length)

    with FileDevice(CURRENT) as dev:
        counting = Counting(dev)
        fs = Ext4(counting)
        assert fs._inode_bytes.cache_info().maxsize == INODE_CACHE > PARSED_INODES
        assert fs.inode.cache_info().maxsize == PARSED_INODES
        ino = lookup(fs, _scenario()["config"])
        first = fs.stat(ino)
        reads = counting.reads
        fs.inode.cache_clear()  # as when many other inodes were parsed in between
        assert fs.stat(ino) == first
        assert counting.reads == reads  # parsed again from the bytes: the disk is not read
        assert not hasattr(fs.inode(ino), "__dict__")


def test_hard_links_are_archived_once(tmp_path: Path) -> None:
    fs = MemFs()
    fs.add_file("/opt/app/bin", b"payload" * 100, mode=0o755)
    fs.add_hardlink("/usr/local/bin/app", "/opt/app/bin")
    fs.add_file("/root/.ssh/id_rsa", b"secret")
    fs.add_hardlink("/opt/key", "/root/.ssh/id_rsa")
    src = SystemSource.from_fs(fs)
    tar_path = tmp_path / "a.tar.gz"
    w = _TarWriter(tar_path, "after", ArchiveOptions())
    for p in ("/opt/app/bin", "/usr/local/bin/app", "/root/.ssh/id_rsa", "/opt/key"):
        w.add(src, p)
    w.close()
    with tarfile.open(tar_path) as tar:
        members = {m.name: m for m in tar}
        assert members["opt/app/bin"].isreg()
        assert members["usr/local/bin/app"].islnk()
        assert members["usr/local/bin/app"].linkname == "opt/app/bin"
        assert tar.extractfile(members["usr/local/bin/app"]).read() == b"payload" * 100
        # The first name was left out (sensitive), so the second carries the data.
        assert "root/.ssh/id_rsa" not in members
        assert members["opt/key"].isreg()
