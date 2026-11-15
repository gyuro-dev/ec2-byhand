"""Docker, summarized under the manifest's "containers" and hidden file by file."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from memfs import MemFs

from diskread.source import SystemSource
from ec2_byhand.analyze import Snapshot, analyze
from ec2_byhand.noise import NoiseFilter

D = "/var/lib/docker"
NGINX = "sha256:" + "1" * 64
NGINX_NEW = "sha256:" + "2" * 64
REDIS = "sha256:" + "3" * 64
WEB = "a" * 64
OLD = "b" * 64


def _docker(
    fs: MemFs,
    images: dict[str, dict[str, str]],
    containers: dict[str, dict],
    volumes: dict[str, dict[str, bytes]],
) -> None:
    fs.add_file(
        f"{D}/image/overlay2/repositories.json", json.dumps({"Repositories": images}).encode()
    )
    fs.add_file(f"{D}/overlay2/{'f' * 64}/diff/usr/bin/nginx", b"layer file")
    for cid, config in containers.items():
        fs.add_file(f"{D}/containers/{cid}/config.v2.json", json.dumps(config).encode())
        fs.add_file(f"{D}/containers/{cid}/{cid}-json.log", b"log\n")
    fs.add_file(f"{D}/volumes/metadata.db", b"bolt")
    for name, files in volumes.items():
        fs.add_dir(f"{D}/volumes/{name}/_data")
        for rel, data in files.items():
            fs.add_file(f"{D}/volumes/{name}/_data/{rel}", data)


def _web(image: str = "nginx:latest") -> dict:
    return {
        "ID": WEB,
        "Name": "/web",
        "Created": "2026-11-14T01:02:03.456789012Z",
        "Config": {"Image": image, "Env": ["DB_PASSWORD=hunter2"]},
    }


def _snap(fs: MemFs) -> Snapshot:
    return Snapshot("test", SystemSource.from_fs(fs))


def test_docker_added_since_the_baseline_is_summarized_not_listed() -> None:
    fs = MemFs()
    _docker(
        fs,
        {
            "nginx": {"nginx:latest": NGINX, "nginx@sha256:" + "9" * 64: NGINX},
            "redis": {"redis@sha256:" + "8" * 64: REDIS},  # pulled by digest only
        },
        {WEB: _web()},
        {"data": {"a.db": b"x" * 10, "sub/b.db": b"y" * 5}},
    )
    m = analyze(_snap(fs), _snap(MemFs()))
    c = m["containers"]
    assert c["images"] == [
        {"engine": "docker", "name": "nginx:latest", "id": NGINX, "status": "added"},
        {"engine": "docker", "name": "redis@sha256:" + "8" * 64, "id": REDIS, "status": "added"},
    ]
    assert c["containers"] == [
        {
            "engine": "docker",
            "name": "web",
            "id": WEB,
            "image": "nginx:latest",
            "created": "2026-11-14T01:02:03.456789012Z",
            "status": "added",
        }
    ]
    assert c["volumes"] == [
        {"engine": "docker", "name": "data", "files": 2, "bytes": 15, "status": "added"}
    ]
    assert m["summary"]["containers"] == 4
    assert not [h for h in m["hand_placed"] if h["path"].startswith(D)]
    assert "hunter2" not in json.dumps(m)  # the environment is not read
    assert m["noise"]["by_rule"]["container"] > 0


def test_the_walk_does_not_enter_image_layers() -> None:
    fs = MemFs()
    _docker(fs, {}, {}, {"data": {"a": b"x"}})
    analyze(_snap(fs))
    assert fs.ino(f"{D}/overlay2") not in fs.listed
    assert fs.ino(f"{D}/volumes/data/_data") in fs.listed  # volumes are counted
    noise = NoiseFilter()
    assert noise.pruned_by(f"{D}/overlay2") == "container"
    assert noise.pruned_by(f"{D}/volumes") is None
    assert noise.match(f"{D}/volumes/data/_data/a") == "container"


def test_only_what_changed_since_the_baseline_is_listed() -> None:
    before, after = MemFs(), MemFs()
    old = {"ID": OLD, "Name": "/old", "Config": {"Image": "redis"}}
    _docker(
        before,
        {"nginx": {"nginx:latest": NGINX}, "redis": {"redis:7": REDIS}},
        {WEB: _web(), OLD: old},
        {"data": {"a": b"x"}, "logs": {"a": b"x"}},
    )
    _docker(
        after,
        {"nginx": {"nginx:latest": NGINX_NEW}, "redis": {"redis:7": REDIS}},  # nginx pulled again
        {WEB: _web()},  # old removed
        {"data": {"a": b"x", "b": b"yy"}, "logs": {"a": b"x"}},  # data grew
    )
    m = analyze(_snap(after), _snap(before))
    c = m["containers"]
    assert c["images"] == [
        {"engine": "docker", "name": "nginx:latest", "id": NGINX_NEW, "status": "modified"}
    ]
    assert [(x["name"], x["status"]) for x in c["containers"]] == [("old", "removed")]
    assert c["volumes"] == [
        {"engine": "docker", "name": "data", "files": 2, "bytes": 3, "status": "modified"}
    ]
    assert m["summary"]["containers_unchanged_since_baseline"] == 3  # redis:7, web, logs


def test_without_a_baseline_everything_is_present() -> None:
    fs = MemFs()
    _docker(fs, {"nginx": {"nginx:latest": NGINX}}, {WEB: _web()}, {})
    c = analyze(_snap(fs))["containers"]
    assert [x["status"] for x in c["images"] + c["containers"]] == ["present", "present"]


def test_no_docker_no_section() -> None:
    m = analyze(_snap(MemFs()), _snap(MemFs()))
    assert m["containers"] is None
    assert m["summary"]["containers"] == 0


def test_damaged_docker_metadata_is_a_warning() -> None:
    fs = MemFs()
    _docker(fs, {}, {}, {})
    fs.add_file(f"{D}/image/overlay2/repositories.json", b"{not json")
    fs.add_file(f"{D}/containers/{WEB}/config.v2.json", b"\0\0\0")  # caught half-written
    m = analyze(_snap(fs))
    (w,) = [w for w in m["warnings"] if w["code"] == "container-metadata-unreadable"]
    assert len(w["entries"]) == 2
    assert m["containers"]["images"] == []


P = "/var/lib/containers/storage"
U = "/home/dev/.local/share/containers/storage"
ALPINE = "a" * 64


def _podman(fs: MemFs, store: str, containers: list[tuple[str, str]], volumes: dict) -> None:
    images = [{"id": ALPINE, "names": ["docker.io/library/alpine:3.20", "localhost/mine:1"]}]
    fs.add_file(f"{store}/overlay-images/images.json", json.dumps(images).encode())
    fs.add_file(f"{store}/overlay/{'l' * 64}/diff/bin/sh", b"layer")
    conts = [
        {
            "id": cid * 64,
            "names": [name],
            "image": ALPINE,
            "metadata": json.dumps({"image-name": "docker.io/library/alpine:3.20", "name": name}),
            "created": "2026-11-14T05:56:28.5Z",
        }
        for cid, name in containers
    ]
    fs.add_file(f"{store}/overlay-containers/containers.json", json.dumps(conts).encode())
    for name, files in volumes.items():
        fs.add_dir(f"{store}/volumes/{name}/_data")
        for rel, data in files.items():
            fs.add_file(f"{store}/volumes/{name}/_data/{rel}", data)


def test_podman_rootful_and_rootless_are_told_apart() -> None:
    # As found on Ubuntu 24.04 with podman 4.9: a tag added with `podman tag`, and a
    # user's own containers under ~/.local/share/containers/storage.
    fs = MemFs()
    _podman(fs, P, [("c", "pweb")], {"pv1": {"x.txt": b"hi\n"}})
    _podman(fs, U, [("d", "rless")], {"uv1": {}})
    fs.add_file("/var/lib/containers/cache/blob-info-cache-v1.sqlite", b"db")  # Podman's own
    fs.add_file("/home/dev/.local/share/containers/cache/blob-info-cache-v1.sqlite", b"db")
    fs.add_file("/home/dev/.config/cni/net.d/cni.lock", b"")
    m = analyze(_snap(fs), _snap(MemFs()))
    c = m["containers"]
    assert [(i.get("user"), i["name"]) for i in c["images"]] == [
        (None, "docker.io/library/alpine:3.20"),
        (None, "localhost/mine:1"),
        ("dev", "docker.io/library/alpine:3.20"),
        ("dev", "localhost/mine:1"),
    ]
    assert {i["engine"] for i in c["images"]} == {"podman"}
    assert [(x.get("user"), x["name"], x["image"]) for x in c["containers"]] == [
        (None, "pweb", "docker.io/library/alpine:3.20"),
        ("dev", "rless", "docker.io/library/alpine:3.20"),
    ]
    assert [(v.get("user"), v["name"], v["files"], v["bytes"]) for v in c["volumes"]] == [
        (None, "pv1", 1, 3),
        ("dev", "uv1", 0, 0),
    ]
    assert not [h for h in m["hand_placed"] if "/containers/" in h["path"]]
    assert fs.ino(f"{P}/overlay") not in fs.listed  # layers are not walked
    assert fs.ino(f"{U}/overlay") not in fs.listed


def _containerd_fs() -> MemFs:
    fs = MemFs()
    db = gzip.decompress((Path(__file__).parent / "data" / "containerd-meta.db.gz").read_bytes())
    fs.add_file("/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db", db)
    fs.add_file("/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs/x", b"")
    return fs


def test_containerd_by_namespace_without_cri_id_aliases() -> None:
    m = analyze(_snap(_containerd_fs()), _snap(MemFs()))
    c = m["containers"]
    assert [(i["namespace"], i["name"]) for i in c["images"]] == [
        ("default", "docker.io/library/redis:7-alpine"),
        ("k8s.io", "docker.io/library/busybox:1.36"),  # its sha256:<id> alias left out
    ]
    assert c["images"][0]["id"].startswith("sha256:7f7d30b7")
    assert [(x["namespace"], x["name"], x["image"]) for x in c["containers"]] == [
        ("default", "credis", "docker.io/library/redis:7-alpine"),
        ("k8s.io", "kbox", "docker.io/library/busybox:1.36"),
    ]
    assert c["containers"][0]["created"].startswith("2026-11-14T06:03:03")
    assert not [h for h in m["hand_placed"] if h["path"].startswith("/var/lib/containerd")]


def test_a_half_written_containerd_database_is_a_warning() -> None:
    fs = MemFs()
    fs.add_file("/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db", b"\0" * 8192)
    m = analyze(_snap(fs))
    (w,) = [w for w in m["warnings"] if w["code"] == "container-metadata-unreadable"]
    assert w["entries"] == ["/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"]


def test_the_same_image_in_two_engines_is_two_items() -> None:
    fs = MemFs()
    _docker(fs, {"alpine": {"docker.io/library/alpine:3.20": NGINX}}, {}, {})
    _podman(fs, P, [], {})
    images = analyze(_snap(fs), _snap(MemFs()))["containers"]["images"]
    alpine = [i for i in images if i["name"] == "docker.io/library/alpine:3.20"]
    assert sorted(i["engine"] for i in alpine) == ["docker", "podman"]
