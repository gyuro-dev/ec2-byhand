"""What was done with containers, read from the engines' own metadata, not file by file.

The engines keep their state in directories nobody edits by hand (the configuration
is under /etc/docker, /etc/containers, /etc/containerd): image layers, containers
and volumes, tens of thousands of files. The noise rules hide them and the walk does
not enter the layers; what they say of the hand work is summarized instead:

  docker      /var/lib/docker
              images      image/<driver>/repositories.json: each tag (or, for an
                          image pulled by digest only, its digest reference) and id
              containers  containers/<id>/config.v2.json: name, image as given to
                          `docker run`, creation time
              volumes     volumes/<name>/_data
  podman      /var/lib/containers/storage, and each user's own (rootless) store
              ~/.local/share/containers/storage, told apart by "user"
              images      overlay-images/images.json: names and id
              containers  overlay-containers/containers.json: name, image name (from
                          its metadata), creation time
              volumes     volumes/<name>/_data
  containerd  /var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db (bbolt),
              by namespace; "moby" is Docker's own and left to docker above
              images      v1/<ns>/images/<name>: target digest
              containers  v1/<ns>/containers/<id>: image name, creation time

A container's environment, which often holds passwords, is never read. A volume is
counted from the walk: its regular files and their bytes. Compared with the baseline
by (engine, user or namespace, image name / container id / volume name).

コンテナでしたことを、ファイル 1 つずつではなく各エンジンのメタデータから読む。エンジンの
状態の置き場は手では編集しない（設定は /etc/docker・/etc/containers・/etc/containerd）。
イメージの層・コンテナ・ボリュームで何万ものファイルがあり、ノイズの規則で隠して層の中は
走査しない。代わりに手作業として何をしたかをまとめる: docker（repositories.json・
config.v2.json・volumes）、podman（/var/lib/containers/storage と各ユーザーの
~/.local/share/containers/storage。images.json・containers.json・volumes。ユーザーで区別）、
containerd（meta.db を名前空間ごとに。"moby" は Docker 自身のものなので docker に任せる）。
パスワードを含みがちな環境変数は読まない。ボリュームは走査の結果から通常ファイルの数と容量を
数える。baseline とは（エンジン、ユーザーまたは名前空間、イメージ名・コンテナ ID・ボリューム
名）で比べる。
"""

from __future__ import annotations

import bisect
import json
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from diskread.errors import DiskReadError
from diskread.fs import FileType, Stat
from diskread.source import SystemSource
from ec2_byhand.bolt import Bolt

DOCKER_DIR = "/var/lib/docker"
PODMAN_DIR = "/var/lib/containers/storage"
PODMAN_USER_DIR = ".local/share/containers/storage"  # below a home directory
CONTAINERD_DIR = "/var/lib/containerd"
CONTAINERD_DB = f"{CONTAINERD_DIR}/io.containerd.metadata.v1.bolt/meta.db"
CONTAINERD_SKIP = {b"moby"}  # Docker's namespace: its containers are Docker's


@dataclass(frozen=True)
class ContainerImage:
    """One image reference (a tag, or a digest reference) and the image it names.

    イメージの参照 1 つ（タグ、またはダイジェストでの参照）と、それが指すイメージ。
    """

    engine: str  # "docker", "podman" or "containerd"
    scope: str | None  # a rootless Podman's user, or a containerd namespace
    name: str  # e.g. "nginx:latest"
    id: str  # e.g. "sha256:..."


@dataclass(frozen=True)
class Container:
    """One container: its name, the image it was created from, and when.

    コンテナ 1 つ: 名前、作成元のイメージ、作成日時。
    """

    engine: str
    scope: str | None
    id: str
    name: str
    image: str | None  # as given to `run` / compose
    created: str | None  # RFC 3339


@dataclass(frozen=True)
class Volume:
    """One named volume: how many regular files it holds, and their bytes.

    名前付きボリューム 1 つ: 通常ファイルの数と、その合計バイト数。
    """

    engine: str
    scope: str | None
    name: str
    files: int
    bytes: int


@dataclass(frozen=True)
class Containers:
    """What read_containers found, and the metadata files it could not read.

    read_containers が見つけたものと、読めなかったメタデータのファイル。
    """

    images: tuple[ContainerImage, ...]
    containers: tuple[Container, ...]
    volumes: tuple[Volume, ...]
    damaged: tuple[str, ...]


@dataclass
class _Found:
    images: list[ContainerImage]
    containers: list[Container]
    volumes: list[Volume]
    damaged: list[str]


def _json(src: SystemSource, path: str, found: _Found) -> Any:
    """The JSON at `path`; None if it is missing, recorded as damaged if not JSON."""
    data = src.try_read(path)
    if data is None:
        return None
    try:
        return json.loads(data.decode("utf-8", "replace"))
    except ValueError:
        found.damaged.append(path)
        return None


def _names(src: SystemSource, path: str, damaged: list[str]) -> list[str] | None:
    """The names in the directory at `path`, None if it is not one. A directory that
    cannot be read (itself, or one on the way to it) is recorded as damaged and counts
    as absent: one bad directory must not cost the run."""
    try:
        return src.listdir(path)
    except DiskReadError:
        damaged.append(path)
        return None


class _Paths:
    """What the walk found, to count what lies below a directory without looking at
    every path for each volume (a server may have a million paths and many volumes)."""

    def __init__(self, stats: Mapping[str, Stat]) -> None:
        self._stats = stats
        self._sorted: list[str] | None = None  # made on first use: most servers have no volume

    def __contains__(self, path: str) -> bool:
        return path in self._stats

    def below(self, directory: str) -> tuple[int, int]:
        """(regular files, their bytes) below `directory`."""
        if self._sorted is None:
            self._sorted = sorted(self._stats)
        prefix = directory + "/"
        files = size = 0
        for path in self._sorted[bisect.bisect_left(self._sorted, prefix) :]:
            if not path.startswith(prefix):
                break
            st = self._stats[path]
            if st.type is FileType.REG:
                files += 1
                size += st.size
        return files, size


def _volumes(
    src: SystemSource, engine: str, scope: str | None, base: str, paths: _Paths, found: _Found
) -> list[Volume]:
    """Each named volume under `base` (<name>/_data): its regular files and bytes."""
    out = []
    for name in _names(src, base, found.damaged) or []:
        data = f"{base}/{name}/_data"
        if data not in paths:
            continue  # metadata.db and backingFsBlockDev are not volumes
        out.append(Volume(engine, scope, name, *paths.below(data)))
    return out


# --- docker --------------------------------------------------------------------------


def _docker(src: SystemSource, paths: _Paths, found: _Found) -> None:
    """Docker's images, containers and volumes into `found`."""
    images: dict[str, ContainerImage] = {}
    for driver in _names(src, f"{DOCKER_DIR}/image", found.damaged) or []:
        path = f"{DOCKER_DIR}/image/{driver}/repositories.json"
        data = _json(src, path, found)
        if data is None:
            continue
        repos = data.get("Repositories") if isinstance(data, dict) else None
        if not isinstance(repos, dict):
            found.damaged.append(path)
            continue
        for refs in repos.values():
            if not isinstance(refs, dict):
                continue
            tagged = {r: i for r, i in refs.items() if "@" not in r}
            # An image pulled by digest only has no tag: its digest reference names it.
            for ref, image_id in (tagged or refs).items():
                if isinstance(ref, str) and isinstance(image_id, str):
                    images[ref] = ContainerImage("docker", None, ref, image_id)
    found.images += images.values()
    for cid in _names(src, f"{DOCKER_DIR}/containers", found.damaged) or []:
        path = f"{DOCKER_DIR}/containers/{cid}/config.v2.json"
        data = _json(src, path, found)
        if data is None:
            continue
        if not isinstance(data, dict):
            found.damaged.append(path)
            continue
        raw_config = data.get("Config")
        config: dict[str, Any] = raw_config if isinstance(raw_config, dict) else {}
        name, image, created = data.get("Name"), config.get("Image"), data.get("Created")
        found.containers.append(
            Container(
                "docker",
                None,
                str(data.get("ID") or cid),
                name.lstrip("/") if isinstance(name, str) and name else cid[:12],
                image if isinstance(image, str) else None,
                created if isinstance(created, str) else None,
            )
        )
    found.volumes += _volumes(src, "docker", None, f"{DOCKER_DIR}/volumes", paths, found)


# --- podman --------------------------------------------------------------------------


def podman_stores(
    src: SystemSource, damaged: list[str] | None = None
) -> list[tuple[str | None, str]]:
    """(user, store directory) of every Podman store: the system's (user None), and
    each home's own, rootless one, for the user it belongs to. A place that cannot be
    read is added to `damaged` and counts as no store.

    Podman のストアすべての（ユーザー、ディレクトリ）。システムのもの（ユーザーは None）と、
    各ホームの rootless のもの（その持ち主）。読めない場所は `damaged` に足し、ストアは無い
    ものとして扱う。
    """
    damaged = [] if damaged is None else damaged
    out: list[tuple[str | None, str]] = []
    if _names(src, PODMAN_DIR, damaged) is not None:
        out.append((None, PODMAN_DIR))
    homes = [("root", "/root")] + [(u, f"/home/{u}") for u in src.try_listdir("/home") or []]
    for user, home in homes:
        store = f"{home}/{PODMAN_USER_DIR}"
        if _names(src, store, damaged) is not None:
            out.append((user, store))
    return out


def _podman(
    src: SystemSource, stores: list[tuple[str | None, str]], paths: _Paths, found: _Found
) -> None:
    """Every Podman store's images, containers and volumes into `found`."""
    for user, store in stores:
        images = _json(src, f"{store}/overlay-images/images.json", found)
        for image in images if isinstance(images, list) else []:
            if not isinstance(image, dict) or not isinstance(image.get("id"), str):
                continue
            names = image.get("names")
            for name in names if isinstance(names, list) else []:
                if isinstance(name, str):
                    found.images.append(
                        ContainerImage("podman", user, name, "sha256:" + image["id"])
                    )
        conts = _json(src, f"{store}/overlay-containers/containers.json", found)
        for c in conts if isinstance(conts, list) else []:
            if not isinstance(c, dict) or not isinstance(c.get("id"), str):
                continue
            try:
                meta = json.loads(c.get("metadata") or "{}")
            except (TypeError, ValueError):
                meta = {}
            names = c.get("names")
            name = c["id"][:12]
            if isinstance(names, list) and names and isinstance(names[0], str):
                name = names[0]
            image = meta.get("image-name") if isinstance(meta, dict) else None
            created = c.get("created")
            found.containers.append(
                Container(
                    "podman",
                    user,
                    c["id"],
                    name,
                    image if isinstance(image, str) else None,
                    created if isinstance(created, str) else None,
                )
            )
        found.volumes += _volumes(src, "podman", user, f"{store}/volumes", paths, found)


# --- containerd ----------------------------------------------------------------------


_GO_EPOCH = datetime(1, 1, 1, tzinfo=UTC)


def go_time(raw: bytes | None) -> str | None:
    """A Go time.Time as MarshalBinary writes it (as containerd stores times), in
    RFC 3339; None if it is not one.

    Go の time.Time を MarshalBinary の形式から RFC 3339 に（containerd が時刻を置く形式）。
    違えば None。
    """
    if raw is None or len(raw) < 15 or raw[0] not in (1, 2):
        return None
    sec, nsec = struct.unpack_from(">qi", raw, 1)
    try:
        t = _GO_EPOCH + timedelta(seconds=sec, microseconds=nsec // 1000)
    except OverflowError:
        return None
    return t.isoformat().replace("+00:00", "Z")


def _text(raw: bytes | None) -> str | None:
    return None if raw is None else raw.decode("utf-8", "replace")


def _is_bare_id(name: str) -> bool:
    """Whether an image name is only an id ("sha256:<hex>"), as Kubernetes' CRI adds."""
    algo, sep, hexa = name.partition(":")
    return sep == ":" and algo == "sha256" and len(hexa) == 64


def _containerd(src: SystemSource, found: _Found) -> None:
    """containerd's images and containers, every namespace but Docker's, into `found`."""
    data = src.try_read(CONTAINERD_DB)
    if data is None:
        return
    try:
        db = Bolt(data)
        namespaces = db.bucket(b"v1") or {}
        for ns in sorted(namespaces):
            if ns in CONTAINERD_SKIP or namespaces[ns] is not None:
                continue
            scope = ns.decode("utf-8", "replace")
            images = {
                name.decode("utf-8", "replace"): _text(
                    (db.bucket(b"v1", ns, b"images", name, b"target") or {}).get(b"digest")
                )
                or ""
                for name in db.bucket(b"v1", ns, b"images") or {}
            }
            named = {digest for name, digest in images.items() if not _is_bare_id(name)}
            for name, digest in sorted(images.items()):
                # Kubernetes' CRI also files each image under its id: an alias, not a pull.
                if _is_bare_id(name) and digest in named:
                    continue
                found.images.append(ContainerImage("containerd", scope, name, digest))
            for cid in sorted(db.bucket(b"v1", ns, b"containers") or {}):
                c = db.bucket(b"v1", ns, b"containers", cid) or {}
                text = cid.decode("utf-8", "replace")
                found.containers.append(
                    Container(
                        "containerd",
                        scope,
                        text,
                        text,
                        _text(c.get(b"image")),
                        go_time(c.get(b"createdat")),
                    )
                )
    except DiskReadError:  # half-written, or not bbolt after all
        found.damaged.append(CONTAINERD_DB)


def _by_name(x: ContainerImage | Volume) -> tuple[str, str, str]:
    return (x.engine, x.scope or "", x.name)


def read_containers(src: SystemSource, stats: Mapping[str, Stat]) -> Containers | None:
    """The container engines' images, containers and volumes on this snapshot, or None
    without any engine. `stats` is what the walk found, path -> stat: the volumes are
    counted from it.

    このスナップショットのコンテナエンジンのイメージ・コンテナ・ボリューム。どのエンジンも
    無ければ None。`stats` は走査が見つけたパス → stat で、ボリュームはそこから数える。
    """
    found = _Found([], [], [], [])
    has_docker = _names(src, DOCKER_DIR, found.damaged) is not None
    stores = podman_stores(src, found.damaged)
    has_containerd = _names(src, CONTAINERD_DIR, found.damaged) is not None
    # A place that could not be looked at is said (damaged), engine or not.
    if not (has_docker or stores or has_containerd or found.damaged):
        return None
    paths = _Paths(stats)
    if has_docker:
        _docker(src, paths, found)
    if stores:
        _podman(src, stores, paths, found)
    if has_containerd:
        _containerd(src, found)
    return Containers(
        tuple(sorted(found.images, key=_by_name)),
        tuple(sorted(found.containers, key=lambda c: (c.engine, c.scope or "", c.name, c.id))),
        tuple(sorted(found.volumes, key=_by_name)),
        tuple(found.damaged),
    )


def _where(x: ContainerImage | Container | Volume) -> dict[str, str]:
    """The manifest fields that say which engine (and user or namespace) an item is of."""
    out = {"engine": x.engine}
    if x.scope is not None:
        out["user" if x.engine == "podman" else "namespace"] = x.scope
    return out


def compare_containers(
    now: Containers | None, then: Containers | None, has_baseline: bool
) -> tuple[dict[str, list[dict[str, Any]]] | None, int]:
    """The manifest's "containers" section and how many items did not change. With a
    baseline, only what was added, removed or modified is listed; without one, all of
    it, as "present". None when neither side has a container engine.

    manifest の "containers" 節と、変わらなかった項目の数。baseline があれば増えた・消えた・
    変わったものだけを挙げ、無ければ全部を "present" で挙げる。どちらにもコンテナエンジンが
    無ければ None。
    """
    if now is None and then is None:
        return None, 0
    unchanged = 0

    def status(current: Any, before: Any, changed: bool) -> str | None:
        nonlocal unchanged
        if not has_baseline:
            return "present"
        if before is None:
            return "added"
        if current is None:
            return "removed"
        if changed:
            return "modified"
        unchanged += 1
        return None

    def order(k: tuple[str, str | None, str]) -> tuple[str, str, str]:
        return (k[0], k[1] or "", k[2])

    section: dict[str, list[dict[str, Any]]] = {"images": [], "containers": [], "volumes": []}
    images = {(i.engine, i.scope, i.name): i for i in now.images} if now else {}
    base_images = {(i.engine, i.scope, i.name): i for i in then.images} if then else {}
    for k in sorted(images.keys() | base_images.keys(), key=order):
        cur, old = images.get(k), base_images.get(k)
        s = status(cur, old, bool(cur and old and cur.id != old.id))
        item = cur or old
        if s is not None and item is not None:
            section["images"].append(
                {**_where(item), "name": item.name, "id": item.id, "status": s}
            )
    conts = {(c.engine, c.scope, c.id): c for c in now.containers} if now else {}
    base_conts = {(c.engine, c.scope, c.id): c for c in then.containers} if then else {}

    def by_name(k: tuple[str, str | None, str]) -> tuple[str, str, str, str]:
        c = conts.get(k) or base_conts[k]
        return (c.engine, c.scope or "", c.name, c.id)

    for k in sorted(conts.keys() | base_conts.keys(), key=by_name):
        cur_c, old_c = conts.get(k), base_conts.get(k)
        s = status(cur_c, old_c, False)
        c = cur_c or old_c
        if s is not None and c is not None:
            section["containers"].append(
                {
                    **_where(c),
                    "name": c.name,
                    "id": c.id,
                    "image": c.image,
                    "created": c.created,
                    "status": s,
                }
            )
    vols = {(v.engine, v.scope, v.name): v for v in now.volumes} if now else {}
    base_vols = {(v.engine, v.scope, v.name): v for v in then.volumes} if then else {}
    for k in sorted(vols.keys() | base_vols.keys(), key=order):
        cur_v, old_v = vols.get(k), base_vols.get(k)
        changed = bool(cur_v and old_v and (cur_v.files, cur_v.bytes) != (old_v.files, old_v.bytes))
        s = status(cur_v, old_v, changed)
        v = cur_v or old_v
        if s is not None and v is not None:
            section["volumes"].append(
                {**_where(v), "name": v.name, "files": v.files, "bytes": v.bytes, "status": s}
            )
    return section, unchanged
