"""rpm header blobs as stored in the rpm database.

A stored header (no lead/magic), big-endian:
  il (u32)  number of index entries
  dl (u32)  size of the data store
  il x { tag (u32), type (u32), offset (u32), count (u32) }
  data store (dl bytes)

Types: 1 CHAR, 2 INT8, 3 INT16, 4 INT32, 5 INT64, 6 STRING, 7 BIN,
8 STRING_ARRAY, 9 I18NSTRING (an array; the first entry is the default).

rpm データベースに入っている形のヘッダ blob: ビッグエンディアンの索引エントリ列とデータストア
（構造と型は上のとおり）。
"""

from __future__ import annotations

import struct
from typing import Any

from diskread.errors import DiskReadError, malformed_as_disk_read_error
from diskread.source import clean_path
from ec2_byhand.packages.model import Package, PackageFile

# Tags used here (rpmtag.h).
NAME, VERSION, RELEASE, EPOCH = 1000, 1001, 1002, 1003
INSTALLTIME = 1008
FILESIZES, FILESTATES, FILEMODES, FILEDIGESTS, FILELINKTOS, FILEFLAGS = (
    1028,
    1029,
    1030,
    1035,
    1036,
    1037,
)
FILEUSERNAME, FILEGROUPNAME, FILEVERIFYFLAGS = 1039, 1040, 1045
OLDFILENAMES = 1027
ARCH = 1022
DIRINDEXES, BASENAMES, DIRNAMES = 1116, 1117, 1118
LONGFILESIZES = 5008
FILEDIGESTALGO = 5011

RPMFILE_CONFIG = 1
# PGP hash algorithm ids used by FILEDIGESTALGO; md5 when the tag is absent.
DIGEST_ALGOS = {1: "md5", 2: "sha1", 8: "sha256", 9: "sha384", 10: "sha512", 11: "sha224"}

_FIXED = {2: ("B", 1), 3: ("H", 2), 4: ("I", 4), 5: ("Q", 8)}  # struct code, bytes
MAX_ENTRIES = 1 << 16


def parse_header(blob: bytes) -> dict[int, object]:
    """Tag -> value: str, bytes, or a list of ints / strs.

    タグ → 値（str・bytes・int / str のリスト）。
    """
    if len(blob) < 8:
        raise DiskReadError("rpm header too short")
    il, dl = struct.unpack_from(">II", blob, 0)
    data_start = 8 + 16 * il
    if il > MAX_ENTRIES or data_start + dl > len(blob):
        raise DiskReadError("rpm header index or data overflows the blob")
    data = blob[data_start : data_start + dl]
    out: dict[int, object] = {}
    for i in range(il):
        tag, typ, off, count = struct.unpack_from(">IIII", blob, 8 + 16 * i)
        if off > dl:
            raise DiskReadError(f"rpm header tag {tag} points outside the data")
        if typ in _FIXED:
            code, size = _FIXED[typ]
            if off + size * count > dl:
                raise DiskReadError(f"rpm header tag {tag} overflows")
            out[tag] = list(struct.unpack_from(f">{count}{code}", data, off))  # one call per tag
        elif typ in (1, 7):  # CHAR, BIN
            out[tag] = bytes(data[off : off + count])
        elif typ in (6, 8, 9):  # STRING, STRING_ARRAY, I18NSTRING
            strings, pos = [], off
            for _ in range(count if typ != 6 else 1):
                end = data.find(b"\0", pos)
                if end < 0:
                    raise DiskReadError(f"rpm header tag {tag}: unterminated string")
                strings.append(data[pos:end].decode("utf-8", "surrogateescape"))
                pos = end + 1
            out[tag] = strings[0] if typ == 6 else strings
    return out


def _str(h: dict[int, object], tag: int) -> str | None:
    """`h[tag]` if it is a str, else None."""
    v = h.get(tag)
    if isinstance(v, list):
        return v[0] if v and isinstance(v[0], str) else None
    return v if isinstance(v, str) else None


def _ints(h: dict[int, object], tag: int) -> list[int]:
    """`h[tag]` as a list of ints (empty when absent or mistyped)."""
    v = h.get(tag)
    return [x for x in v if isinstance(x, int)] if isinstance(v, list) else []


def _strs(h: dict[int, object], tag: int) -> list[str]:
    """`h[tag]` as a list of strs (empty when absent or mistyped)."""
    v = h.get(tag)
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def _files(h: dict[int, object]) -> tuple[PackageFile, ...]:
    """The package's files from the name/dir tags and the per-file columns."""
    basenames = _strs(h, BASENAMES)
    if basenames:
        dirnames = _strs(h, DIRNAMES)
        dirindexes = _ints(h, DIRINDEXES)
        if len(dirindexes) != len(basenames) or any(i >= len(dirnames) for i in dirindexes):
            raise DiskReadError("rpm header: inconsistent file name tags")
        paths = [dirnames[i] + b for i, b in zip(dirindexes, basenames, strict=True)]
    else:
        paths = _strs(h, OLDFILENAMES)
    n = len(paths)

    def column(values: list[Any], default: Any) -> list[Any]:
        return values if len(values) == n else [default] * n

    digests = column(_strs(h, FILEDIGESTS), "")
    modes = column(_ints(h, FILEMODES), None)
    flags = column(_ints(h, FILEFLAGS), 0)
    sizes = column(_ints(h, LONGFILESIZES) or _ints(h, FILESIZES), None)
    raw_states = h.get(FILESTATES)
    states = column(list(raw_states) if isinstance(raw_states, bytes) else [], None)
    verify = column(_ints(h, FILEVERIFYFLAGS), None)
    links = column(_strs(h, FILELINKTOS), "")
    users = column(_strs(h, FILEUSERNAME), None)
    groups = column(_strs(h, FILEGROUPNAME), None)
    algo_ids = _ints(h, FILEDIGESTALGO)
    algo = DIGEST_ALGOS.get(algo_ids[0], str(algo_ids[0])) if algo_ids else "md5"
    return tuple(
        PackageFile(
            path=paths[i],
            digest=digests[i] or None,
            digest_algo=algo if digests[i] else None,
            mode=modes[i],
            size=sizes[i],
            is_config=bool(flags[i] & RPMFILE_CONFIG),
            flags=flags[i],
            state=states[i],
            verify=verify[i],
            link_to=links[i] or None,
            user=users[i],
            group=groups[i],
        )
        for i in range(n)
        # Not a plain absolute path (a ".." in it): no file of the package, and left
        # to be listed as what no package owns.
        if clean_path(paths[i])
    )


@malformed_as_disk_read_error
def package_from_header(blob: bytes) -> Package:
    """A Package from one header blob.

    ヘッダ blob 1 つから Package を作る。
    """
    h = parse_header(blob)
    name, version, release = _str(h, NAME), _str(h, VERSION), _str(h, RELEASE)
    if name is None or version is None or release is None:
        raise DiskReadError("rpm header lacks name, version or release")
    epoch = _ints(h, EPOCH)
    install_time = _ints(h, INSTALLTIME)
    return Package(
        manager="rpm",
        name=name,
        arch=_str(h, ARCH),
        epoch=epoch[0] if epoch else None,
        version=version,
        release=release,
        install_time=install_time[0] if install_time else None,
        files=_files(h),
    )
