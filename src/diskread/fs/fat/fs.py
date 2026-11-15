"""Read-only FAT12/16/32 (vfat) reader, presenting files as Linux would.

FAT has no owners, permissions, links or inode numbers. Linux derives
them from mount options, so this reader takes the same options (as the
fstab options string) and applies the same rules:

  uid, gid           owner of every file (default 0)
  umask/fmask/dmask  mode = 0777 & ~mask for files / directories (default 0022)
  showexec           files get x bits only for .EXE/.COM/.BAT names
  rodir              the read-only attribute also applies to directories
  tz=UTC, time_offset=MINUTES   how FAT's local times map to UTC
                     (the kernel otherwise uses the system timezone, which
                     this reader cannot know; it then assumes UTC)
  shortname=lower    8.3-only names are shown in lower case
  codepage=N         code page of 8.3 names (default 437)

Inode numbers: Linux makes them up when it reads a directory, so they are
not reproducible. Here the root is 1 (as in Linux) and every other file
gets its short entry's byte offset on the device / 32, which is unique and
stable. ctime equals mtime (as in current kernels); atime has day
precision; birth time is the creation time.

読み取り専用の FAT12/16/32（vfat）リーダー。Linux がマウントしたときと同じ見え方にする: FAT に
は所有者・権限・リンク・inode 番号が無いので、Linux と同じくマウントオプション（uid, umask,
showexec, tz=UTC など）から導く。inode 番号はルートが 1、それ以外は短いエントリのデバイス上オ
フセット / 32（一意で再現可能）。ctime は mtime と同じ、atime は日精度。
"""

from __future__ import annotations

import codecs
import os.path

from diskread.blockdev import BlockDevice, SliceDevice
from diskread.errors import DiskReadError
from diskread.fs import Stat, reads_disk_metadata
from diskread.fs.extents import MappedContent, Run
from diskread.fs.fat.bpb import BootSector, Fat, parse_boot_sector
from diskread.fs.fat.dirent import (
    ATTR_RO,
    Entry,
    count_subdirs,
    fat_time_ns,
    parse_dir,
    volume_label,
)

ROOT_INO = 1
S_IFDIR = 0o040000
S_IFREG = 0o100000


def parse_options(options: str) -> dict[str, str]:
    """The mount options string as a key -> value dict (a bare flag maps to "").

    マウントオプションの文字列を key→value の dict に（値の無いフラグは ""）。
    """
    out = {}
    for item in options.split(","):
        key, sep, value = item.partition("=")
        if key:
            out[key.strip()] = value.strip() if sep else ""
    return out


def _int_option(opts: dict[str, str], key: str, default: int, base: int = 10) -> int:
    """A numeric mount option, or `default` if it is not a number. mount(8) also
    takes user and group names (uid=ec2-user), which only the running system can
    resolve; a wrong owner in the report is better than no report."""
    try:
        return int(opts[key], base)
    except (KeyError, ValueError):
        return default


def _codepage_option(opts: dict[str, str]) -> str:
    """The codec for 8.3 names; the kernel's default if Python does not know the code page."""
    codec = f"cp{opts.get('codepage', '437')}"
    try:
        codecs.lookup(codec)
    except (LookupError, ValueError):  # unknown, or not a name at all (a NUL, stray bytes)
        return "cp437"
    return codec


@reads_disk_metadata
class Vfat:
    """The FAT reader; presents files as Linux would with the same mount options.

    FAT のリーダー。同じマウントオプションで Linux がマウントしたときの見え方にする。
    """

    fs_type = "vfat"

    def __init__(self, dev: BlockDevice, options: str = "") -> None:
        self._dev = dev
        self.boot: BootSector = parse_boot_sector(dev.read_at(0, 512))
        bs = self.boot
        if bs.data_offset + bs.cluster_count * bs.cluster_size > dev.size:
            raise DiskReadError("FAT filesystem is larger than the device")
        self._fat = Fat(dev, bs)
        # Cluster 2 is the first data cluster: map cluster n to block n - 2.
        self._data = SliceDevice(dev, bs.data_offset, dev.size - bs.data_offset)

        opts = parse_options(options)
        umask = _int_option(opts, "umask", 0o022, 8)
        self._uid = _int_option(opts, "uid", 0)
        self._gid = _int_option(opts, "gid", 0)
        self._fmask = _int_option(opts, "fmask", umask, 8)
        self._dmask = _int_option(opts, "dmask", umask, 8)
        self._showexec = "showexec" in opts
        self._rodir = "rodir" in opts
        if opts.get("tz") == "UTC":
            self._tz = 0
        else:
            self._tz = _int_option(opts, "time_offset", 0) * 60
        self._lower_short = opts.get("shortname") == "lower"
        self._codepage = _codepage_option(opts)
        self._entries: dict[int, Entry] = {}

    # --- identity -------------------------------------------------------------

    @property
    def uuid(self) -> str:
        """Volume serial number as blkid prints it, e.g. "1A2B-3C4D".

        blkid が表示する形のボリュームシリアル番号（例「1A2B-3C4D」）。
        """
        v = self.boot.volume_id
        return f"{v >> 16:04X}-{v & 0xFFFF:04X}"

    @property
    def label(self) -> str:
        """The root directory's label entry, else the boot sector's (like blkid).

        ルートディレクトリのラベルエントリ、なければブートセクタのもの（blkid と同じ）。
        """
        found = volume_label(self._root_dir_bytes(), self._codepage)
        if found is not None:
            return found
        return "" if self.boot.label == "NO NAME" else self.boot.label

    @property
    def is_dirty(self) -> bool:
        return False  # FAT has no journal or log

    @property
    def root_ino(self) -> int:
        return ROOT_INO

    # --- low level --------------------------------------------------------------

    def _chain_content(
        self, first: int, size: int | None = None
    ) -> tuple[MappedContent, list[int]]:
        """A cluster chain as readable content, plus the chain itself; `size` caps the length."""
        clusters = self._fat.chain(first)
        runs: list[Run] = []
        for i, c in enumerate(clusters):
            last = runs[-1] if runs else None
            if last and last.physical + last.length == c - 2:
                runs[-1] = Run(last.logical, last.physical, last.length + 1)
            else:
                runs.append(Run(i, c - 2, 1))
        cs = self.boot.cluster_size
        total = len(clusters) * cs
        if size is not None and size > total:
            raise DiskReadError(f"file of {size} bytes has only {len(clusters)} clusters")
        return MappedContent(self._data, cs, runs, total if size is None else size), clusters

    def _root_dir_bytes(self) -> bytes:
        """The root directory's bytes: the fixed area on FAT12/16, a cluster chain on FAT32."""
        bs = self.boot
        if bs.fat_type == 32:
            content, _ = self._chain_content(bs.root_cluster)
            return content.read_at(0, content.size)
        return self._dev.read_at(bs.root_dir_offset, bs.root_dir_bytes)

    def _dir_data(self, ino: int) -> tuple[bytes, list[tuple[int, int]]]:
        """Raw directory bytes and (data offset, device offset) pieces."""
        bs = self.boot
        if ino == ROOT_INO and bs.fat_type != 32:
            return self._dev.read_at(bs.root_dir_offset, bs.root_dir_bytes), [
                (0, bs.root_dir_offset)
            ]
        first = bs.root_cluster if ino == ROOT_INO else self._entry(ino).first_cluster
        content, clusters = self._chain_content(first)
        cs = bs.cluster_size
        pieces = [(i * cs, bs.data_offset + (c - 2) * cs) for i, c in enumerate(clusters)]
        return content.read_at(0, content.size), pieces

    def _entry(self, ino: int) -> Entry:
        """The Entry listdir cached for `ino`; an inode never listed is an error."""
        e = self._entries.get(ino)
        if e is None:
            raise DiskReadError(f"inode {ino} was not reached through listdir")
        return e

    # --- public API ----------------------------------------------------------------

    def listdir(self, ino: int) -> list[tuple[bytes, int]]:
        if ino != ROOT_INO and not self._entry(ino).is_dir:
            raise DiskReadError(f"inode {ino} is not a directory")
        data, pieces = self._dir_data(ino)
        out = []
        for e in parse_dir(data, pieces, self._lower_short, self._codepage):
            child = e.offset // 32
            self._entries[child] = e
            out.append((e.name, child))
        return out

    def _mode(self, e: Entry | None) -> int:
        """st_mode from the attributes and mount options, the way the kernel derives it."""
        if e is None or e.is_dir:
            mode = S_IFDIR | (0o777 & ~self._dmask)
        else:
            perm = 0o777 & ~self._fmask
            # e.name is bytes, which pathlib does not take, so os.path stays.
            if self._showexec and os.path.splitext(e.name)[1].lower() not in (  # noqa: PTH122
                b".exe",
                b".com",
                b".bat",
            ):
                perm &= ~0o111
            mode = S_IFREG | perm
        if e is not None and e.attr & ATTR_RO and (not e.is_dir or self._rodir):
            mode &= ~0o222
        return mode

    def stat(self, ino: int) -> Stat:
        cs = self.boot.cluster_size
        if ino == ROOT_INO:
            data, _ = self._dir_data(ino)
            return Stat(
                ino=ROOT_INO,
                mode=self._mode(None),
                uid=self._uid,
                gid=self._gid,
                size=len(data),
                nlink=count_subdirs(data) + 2,
                blocks=(len(data) + cs - 1) // cs * cs // 512,
                atime_ns=0,
                mtime_ns=0,
                ctime_ns=0,
                btime_ns=0,
                rdev=None,
            )
        e = self._entry(ino)
        if e.is_dir:
            data, _ = self._dir_data(ino)
            size, nlink = len(data), count_subdirs(data)
        else:
            size, nlink = e.size, 1
        mtime = fat_time_ns(e.wrt_time, e.wrt_date, 0, self._tz)
        return Stat(
            ino=ino,
            mode=self._mode(e),
            uid=self._uid,
            gid=self._gid,
            size=size,
            nlink=nlink,
            blocks=(size + cs - 1) // cs * cs // 512,
            atime_ns=fat_time_ns(0, e.acc_date, 0, self._tz),
            mtime_ns=mtime,
            ctime_ns=mtime,
            btime_ns=fat_time_ns(e.crt_time, e.crt_date, e.crt_cs, self._tz),
            rdev=None,
        )

    def open(self, ino: int) -> BlockDevice:
        e = self._entry(ino)
        if e.is_dir:
            raise DiskReadError(f"inode {ino} is not a regular file")
        if e.size == 0:
            return SliceDevice(self._dev, 0, 0)
        content, _ = self._chain_content(e.first_cluster, e.size)
        return content

    def readlink(self, ino: int) -> bytes:
        raise DiskReadError("FAT has no symbolic links")

    def xattrs(self, ino: int) -> dict[str, bytes]:
        return {}
