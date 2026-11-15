"""Read-only XFS filesystem reader (v5, and the older v4 / crc=0 format).

Covers extent-list and B+tree forks, unwritten extents, all directory
forms (shortform, block, leaf, node, btree), local and remote symlinks,
device nodes, xattrs (shortform, leaf, node, remote values), POSIX ACLs,
bigtime and nrext64 inodes, and hides parent pointers.

Optionally verifies v5 metadata CRCs (Xfs(dev, verify_checksums=True)).

Not covered: log replay (see Xfs.log_state), realtime files.

読み取り専用の XFS リーダー（v5 と、古い v4 / crc=0 形式）。エクステントリスト・B+tree フォー
ク、未書き込みエクステント、全ディレクトリ形式、ローカル・リモートのシンボリックリンク、デバイ
スノード、xattr、POSIX ACL、bigtime・nrext64 に対応し、親ポインタは隠す。v5 の CRC 検証は任意
。ログ再生と realtime ファイルには非対応。
"""

from __future__ import annotations

import stat as _stat
import struct
from functools import lru_cache

from diskread.blockdev import BlockDevice, BytesDevice, will_read
from diskread.errors import DiskReadError
from diskread.fs import (
    INODE_CACHE,
    PARSED_INODES,
    FileType,
    Stat,
    file_type,
    reads_disk_metadata,
)
from diskread.fs.extents import MappedContent, Run
from diskread.fs.xfs import attr, csum
from diskread.fs.xfs import dir as xdir
from diskread.fs.xfs import log as xlog
from diskread.fs.xfs.bmap import fork_runs
from diskread.fs.xfs.inode import FMT_DEV, FMT_LOCAL, Fork, Inode, parse_inode
from diskread.fs.xfs.superblock import Superblock, parse_superblock

_UNSET = object()
SYMLINK_MAGIC = b"XSLM"
SYMLINK_HEADER_SIZE = 56
# The longest target XFS stores (XFS_SYMLINK_MAXLEN). Checked before any block is read:
# a damaged inode may say anything, and name extents of gigabytes.
MAX_SYMLINK_BYTES = 1024
ATTR_CRC_MAGICS = tuple(struct.pack(">H", m) for m in (attr.LEAF_MAGIC, attr.NODE_MAGIC))


@reads_disk_metadata
class Xfs:
    """The XFS reader; one instance per filesystem.

    XFS のリーダー。ファイルシステムごとに 1 インスタンス。
    """

    fs_type = "xfs"

    def __init__(self, dev: BlockDevice, verify_checksums: bool = False) -> None:
        """With verify_checksums, the CRC of every v5 metadata buffer read
        (superblock, inodes, bmap btree, directory, xattr and remote symlink
        blocks) is checked and a mismatch raises DiskReadError. v4
        filesystems carry no CRCs, so there is nothing to check."""
        self._dev = dev
        raw_sb = dev.read_at(0, 512)
        self.superblock: Superblock = parse_superblock(raw_sb)
        sb = self.superblock
        if sb.dblocks * sb.block_size > dev.size:
            raise DiskReadError(
                f"filesystem ({sb.dblocks * sb.block_size} bytes) "
                f"is larger than the device ({dev.size})"
            )
        self._verify = verify_checksums and sb.is_v5
        if self._verify:
            (sectsize,) = struct.unpack_from(">H", raw_sb, 0x66)
            if not 512 <= sectsize <= 32768 or sectsize & (sectsize - 1):
                raise DiskReadError(f"bad XFS sector size {sectsize}")
            csum.check(dev.read_at(0, sectsize), 0xE0, "superblock")
        # Two caches. The bytes of many inodes, so that the files a walk found need no
        # second read of the disk when they are opened (verification, hashing,
        # archiving): a stock image has ~50k, an application server a few hundred
        # thousand. And few of them parsed, those in use right now: a parsed inode
        # takes four times its bytes, and parsing again costs microseconds (measured
        # 2026-11-15: with all of them kept parsed, half of a run's memory was here).
        self._inode_bytes = lru_cache(maxsize=INODE_CACHE)(self._read_inode_bytes)
        self.inode = lru_cache(maxsize=PARSED_INODES)(self._read_inode)
        self._log_state: object = _UNSET

    @property
    def is_dirty(self) -> bool:
        try:
            return self.log_state == "dirty"
        except DiskReadError:  # a log that cannot be read cannot show it is clean
            return True

    @property
    def root_ino(self) -> int:
        return self.superblock.root_ino

    @property
    def log_state(self) -> xlog.LogState | None:
        """ "clean", "covered" or "dirty"; see diskread.fs.xfs.log.

        "dirty" means the newest metadata may exist only in the log, which
        diskread does not replay (e.g. a snapshot of a busy, mounted
        filesystem), so recent changes may be missing. None for an
        external log. Reads megabytes of the log (all of it when its head
        cannot be found by its cycle numbers), so it is computed once.

        「clean」「covered」「dirty」のどれか（diskread.fs.xfs.log 参照）。dirty は最新のメタ
        データがログにしか無いかもしれない状態（マウント中の忙しいファイルシステムのスナップシ
        ョットなど）。外部ログなら None。ログを数 MiB 読む（サイクル番号から先頭が見つから
        なければ全体）ので、一度だけ計算する。
        """
        if self._log_state is _UNSET:
            self._log_state = xlog.log_state(self._dev, self.superblock)
        return self._log_state  # type: ignore[return-value]

    # --- low level ---------------------------------------------------------

    def _read_block(self, linear: int) -> bytes:
        """One filesystem block by linear block number."""
        bs = self.superblock.block_size
        return self._dev.read_at(linear * bs, bs)

    def _read_bmbt_block(self, linear: int) -> bytes:
        """A bmap btree block, CRC-checked when verifying."""
        block = self._read_block(linear)
        if self._verify:
            csum.check(block, 0x40, f"bmap btree block {linear}")
        return block

    def _read_inode_bytes(self, ino: int) -> bytes:
        """The bytes of inode `ino`, CRC-checked when verifying (cached behind
        `self._inode_bytes`)."""
        sb = self.superblock
        raw = self._dev.read_at(sb.inode_offset(ino), sb.inode_size)
        if self._verify:
            csum.check(raw, 0x64, f"inode {ino}")
        return raw

    def _read_inode(self, ino: int) -> Inode:
        """Inode `ino` parsed from its bytes (cached behind `self.inode`)."""
        return parse_inode(ino, self._inode_bytes(ino))

    def _runs(self, fork: Fork, ino: int) -> list[Run]:
        """The fork's runs, whatever its format."""
        return fork_runs(fork, self.superblock, self._read_bmbt_block, ino)

    def _mapped(self, fork: Fork, size: int, ino: int) -> MappedContent:
        """The fork's runs as readable content of `size` bytes."""
        return MappedContent(self._dev, self.superblock.block_size, self._runs(fork, ino), size)

    def _mapped_fork(self, fork: Fork, ino: int, max_size: int | None = None) -> MappedContent:
        """The fork's bytes up to its last mapped block below `max_size` (if given).

        The runs at or above `max_size` are left out before the end is found: a
        directory of two blocks or more keeps its leaf blocks at 32 GiB
        (xdir.LEAF_OFFSET), so capping only the end made every such directory span
        32 GiB, and listdir stepped through all of it, 8 million blocks a directory
        (about 340 s of a run on AL2, which has a hundred of them).
        """
        bs = self.superblock.block_size
        runs = self._runs(fork, ino)
        if max_size is not None:
            limit = max_size // bs
            runs = [
                Run(r.logical, r.physical, min(r.length, limit - r.logical), r.unwritten)
                for r in runs
                if r.logical < limit
            ]
        end = max((r.logical + r.length for r in runs), default=0) * bs
        return MappedContent(self._dev, bs, runs, end)

    # --- public API ----------------------------------------------------------

    def stat(self, ino: int) -> Stat:
        inode = self.inode(ino)
        ftype = file_type(inode.mode)
        rdev = None
        if ftype in (FileType.CHR, FileType.BLK):
            if inode.data_fork.format != FMT_DEV:
                raise DiskReadError(f"inode {ino}: device node without a device fork")
            (dev,) = struct.unpack_from(">I", inode.data_fork.data, 0)
            # xfs_to_linux_dev_t: SysV-style 14-bit major (masked to 9), 18-bit minor.
            rdev = ((dev >> 18) & 0x1FF, dev & 0x3FFFF)
        return Stat(
            ino=ino,
            mode=inode.mode,
            uid=inode.uid,
            gid=inode.gid,
            size=inode.size,
            nlink=inode.nlink,
            blocks=inode.nblocks << (self.superblock.blocklog - 9),
            atime_ns=inode.atime_ns,
            mtime_ns=inode.mtime_ns,
            ctime_ns=inode.ctime_ns,
            btime_ns=inode.crtime_ns,
            rdev=rdev,
        )

    def open(self, ino: int) -> BlockDevice:
        inode = self.inode(ino)
        if not _stat.S_ISREG(inode.mode):
            raise DiskReadError(f"inode {ino} is not a regular file")
        if inode.data_fork.format == FMT_LOCAL:
            return BytesDevice(inode.data_fork.data[: inode.size])
        return self._mapped(inode.data_fork, inode.size, ino)

    def readlink(self, ino: int) -> bytes:
        inode = self.inode(ino)
        if not _stat.S_ISLNK(inode.mode):
            raise DiskReadError(f"inode {ino} is not a symlink")
        fork = inode.data_fork
        if fork.format == FMT_LOCAL:
            if inode.size > len(fork.data):
                raise DiskReadError(f"inode {ino}: local symlink longer than its fork")
            return fork.data[: inode.size]

        # Remote symlink: on v5 one header per extent (the kernel reads each
        # mapping as a single buffer), unlike remote xattr values; on v4 the
        # target's bytes with no header at all.
        bs = self.superblock.block_size
        out = bytearray()
        runs = self._runs(fork, ino)
        # What the longest target takes, a header in each block: more is not a symlink's.
        most_blocks = MAX_SYMLINK_BYTES // (bs - SYMLINK_HEADER_SIZE) + 1
        if inode.size > MAX_SYMLINK_BYTES or sum(r.length for r in runs) > most_blocks:
            raise DiskReadError(f"inode {ino}: implausible symlink ({inode.size} bytes)")
        if not self.superblock.is_v5:
            for run in runs:
                out += self._dev.read_at(run.physical * bs, run.length * bs)
            if len(out) < inode.size:
                raise DiskReadError(f"inode {ino}: symlink blocks shorter than its size")
            return bytes(out[: inode.size])
        for run in runs:
            buf = self._dev.read_at(run.physical * bs, run.length * bs)
            if buf[:4] != SYMLINK_MAGIC:
                raise DiskReadError(f"inode {ino}: bad remote symlink block magic")
            if self._verify:
                csum.check(buf, 0x0C, f"remote symlink block of inode {ino}")
            offset, nbytes = struct.unpack_from(">II", buf, 4)
            if offset != len(out) or SYMLINK_HEADER_SIZE + nbytes > len(buf):
                raise DiskReadError(f"inode {ino}: inconsistent remote symlink block")
            out += buf[SYMLINK_HEADER_SIZE : SYMLINK_HEADER_SIZE + nbytes]
        if len(out) != inode.size:
            raise DiskReadError(f"inode {ino}: symlink length mismatch")
        return bytes(out)

    def will_list(self, ino: int) -> None:
        """Tell the disk the blocks listdir(ino) will read (see diskread.fs.will_list).

        listdir(ino) が読むブロックをディスクに告げる（diskread.fs.will_list 参照）。
        """
        inode = self.inode(ino)
        fork = inode.data_fork
        if not _stat.S_ISDIR(inode.mode) or fork.format == FMT_LOCAL:
            return  # listdir reads no blocks for it (or refuses it)
        # The mapped data blocks below the leaf offset, as listdir reads them.
        will_read(self._mapped_fork(fork, ino, xdir.LEAF_OFFSET))

    def listdir(self, ino: int) -> list[tuple[bytes, int]]:
        inode = self.inode(ino)
        if not _stat.S_ISDIR(inode.mode):
            raise DiskReadError(f"inode {ino} is not a directory")
        sb = self.superblock
        fork = inode.data_fork
        if fork.format == FMT_LOCAL:
            return xdir.parse_shortform(fork.data, sb.has_ftype, ino)

        dbs = sb.dir_block_size
        content = self._mapped_fork(fork, ino, xdir.LEAF_OFFSET)
        out = []
        # Data blocks emptied by deletions may be freed, leaving holes: only the mapped
        # blocks are visited.
        for off in content.offsets(dbs):
            block = content.read_at(off, dbs)
            if self._verify:
                csum.check(block, 0x04, f"directory block of inode {ino}")
            out += xdir.parse_data_block(block, sb.has_ftype, ino, sb.is_v5)
        return out

    def _raw_xattrs(self, inode: Inode) -> dict[str, bytes]:
        """All stored xattrs in on-disk form (ACLs included), from any attr fork format."""
        fork = inode.attr_fork
        if fork is None:
            return {}
        if fork.format == FMT_LOCAL:
            return attr.parse_shortform(fork.data, inode.ino)

        bs = self.superblock.block_size
        content = self._mapped_fork(fork, inode.ino)

        def read_fork_block(blk: int) -> bytes:
            block = content.read_at(blk * bs, bs)
            # Leaf / node blocks and remote value blocks (XARM) all keep the
            # CRC at offset 12; anything else fails its own magic check.
            if self._verify and (block[:4] == attr.RMT_MAGIC or block[8:10] in ATTR_CRC_MAGICS):
                csum.check(block, 0x0C, f"xattr block of inode {inode.ino}")
            return block

        if content.size == 0:  # an attr fork with no extents: nothing stored
            return {}
        v5 = self.superblock.is_v5

        def read_remote(valueblk: int, valuelen: int) -> bytes:
            return attr.read_remote_value(read_fork_block, valueblk, valuelen, inode.ino, v5)

        out: dict[str, bytes] = {}
        for blk in attr.leaf_blocks(read_fork_block, inode.ino, v5):
            leaf = attr.parse_leaf(read_fork_block(blk), read_remote, inode.ino, v5)
            if leaf:
                out.update(leaf)
        return out

    def xattrs(self, ino: int) -> dict[str, bytes]:
        out = self._raw_xattrs(self.inode(ino))
        for raw_name, posix_name in attr.ACL_NAMES.items():
            if raw_name in out:
                out[posix_name] = attr.acl_to_xattr(out[raw_name], ino)
        return dict(sorted(out.items()))
