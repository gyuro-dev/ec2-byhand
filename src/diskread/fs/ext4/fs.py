"""Read-only ext2/3/4 filesystem reader.

Covers extents and indirect block maps, inline data, linear and htree
directories (htree blocks are read linearly; the index is not needed to
list a directory), fast and slow symlinks, device nodes, xattrs in the
inode, in a block and in EA inodes, and POSIX ACLs. Optionally verifies
metadata_csum checksums (Ext4(dev, verify_checksums=True)).

Not covered: journal replay (see Superblock.needs_recovery), encrypted
files and directories.

読み取り専用の ext2/3/4 ファイルシステムリーダー。エクステントと間接ブロックマップ、インライン
データ、線形・htree ディレクトリ、fast / slow シンボリックリンク、デバイスノード、xattr（inode
内・ブロック・EA inode）、POSIX ACL に対応。metadata_csum の検証は任意。ジャーナル再生と暗号化
ファイルには非対応。
"""

from __future__ import annotations

import stat as _stat
import struct
from collections.abc import Iterable
from functools import lru_cache

from diskread.blockdev import BlockDevice, BytesDevice, will_read
from diskread.errors import DiskReadError, UnsupportedError
from diskread.fs import (
    INODE_CACHE,
    PARSED_INODES,
    FileType,
    Stat,
    file_type,
    reads_disk_metadata,
)
from diskread.fs.ext4 import csum, xattr
from diskread.fs.ext4.blockmap import MappedContent, extent_runs, indirect_runs
from diskread.fs.ext4.inode import (
    FLAG_ENCRYPT,
    FLAG_EXTENTS,
    FLAG_HUGE_FILE,
    FLAG_INDEX,
    FLAG_INLINE_DATA,
    GOOD_OLD_INODE_SIZE,
    N_BLOCK_BYTES,
    Inode,
    parse_inode,
)
from diskread.fs.ext4.superblock import (
    INCOMPAT_CSUM_SEED,
    INCOMPAT_EA_INODE,
    INCOMPAT_FILETYPE,
    INCOMPAT_LARGEDIR,
    RO_COMPAT_HUGE_FILE,
    RO_COMPAT_METADATA_CSUM,
    SUPERBLOCK_OFFSET,
    GroupDescriptors,
    Superblock,
    parse_superblock,
)

ROOT_INO = 2
DIRENT_HEADER = 8
# Far above what the kernel allows (a block; EXT4_XATTR_SIZE_MAX), low enough
# that a corrupt size cannot make a read allocate gigabytes of "holes".
MAX_SYMLINK_BYTES = 1 << 16
MAX_EA_INODE_VALUE_BYTES = 1 << 24


@reads_disk_metadata
class Ext4:
    """The ext2/3/4 reader; one instance per filesystem.

    ext2/3/4 のリーダー。ファイルシステムごとに 1 インスタンス。
    """

    fs_type = "ext4"

    def __init__(self, dev: BlockDevice, verify_checksums: bool = False) -> None:
        """With verify_checksums, metadata_csum checksums of everything read
        (superblock, group descriptors, inodes, extent / directory / xattr
        blocks) are checked and a mismatch raises DiskReadError. Filesystems
        without metadata_csum have nothing to check."""
        self._dev = dev
        raw_sb = dev.read_at(SUPERBLOCK_OFFSET, 1024)
        self.superblock: Superblock = parse_superblock(raw_sb)
        sb = self.superblock
        if sb.blocks_count * sb.block_size > dev.size:
            raise DiskReadError(
                f"filesystem ({sb.blocks_count * sb.block_size} bytes) "
                f"is larger than the device ({dev.size})"
            )
        self._csum_seed: int | None = None
        if verify_checksums and sb.ro_compat & RO_COMPAT_METADATA_CSUM:
            csum.check_superblock(raw_sb)
            self._csum_seed = csum.fs_seed(raw_sb, sb.has_incompat(INCOMPAT_CSUM_SEED))
        self._groups = GroupDescriptors(dev, sb, self._csum_seed)
        self._huge_file = bool(sb.ro_compat & RO_COMPAT_HUGE_FILE)
        self._filetype = sb.has_incompat(INCOMPAT_FILETYPE)
        self._large_dir = sb.has_incompat(INCOMPAT_LARGEDIR)
        # Two caches. The bytes of many inodes, so that the files a walk found need no
        # second read of the disk when they are opened (verification, hashing,
        # archiving): a stock image has ~50k, an application server a few hundred
        # thousand. And few of them parsed, those in use right now: a parsed inode
        # takes four times its bytes, and parsing again costs microseconds (measured
        # 2026-11-15: with all of them kept parsed, half of a run's memory was here).
        self._inode_bytes = lru_cache(maxsize=INODE_CACHE)(self._read_inode_bytes)
        self.inode = lru_cache(maxsize=PARSED_INODES)(self._read_inode)

    # --- low level ---------------------------------------------------------

    @property
    def is_dirty(self) -> bool:
        return self.superblock.needs_recovery

    @property
    def root_ino(self) -> int:
        return ROOT_INO

    def _read_block(self, block: int) -> bytes:
        """One filesystem block, range-checked (block 0 is never valid to read)."""
        bs = self.superblock.block_size
        if block == 0 or block >= self.superblock.blocks_count:
            raise DiskReadError(f"block {block} out of range")
        return self._dev.read_at(block * bs, bs)

    def _read_inode_bytes(self, ino: int) -> bytes:
        """The bytes of inode `ino` from its group's table, checked when checksums are
        verified (cached behind `self._inode_bytes`)."""
        sb = self.superblock
        if not 1 <= ino <= sb.inodes_count:
            raise DiskReadError(f"inode {ino} out of range")
        group, index = divmod(ino - 1, sb.inodes_per_group)
        table = self._groups.inode_table(group)
        raw = self._dev.read_at(table * sb.block_size + index * sb.inode_size, sb.inode_size)
        if self._csum_seed is not None:
            extra_isize = parse_inode(ino, raw, self._huge_file, self._large_dir).extra_isize
            csum.check_inode(self._csum_seed, ino, raw, extra_isize)
        return raw

    def _read_inode(self, ino: int) -> Inode:
        """Inode `ino` parsed from its bytes (cached behind `self.inode`)."""
        return parse_inode(ino, self._inode_bytes(ino), self._huge_file, self._large_dir)

    def _iseed(self, inode: Inode) -> int:
        """The checksum seed of this inode."""
        assert self._csum_seed is not None
        return csum.inode_seed(self._csum_seed, inode.ino, inode.raw)

    def _content(self, inode: Inode) -> BlockDevice:
        """Raw stored bytes of any inode (file, directory, slow symlink, EA inode)."""
        if inode.has_flag(FLAG_INLINE_DATA):
            data = inode.i_block + self._raw_xattrs(inode).get(xattr.SYSTEM_DATA, b"")
            if len(data) < inode.size:
                raise DiskReadError(f"inode {inode.ino}: inline data shorter than i_size")
            return BytesDevice(data[: inode.size])
        bs = self.superblock.block_size
        if inode.has_flag(FLAG_EXTENTS):
            read = self._read_block
            if self._csum_seed is not None:
                iseed = self._iseed(inode)

                def read(block: int, iseed: int = iseed) -> bytes:  # extent tree nodes only
                    data = self._read_block(block)
                    csum.check_extent_block(iseed, data, inode.ino)
                    return data

            runs = extent_runs(inode.i_block, read, inode.ino)
        else:
            nblocks = (inode.size + bs - 1) // bs
            runs = indirect_runs(inode.i_block, self._read_block, bs, nblocks, inode.ino)
        return MappedContent(self._dev, bs, runs, inode.size)

    # --- xattrs ------------------------------------------------------------

    def _read_ea_inode(self, ino: int, size: int) -> bytes:
        """The first `size` bytes of an EA inode's content."""
        if size > MAX_EA_INODE_VALUE_BYTES:
            raise DiskReadError(f"EA inode {ino}: implausible xattr value size {size}")
        dev = self._content(self.inode(ino))
        if dev.size < size:
            raise DiskReadError(f"EA inode {ino} is shorter than its xattr value")
        return dev.read_at(0, size)

    def _raw_xattrs(self, inode: Inode) -> dict[str, bytes]:
        """All stored xattrs including system.data, ACLs in on-disk format."""
        out: dict[str, bytes] = {}
        raw = inode.raw
        where = f"inode {inode.ino}"
        ibody = GOOD_OLD_INODE_SIZE + inode.extra_isize
        if len(raw) > GOOD_OLD_INODE_SIZE and ibody + 4 <= len(raw):
            (magic,) = struct.unpack_from("<I", raw, ibody)
            if magic == xattr.XATTR_MAGIC:
                start = ibody + 4
                entries = xattr.parse_entries(raw, start, len(raw), where)
                out.update(xattr.read_values(raw, entries, start, self._read_ea_inode, where))
        if inode.file_acl:
            block = self._read_block(inode.file_acl)
            if self._csum_seed is not None:
                csum.check_xattr_block(self._csum_seed, inode.file_acl, block)
            magic, _refcount, nblocks = struct.unpack_from("<III", block, 0)
            if magic != xattr.XATTR_MAGIC or nblocks != 1:
                raise DiskReadError(f"{where}: bad xattr block {inode.file_acl}")
            entries = xattr.parse_entries(block, xattr.BLOCK_HEADER_SIZE, len(block), where)
            # In-inode values win if a name somehow appears in both.
            for k, v in xattr.read_values(block, entries, 0, self._read_ea_inode, where).items():
                out.setdefault(k, v)
        return out

    def xattrs(self, ino: int) -> dict[str, bytes]:
        out = {}
        for name, value in self._raw_xattrs(self.inode(ino)).items():
            if name == xattr.SYSTEM_DATA:
                continue
            if name in ("system.posix_acl_access", "system.posix_acl_default"):
                value = xattr.acl_to_xattr(value, f"inode {ino}")
            out[name] = value
        return dict(sorted(out.items()))

    # --- public API ----------------------------------------------------------

    def stat(self, ino: int) -> Stat:
        inode = self.inode(ino)
        ftype = file_type(inode.mode)
        bs = self.superblock.block_size

        blocks = inode.blocks_raw
        if inode.has_flag(FLAG_HUGE_FILE) and self._huge_file:
            blocks *= bs // 512
        if inode.has_flag(FLAG_INLINE_DATA) and ftype is FileType.REG:
            # ext4_file_getattr (regular files only) counts inline bytes as
            # if they took 512-byte units.
            blocks += (inode.size + 511) >> 9

        rdev = None
        if ftype in (FileType.CHR, FileType.BLK):
            old, new = struct.unpack_from("<II", inode.i_block, 0)
            if old:
                rdev = ((old >> 8) & 0xFF, old & 0xFF)
            else:
                rdev = ((new & 0xFFF00) >> 8, (new & 0xFF) | ((new >> 12) & 0xFFF00))

        return Stat(
            ino=ino,
            mode=inode.mode,
            uid=inode.uid,
            gid=inode.gid,
            size=inode.size,
            nlink=inode.links_count,
            blocks=blocks,
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
        if inode.has_flag(FLAG_ENCRYPT):
            raise UnsupportedError(f"inode {ino} is encrypted")
        return self._content(inode)

    def readlink(self, ino: int) -> bytes:
        inode = self.inode(ino)
        if not _stat.S_ISLNK(inode.mode):
            raise DiskReadError(f"inode {ino} is not a symlink")
        if inode.has_flag(FLAG_ENCRYPT):
            raise UnsupportedError(f"inode {ino} is encrypted")
        if inode.size > MAX_SYMLINK_BYTES:
            raise DiskReadError(f"inode {ino}: implausible symlink length {inode.size}")
        if inode.has_flag(FLAG_INLINE_DATA):
            return self._content(inode).read_at(0, inode.size)
        if self._is_fast_symlink(inode):
            if inode.size > N_BLOCK_BYTES:
                raise DiskReadError(f"inode {ino}: fast symlink longer than i_block")
            return inode.i_block[: inode.size]
        return self._content(inode).read_at(0, inode.size)

    def _is_fast_symlink(self, inode: Inode) -> bool:
        """Mirror ext4_inode_is_fast_symlink: is the target stored in i_block?"""
        sb = self.superblock
        if sb.has_incompat(INCOMPAT_EA_INODE):
            # EA inode blocks are charged to i_blocks, so it says nothing here.
            return 0 < inode.size < N_BLOCK_BYTES
        # Otherwise a fast symlink owns no blocks except maybe an xattr block.
        ea_blocks = sb.cluster_size // 512 if inode.file_acl else 0
        return inode.blocks_raw - ea_blocks == 0

    def will_list(self, ino: int) -> None:
        """Tell the disk the blocks listdir(ino) will read (see diskread.fs.will_list).

        listdir(ino) が読むブロックをディスクに告げる（diskread.fs.will_list 参照）。
        """
        inode = self.inode(ino)
        if (
            not _stat.S_ISDIR(inode.mode)
            or inode.has_flag(FLAG_ENCRYPT)
            or inode.has_flag(FLAG_INLINE_DATA)  # in the inode itself
            or inode.size > self.superblock.blocks_count * self.superblock.block_size
        ):
            return  # listdir reads no blocks for it (or refuses it)
        will_read(self._content(inode))  # its written blocks: holes are not read

    def listdir(self, ino: int) -> list[tuple[bytes, int]]:
        inode = self.inode(ino)
        if not _stat.S_ISDIR(inode.mode):
            raise DiskReadError(f"inode {ino} is not a directory")
        if inode.has_flag(FLAG_ENCRYPT):
            raise UnsupportedError(f"directory inode {ino} is encrypted")
        if inode.has_flag(FLAG_INLINE_DATA):
            # i_block: 4-byte parent inode, then dirents; overflow in system.data.
            out = self._parse_dirents(inode.i_block, 4, N_BLOCK_BYTES, ino)
            extra = self._raw_xattrs(inode).get(xattr.SYSTEM_DATA, b"")
            if extra:
                out += self._parse_dirents(extra, 0, len(extra), ino)
            return out

        bs = self.superblock.block_size
        # The loop below visits every block, holes too: a corrupt i_size must not make it endless.
        if inode.size > self.superblock.blocks_count * bs:
            raise DiskReadError(f"directory {ino}: larger than the filesystem")
        content = self._content(inode)
        out = []
        # Like ext4_readdir, skip holes (and unwritten blocks, which ext4_bread also
        # treats as holes) instead of parsing zeros: only the written blocks are visited.
        if isinstance(content, MappedContent):
            offsets: Iterable[int] = content.offsets(bs, written=True)
        else:
            offsets = range(0, content.size - content.size % bs, bs)
        for off in offsets:
            block = content.read_at(off, bs)
            # htree index blocks (block 0 of an indexed directory, and nodes
            # that are one empty dirent spanning the block) carry a dx_tail
            # instead of the leaf tail; they are not checked.
            first_rec = int.from_bytes(block[4:6], "little")
            if bs >= 65536 and first_rec in (0, 65535):  # ext4_rec_len_from_disk
                first_rec = bs
            is_index = (off == 0 and inode.has_flag(FLAG_INDEX)) or (
                block[:4] == b"\0\0\0\0" and first_rec == bs
            )
            if self._csum_seed is not None and not is_index:
                csum.check_dir_block(self._iseed(inode), block, ino)
            out += self._parse_dirents(block, 0, bs, ino)
        return out

    def _parse_dirents(self, buf: bytes, start: int, end: int, ino: int) -> list[tuple[bytes, int]]:
        """Parse a run of linear directory entries in buf[start:end].

        Entry: inode (u32), rec_len (u16), then name_len (u8) + file_type (u8)
        with the filetype feature, otherwise name_len (u16); then the name.
        Unused space and htree index nodes appear as entries with inode 0.
        """
        out = []
        pos = start
        while pos < end:
            if pos + DIRENT_HEADER > end:
                raise DiskReadError(f"directory {ino}: truncated entry at {pos}")
            child, rec_len = struct.unpack_from("<IH", buf, pos)
            if self._filetype:
                name_len = buf[pos + 6]
            else:
                (name_len,) = struct.unpack_from("<H", buf, pos + 6)
            if rec_len in (0, 65535) and self.superblock.block_size >= 65536:
                rec_len = 65536  # ext4_rec_len_from_disk
            if rec_len < DIRENT_HEADER or rec_len % 4 or pos + rec_len > end:
                raise DiskReadError(f"directory {ino}: bad rec_len {rec_len} at {pos}")
            if child:
                if DIRENT_HEADER + name_len > rec_len:
                    raise DiskReadError(f"directory {ino}: name overflows entry at {pos}")
                name = bytes(buf[pos + DIRENT_HEADER : pos + DIRENT_HEADER + name_len])
                if name not in (b".", b".."):
                    out.append((name, child))
            pos += rec_len
        return out
