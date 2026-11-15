"""Turn every inode of an XFS v4 image into a version 1 inode.

Version 1 inodes come from filesystems made before the NLINK feature (IRIX
era) and keep the link count in the 16-bit di_onlink at 0x06; version 2
moved it to the 32-bit di_nlink at 0x10. mkfs has not made them for a
long time, so this rewrites a fresh v4 image the way such a filesystem
looks: NLINK cleared from sb_versionnum, each inode's di_version set to 1,
di_onlink set to the link count and di_nlink zeroed (the kernel ignores
it for version 1, so a reader that uses it is caught). The kernel's view
of the result, not this script, is the ground truth.

Run as root on an unmounted image (it mounts it read-only to list inodes):
    python3 xfs_inode1.py IMAGE
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import tempfile

VERSION_NLINKBIT = 0x0020


def inodes(image: str) -> dict[int, int]:
    """inode number -> link count, as the kernel reports them."""
    mnt = tempfile.mkdtemp()
    subprocess.run(["mount", "-o", "loop,ro", image, mnt], check=True)
    try:
        out = {}
        for top, dirs, files in os.walk(mnt):
            for name in [top] + [os.path.join(top, n) for n in dirs + files]:
                st = os.lstat(name)
                out[st.st_ino] = st.st_nlink
        return out
    finally:
        subprocess.run(["umount", mnt], check=True)
        os.rmdir(mnt)


def main(image: str) -> None:
    found = inodes(image)
    with open(image, "r+b") as f:
        sb = bytearray(f.read(512))
        assert sb[:4] == b"XFSB", "not XFS"
        assert struct.unpack_from(">H", sb, 0x64)[0] & 0xF == 4, "not XFS v4"
        (versionnum,) = struct.unpack_from(">H", sb, 0x64)
        struct.pack_into(">H", sb, 0x64, versionnum & ~VERSION_NLINKBIT)
        f.seek(0)
        f.write(sb)

        (bs,) = struct.unpack_from(">I", sb, 0x04)
        (agblocks,) = struct.unpack_from(">I", sb, 0x54)
        (isize,) = struct.unpack_from(">H", sb, 0x68)
        inopblog, agblklog = sb[0x7B], sb[0x7C]
        for ino, nlink in sorted(found.items()):
            assert nlink <= 0xFFFF
            agno, agino = ino >> (agblklog + inopblog), ino & ((1 << (agblklog + inopblog)) - 1)
            offset = (agno * agblocks + (agino >> inopblog)) * bs + (
                agino & ((1 << inopblog) - 1)
            ) * isize
            f.seek(offset)
            core = bytearray(f.read(0x14))
            assert core[:2] == b"IN", f"inode {ino}: bad magic"
            assert core[4] == 2, f"inode {ino}: not a version 2 inode"
            assert struct.unpack_from(">I", core, 0x10)[0] == nlink, f"inode {ino}: link count"
            core[4] = 1
            struct.pack_into(">H", core, 0x06, nlink)
            struct.pack_into(">I", core, 0x10, 0)
            f.seek(offset)
            f.write(core)
    print(f"converted {len(found)} inodes to version 1", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1])
