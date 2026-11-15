"""Fill the disk blocks behind unwritten (preallocated) extents with garbage.

On a freshly made image those blocks are already zero, so a reader that
ignores the "unwritten" flag would still pass. After poisoning, the kernel
keeps returning zeros (it honours the flag) while a buggy reader returns
the garbage.

    python3 fs_poison.py collect [--allow-none] MOUNTPOINT FILE... > ranges.json   (mounted)
    python3 fs_poison.py apply IMAGE ranges.json                     (unmounted)

Physical offsets come from the FIEMAP ioctl and are relative to the block
device, which is the image file itself when mounted via a loop device.
"""

from __future__ import annotations

import fcntl
import json
import os
import struct
import sys

FS_IOC_FIEMAP = 0xC020660B
FIEMAP_FLAG_SYNC = 0x1
FIEMAP_EXTENT_LAST = 0x1
FIEMAP_EXTENT_UNWRITTEN = 0x800
HEADER = struct.Struct(
    "<QQIIII"
)  # fm_start, fm_length, fm_flags, fm_mapped_extents, fm_extent_count, fm_reserved
EXTENT = struct.Struct(
    "<QQQ16xI12x"
)  # fe_logical, fe_physical, fe_length, reserved, fe_flags, reserved
MAX_EXTENTS = 512


def unwritten_ranges(path: str) -> list[tuple[int, int]]:
    out = []
    start = 0
    with open(path, "rb") as f:
        while True:
            buf = bytearray(
                HEADER.pack(start, 2**64 - 1 - start, FIEMAP_FLAG_SYNC, 0, MAX_EXTENTS, 0)
            )
            buf += bytes(EXTENT.size * MAX_EXTENTS)
            fcntl.ioctl(f.fileno(), FS_IOC_FIEMAP, buf)
            mapped = HEADER.unpack_from(buf, 0)[3]
            if mapped == 0:
                return out
            for i in range(mapped):
                logical, physical, length, flags = EXTENT.unpack_from(
                    buf, HEADER.size + i * EXTENT.size
                )
                if flags & FIEMAP_EXTENT_UNWRITTEN:
                    out.append((physical, length))
                start = logical + length
                if flags & FIEMAP_EXTENT_LAST:
                    return out


def main() -> None:
    mode = sys.argv[1]
    if mode == "collect":
        args = sys.argv[2:]
        # Block-mapped (non-extent) ext4 cannot represent unwritten extents.
        allow_none = args[:1] == ["--allow-none"]
        if allow_none:
            args = args[1:]
        root, files = args[0], args[1:]
        ranges = []
        for name in files:
            ranges += unwritten_ranges(os.path.join(root, name))
        if not ranges and not allow_none:
            sys.exit("no unwritten extents found; the poison check would be vacuous")
        json.dump(ranges, sys.stdout)
    elif mode == "apply":
        image, ranges_file = sys.argv[2], sys.argv[3]
        with open(ranges_file) as f:
            ranges = json.load(f)
        with open(image, "r+b") as img:
            for physical, length in ranges:
                img.seek(physical)
                img.write((b"POISON!" * (length // 7 + 1))[:length])
    else:
        sys.exit(f"unknown mode {mode}")


main()
