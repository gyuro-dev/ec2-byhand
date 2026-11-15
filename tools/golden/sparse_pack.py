"""Pack a mostly empty disk image into a small file, and read it back.

A filesystem large enough for 64-bit XFS inode numbers is terabytes in
size but holds only megabytes of data. The pack keeps the image's size
and its non-zero 64 KiB chunks; everything else reads as zeros, exactly
as the holes of the sparse image did for the kernel.

    python3 sparse_pack.py IMAGE OUT.sparse.gz

Format (gzip): b"diskread-sparse1\n", u64 size, then (u64 offset,
u32 length, bytes) records in offset order, ended by offset 2**64-1.
"""

from __future__ import annotations

import gzip
import os
import struct
import sys

MAGIC = b"diskread-sparse1\n"
CHUNK = 64 << 10
END = (1 << 64) - 1


def data_regions(fd: int, size: int):
    pos = 0
    while pos < size:
        try:
            start = os.lseek(fd, pos, os.SEEK_DATA)
        except OSError:  # ENXIO: only a hole remains
            return
        end = os.lseek(fd, start, os.SEEK_HOLE)
        yield start, end
        pos = end


def pack(image: str, out: str) -> tuple[int, int]:
    size = os.path.getsize(image)
    kept = 0
    fd = os.open(image, os.O_RDONLY)
    try:
        with gzip.GzipFile(out, "wb", mtime=0) as gz:
            gz.write(MAGIC + struct.pack("<Q", size))
            for start, end in data_regions(fd, size):
                pos = start - start % CHUNK
                while pos < end:
                    data = os.pread(fd, CHUNK, pos)
                    if data.strip(b"\0"):
                        gz.write(struct.pack("<QI", pos, len(data)) + data)
                        kept += len(data)
                    pos += CHUNK
            gz.write(struct.pack("<QI", END, 0))
    finally:
        os.close(fd)
    return size, kept


def load(path: str) -> tuple[int, list[tuple[int, bytes]]]:
    with gzip.open(path, "rb") as gz:
        if gz.read(len(MAGIC)) != MAGIC:
            raise ValueError(f"{path}: not a diskread sparse pack")
        (size,) = struct.unpack("<Q", gz.read(8))
        records = []
        while True:
            offset, length = struct.unpack("<QI", gz.read(12))
            if offset == END:
                return size, records
            records.append((offset, gz.read(length)))


if __name__ == "__main__":
    total, kept = pack(sys.argv[1], sys.argv[2])
    print(f"packed {total} bytes, kept {kept}", file=sys.stderr)
