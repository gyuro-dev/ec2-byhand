"""Fill a freshly made FAT filesystem with a deterministic tree.

    python3 fat_populate.py ROOT

FAT has no symlinks, owners, devices or xattrs, so this is separate from
fs_populate.py. It exercises long names (LFN) and their 8.3 aliases, case
handling, UTF-16 surrogate pairs, deleted entries, multi-cluster
directories, fragmented cluster chains, the read-only attribute and the
limits of FAT timestamps.
"""

from __future__ import annotations

import os
import random
import sys

root = sys.argv[1]
rng = random.Random(20261024)


def p(*parts: str) -> str:
    return os.path.join(root, *parts)


def write(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


# An EFI system partition as Amazon Linux lays it out.
os.makedirs(p("EFI", "BOOT"))
os.makedirs(p("EFI", "amzn"))
write(p("EFI", "BOOT", "BOOTX64.EFI"), rng.randbytes(100_000))
write(p("EFI", "amzn", "grubx64.efi"), rng.randbytes(300_000))
write(p("EFI", "amzn", "grub.cfg"), b"search --no-floppy --fs-uuid --set=dev 1234\n")

# Names.
write(p("README.TXT"), b"8.3 upper case\n")
write(p("lower.txt"), b"8.3 lower case (stored with case bits)\n")
write(p("MixedCase.Txt"), b"needs a long name\n")
write(p("L" * 200 + ".txt"), b"long name\n")
write(p("日本語ファイル.txt"), "こんにちは\n".encode())
write(p("emoji-🎉.txt"), b"surrogate pair in UTF-16\n")
write(p("with space.txt"), b"space\n")
write(p("longfilename1.txt"), b"alias ~1\n")
write(p("longfilename2.txt"), b"alias ~2\n")
write(p(".hidden-ish"), b"leading dot\n")
write(p("a.b.c.txt"), b"many dots\n")
write(p("NOEXT"), b"no extension\n")

# Sizes and layouts.
write(p("empty"), b"")
write(p("medium.bin"), rng.randbytes(200_000))
with open(p("frag-a.bin"), "wb") as fa, open(p("frag-b.bin"), "wb") as fb:
    for _ in range(50):  # interleave writes so the cluster chains interleave
        fa.write(rng.randbytes(4096))
        fa.flush()
        os.fsync(fa.fileno())
        fb.write(rng.randbytes(4096))
        fb.flush()
        os.fsync(fb.fileno())

# A directory spanning many clusters, with deleted entries.
os.mkdir(p("many"))
for i in range(500):
    write(p("many", f"entry-number-{i:04d}.txt"), f"{i}\n".encode())
for i in range(0, 500, 3):
    os.unlink(p("many", f"entry-number-{i:04d}.txt"))

deep = root
for i in range(10):
    deep = os.path.join(deep, f"level{i}")
os.makedirs(deep)
write(os.path.join(deep, "leaf.txt"), b"deep\n")

write(p("readonly.txt"), b"read-only attribute\n")
# vfat silently ignores chmod unless r/x stay as they are; dropping only
# the w bits is what sets the read-only attribute.
os.chmod(p("readonly.txt"), 0o555)

# Timestamps at FAT's limits (local time, 2-second resolution, 1980-2107).
NS = 123_456_789
for name, sec in [
    ("README.TXT", 315532800),  # 1980-01-01 00:00:00, the earliest
    ("lower.txt", 4354819198),  # 2107-12-31 23:59:58, the latest
    ("medium.bin", 1700000001),  # an odd second
]:
    t = sec * 1_000_000_000 + NS
    os.utime(p(name), ns=(t, t))
os.utime(p("EFI"), ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))
