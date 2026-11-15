"""FAT directory entries: 8.3 entries, VFAT long names and timestamps.

Short entry (32 bytes, little-endian):
  0x00 name[8] ext[3] (name[0]: 0x00 end, 0xE5 deleted, 0x05 = a real 0xE5)
  0x0B attr   0x0C lcase (0x08 base / 0x10 extension in lower case)
  0x0D creation time, 10 ms units (0-199)   0x0E creation time  0x10 creation date
  0x12 access date   0x14 first cluster high   0x16 write time   0x18 write date
  0x1A first cluster low   0x1C size (u32)
Long-name entry (attr 0x0F), stored in reverse order right before its
short entry: 0x00 order (0x40 = last), 0x01 5 UTF-16 chars, 0x0D checksum
of the short name, 0x0E 6 chars, 0x1C 2 chars.

Dates: bits 15-9 year since 1980, 8-5 month, 4-0 day. Times: bits 15-11
hours, 10-5 minutes, 4-0 seconds / 2. FAT stores local time; the offset to
UTC comes from mount options.

FAT のディレクトリエントリ: 8.3 エントリ、VFAT の長い名前、タイムスタンプ（レイアウトは上の表
のとおり）。日時はローカル時刻で記録されており、UTC への補正はマウントオプションから来る。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

ATTR_RO = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME = 0x08
ATTR_DIR = 0x10
ATTR_ARCH = 0x20
ATTR_LFN = 0x0F
CASE_LOWER_BASE = 0x08
CASE_LOWER_EXT = 0x10

# fat_time_fat2unix: days before each month (index 1-12), 1970 -> 1980.
_DAYS_IN_YEAR = (0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 0, 0, 0)
_DAYS_DELTA = 365 * 10 + 2  # two leap years (1972, 1976)
_YEAR_2100 = 120


@dataclass(frozen=True)
class Entry:
    """One directory entry, as the kernel would present it.

    カーネルが見せる形のディレクトリエントリ 1 つ。
    """

    name: bytes  # as the kernel shows it (UTF-8)
    attr: int
    first_cluster: int
    size: int
    crt_cs: int
    crt_time: int
    crt_date: int
    acc_date: int
    wrt_time: int
    wrt_date: int
    offset: int  # byte offset of the short entry on the device

    @property
    def is_dir(self) -> bool:
        """Whether the directory attribute is set.

        ディレクトリ属性が立っているか。
        """
        return bool(self.attr & ATTR_DIR)


def fat_time_ns(time: int, date: int, cs: int, tz_offset_s: int) -> int:
    """Mirror the kernel's fat_time_fat2unix, including its clamping of
    month/day 0 and its leap-year rule (2100 is not a leap year).

    カーネルの fat_time_fat2unix を再現する。月・日が 0 のときの丸めと、2100 年を閏年にしない
    規則も含めて。
    """
    year = date >> 9
    month = max(1, (date >> 5) & 0xF)
    day = max(1, date & 0x1F) - 1
    leap_day = (year + 3) // 4
    if year > _YEAR_2100:
        leap_day -= 1
    if year & 3 == 0 and year != _YEAR_2100 and month > 2:
        leap_day += 1
    second = (time & 0x1F) << 1
    second += ((time >> 5) & 0x3F) * 60
    second += (time >> 11) * 3600
    second += (year * 365 + leap_day + _DAYS_IN_YEAR[month] + day + _DAYS_DELTA) * 86400
    second -= tz_offset_s
    return (second + cs // 100) * 1_000_000_000 + (cs % 100) * 10_000_000


def lfn_checksum(short_name: bytes) -> int:
    """The one-byte checksum of a short name that its long-name entries carry.

    長い名前のエントリが持つ、短い名前の 1 バイトチェックサム。
    """
    s = 0
    for b in short_name:
        s = (((s & 1) << 7) | (s >> 1)) + b & 0xFF
    return s


def _short_name(raw: bytes, lcase: int, lower_all: bool, codepage: str) -> bytes:
    """Decode an 8.3 name, honouring the lcase bits and the codepage."""
    base = bytearray(raw[:8])
    if base[0] == 0x05:
        base[0] = 0xE5
    # "replace": bytes the code page does not have (codepage=932 and a name written in
    # another) cost that character, not the listing of the whole directory.
    b = bytes(base).rstrip(b" ").decode(codepage, "replace")
    e = raw[8:11].rstrip(b" ").decode(codepage, "replace")
    if lower_all or lcase & CASE_LOWER_BASE:
        b = b.lower()
    if lower_all or lcase & CASE_LOWER_EXT:
        e = e.lower()
    return (b + "." + e if e else b).encode("utf-8")


def parse_dir(
    data: bytes, base_offsets: list[tuple[int, int]], lower_short: bool, codepage: str
) -> list[Entry]:
    """Parse directory bytes. base_offsets maps (start in data, device offset)
    for each contiguous piece, so each entry's on-disk position is known.

    ディレクトリのバイト列を解析する。base_offsets は連続した断片ごとの（data 内の開始, デバイ
    ス上のオフセット）の対応で、各エントリのディスク上の位置が分かる。
    """

    def device_offset(pos: int) -> int:
        dev = 0
        for start, off in base_offsets:
            if start > pos:
                break
            dev = off + (pos - start)
        return dev

    out: list[Entry] = []
    lfn_parts: dict[int, bytes] = {}
    lfn_sum = -1
    for pos in range(0, len(data) - len(data) % 32, 32):
        e = data[pos : pos + 32]
        first = e[0]
        if first == 0x00:
            break
        if first == 0xE5:
            lfn_parts, lfn_sum = {}, -1
            continue
        attr = e[11]
        if attr & 0x3F == ATTR_LFN:
            order = first & 0x1F
            if first & 0x40:
                lfn_parts, lfn_sum = {}, e[13]
            if e[13] != lfn_sum or order == 0:
                lfn_parts, lfn_sum = {}, -1
                continue
            # Keep raw UTF-16 so a surrogate pair split across entries survives.
            lfn_parts[order] = e[1:11] + e[14:26] + e[28:32]
            continue
        long_name = None
        if (
            lfn_parts
            and lfn_sum == lfn_checksum(e[:11])
            and sorted(lfn_parts) == list(range(1, len(lfn_parts) + 1))
        ):
            raw = b"".join(lfn_parts[i] for i in sorted(lfn_parts))
            units = [raw[i : i + 2] for i in range(0, len(raw), 2)]
            if b"\0\0" in units:  # the name ends at a NUL; 0xFFFF pads the rest
                units = units[: units.index(b"\0\0")]
            long_name = b"".join(units).decode("utf-16-le", "replace").encode("utf-8")
        lfn_parts, lfn_sum = {}, -1
        if attr & ATTR_VOLUME:
            continue
        name = long_name or _short_name(e[:11], e[12], lower_short, codepage)
        if name in (b".", b".."):
            continue
        crt_cs, crt_time, crt_date, acc_date, hi = struct.unpack_from("<BHHHH", e, 13)
        wrt_time, wrt_date, lo, size = struct.unpack_from("<HHHI", e, 22)
        out.append(
            Entry(
                name,
                attr,
                (hi << 16) | lo,
                size,
                crt_cs,
                crt_time,
                crt_date,
                acc_date,
                wrt_time,
                wrt_date,
                device_offset(pos),
            )
        )
    return out


def count_subdirs(data: bytes) -> int:
    """fat_subdirs: entries with the directory attribute, "." and ".." included.

    fat_subdirs: ディレクトリ属性を持つエントリ数（「.」と「..」を含む）。
    """
    n = 0
    for pos in range(0, len(data) - len(data) % 32, 32):
        first, attr = data[pos], data[pos + 11]
        if first == 0x00:
            break
        if first != 0xE5 and attr & 0x3F != ATTR_LFN and attr & ATTR_DIR:
            n += 1
    return n


def volume_label(data: bytes, codepage: str) -> str | None:
    """The volume label entry in the root directory, if any.

    ルートディレクトリのボリュームラベルエントリ（あれば）。
    """
    for pos in range(0, len(data) - len(data) % 32, 32):
        first, attr = data[pos], data[pos + 11]
        if first == 0x00:
            return None
        if first != 0xE5 and attr & 0x3F != ATTR_LFN and attr & ATTR_VOLUME:
            return data[pos : pos + 11].decode(codepage, "replace").rstrip(" ")
    return None
