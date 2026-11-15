"""The two rpm database formats found on EC2 images.

SQLite (rpm >= 4.16: AL2023, RHEL 9): rpmdb.sqlite, table
  Packages(hnum INTEGER PRIMARY KEY, blob BLOB)
A snapshot of a running system may still hold recent transactions in
rpmdb.sqlite-wal, so the database is opened together with its WAL.

Berkeley DB hash (rpm < 4.16: AL2, RHEL 7/8): Packages, key = header
number (u32, host order), value = header blob. Parsed directly; layout of
Berkeley DB 4/5 hash databases (host byte order, detected from the magic):
  page header (26 bytes): lsn (8), pgno (4) @8, prev_pgno (4) @12,
    next_pgno (4) @16, entries (u16) @20, hf_offset (u16) @22,
    level (u8) @24, type (u8) @25
  metadata page 0: magic (4) @12 = 0x061561, pagesize (4) @20,
    last_pgno (4) @32
  hash pages (type 13, or 2 "unsorted"): `entries` u16 offsets at 26,
    items in key/value pairs; item type H_KEYDATA (1) holds the bytes
    inline, H_OFFPAGE (3) is {type, pad[3], pgno (4), tlen (4)} pointing
    to a chain of overflow pages (type 7) whose hf_offset is the number of
    bytes on that page, data at 26.

EC2 のイメージで見かける 2 つの rpm データベース形式。SQLite（rpm >= 4.16: AL2023, RHEL 9）は
rpmdb.sqlite で、実行中に取ったスナップショットに備えて WAL ごと開く。Berkeley DB hash（rpm <
4.16: AL2, RHEL 7/8）は自前で解析する（レイアウトは上の表のとおり）。
"""

from __future__ import annotations

import sqlite3
import struct
import tempfile
from collections.abc import Iterable
from pathlib import Path

from diskread.errors import (
    MALFORMED_DATA_ERRORS,
    DiskReadError,
    UnsupportedError,
    malformed_as_disk_read_error,
)
from ec2_byhand.packages.model import OnDamage, Package
from ec2_byhand.packages.rpmheader import package_from_header

HASH_MAGIC = 0x061561
P_HASH_UNSORTED, P_OVERFLOW, P_HASH = 2, 7, 13
H_KEYDATA, H_OFFPAGE = 1, 3
PAGE_HEADER = 26


def _read_headers(
    headers: Iterable[tuple[str, object]], on_damage: OnDamage | None
) -> list[Package]:
    """Packages from (where, header) pairs; a bad header goes to on_damage, or raises without."""
    packages = []
    for where, blob in headers:
        try:
            if not isinstance(blob, bytes):  # SQLite columns are untyped
                raise DiskReadError("the package header is not a blob")
            packages.append(package_from_header(blob))
        except DiskReadError as err:
            if on_damage is None:
                raise
            on_damage(f"{where}: {err}")
    return packages


def _sqlite_headers(
    con: sqlite3.Connection, on_damage: OnDamage | None
) -> list[tuple[str, object]]:
    """(where, header) of every row, each fetched on its own: a header mostly lives in
    overflow pages, so a bad page then costs that package instead of ending the scan.
    Bad table pages do end the scan, costing the rows after them; those go to on_damage."""
    hnums: list[int] = []
    try:
        for (hnum,) in con.execute("SELECT hnum FROM Packages ORDER BY hnum"):
            hnums.append(hnum)
    except sqlite3.DatabaseError as err:
        if on_damage is None or not hnums:  # nothing to go on with
            raise
        on_damage(f"rpmdb.sqlite after header {hnums[-1]}: {err}")
    headers: list[tuple[str, object]] = []
    for hnum in hnums:
        where = f"rpmdb.sqlite header {hnum}"
        try:
            row = con.execute("SELECT blob FROM Packages WHERE hnum = ?", (hnum,)).fetchone()
        except sqlite3.DatabaseError as err:
            if on_damage is None:
                raise
            on_damage(f"{where}: {err}")
        else:
            headers.append((where, row[0] if row else None))
    return headers


@malformed_as_disk_read_error
def read_sqlite(db: bytes, wal: bytes | None, on_damage: OnDamage | None = None) -> list[Package]:
    """Packages from rpmdb.sqlite (with its WAL applied, via a temp copy).
    A package that cannot be read goes to `on_damage`, or raises without one.

    rpmdb.sqlite からパッケージを読む（一時コピー経由で WAL も適用）。読めないパッケージは
    `on_damage` に渡す（無ければ例外）。
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "rpmdb.sqlite"
        path.write_bytes(db)
        if wal:
            (Path(tmp) / "rpmdb.sqlite-wal").write_bytes(wal)
        con = sqlite3.connect(path)
        try:
            con.execute("PRAGMA trusted_schema = OFF")  # the database comes from the snapshot
            headers = _sqlite_headers(con, on_damage)
        except sqlite3.DatabaseError as err:
            raise DiskReadError(f"rpmdb.sqlite: {err}") from err
        finally:
            con.close()
    return _read_headers(headers, on_damage)


def _bdb_records(db: bytes, on_damage: OnDamage | None) -> list[tuple[bytes, bytes]]:
    """Every (key, value) record of a Berkeley DB hash database. A bad page or record
    goes to on_damage, or raises without one; a bad file header always raises."""
    if len(db) < 512:
        raise DiskReadError("Berkeley DB file too short")
    for endian in ("<", ">"):
        if struct.unpack_from(endian + "I", db, 12)[0] == HASH_MAGIC:
            break
    else:
        raise UnsupportedError("rpm Packages is not a Berkeley DB hash database")
    (pagesize,) = struct.unpack_from(endian + "I", db, 20)
    (last_pgno,) = struct.unpack_from(endian + "I", db, 32)
    if pagesize < 512 or pagesize & (pagesize - 1) or (last_pgno + 1) * pagesize > len(db):
        raise DiskReadError("bad Berkeley DB geometry")

    def page(n: int) -> bytes:
        return db[n * pagesize : (n + 1) * pagesize]

    def overflow(pgno: int, tlen: int) -> bytes:
        out = bytearray()
        seen: set[int] = set()
        while pgno and len(out) < tlen:
            if pgno in seen or pgno > last_pgno:
                raise DiskReadError("broken Berkeley DB overflow chain")
            seen.add(pgno)
            p = page(pgno)
            if p[25] != P_OVERFLOW:
                raise DiskReadError(f"page {pgno} is not an overflow page")
            (nxt,) = struct.unpack_from(endian + "I", p, 16)
            (used,) = struct.unpack_from(endian + "H", p, 22)
            out += p[PAGE_HEADER : PAGE_HEADER + used]
            pgno = nxt
        if len(out) < tlen:
            raise DiskReadError("Berkeley DB overflow chain too short")
        return bytes(out[:tlen])

    def item(p: bytes, offsets: tuple[int, ...], n: int, i: int) -> bytes:
        off = offsets[i]
        end = offsets[i - 1] if i > 0 else pagesize  # items grow down from the page end
        kind = p[off]
        if kind == H_KEYDATA:
            return p[off + 1 : end]
        if kind == H_OFFPAGE:
            pgno, tlen = struct.unpack_from(endian + "II", p, off + 4)
            return overflow(pgno, tlen)
        raise UnsupportedError(f"Berkeley DB item type {kind} on page {n}")

    records: list[tuple[bytes, bytes]] = []
    for n in range(1, last_pgno + 1):
        p = page(n)
        if p[25] not in (P_HASH, P_HASH_UNSORTED):
            continue
        try:
            (entries,) = struct.unpack_from(endian + "H", p, 20)
            offsets = struct.unpack_from(f"{endian}{entries}H", p, PAGE_HEADER)
        except struct.error as err:
            if on_damage is None:
                raise
            on_damage(f"Berkeley DB page {n}: {err}")
            continue
        for i in range(0, entries - 1, 2):
            try:
                records.append((item(p, offsets, n, i), item(p, offsets, n, i + 1)))
            except (DiskReadError, *MALFORMED_DATA_ERRORS) as err:
                if on_damage is None:
                    raise
                on_damage(f"Berkeley DB page {n} item {i}: {err}")
    return records


@malformed_as_disk_read_error
def read_bdb(db: bytes, on_damage: OnDamage | None = None) -> list[Package]:
    """Packages from a Berkeley DB Packages file; record 0 is rpm's bookkeeping.
    A package that cannot be read goes to `on_damage`, or raises without one.

    Berkeley DB の Packages ファイルからパッケージを読む（レコード 0 は rpm の管理情報）。読めな
    いパッケージは `on_damage` に渡す（無ければ例外）。
    """
    headers = []
    for key, value in _bdb_records(db, on_damage):
        # Key 0 holds rpm's bookkeeping (the next header number), not a package.
        if (len(key) == 4 and struct.unpack("<I", key)[0] == 0) or len(value) < 8:
            continue
        headers.append((f"Berkeley DB record {key.hex()}", value))
    return _read_headers(headers, on_damage)
