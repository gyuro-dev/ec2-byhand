"""Errors every diskread parser raises.

diskread の全パーサーが投げるエラー。
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from functools import wraps

# What parsing truncated or nonsensical bytes raises when no explicit check
# caught it first: short struct.unpack_from, indexing past the end, bad UTF-8,
# dividing by a size that reads as zero (ArithmeticError, with OverflowError)...
MALFORMED_DATA_ERRORS = (struct.error, LookupError, ValueError, ArithmeticError, RecursionError)


class DiskReadError(Exception):
    """The on-disk data is malformed, truncated, or fails a checksum.

    ディスク上のデータが壊れている・切れている・チェックサムが合わない。
    """


class UnsupportedError(DiskReadError):
    """The on-disk data is valid but uses a feature diskread does not handle.

    データ自体は正しいが、diskread が扱わない機能を使っている。
    """


def malformed_as_disk_read_error[**P, R](func: Callable[P, R]) -> Callable[P, R]:
    """Make `func`, which parses on-disk bytes, report malformed data as DiskReadError.

    Callers only handle DiskReadError, so that one bad inode costs one
    warning. Every check a parser could miss must not become a traceback.

    ディスク上のバイト列を解析する `func` が、壊れたデータを DiskReadError として報告するように
    する。呼び出し側は DiskReadError だけを扱うので、inode が 1 つ壊れていても警告 1 件で済む。
    パーサーの検査漏れがトレースバックにならないようにするためのもの。
    """

    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return func(*args, **kwargs)
        except MALFORMED_DATA_ERRORS as err:
            raise DiskReadError(f"malformed on-disk data: {err!r}") from err

    return wrapper
