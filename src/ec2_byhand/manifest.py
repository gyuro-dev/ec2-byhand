"""Write and read manifest.json (schema "ec2-byhand/manifest/v1").

Paths that are not valid UTF-8 are written escaped in "path" and exactly
in "path_hex" (see ec2_byhand.analyze.path_fields), so the file is always
valid UTF-8 JSON.

manifest.json（スキーマ "ec2-byhand/manifest/v1"）の読み書き。正しい UTF-8 でないパスは "path"
にエスケープして、正確な値を "path_hex" に書くので、ファイルは常に正しい UTF-8 の JSON になる
。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ec2_byhand.analyze import SCHEMA


def dumps(manifest: dict[str, Any]) -> str:
    """The manifest as pretty-printed JSON text.

    manifest を整形した JSON テキストにする。
    """
    return json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"


def write(manifest: dict[str, Any], path: str | Path) -> None:
    """Write the manifest to `path` as UTF-8 JSON.

    manifest を UTF-8 の JSON として `path` に書く。
    """
    # Most strings are sanitised at the source (see path_fields), but a few
    # free-form ones (fstab fields, package names) may carry surrogates from
    # surrogateescape decoding; escape rather than crash on them.
    Path(path).write_text(dumps(manifest), encoding="utf-8", errors="backslashreplace", newline="")


def read(path: str | Path) -> dict[str, Any]:
    """Read a manifest back; a file with the wrong schema raises ValueError.

    manifest を読み戻す。スキーマが違うファイルは ValueError。
    """
    data: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA:
        raise ValueError(f"not an {SCHEMA} manifest: {path}")
    return data
