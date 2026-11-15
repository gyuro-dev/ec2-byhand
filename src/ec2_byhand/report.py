"""report.txt: the manifest as a person reads it.

The summary printed at the end of a run gives numbers; this file gives the paths
behind them, one item a line, under the same headings:

    hand-placed (17)
      added     2026-10-24 13:10  /etc/myapp.conf
      modified  2026-10-24 13:11  /opt/legacy/change.txt [changed: sha256]

    modified package files (10)
      2026-10-24 13:11  /etc/ssh/sshd_config  (openssh-server: content) [since baseline]

It holds nothing the manifest does not: manifest.json stays the one source, for
programs, and keeps its English whatever the language of the messages. Here the
headings and the few notes are in that language, and the words of the items (status,
problems, kinds) are the manifest's own, so that a line is found again in it. Names
from the analyzed disk are written as printable() writes them.

report.txt: manifest を人が読む形にしたもの。実行の最後に出るまとめは件数だけなので、その裏に
あるパスを、同じ見出しの下に 1 行 1 項目で並べる。manifest に無いことは書かない: manifest.json
がプログラムのための唯一の元で、メッセージの言語によらず英語のまま。こちらは見出しと少しの注記
がその言語で、項目の言葉（status・problems・kind）は manifest のものをそのまま使うので、行を
manifest の中で探し直せる。解析対象のディスクから来た名前は printable() の形で書く。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ec2_byhand.archive import printable
from ec2_byhand.messages import label, msg, row

NAME = "report.txt"


def _when(item: dict[str, Any]) -> str:
    """The item's last change to the minute (UTC), or as many blanks."""
    ctime = item.get("ctime")
    return ctime[:16].replace("T", " ") if ctime else " " * 16


def _path(item: dict[str, Any]) -> str:
    """The item's path: a directory with its slash, a link with its target."""
    path = printable(item["path"])
    if item.get("type") == "dir" and path != "/":
        path += "/"
    if item.get("target"):
        path += f" -> {printable(item['target'])}"
    return path


def _notes(*notes: str | None) -> str:
    """What else is said of an item, each note in brackets."""
    return "".join(f" [{printable(note)}]" for note in notes if note)


def _secrets(item: dict[str, Any]) -> str | None:
    found = item.get("secrets")
    return "secrets: " + ", ".join(f"{s['kind']} ({s['line']})" for s in found) if found else None


def _file(item: dict[str, Any], indent: str = "  ") -> str:
    """One hand-placed path (also those under package_scripts and cloud_init)."""
    changed = item.get("changed")
    skipped = item.get("hash_skipped")
    notes = _notes(
        "changed: " + ", ".join(changed) if changed else None,
        f"hash_skipped: {skipped}" if skipped else None,
        "xattrs: " + ", ".join(item["xattrs"]) if item.get("xattrs") else None,
        f"selinux: {item['selinux']}" if item.get("selinux") else None,
        "sensitive" if item.get("sensitive") else None,
        _secrets(item),
        f"error: {item['error']}" if item.get("error") else None,
    )
    return f"{indent}{item['status']:<10}{_when(item)}  {_path(item)}{notes}"


def _package_file(item: dict[str, Any]) -> str:
    since = item["since_baseline"]
    notes = _notes(
        None if since is None else msg("report_since_baseline" if since else "report_in_baseline"),
        "config" if item.get("config") else None,
        f"cloud_init: {item['cloud_init']}" if item.get("cloud_init") else None,
        "sensitive" if item.get("sensitive") else None,
        _secrets(item),
        f"error: {item['error']}" if item.get("error") else None,
    )
    what = f"({item['package']}: {', '.join(item['problems'])})"
    return f"  {_when(item)}  {_path(item)}  {printable(what)}{notes}"


def _to_review(item: dict[str, Any]) -> str:
    what = f"({item['package']}: {', '.join(item['reasons'])})"
    return f"  {item['mode']} {item['uid']}:{item['gid']}  {_path(item)}  {printable(what)}"


def _deleted(item: dict[str, Any]) -> str:
    below = item.get("entries_below")
    return f"  {_path(item)}" + (msg("report_below", count=below) if below else "")


def _package(change: dict[str, Any]) -> str:
    name = change["name"] + (f".{change['arch']}" if change.get("arch") else "")
    versions = " -> ".join(v for v in (change["before"], change["after"]) if v)
    via = change.get("via")
    how = f"  ({via['source']}: {via['cmdline']})" if via and via.get("cmdline") else ""
    return printable(f"  {change['kind']:<12}{name}  {versions}{how}")


def _snap(item: dict[str, Any]) -> str:
    before = item.get("from")
    was = f" <- {before['revision']} ({before['channel']})" if before else ""
    line = f"  {item['status']:<10}{item['name']} {item['revision']} ({item['channel']}){was}"
    return printable(line)


def _language_package(item: dict[str, Any]) -> list[str]:
    """A pip / npm package, and under it its files that are not as installed."""
    before = f" <- {item['version_before']}" if item.get("version_before") else ""
    head = f"{item['ecosystem']} {item['name']} {item['version']}{before}  {item['location']}"
    lines = [printable(f"  {item['status']:<10}{head}")]
    for key in ("modified", "missing", "edited_after_install"):
        lines += [f"      {key}: {printable(path)}" for path in item[key]]
    return lines


def _groups(groups: list[dict[str, Any]], heading: Any) -> list[str]:
    """Files listed in groups (by package transaction, by cloud-init module)."""
    lines = []
    for group in groups:
        lines.append(printable(f"  {heading(group)}"))
        lines += [_file(item, "    ") for item in group["files"]]
    return lines


def _transaction(group: dict[str, Any]) -> str:
    t = group["transaction"]
    return f"{t['source']} {t['id']}: {t['cmdline'] or ''}".rstrip(": ")


def _alternative(item: dict[str, Any]) -> str:
    was = ""
    if "current_before" in item:
        was = f" <- {item['current_before']} ({item['mode_before']})"
    line = f"  {item['status']:<10}{item['name']}: {item['current']} ({item['mode']}){was}"
    return printable(line)


def _service(item: dict[str, Any]) -> str:
    notes = _notes(
        item["kind"],
        msg("report_by_package") if item.get("by_package") else None,
        f"snap: {item['snap']}" if item.get("snap") else None,
        f"package: {item['package']}" if item.get("package") else None,
    )
    return f"  {item['status']:<10}{_when(item)}  {_path(item)}{notes}"


def _containers(section: dict[str, list[dict[str, Any]]]) -> list[str]:
    lines = []
    for kind in ("images", "containers", "volumes"):
        for item in section.get(kind, []):
            more = ""
            if kind == "containers":
                more = f" ({item['image']})"
            elif kind == "volumes":
                more = f" (files {item['files']}, bytes {item['bytes']})"
            where = " ".join(str(item[k]) for k in ("engine", "user", "namespace") if item.get(k))
            line = f"  {item['status']:<10}{where} {kind[:-1]} {item['name']}{more}"
            lines.append(printable(line))
    return lines


def _left_out(items: list[dict[str, Any]]) -> list[str]:
    """What an archive or the patches left out (with the reason) or hold masked (with
    the kinds of what was masked)."""
    return [
        f"  {item['archive']:<8}{_path(item)}"
        + _notes(item.get("reason"), ", ".join(item.get("kinds", [])))
        for item in items
    ]


def report_lines(manifest: dict[str, Any], summary: list[str]) -> list[str]:
    """The lines of report.txt: a title, the summary as the run printed it (`summary`),
    then each section of the manifest that holds something, in the summary's order.

    report.txt の各行: 表題、実行が出したとおりのまとめ（`summary`）、そのあとに manifest の
    中身のある節を、まとめと同じ順で。
    """
    m = manifest
    containers = m.get("containers") or {}
    archives = m.get("archives") or {}
    # (heading, how many items, their lines): a group or a package takes several lines.
    sections: list[tuple[str, int, list[str]]] = [
        (label("hand_placed"), len(m["hand_placed"]), [_file(item) for item in m["hand_placed"]]),
        (
            label("modified_package_files"),
            len(m["modified_package_files"]),
            [_package_file(item) for item in m["modified_package_files"]],
        ),
        (
            label("to_review"),
            len(m["package_files_to_review"]),
            [_to_review(item) for item in m["package_files_to_review"]],
        ),
        (label("deleted"), len(m["deleted"]), [_deleted(item) for item in m["deleted"]]),
        (
            label("packages"),
            len(m["packages"]["changes"] or []),
            [_package(change) for change in m["packages"]["changes"] or []],
        ),
        (label("snaps"), len(m.get("snaps") or []), [_snap(item) for item in m.get("snaps") or []]),
        (
            label("language_packages"),
            len(m["language_packages"]),
            [line for item in m["language_packages"] for line in _language_package(item)],
        ),
        (
            label("package_scripts"),
            sum(len(group["files"]) for group in m["package_scripts"]),
            _groups(m["package_scripts"], _transaction),
        ),
        (
            label("cloud_init"),
            sum(len(group["files"]) for group in m["cloud_init"]),
            _groups(m["cloud_init"], lambda group: group["module"]),
        ),
        (
            label("alternatives"),
            len(m["alternatives"]),
            [_alternative(x) for x in m["alternatives"]],
        ),
        (label("services"), len(m["services"]), [_service(item) for item in m["services"]]),
        (label("containers"), sum(len(v) for v in containers.values()), _containers(containers)),
        (
            label("skipped"),
            len(archives.get("skipped", [])),
            _left_out(archives.get("skipped", [])),
        ),
        (label("masked"), len(archives.get("masked", [])), _left_out(archives.get("masked", []))),
    ]
    time = m["generated_at"][:16].replace("T", " ")
    lines = [
        msg("report_title", version=m["tool"]["version"], time=time),
        "",
        row("current", printable(m["current"]["label"])),
        *summary,
    ]
    if any(items for _, _, items in sections):
        lines += ["", msg("report_note")]
    for title, count, items in sections:
        if items:
            lines += ["", f"{title} ({count})", *items]
    return lines


def write(manifest: dict[str, Any], summary: list[str], path: str | Path) -> None:
    """Write report.txt to `path`: UTF-8, lines ending in a newline on every OS.

    report.txt を `path` に書く。UTF-8 で、どの OS でも行末は改行 1 文字。
    """
    text = "\n".join(report_lines(manifest, summary)) + "\n"
    Path(path).write_text(text, encoding="utf-8", errors="backslashreplace", newline="")
