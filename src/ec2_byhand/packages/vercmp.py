"""Version comparison exactly as rpm and dpkg do it.

rpm (rpmvercmp, rpm >= 4.15): compare segment by segment, where segments
are maximal runs of digits or of letters and everything else separates
them. "~" sorts before anything (even the end of the string); "^" sorts
after the end of the string but before any other segment. Digit segments
compare numerically (leading zeros ignored) and beat letter segments.
EVR: epoch (missing = 0) numerically, then version, then release.

dpkg (verrevcmp): epoch numerically, then upstream version, then Debian
revision (missing = "0"). Within each, alternate non-digit and digit runs;
non-digit runs compare character by character with "~" lowest, then the
end of the run, then letters, then everything else (by ASCII value).

Both tools classify characters in ASCII only (rpm's risalnum, dpkg's
c_isdigit / c_isalpha), unlike Python's str.isdigit / str.isalpha.

rpm と dpkg の実装そのままの版比較。rpm（rpmvercmp）は数字の連・英字の連をセグメントとして順に
比べ、「~」は何よりも（文字列の終わりよりも）先、「^」は終わりの直後に並ぶ。dpkg（verrevcmp）
は epoch → upstream → revision を、それぞれ非数字と数字の連を交互に比べる。文字の分類はどちら
も ASCII だけで、Python の str.isdigit / str.isalpha とは違う。
"""

from __future__ import annotations


def _digit(c: str) -> bool:
    """ASCII '0'-'9' only, unlike str.isdigit."""
    return "0" <= c <= "9"


def _alpha(c: str) -> bool:
    """ASCII letters only, unlike str.isalpha."""
    return "a" <= c <= "z" or "A" <= c <= "Z"


def _alnum(c: str) -> bool:
    """ASCII letters and digits only."""
    return _digit(c) or _alpha(c)


def rpmvercmp(a: str, b: str) -> int:
    """rpm's rpmvercmp: -1, 0 or 1 for one version string against another.

    rpm の rpmvercmp: 版文字列同士の比較で -1 / 0 / 1。
    """
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not _alnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < len(b) and not _alnum(b[j]) and b[j] not in "~^":
            j += 1
        # Tilde: older than anything, even the end of the string.
        ta, tb = i < len(a) and a[i] == "~", j < len(b) and b[j] == "~"
        if ta or tb:
            if not (ta and tb):
                return -1 if ta else 1
            i += 1
            j += 1
            continue
        # Caret: newer than the end of the string, older than any segment.
        ca, cb = i < len(a) and a[i] == "^", j < len(b) and b[j] == "^"
        if ca or cb:
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if not (ca and cb):
                return -1 if ca else 1
            i += 1
            j += 1
            continue
        if i >= len(a) or j >= len(b):
            break
        si, sj = i, j
        isnum = _digit(a[i])
        same_kind = _digit if isnum else _alpha
        while i < len(a) and same_kind(a[i]):
            i += 1
        while j < len(b) and same_kind(b[j]):
            j += 1
        seg_a, seg_b = a[si:i], b[sj:j]
        if not seg_b:
            # Different segment types: numeric is newer.
            return 1 if isnum else -1
        if isnum:
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def rpm_evr_compare(
    a: tuple[int | None, str, str | None], b: tuple[int | None, str, str | None]
) -> int:
    """Compare two rpm (epoch, version, release) triples like rpmVersionCompare.

    rpm の (epoch, version, release) の組を rpmVersionCompare と同じに比べる。
    """
    ea, eb = a[0] or 0, b[0] or 0
    if ea != eb:
        return 1 if ea > eb else -1
    r = rpmvercmp(a[1], b[1])
    if r:
        return r
    # Like rpm.labelCompare: a missing release sorts before any release.
    # (Installed packages always have one, so this only matters for edge input.)
    if a[2] is None or b[2] is None:
        return (a[2] is not None) - (b[2] is not None)
    return rpmvercmp(a[2], b[2])


def parse_rpm_evr(s: str) -> tuple[int | None, str, str | None]:
    """An "e:v-r" string split into (epoch, version, release).

    「e:v-r」形式の文字列を (epoch, version, release) に分ける。
    """
    epoch = None
    if ":" in s:
        e, s = s.split(":", 1)
        epoch = int(e) if e else None
    version, sep, release = s.partition("-")
    return epoch, version, release if sep else None


def _dpkg_order(c: str) -> int:
    """dpkg's character order: '~' lowest, then end-of-run, letters, the rest by ASCII."""
    if not c or _digit(c):
        return 0
    if _alpha(c):
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    """dpkg's verrevcmp over one version component."""
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not _digit(a[i])) or (j < len(b) and not _digit(b[j])):
            ac = _dpkg_order(a[i]) if i < len(a) else 0
            bc = _dpkg_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and _digit(a[i]) and j < len(b) and _digit(b[j]):
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and _digit(a[i]):
            return 1
        if j < len(b) and _digit(b[j]):
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_dpkg(v: str) -> tuple[int, str, str]:
    """A dpkg version as (epoch, upstream, revision)."""
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e and all(_digit(c) for c in e) else 0
    upstream, sep, revision = v.rpartition("-")
    if not sep:
        upstream, revision = v, ""
    return epoch, upstream, revision


def dpkg_compare(a: str, b: str) -> int:
    """dpkg --compare-versions: -1, 0 or 1 for one version against another.

    dpkg --compare-versions 相当: 版同士の比較で -1 / 0 / 1。
    """
    ea, ua, ra = _split_dpkg(a)
    eb, ub, rb = _split_dpkg(b)
    if ea != eb:
        return 1 if ea > eb else -1
    r = _verrevcmp(ua, ub) or _verrevcmp(ra, rb)
    return (r > 0) - (r < 0)
