#!/usr/bin/env bash
# Runs inside a distribution container (see build_pkgdb.sh): makes package
# changes and saves the package database before and after, together with
# what rpm / dpkg-query themselves report (the expected output).
#
#   pkgdb_inside.sh OUTDIR
#
# Before: an old version of package U (to be upgraded), the newest version
# of package D (to be downgraded), and package R (to be removed).
# After:  U upgraded, D downgraded, R removed, package A added.
set -euo pipefail
out=$1
mkdir -p "$out"

if command -v rpm > /dev/null && [ -d /var/lib/rpm -o -d /usr/lib/sysimage/rpm ]; then
    kind=rpm
    pm=$(command -v dnf || command -v yum)
else
    kind=dpkg
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
fi

# versions PKG -> all available versions, oldest first
versions() {
    if [ $kind = rpm ]; then
        $pm -q --showduplicates list available "$1" 2> /dev/null \
            | awk -v p="$1" '$1 ~ "^"p"\\." {print $2}' | uniq
    else
        apt-cache madison "$1" | awk '{print $3}' | tac | uniq
    fi
}

# first candidate with at least two versions available, skipping $SKIP.
# Prints nothing if there is none (e.g. AlmaLinux 9 repos keep only the
# newest version of each package).
pick_multi() {
    for p in "$@"; do
        [ "$p" = "${SKIP:-}" ] && continue
        if [ "$(versions "$p" | wc -l)" -ge 2 ]; then echo "$p"; return; fi
    done
}

install_version() {  # install_version PKG VERSION
    if [ $kind = rpm ]; then
        v=${2#*:}  # dnf/yum want NAME-VERSION-RELEASE without the epoch
        # AL2's yum answers "already installed" (exit 0) when asked for an
        # older version, so check what is installed and downgrade if needed.
        $pm install -q -y "$1-$v" > /dev/null 2>&1 || true
        rpm -q "$1-$v" > /dev/null 2>&1 || $pm downgrade -q -y "$1-$v" > /dev/null 2>&1 || true
        rpm -q "$1-$v" > /dev/null 2>&1
    else
        apt-get install -qq -y --allow-downgrades "$1=$2" > /dev/null
    fi
}
install() { if [ $kind = rpm ]; then $pm install -q -y "$@" > /dev/null; else apt-get install -qq -y "$@" > /dev/null; fi; }
remove() { if [ $kind = rpm ]; then $pm remove -q -y "$@" > /dev/null; else apt-get remove -qq -y "$@" > /dev/null; fi; }

snap() {  # snap NAME
    local d="$out/$1"
    mkdir -p "$d"
    if [ $kind = rpm ]; then
        src=/var/lib/rpm
        [ -d /usr/lib/sysimage/rpm ] && src=/usr/lib/sysimage/rpm
        cp -aL "$src" "$d/rpm"
        rpm -qa --qf '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\n' | sort > "$d/expected.tsv"
        rpm -qa --qf '[%{=NAME}\t%{=ARCH}\t%{FILENAMES}\t%{FILEDIGESTS}\t%{FILEMODES}\t%{FILEFLAGS}\t%{FILESIZES}\n]' \
            | sort > "$d/files.tsv"
        # Transaction history as stored, and as the package manager's API reads it.
        mkdir -p "$d/dnf" "$d/yum"
        cp -a /var/lib/dnf/history.sqlite* "$d/dnf/" 2> /dev/null || true
        cp -a /var/lib/yum/history/history-*.sqlite* "$d/yum/" 2> /dev/null || true
        py=python3
        [ -x /usr/libexec/platform-python ] && py=/usr/libexec/platform-python
        command -v dnf > /dev/null || py=python2
        $py /tools/history_truth.py > "$d/history.json"
    else
        mkdir -p "$d/dpkg"
        cp -a /var/lib/dpkg/status "$d/dpkg/"
        cp -a /var/lib/dpkg/info "$d/dpkg/"
        mkdir -p "$d/apt"
        cp -a /var/log/apt/history.log* "$d/apt/" 2> /dev/null || true
        dpkg-query -W -f '${Package}\t${Architecture}\t${Version}\t${db:Status-Abbrev}\n' | sort > "$d/expected.tsv"
        dpkg-query -W -f '${binary:Package}\t${Package}\t${Architecture}\n' | while IFS=$(printf '\t') read -r bp p a; do
            dpkg-query -L "$bp" 2> /dev/null | sed "s|^|$p\t$a\t|"
        done | sort > "$d/files.tsv"
    fi
}

if [ $kind = rpm ]; then
    candidates="jq tree less which file bc zip unzip diffutils findutils"
    R=tar; A=gzip
    rpm -q "$R" > /dev/null 2>&1 || install "$R"
    rpm -q "$A" > /dev/null 2>&1 && A=cpio
else
    # Packages without tight versioned dependencies, so old versions install.
    candidates="tzdata distro-info-data ca-certificates libsqlite3-0 gpgv less"
    R=tree; A=zip
    install "$R"
fi
# first_installable WHICH PKG... -> the first package (with two or more
# versions) whose oldest ("head") or newest ("tail") version installs.
first_installable() {
    local which=$1 p
    shift
    for p in "$@"; do
        [ "$p" = "${SKIP:-}" ] && continue
        [ "$(versions "$p" | wc -l)" -ge 2 ] || continue
        if install_version "$p" "$(versions "$p" | $which -1)" 2> /dev/null; then echo "$p"; return; fi
    done
}
U=$(first_installable head $candidates)
D=$(SKIP=$U first_installable tail $candidates)
snap before

if [ -n "$U" ]; then install_version "$U" "$(versions "$U" | tail -1)"; fi
if [ -n "$D" ]; then install_version "$D" "$(versions "$D" | head -1)"; fi
remove "$R"
install "$A"
snap after

printf 'upgraded=%s\ndowngraded=%s\nremoved=%s\nadded=%s\n' "$U" "$D" "$R" "$A" > "$out/scenario.txt"
cat "$out/scenario.txt"
