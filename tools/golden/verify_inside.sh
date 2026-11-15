#!/usr/bin/env bash
# Runs inside a distribution container (see build_verify.sh) in two phases.
#
#   verify_inside.sh pre    the "AMI" state: tools the scan needs, plus some
#                           hand-placed files that already exist at baseline
#   verify_inside.sh post   hand work since then; prints scenario.txt
#
# post, package files: edit a config file, edit a non-config file, chmod
# one, chown one, delete one, re-point a symlink, and touch one (mtime only:
# must NOT be reported).
# post, unowned: an app under /opt, a tool and a symlink in /usr/local/bin,
# an /etc config, a web root, an empty /srv dir, a systemd unit enabled by
# hand; change one baseline file, delete another, keep a third unchanged.
# post, packages: install "tree".
set -euo pipefail
phase=${1:?usage: verify_inside.sh pre|post}

if command -v rpm > /dev/null && [ -d /var/lib/rpm ]; then
    kind=rpm
    pm=$(command -v dnf || command -v yum)
    files_of() { rpm -ql "$1"; }
    links_of() { rpm -q --qf '[%{FILENAMES}\t%{FILELINKTOS}\n]' "$1" | awk -F'\t' '$2 != ""'; }
    install() { $pm install -q -y "$@" > /dev/null 2>&1; }
    config=/etc/profile                 # %config(noreplace) in setup
else
    kind=dpkg
    export DEBIAN_FRONTEND=noninteractive
    files_of() { dpkg-query -L "$1"; }
    links_of() { for f in $(dpkg-query -L "$1"); do [ -L "$f" ] && printf '%s\t%s\n' "$f" "$(readlink "$f")"; done; true; }
    install() { apt-get update -qq > /dev/null && apt-get install -qq -y "$@" > /dev/null 2>&1; }
    config=/etc/bash.bashrc             # a conffile of bash
fi

if [ "$phase" = pre ]; then
    if [ $kind = rpm ]; then
        # find is needed by the scan; AL2023's image lacks it. (Not
        # "coreutils": it conflicts with the image's coreutils-single.)
        install findutils || true
        $pm clean all > /dev/null 2>&1 || true
    fi
    mkdir -p /opt/legacy /etc/systemd/system/multi-user.target.wants
    echo "unchanged since the AMI" > /opt/legacy/keep.txt
    echo "version 1" > /opt/legacy/change.txt
    echo "to be removed" > /opt/legacy/remove.txt
    printf '[Service]\nExecStart=/opt/legacy/run\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/legacy.service
    ln -sfn /etc/systemd/system/legacy.service /etc/systemd/system/multi-user.target.wants/legacy.service
    exit 0
fi

# Regular package files in /usr/bin, to edit / chmod / chown / delete / touch.
# (AL2023's container has coreutils-single, so draw from several packages.)
pkgs="coreutils coreutils-single findutils grep sed gawk bash util-linux util-linux-core diffutils"
mapfile -t bins < <(for p in $pkgs; do files_of "$p" 2> /dev/null || true; done | grep '^/usr/bin/' | sort -u \
    | while read -r f; do [ -f "$f" ] && [ ! -L "$f" ] && echo "$f"; done | head -5)
[ ${#bins[@]} -eq 5 ] || { echo "need 5 regular package files, found ${#bins[@]}" >&2; exit 1; }
echo "# hand edit" >> "$config"
printf '\0hand' >> "${bins[0]}"           # content change, size changes too
chmod 0700 "${bins[1]}"                   # mode change only
chown 1234:1234 "${bins[2]}"              # owner change only
rm -f "${bins[3]}"                        # deleted package file
touch -d '2001-01-01' "${bins[4]}"        # mtime only: not a modification of interest
# A package symlink that exists on disk (headers also list ones a minimal
# container did not install), not a debug /usr/lib/.build-id link (noise).
link=$(for p in $pkgs; do links_of "$p" 2> /dev/null || true; done | grep '^/usr/' | grep -v '/\.build-id/' | cut -f1 \
    | while read -r l; do [ -L "$l" ] && { echo "$l"; break; }; done || true)  # break -> SIGPIPE upstream
if [ -n "$link" ]; then ln -sfn /nonexistent/target "$link"; fi

# Hand-placed files nobody's package owns.
mkdir -p /opt/myapp/bin /opt/myapp/conf /usr/local/bin /var/www/html /srv/data
printf '#!/bin/sh\nexec /opt/myapp/bin/server "$@"\n' > /opt/myapp/bin/run.sh
chmod 0755 /opt/myapp/bin/run.sh
head -c 50000 /dev/urandom > /opt/myapp/bin/server
echo "port: 8080" > /opt/myapp/conf/app.yml
printf '#!/bin/sh\necho tool\n' > /usr/local/bin/tool
ln -s tool /usr/local/bin/tool-link
echo "key=value" > /etc/myapp.conf
echo "<h1>hello</h1>" > /var/www/html/index.html
# A secret: reported, but its content must stay out of the archives.
mkdir -p /root/.ssh
echo "-----BEGIN OPENSSH PRIVATE KEY----- (dummy) -----END OPENSSH PRIVATE KEY-----" > /root/.ssh/id_rsa
chmod 0600 /root/.ssh/id_rsa
printf '[Service]\nExecStart=/opt/myapp/bin/run.sh\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/myapp.service
ln -s /etc/systemd/system/myapp.service /etc/systemd/system/multi-user.target.wants/myapp.service

# Changes to what the baseline already had.
echo "version 2" > /opt/legacy/change.txt
rm /opt/legacy/remove.txt

install tree

# Grey zone: a pip package (then edit one of its files and delete another),
# and an alternative chosen by hand.
if [ $kind = rpm ]; then
    install python3-pip
    pip3 install -q requests > /dev/null 2>&1
    alternatives --install /usr/local/bin/myeditor myeditor /usr/bin/cat 10
    alternatives --install /usr/local/bin/myeditor myeditor /usr/bin/tac 20
    alternatives --set myeditor /usr/bin/cat
else
    install python3-pip
    pip3 install -q --break-system-packages requests > /dev/null 2>&1
    update-alternatives --quiet --install /usr/local/bin/myeditor myeditor /usr/bin/cat 10
    update-alternatives --quiet --install /usr/local/bin/myeditor myeditor /usr/bin/tac 20
    update-alternatives --quiet --set myeditor /usr/bin/cat
fi
site=$(python3 -c 'import requests, os; print(os.path.dirname(os.path.dirname(requests.__file__)))')
echo "# hand patch" >> "$site/requests/__version__.py"
rm "$site/requests/help.py"

printf 'kind=%s\nconfig=%s\nedited=%s\nchmodded=%s\nchowned=%s\ndeleted=%s\ntouched=%s\nrelinked=%s\nsite=%s\n' \
    "$kind" "$config" "${bins[0]}" "${bins[1]}" "${bins[2]}" "${bins[3]}" "${bins[4]}" "$link" "$site"
