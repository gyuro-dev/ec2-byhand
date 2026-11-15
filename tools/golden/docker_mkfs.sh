#!/usr/bin/env bash
# Run a mkfs command from another distribution's userland via Docker.
#
#   docker_mkfs.sh al2023|latest IMAGE_FILE MKFS_COMMAND [ARGS...]
#   docker_mkfs.sh al2023|latest --version
#
# The image file's directory is bind-mounted, so no loop device or
# privileges are needed: mkfs just writes into a regular file. The
# containers are built from tools/golden/docker/<tag>.Dockerfile.
set -euo pipefail

tag=${1:?usage: docker_mkfs.sh TAG IMAGE_FILE MKFS...}
shift
here=$(cd "$(dirname "$0")" && pwd)
docker build -q -t "ec2byhand-mkfs-$tag" -f "$here/docker/$tag.Dockerfile" "$here/docker" > /dev/null

if [ "$1" = "--version" ]; then
    docker run --rm "ec2byhand-mkfs-$tag" bash -c \
        'grep PRETTY_NAME /etc/os-release; mkfs.xfs -V; mke2fs -V 2>&1 | head -1'
    exit
fi

img=$(realpath "$1")
shift
# TEST_DIR + TEST_DEV + QA_CHECK_FS together lift mkfs.xfs's 300 MB minimum
# (an fstests escape hatch) so golden images stay small. They do not change
# any other default.
docker run --rm -e TEST_DIR=1 -e TEST_DEV=1 -e QA_CHECK_FS=1 -v "$(dirname "$img"):/w" "ec2byhand-mkfs-$tag" \
    "$@" "/w/$(basename "$img")"
