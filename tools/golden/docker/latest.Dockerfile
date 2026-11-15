# The newest mkfs tools from Fedora, to cover recent on-disk features.
FROM fedora:latest
RUN dnf install -y xfsprogs e2fsprogs && dnf clean all
