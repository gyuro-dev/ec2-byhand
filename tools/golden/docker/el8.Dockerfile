# mkfs tools of RHEL 8. UBI's repos do not ship xfsprogs; AlmaLinux rebuilds
# RHEL's source packages, so versions, patches and defaults are the same.
FROM almalinux:8
RUN dnf install -y xfsprogs e2fsprogs && dnf clean all
