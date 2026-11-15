# mkfs tools exactly as shipped in Amazon Linux 2023.
FROM amazonlinux:2023
RUN dnf install -y xfsprogs e2fsprogs && dnf clean all
