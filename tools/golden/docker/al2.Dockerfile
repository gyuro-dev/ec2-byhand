# mkfs tools as shipped in Amazon Linux 2.
FROM amazonlinux:2
RUN yum install -y xfsprogs e2fsprogs && yum clean all
