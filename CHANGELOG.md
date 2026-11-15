# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-11-15

### Changed

- README: a rough cost and time of a run, near the top.

### Fixed

- The first run on a server launched from a public AMI (Amazon Linux, Ubuntu, ...).
  AWS does not let the snapshots behind a public AMI be read, so the quick start's
  command ended in an error there.
  - README: the quick start shows the command with a baseline and the one without, and
    says that a public AMI has to be copied first; the steps are under "Choosing the
    baseline".
  - The error now ends with the `aws ec2 copy-image` command to run, on a line of its
    own, filled in with the AMI, the region and the profile of the run.
- README: the link to "What is reported and what is not" did nothing on the PyPI page.

## [0.1.0] - 2026-11-15

The first release.

### Added

- `ec2-byhand --instance-id ID -o DIR`: snapshots the EBS volumes of an EC2 instance,
  compares them with the AMI it was launched from, and deletes the snapshots it made.
  Existing snapshots (`--current-snapshot`) and raw disk images (`--current-image`)
  work too, with a baseline (`--baseline-ami`, `--baseline-snapshot`,
  `--baseline-image`) or without one (`--no-baseline`).
- What it finds, without logging in to the server: files put there by hand, package
  files edited or deleted by hand (as `rpm -V` / `dpkg --verify` would tell), deleted
  files, packages added, removed and upgraded with the command that did it, pip and
  npm packages, services enabled and disabled, containers, snaps, and what cloud-init
  wrote at first boot.
- What it writes: report.txt and manifest.json (the list), after.tar.gz and
  before.tar.gz (the files as they are now and as they were), patches/ (diffs of the
  text files). `--upload` sends them to S3.
- What it leaves out: noise (logs, caches, the package managers' own state...), the
  contents of paths likely to hold secrets, and secret-like strings, which are masked.
- Disks are read without mounting them, through the EBS direct APIs: ext4, XFS, LVM,
  GPT / MBR and FAT (the `diskread` package).
- Messages in English and Japanese (`EC2_BYHAND_LANG`).

[Unreleased]: https://github.com/gyuro-dev/ec2-byhand/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/gyuro-dev/ec2-byhand/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/gyuro-dev/ec2-byhand/releases/tag/v0.1.0
