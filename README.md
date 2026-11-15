# ec2-byhand

[日本語版 README](https://github.com/gyuro-dev/ec2-byhand/blob/main/README.ja.md)

A CLI tool that compares an EC2 instance (or its EBS snapshots) with the AMI it was launched from and writes out **a list of what was added or changed by hand since launch**, together with **the files themselves (as they are now, as they were, and patches of the differences)**.

No login to the server and no agent. It reads EBS snapshots directly, so a running production server carries no load.

## Quick start

```bash
pip install ec2-byhand
ec2-byhand --instance-id i-0123456789abcdef0 -o out/
```

That one command takes the snapshots, compares them with the launch AMI and deletes the snapshots it made. The result is in `out/`.

```text
out/
├── report.txt      the list, for people: files and packages added or changed, one a line
├── manifest.json   the list, for programs: the same as JSON
├── after.tar.gz    the actual files (now): what was added or edited by hand, with modes and owners
├── before.tar.gz   the actual files (AMI): as they were before being edited or deleted
└── patches/        patches: what was changed in configuration files (for patch / git apply)
```

It needs Python 3.12 or later. Credentials and region come from the same configuration the AWS CLI uses ([Permissions](#permissions)).

## What it finds and extracts

What changes by itself (logs, caches: `/var/log`, `/tmp`, `/var/cache` and the like) is left out.

| What | For example | In the list | Files you get |
|---|---|---|---|
| **Files put there by hand** | `/opt/myapp/`, `/etc/myapp.conf`, scripts, systemd units, cron jobs | path, type, mode, hash, when it last changed | the file as it is now in after.tar.gz; for an edited one also before.tar.gz and patches/ |
| **Package files edited by hand** | `/etc/ssh/sshd_config`, `/etc/nginx/nginx.conf`, a command whose mode was changed | which package it belongs to and what changed (content, mode, owner) | now in after.tar.gz, as in the AMI in before.tar.gz, the difference in patches/ |
| **Deleted files** | files and directories the AMI had and the server no longer has | the path, and how many entries lay below it | the files before they were deleted, in before.tar.gz |
| **OS packages installed later** | `dnf install nginx`, `apt install jq` | packages added, removed and upgraded, their versions, the command that was run | (the list only) |
| **pip / npm packages** | `pip install`, `npm install` (global, or inside an app) | name and version, and files edited after the install | the edited files in after.tar.gz |
| **Services switched on or off** | `systemctl enable myapp`, `systemctl disable ...` | services enabled, disabled or masked (a package's doing is told from hand work) | units and drop-ins you wrote, in after.tar.gz |
| **Containers** | Docker / Podman / containerd | images, containers and volumes that came or went | (the list only; settings under `/etc/docker` are files like any other) |

- **Works on**: Amazon Linux 2 / 2023, the RHEL family (rpm), Ubuntu / Debian (dpkg). Filesystems: ext4, XFS, LVM, vfat.
- **Secrets**: private keys (`id_rsa`, `*.pem`), `/etc/shadow`, `.env` and the like are listed as `[sensitive]`, and by default their contents stay out of the archives. Passwords and tokens inside text files are replaced with `***MASKED***` (`--include-sensitive` turns that off).

### An example of the output

`out/report.txt` lists the changes it found, one a line (an excerpt):

```text
hand-placed (17)
  added     2026-10-24 13:10  /etc/myapp.conf
  added     2026-10-24 13:10  /etc/systemd/system/myapp.service
  modified  2026-10-24 13:10  /opt/legacy/change.txt [changed: sha256]
  added     2026-10-24 13:10  /opt/myapp/bin/run.sh
  added     2026-10-24 13:10  /root/.ssh/id_rsa [sensitive]

modified package files (10)
  2026-10-24 13:11  /etc/profile  (setup: content, size) [since baseline] [config]
  2026-10-24 13:11  /usr/bin/alias  (bash: mode) [since baseline]

packages (3)
  added       tree.x86_64  1.8.0-6.amzn2023.0.2  (dnf: install -q -y tree)
```

`added` is new since the AMI, `modified` has changed since; then comes when it last changed (UTC).

On the screen, a summary of the numbers (an example):

```text
manifest:              out/manifest.json
report:                out/report.txt
baseline:              ami-0123456789abcdef0 /dev/xvda=snap-0aaaa1111bbbb2222c
changed between:       2026-10-24 13:10 and 2026-10-24 13:11 UTC (last change of each)
hand-placed:           17
modified package files:   10 (6 since baseline)
deleted:               1
packages:              110 installed, +3 -0 ^0 v0
language packages:     5
services:              1
noise:                 628
after.tar.gz:          22 entries
before.tar.gz:         8 entries
patches:               2
```

| Line | Meaning |
|---|---|
| hand-placed | paths no package owns, added or changed since the AMI |
| modified package files | files that differ from what their package installed (in brackets: changed since the AMI) |
| deleted | hand-placed paths the AMI had and the server no longer has |
| packages | how many are installed, and since the AMI: added (+), removed (-), upgraded (^), downgraded (v) |
| noise | paths left out of the lists; see [What is reported and what is not](#scope) |

<a id="scope"></a>

## What is reported and what is not

**Reported**: what the table above lists. And what cloud-init wrote at first boot, what package scripts made, alternatives and snaps, each under its own heading.

**Left out by default (noise)**: what changes on any running server without anyone's hand. The summary gives the number; `noise` in the manifest gives it by rule.

| Rule | Examples |
|---|---|
| Logs | `/var/log/**` (a directory made there by hand is reported), the systemd journal |
| Temporary and runtime files | `/tmp`, `/var/tmp`, `/var/run`, `/run` |
| Package managers' state and caches | `/var/lib/rpm`, `/var/lib/dpkg`, `/var/cache` |
| What the system regenerates | `/etc/machine-id`, `/etc/ld.so.cache`, `/etc/ssh/ssh_host_*`, `/var/lib/cloud`, `*.pyc` |
| Shell and editor history | `.bash_history`, `.viminfo`, `~/.cache` |
| What containers hold | `/var/lib/docker`, `/var/lib/containers` (listed under `containers` instead) |
| Agents' state | the SSM Agent's `/var/lib/amazon` |

`--include GLOB` reports a path whatever the rules say; `--exclude GLOB` adds to them.
Nothing a person may have changed by hand is noise: `/etc/hosts`, crontabs, `/etc/alternatives` are reported.

**Listed, but their contents left out**:

- Paths likely to hold secrets, and secret-like strings (see "Secrets" above). `*.key` and `.aws/credentials` are among the paths.
- Files over 1 GiB (`--max-file-size` changes that), and swap files.

The outputs hold copies of a server's files: please read [SECURITY.md](https://github.com/gyuro-dev/ec2-byhand/blob/main/SECURITY.md) too.

**Not looked at**:

- Volumes that /etc/fstab does not mount (a warning says so), and instance store volumes.
- The layers of container images.

## Usage

### The server now, and what to compare it with

You always give two things: **the server now**, and **what to compare it with (the baseline)**.

```bash
# An EC2 instance: snapshot it and compare with the AMI it was launched from
ec2-byhand --instance-id i-0123456789abcdef0 -o out/

# Snapshots that already exist
ec2-byhand --current-snapshot snap-aaa snap-bbb --baseline-snapshot snap-ccc -o out/

# Local raw disk images, one per EBS volume
ec2-byhand --current-image server-root.img server-data.img --baseline-image ami-root.img -o out/
```

| | The server now | The baseline |
|---|---|---|
| An instance | `--instance-id` | its launch AMI, by default |
| An AMI | | `--baseline-ami` |
| Snapshots | `--current-snapshot` | `--baseline-snapshot` |
| Disk images | `--current-image` | `--baseline-image` |
| No comparison | | `--no-baseline` |

With `--no-baseline` the results include the files the AMI itself provided. `ec2-byhand --help` groups the options the same way.

### Main options

| Option | Does |
|---|---|
| `--exclude GLOB` | leave more paths out. `'DIR/**'` is not even read, which saves time and API charges |
| `--include GLOB` | report a path whatever the noise rules say |
| `--max-file-size SIZE` | do not read larger files (default `1G`; `none` reads all) |
| `--sensitive GLOB` | treat more paths as secrets |
| `--include-sensitive` | archive the contents of secrets too, and leave secret-like strings unmasked |
| `--no-archives` | write manifest.json and report.txt only |
| `--upload s3://bucket/prefix` | also upload the outputs to S3 |
| `--keep-snapshots` | keep the snapshots the run made |
| `--profile` / `--region` | override the AWS configuration |
| `--parallel N` | how many snapshot blocks to fetch at once (default 32) |
| `--verify-checksums` | check the ext4 / XFS v5 metadata checksums |

Patterns match the whole absolute path (`'/opt/app/**'`, `'**/*.bak'`).

<a id="permissions"></a>

### Permissions

[docs/iam-policy.json](https://github.com/gyuro-dev/ec2-byhand/blob/main/docs/iam-policy.json) is the least a run needs (checked on AWS). It may delete only the snapshots it tagged itself.
Snapshots encrypted with the default `aws/ebs` key need nothing more; with a customer managed key, its key policy must allow `kms:Decrypt`.
For `--upload`, add [docs/iam-policy-upload.json](https://github.com/gyuro-dev/ec2-byhand/blob/main/docs/iam-policy-upload.json) (BUCKET and PREFIX are yours to fill in).

### Language of the messages

The messages, the summary and `--help` come in English and Japanese. `EC2_BYHAND_LANG=ja` (or `=en`) chooses; without it the locale does (`LC_ALL`, `LC_MESSAGES`, `LANG`, then the OS setting), and anything but Japanese gives English.
manifest.json is the same in both: it is data for programs and stays English, as does the text of a warning in the summary, which comes from it.

## Details

### The snapshots a run makes

The wait for them has no limit (the first snapshot of a large volume can take hours) and says how far they are every few minutes.
A run that is stopped (Ctrl+C, SIGTERM, a closed terminal or SSH session) deletes its snapshots on the way out.
One that was killed outright leaves them, tagged `ec2-byhand=<instance id>`: `aws ec2 describe-snapshots --owner-ids self --filters Name=tag-key,Values=ec2-byhand` lists them.

### Choosing the baseline

**A backup as the baseline**: an older snapshot of the same server (taken by hand, by DLM, ...) works as the baseline too:
`--instance-id i-... --baseline-snapshot snap-<backup>` lists what was done since that backup,
and `--current-snapshot snap-<newer> --baseline-snapshot snap-<older>` what was done between two backups.
What cloud-init did at first boot is in the backup as well, so it no longer shows.

**Public AMIs**: the EBS direct APIs do not read the snapshots behind a public AMI (AWS answers `Public snapshots are not supported`).
Copy the AMI into your account (`aws ec2 copy-image`) and pass the copy with `--baseline-ami`,
or use `--no-baseline`.
Red Hat's RHEL AMIs cannot be copied (`You do not have permission to access the storage of this ami`): use `--no-baseline` for them.

**dpkg (Ubuntu / Debian)**: dpkg records no permissions, owners or link targets, so a package file is compared with the baseline's copy only when its package has the same version on both sides.
For the other packages (all of them without a baseline) `package_files_to_review` lists the setuid, setgid and world-writable files for a person to read (sudo and friends are among them);
without a baseline a `dpkg-metadata-unverified` warning also says so.
It also lists, as `changed-since-boot`, package files whose ctime is later than both their package's install and the instance's first boot (from cloud-init's log), outside any apt run: a chmod or chown by hand leaves that trace.

### Data volumes

`--instance-id` snapshots every EBS volume; analyzed is what /etc/fstab mounts.
A filesystem nothing mounts gives an `unmounted-volume` warning, and a volume that cannot be opened (damaged LVM metadata, an LV of a kind that is not read) an `unreadable-volume` one.
fstab entries by `UUID=`, `LABEL=` and LVM names always resolve.
`/dev/xvdf` and `/dev/sdf` resolve where the device names are known: with `--instance-id` and `--baseline-ami`, and for snapshots given by id when they are of the instance's own volumes
(`--instance-id i-... --baseline-snapshot snap-<backup of root> snap-<backup of data>`; DescribeSnapshots tells their volumes).
`/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol...` resolves for any snapshot of the volume. Disk images, and snapshots without `--instance-id`, carry no device names: such entries are `unresolved-mount`.
The number in `/dev/nvme1n1` names no volume: when exactly one unmounted volume fits (filesystem type, partition number) it is mounted with an `inferred-mount` warning, otherwise the entry is `unresolved-mount`.
To skip a large volume you do not need, snapshot the root yourself and pass it with `--current-snapshot`.

### The outputs, more closely

report.txt holds nothing manifest.json does not.
Each item carries its `ctime`, when it last changed (the kernel sets it; `touch` cannot), and the summary says between when and when the hand work was done.
ACLs (`setfacl`), capabilities (`setcap`) and other extended attributes count as part of a path: one changed alone is reported (`changed: xattrs`), and `xattrs` names what a path carries; the archives keep the values.
The SELinux label is compared as well: a `chcon` shows as `changed: selinux`, with the label the path has now. When only one side has labels at all (SELinux switched on or off since), that is not counted as a change of each path.
This holds for hand-placed paths; the labels and attributes of package files are not compared (a package's own scripts set them).
The outputs hold copies of files that may be root-only on the server: on Linux and macOS only you can read them; on Windows, protect the folder yourself.

### Large files, large servers

Files over `--max-file-size` get no sha256 and stay out of the archives; against a baseline, size and mtime decide.
Package and pip files over the limit are not checked against their recorded hashes (`content-not-verified` warning). The summary counts what the limit left unread.
Before reading any content, the run says on stderr how much it is about to read in files no package owns; from 1 GiB on it names the largest ones:
the moment to Ctrl+C and `--exclude` a data directory (with `--instance-id` this also deletes the snapshots just made; `--keep-snapshots` keeps them for a `--current-snapshot` run).

Memory grows with the number of files on both sides, about 1.5 to 1.8 KB a path a side (measured: 300,000 files on each side take 0.9 GB on ext4 and 1.0 GB on XFS; a million on each side would need about 3 GB).
With millions of files, leave the data directories out with `--exclude 'DIR/**'`: they are then not walked at all (any `--include` makes the run read everything).

### Uploading to S3

`--upload s3://bucket/prefix` uploads the files the run wrote (report.txt among them, nothing else that `-o` holds),
to `prefix/<label>/<time>/` (the label is the instance or snapshot id, or `--label`; the time is UTC), so no run overwrites another.
Every object is encrypted with SSE-KMS (the aws/s3 key, or `--kms-key-id KEY`) and checked on arrival with SHA-256; large files go up in parts. manifest.json goes last.
The bucket is checked before the analysis starts. With a customer managed key (`--kms-key-id`), the key must also allow `kms:GenerateDataKey`, and `kms:Decrypt` for the files that go up in parts.
If the upload fails, the outputs stay in `-o` and the exit code is 1.

### Secret-like strings

Text files of up to 1 MiB that are reported are scanned for secret-like strings: private keys, AWS access keys, GitHub and Slack tokens, passwords in URLs,
and values given to `password`, `secret`, `token`, `api_key` and the like, written as `key = value`, `key: value`, `'key' => 'value'`, `define('KEY', 'value')` or `<key>value</key>`
(not references such as `${DB_PASSWORD}`, a path, or a call like `getenv(...)`).
A value that only a space separates from its key (redis' `requirepass`) is not found: name such files with `--sensitive`. The manifest says which kind on which line, never the value;
what was masked is listed in `archives.masked`. Swap files are never read: they hold memory, not configuration.

### npm

An app's `node_modules` and global packages are grouped under `language_packages`.
Each package is compared with its own tarball in the server's npm cache (`~/.npm/_cacache`), found by the integrity its lockfile records, or for a global install by the cache's index: `modified` and `missing` are then exact (`verified_by: npm-cache`).
Nothing is downloaded. Without the tarball (a node_modules copied from elsewhere, a cleaned cache), npm records no per-file hashes, so a file changed more than 10 minutes after the install
is listed in `edited_after_install` as a suspected hand edit and goes into after.tar.gz. That one is a guess from times: `npm install` after an edit moves the reference time and hides the edit.

### Containers

Docker (`/var/lib/docker`), Podman (`/var/lib/containers`, and each user's rootless `~/.local/share/containers`) and containerd (`/var/lib/containerd`)
keep their own state there, not edited by hand (the configuration is under `/etc/docker`, `/etc/containers`, `/etc/containerd`, which shows as usual).
Those files are neither listed nor archived, and the image layers are not even read; `containers` in the manifest lists, for each engine,
the images (name and id), the containers (name, image, creation time: not their environment, which often holds passwords) and the volumes (files and bytes) instead,
with a baseline only those added, removed or changed. A rootless Podman's items carry its `user`, containerd's their `namespace`
(Docker's own namespace `moby` is left to Docker).

### Services

Each link under `/etc/systemd/system` in `services` says whether a package made it (`by_package`): deb-systemd-helper recorded it (Debian, Ubuntu),
or it was created inside a dnf / yum / apt run, which is then named in `transaction`. `apt install nginx` enabling nginx is the package's doing; `systemctl enable`, `disable` and `mask` afterwards are not.
A link that went away is the package's doing only when the unit it pointed to went with it.
A service its package enabled and someone then disabled (`apt install apache2`, then `systemctl disable apache2`) is listed as `disabled`: a new server would have it enabled.
Debian and Ubuntu record what a package enabled; for rpm it is worked out from the presets and the unit's `[Install]`, for packages installed since the baseline.

### Snaps

Ubuntu's snaps are listed under `snaps`, read from snapd's own state (`/var/lib/snapd/state.json`): name, type, revision, channel, whether the image came with it (`seeded`),
and for one installed by hand, the snapd change that did it (`via`). With a baseline only those added, removed or refreshed.
What comes with a snap (its `.snap` file, `/snap/<name>`, the units snapd writes, the bare `/var/snap/<name>` directories) is not listed as hand work; what was put in `/var/snap/<name>` is.

### cloud-init

An AMI's snapshot is taken before its first boot, so what cloud-init writes then (the default user's home, `sudoers.d`, `authorized_keys`, the hostname, the network configuration)
would show up as hand work on every instance. Its own log, `/var/log/cloud-init.log`, names each file it writes and each user it adds, with the time.
A file whose ctime falls inside such a write is listed under `cloud_init` in the manifest, by module, instead of `hand_placed`. It is still archived:
user-data's `write_files` is your own configuration. A package file cloud-init rewrote stays in `modified_package_files`, marked with `cloud_init`.
Anything changed afterwards, by hand or by a `runcmd` script, has a later ctime and stays hand work (a key appended to `authorized_keys`, a file put in the home).
If cloud-init ran but its log is gone, nothing is moved and the warning `cloud-init-log-missing` says so.

## How it works

```
hand-placed / hand-modified files
  = files in the current snapshot
  − files unchanged since the AMI
  − files owned by a package (rpm/dpkg) whose hash still matches
  − auto-generated noise (logs, caches, ...)
```

- Disks are read block by block through the **EBS direct APIs**; nothing is mounted
- ext4, XFS and LVM are **parsed in user space**
- Package databases are read from the snapshot too; no rpm command runs on the server
- Even without the AMI, most files are told by "owned by no package, or hash mismatch"

## From Python

```python
from diskread import FileDevice
from ec2_byhand import manifest
from ec2_byhand.analyze import analyze
from ec2_byhand.cli import open_disks

with FileDevice("current.img") as cur, FileDevice("ami.img") as ami:
    m = analyze(open_disks({"disk0": cur}, "current"), open_disks({"disk0": ami}, "ami"))
manifest.write(m, "manifest.json")
```

`open_disks` resolves partitions, LVM and fstab. A server with several disks: list them all (`{"disk0": root, "disk1": data}`).

## Development

```bash
uv sync
uv run pytest
```

Everything CI checks (ruff, mypy, and the tests under each supported Python), in one go:

```bash
bash scripts/check.sh
```

`bash scripts/check.sh 3.13` checks only the versions named. The results are kept in reports/check/ (summary.txt first).

The CLI tests are YAML cases ([tests/casebook_cli.yaml](https://github.com/gyuro-dev/ec2-byhand/blob/main/tests/casebook_cli.yaml) and
[tests/casebook_verify.yaml](https://github.com/gyuro-dev/ec2-byhand/blob/main/tests/casebook_verify.yaml), run with [pytest-casebook](https://pypi.org/project/pytest-casebook/)).
`uv run pytest --casebook-html=reports/casebook.html` renders the test specification (an HTML table).
After changing an expectation, `uv run pytest --casebook-update` rebuilds the goldens (tests/golden/casebook_*/); review the diff.

The EBS direct API path runs end to end against [moto](https://github.com/getmoto/moto), no account needed:

```bash
uv run --group integration pytest tests/test_integration_moto.py
```

It uploads a golden image as a snapshot and compares the output with a run on the image file.
moto's blocks are 512 bytes (EBS: 512 KiB), so it takes about a minute; without the `integration` group it is skipped.
Expiring block tokens, paging, throttling and encrypted snapshots are not reproduced: those need an account.

The golden images are built in WSL as root (packages: `gdisk` `lvm2` `xfsprogs` `acl` `dosfstools`);
some XFS cases (AL2023 / Fedora mkfs defaults) need Docker. They land in `tests/golden/out/`, which is not committed.

```bash
wsl -u root -- bash tools/golden/build_partition.sh tests/golden/out
wsl -u root -- bash tools/golden/build_lvm.sh tests/golden/out
wsl -u root -- bash tools/golden/build_fs.sh tests/golden/out
wsl -u root -- bash tools/golden/build_dirty.sh tests/golden/out
wsl -u root -- bash tools/golden/build_system.sh tests/golden/out
wsl -u root -- bash tools/golden/build_vfat.sh tests/golden/out
# Package DB and version-comparison goldens (Docker)
wsl -u root -- bash tools/golden/build_pkgdb.sh tests/golden/out
wsl -u root -- bash tools/golden/build_vercmp.sh tests/golden/out
wsl -u root -- bash tools/golden/build_verify.sh tests/golden/out
# XFS v4 cannot be mounted by the WSL kernel, so it is built in an AlmaLinux 8 VM
# (requires qemu-system-x86 qemu-utils cloud-image-utils)
wsl -u root -- bash tools/golden/fetch_almalinux8.sh
wsl -u root -- bash tools/golden/vm_almalinux8.sh tests/golden/out xfs-v4 xfs-v4-noftype xfs-v4-1k
```

Without the images, the golden tests are skipped.

## Documentation

- [SECURITY.md](https://github.com/gyuro-dev/ec2-byhand/blob/main/SECURITY.md) — how to report a vulnerability, and what to keep in mind about the outputs
- [CHANGELOG.md](https://github.com/gyuro-dev/ec2-byhand/blob/main/CHANGELOG.md) — what changed in each release

## License

MIT. See [LICENSE](https://github.com/gyuro-dev/ec2-byhand/blob/main/LICENSE).
