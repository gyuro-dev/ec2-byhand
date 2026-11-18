"""What the command says to its user, in English and Japanese.

  TEXTS   every message: errors, progress, the values of the summary, --help
  LABELS  the labels of the summary, which row() lines up in one column; report.txt
          heads its sections with them (label)

The language is English unless language() says otherwise. The command takes it from
the environment (language_from_environment): EC2_BYHAND_LANG=ja or =en, else the
locale. manifest.json is data for programs and stays English whatever the language,
so the text of a warning, which comes from it, does too; so do the errors of
diskread, of AWS and of argparse itself ("the following arguments are required").

コマンドが利用者に見せる文言の英語と日本語の表。TEXTS は全メッセージ（エラー・進捗・まとめの
値・--help）、LABELS はまとめの見出しで、row() が 1 つの列にそろえる。言語は language() で
変えない限り英語。コマンドは環境から決める（language_from_environment）: EC2_BYHAND_LANG=ja か
=en、無ければロケール。manifest.json はプログラムが読むデータなので、言語によらず英語のまま。
そこから来る警告の本文と、diskread・AWS・argparse 自身のエラーも英語のまま。
"""

from __future__ import annotations

import contextlib
import locale
import os
import re
import unicodedata
from collections.abc import Iterator
from typing import Any

ENV = "EC2_BYHAND_LANG"

TEXTS: dict[str, dict[str, str]] = {
    "en": {
        # --- arguments that are not what they should be ---
        "not_a_size": "not a size: {text!r} (examples: 500K, 100M, 2G)",
        "not_a_path_glob": (
            "not a path glob: {text!r} (it must match the whole absolute path; "
            "examples: '/opt/app/**', '**/*.bak')"
        ),
        "not_a_parallel_count": "a whole number from 1 to {max}, not {text!r}",
        "not_an_s3_url": "not an s3:// URL: {text!r}",
        "not_a_bucket_name": "not a bucket name: {bucket!r}",
        "no_such_image": "{label}: no such image file: {image}",
        "cannot_assemble": "{label}: {error}; volumes found: {found}",
        "no_filesystem": "no filesystem",
        "no_volumes": "none",
        "output_not_a_directory": "output path is not a directory: {path}",
        "output_not_empty": "output directory is not empty: {path} (use --force to overwrite)",
        "kms_key_without_upload": "--kms-key-id is for --upload",
        # --- how a run ends when it fails ---
        "interrupted": "interrupted",
        "error": "error: {error}",
        "cannot_read_disks": "cannot read the disk images: {error}",
        "aws_error": "AWS error: {error}",
        # --- AWS: the instance, the AMI, the snapshots ---
        "instance_not_found": "instance {instance} not found",
        "instance_no_volumes": "instance {instance} has no EBS volumes",
        "ami_cannot_be_described": (
            "AMI {image} cannot be described ({code}); it may be deregistered "
            "or not shared with this account. "
            "Pass the baseline snapshots with --baseline-snapshot."
        ),
        "ami_not_found": (
            "AMI {image} not found; it may be deregistered. "
            "Pass the baseline snapshots with --baseline-snapshot."
        ),
        "ami_no_snapshots": "AMI {image} has no EBS snapshots (instance store AMI?)",
        "cannot_read_blocks": (
            "{label}: cannot read the blocks of {snapshot} ({code}): {reason}{next_step}"
        ),
        "blocks_public": (
            "it is a public snapshot (such as one behind a public AMI), "
            "which the EBS direct APIs do not read."
        ),
        "blocks_denied": (
            "the IAM policy must allow ebs:ListSnapshotBlocks and "
            "ebs:GetSnapshotBlock, and snapshots owned by another account "
            "may not be readable at all."
        ),
        "blocks_next_step": (
            " Copy the AMI into this account (aws ec2 copy-image) and pass the copy "
            "with --baseline-ami, pass snapshots you own with --baseline-snapshot, "
            "or compare with nothing using --no-baseline."
        ),
        "cannot_copy_ami": (
            "baseline: {image} is a public AMI, whose snapshots the EBS direct APIs do not "
            "read, and copying it into this account was refused ({code}: {why}).{next_step}"
        ),
        "copy_ami_denied": (
            " The IAM policy must allow ec2:CopyImage (see docs/iam-policy.json), or copy it "
            "with the command below and pass the copy with --baseline-ami. Or pass snapshots "
            "you own with --baseline-snapshot, or compare with nothing using --no-baseline."
        ),
        "copy_ami_refused": (
            " Pass snapshots you own with --baseline-snapshot, "
            "or compare with nothing using --no-baseline."
        ),
        "ami_copy_failed": "the copy {copy} of the AMI failed: {why}",
        "ami_copy_gone": (
            "the copy {copy} of the AMI is not there (deregistered by someone else?)"
        ),
        # --- progress ---
        "copying_ami": (
            "baseline: {image} is a public AMI, whose snapshots the EBS direct APIs do not "
            "read: copying it into this account as {copy} (deleted at the end)"
        ),
        "copying_ami_kept": (
            "baseline: {image} is a public AMI, whose snapshots the EBS direct APIs do not "
            "read: copying it into this account as {copy} (kept: --keep-snapshots)"
        ),
        "waiting_for_copy": "waiting for the copy {copy} of the AMI (minutes)",
        "copy_progress": "the copy of the AMI so far: {progress}",
        "creating_snapshots": "creating snapshots of {instance} (CreateSnapshots)",
        "waiting_for_snapshots": (
            "waiting for {count} snapshot(s) to complete (minutes, longer for large volumes)"
        ),
        "snapshots_progress": "snapshots so far: {progress}",
        "snapshot_failed": "the snapshot {snapshot} failed: {why}",
        "reading_snapshots": "{label}: reading {snapshots} over the EBS direct APIs",
        "cannot_tell_volumes": "{label}: cannot tell the snapshots' volumes ({error})",
        "analyzing": "analyzing (file contents are read over the EBS direct APIs)",
        "read_so_far": "read {reads} blocks ({mib:.0f} MiB) so far",
        "keeping_snapshots": "keeping snapshots: {ids}",
        "deleting_snapshots": "deleting the snapshots this run made: {ids}",
        "snapshots_deleted": "snapshots deleted",
        "could_not_delete": "warning: could not delete {snapshot}: {why}",
        "snapshots_left": "warning: stopped while deleting the snapshots; "
        "still there, delete them by hand: {ids}",
        "keeping_copies": (
            "keeping the AMI copies: {ids} (--baseline-ami takes them; deregister them "
            "and delete their snapshots when done)"
        ),
        "deleting_copies": "deleting the AMI copies this run made, and their snapshots: {ids}",
        "copies_deleted": "AMI copies deleted",
        "copy_snapshots_left": (
            "{count} snapshot(s) of the copy, stopped before it was done, were not there "
            "to delete yet; they carry the tag {tag}"
        ),
        "copies_left": "warning: stopped while deleting the AMI copies; still there, "
        "deregister them and delete their snapshots by hand: {ids}",
        # --- what there is to read, said before reading it ---
        "one_byte": "1 byte",
        "bytes": "{size} bytes",
        "plan": "will read up to {size} in {files} files that no package owns",
        "plan_over_limit": "; {count} over {limit} left unread",
        "plan_largest": "; the largest:",
        "plan_hint": "to leave data out: Ctrl+C, then run again with --exclude 'DIR/**'",
        "plan_hint_snapshots": (
            " (this also deletes the snapshots just made; "
            "--keep-snapshots keeps them for --current-snapshot)"
        ),
        "plan_hint_copy": (
            " (this also deletes the AMI copy just made, and the snapshots if any; "
            "--keep-snapshots keeps them, for --baseline-ami and --current-snapshot)"
        ),
        # --- --upload ---
        "no_such_bucket": "no such bucket: {bucket}",
        "bucket_access_denied": (
            "cannot reach bucket {bucket}: access denied "
            "(--upload needs s3:ListBucket on the bucket and s3:PutObject below the prefix)"
        ),
        "bucket_unreachable": "cannot reach bucket {bucket}: {error}",
        "upload_file_failed": "uploading {name} to s3://{bucket}/{key} failed: {error}",
        "uploading": "uploading to s3://{bucket}/{prefix}/",
        "upload_failed": "{error} (the outputs are in {outdir})",
        "uploaded_to": "s3://{bucket}/{prefix}/ ({count} files)",
        # --- the summary: what stands after the labels ---
        "unknown": "unknown",
        "since_baseline": " ({count} since baseline)",
        "modified_without_baseline": (
            " (changed; which lines, and whether by the AMI or by hand: unknown)"
        ),
        "packages_installed": "{count} installed",
        "package_changes_unknown": " (changes since baseline unknown)",
        "package_entries_unreadable": " (some entries unreadable)",
        "baseline_none": (
            "none: the AMI's own files are listed with the hand work, and\n"
            "what was deleted, earlier versions and patches cannot be shown\n"
            "(give an early backup: --baseline-snapshot, --baseline-ami)"
        ),
        "changed_between": "{first} and {last} UTC (last change of each)",
        "ami_files_too": " (the AMI's own files too)",
        "may_include_package_files": " (may include package files)",
        "deleted_unknown": "unknown (no baseline)",
        "edited_after_install": " ({count} files edited after install)",
        "count_files": "{count} files",
        "services_by_package": " ({count} by packages)",
        "containers": "{images} images, {containers} containers, {volumes} volumes",
        "not_read": "{count} files over {limit}",
        "not_read_package_files": ", {count} of them package files",
        "not_read_hint": " (--max-file-size none reads them)",
        "secrets": '{count} files hold secret-like strings (see "secrets" in the manifest)',
        "to_review": (
            "{count} package files "
            "are setuid, setgid, world-writable or changed since the first boot "
            "(see manifest package_files_to_review)"
        ),
        "count_entries": "{count} entries",
        "patches_none": "none (no baseline to compare with)",
        "skipped": "{count} (see manifest archives.skipped)",
        "masked": (
            "{count} files with secret-like strings masked (--include-sensitive keeps them)"
        ),
        "snapshots_made": "{ids} ({fate})",
        "kept": "kept",
        "deleted": "deleted",
        "not_deleted": "NOT deleted: delete them by hand",
        "warning": "warning: {code}{place}: {message}",
        "warnings_more": 'warning: {code}: {count} more (see "warnings" in the manifest)',
        # --- report.txt ---
        "report_title": "ec2-byhand {version} report, {time} UTC",
        "report_note": (
            "Below: what the numbers above count, one item a line, in the words of\n"
            "manifest.json (status, problems, kinds). The time is the item's last change\n"
            "(ctime, UTC); brackets hold what else the manifest says of it, secrets as\n"
            "kind (line)."
        ),
        "report_since_baseline": "since baseline",
        "report_in_baseline": "already so in the baseline",
        "report_by_package": "by a package",
        "report_below": " (and {count} below it)",
        # --- --help ---
        "help_description": (
            "Find what was done by hand on a server: compare its disks with the AMI\n"
            "it started from, and write manifest.json and the changed files to --output."
        ),
        "help_epilog": (
            "example: ec2-byhand --instance-id i-0123456789abcdef0 -o out/\n"
            "messages in Japanese: set the environment variable EC2_BYHAND_LANG=ja"
        ),
        "help_group_options": "options",
        "help_help": "show this help message and exit",
        "help_version": "show program's version number and exit",
        "help_group_now": "the server now (choose one)",
        "help_instance_id": "snapshot this instance's EBS volumes now and analyze them",
        "help_current_snapshot": "EBS snapshots of the server now",
        "help_current_image": "raw disk images of the server now",
        "help_group_baseline": (
            "the AMI to compare with (default: the AMI the instance started from)"
        ),
        "help_baseline_ami": "compare with this AMI instead of the launch AMI",
        "help_baseline_snapshot": "EBS snapshots of the AMI",
        "help_baseline_image": "raw disk images of the AMI",
        "help_no_baseline": "do not compare with an AMI",
        "help_group_what": "what counts as a change",
        "help_exclude": (
            "extra noise pattern, matched against the whole path, e.g. '/opt/app/**' "
            "(not read at all) or '**/*.bak' (repeatable)"
        ),
        "help_include": "never treat as noise, same form as --exclude (repeatable)",
        "help_verify_checksums": (
            "check ext4 / XFS v5 metadata checksums; a mismatch is a read error"
        ),
        "help_group_output": "output",
        "help_output": "where to write manifest.json, report.txt and the archives",
        "help_max_file_size": (
            "do not read larger files (default: 1G; 'none' reads every file): no sha256 "
            "in the manifest, not checked against their package, left out of the archives"
        ),
        "help_include_sensitive": (
            "also archive the contents of likely secrets, and leave secret-like strings "
            "(passwords, keys, tokens) unmasked in the archives and patches"
        ),
        "help_sensitive": (
            "treat these paths as secrets too: listed in the manifest, their contents kept "
            "out of the archives, e.g. '/opt/app/conf/prod.yml' (repeatable)"
        ),
        "help_no_archives": "write manifest.json and report.txt only: no archives, no patches",
        "help_upload": (
            "also upload the outputs to s3://bucket/prefix/<label>/<time>/, encrypted with "
            "SSE-KMS; the bucket is checked before the analysis starts"
        ),
        "help_kms_key_id": "KMS key for --upload (default: the aws/s3 key)",
        "help_label": "name for the current snapshot in the manifest",
        "help_force": (
            "write into a non-empty output directory, replacing an earlier run's outputs"
        ),
        "help_quiet": "no summary on stdout",
        "help_group_aws": "AWS",
        "help_region": "AWS region (default: from the AWS configuration)",
        "help_profile": "AWS profile name",
        "help_keep_snapshots": (
            "keep the snapshots --instance-id made, and the copy made of a public AMI"
        ),
        "help_parallel": (
            "snapshot blocks fetched at once (default: {default}): fewer on a "
            "slow line, more from inside AWS"
        ),
    },
    "ja": {
        # --- arguments that are not what they should be ---
        "not_a_size": "サイズではありません: {text!r}（例: 500K, 100M, 2G）",
        "not_a_path_glob": (
            "パスのパターンではありません: {text!r}（絶対パス全体と照合します。"
            "例: '/opt/app/**', '**/*.bak'）"
        ),
        "not_a_parallel_count": "1 から {max} までの整数を指定してください: {text!r}",
        "not_an_s3_url": "s3:// の URL ではありません: {text!r}",
        "not_a_bucket_name": "バケット名ではありません: {bucket!r}",
        "no_such_image": "{label}: イメージファイルがありません: {image}",
        "cannot_assemble": "{label}: {error}。見つかったボリューム: {found}",
        "no_filesystem": "ファイルシステムなし",
        "no_volumes": "なし",
        "output_not_a_directory": "出力先がディレクトリではありません: {path}",
        "output_not_empty": (
            "出力先のディレクトリが空ではありません: {path}（--force で上書きします）"
        ),
        "kms_key_without_upload": "--kms-key-id は --upload と一緒に使います",
        # --- how a run ends when it fails ---
        "interrupted": "中断しました",
        "error": "エラー: {error}",
        "cannot_read_disks": "ディスクイメージを読み込めません: {error}",
        "aws_error": "AWS のエラー: {error}",
        # --- AWS: the instance, the AMI, the snapshots ---
        "instance_not_found": "インスタンス {instance} が見つかりません",
        "instance_no_volumes": "インスタンス {instance} に EBS ボリュームがありません",
        "ami_cannot_be_described": (
            "AMI {image} の情報を取得できません（{code}）。登録を解除されたか、"
            "このアカウントに共有されていない可能性があります。"
            "baseline のスナップショットを --baseline-snapshot で渡してください。"
        ),
        "ami_not_found": (
            "AMI {image} が見つかりません。登録を解除された可能性があります。"
            "baseline のスナップショットを --baseline-snapshot で渡してください。"
        ),
        "ami_no_snapshots": (
            "AMI {image} に EBS スナップショットがありません"
            "（インスタンスストアの AMI かもしれません）"
        ),
        "cannot_read_blocks": (
            "{label}: {snapshot} のブロックを読み込めません（{code}）: {reason}{next_step}"
        ),
        "blocks_public": (
            "公開スナップショット（公開 AMI のものなど）は、EBS direct API では読み込めません。"
        ),
        "blocks_denied": (
            "IAM ポリシーで ebs:ListSnapshotBlocks と ebs:GetSnapshotBlock を"
            "許可する必要があります。他のアカウントが所有するスナップショットは、"
            "許可しても読み込めないことがあります。"
        ),
        "blocks_next_step": (
            "AMI を自分のアカウントにコピーして（aws ec2 copy-image）--baseline-ami で渡すか、"
            "自分のスナップショットを --baseline-snapshot で渡すか、"
            "--no-baseline で比較なしにしてください。"
        ),
        "cannot_copy_ami": (
            "baseline: {image} は公開 AMI で、そのスナップショットは EBS direct API では"
            "読み込めません。このアカウントへのコピーも拒否されました（{code}: {why}）。{next_step}"
        ),
        "copy_ami_denied": (
            "IAM ポリシーで ec2:CopyImage を許可するか（docs/iam-policy.json を参照）、"
            "下のコマンドでコピーして、そのコピーを --baseline-ami で渡してください。"
            "自分のスナップショットを --baseline-snapshot で渡すか、"
            "--no-baseline で比較なしにすることもできます。"
        ),
        "copy_ami_refused": (
            "自分のスナップショットを --baseline-snapshot で渡すか、"
            "--no-baseline で比較なしにしてください。"
        ),
        "ami_copy_failed": "AMI のコピー {copy} が失敗しました: {why}",
        "ami_copy_gone": (
            "AMI のコピー {copy} が見つかりません（ほかで登録を解除された可能性があります）"
        ),
        # --- progress ---
        "copying_ami": (
            "baseline: {image} は公開 AMI で、そのスナップショットは EBS direct API では"
            "読み込めないため、このアカウントに {copy} としてコピーします（最後に削除します）"
        ),
        "copying_ami_kept": (
            "baseline: {image} は公開 AMI で、そのスナップショットは EBS direct API では"
            "読み込めないため、このアカウントに {copy} としてコピーします"
            "（--keep-snapshots のため残します）"
        ),
        "waiting_for_copy": "AMI のコピー {copy} の完了を待ちます（数分）",
        "copy_progress": "AMI のコピーの進捗: {progress}",
        "creating_snapshots": "{instance} のスナップショットを作成します（CreateSnapshots）",
        "waiting_for_snapshots": (
            "{count} 個のスナップショットの完了を待ちます"
            "（数分。大きなボリュームではさらにかかります）"
        ),
        "snapshots_progress": "スナップショットの進捗: {progress}",
        "snapshot_failed": "スナップショット {snapshot} が失敗しました: {why}",
        "reading_snapshots": "{label}: {snapshots} を EBS direct API で読み込みます",
        "cannot_tell_volumes": (
            "{label}: スナップショットの元のボリュームが分かりません（{error}）"
        ),
        "analyzing": "解析します（ファイルの中身は EBS direct API で読み込みます）",
        "read_so_far": "ここまでに {reads} ブロック（{mib:.0f} MiB）を読み込みました",
        "keeping_snapshots": "スナップショットを残します: {ids}",
        "deleting_snapshots": "この実行で作成したスナップショットを削除します: {ids}",
        "snapshots_deleted": "スナップショットを削除しました",
        "could_not_delete": "警告: {snapshot} を削除できませんでした: {why}",
        "snapshots_left": "警告: スナップショットの削除が途中で止まりました。"
        "残っているものを手動で削除してください: {ids}",
        "keeping_copies": (
            "AMI のコピーを残します: {ids}（--baseline-ami で使えます。"
            "使い終わったら登録を解除し、そのスナップショットを削除してください）"
        ),
        "deleting_copies": (
            "この実行で作成した AMI のコピーとそのスナップショットを削除します: {ids}"
        ),
        "copies_deleted": "AMI のコピーを削除しました",
        "copy_snapshots_left": (
            "完了前に止めたコピーのスナップショット {count} 個が、まだ削除できる状態に"
            "なっていませんでした。タグ {tag} が付いています"
        ),
        "copies_left": "警告: AMI のコピーの削除が途中で止まりました。残っているものの登録を"
        "解除し、そのスナップショットを手動で削除してください: {ids}",
        # --- what there is to read, said before reading it ---
        "one_byte": "1 バイト",
        "bytes": "{size} バイト",
        "plan": "どのパッケージにも属さない {files} ファイル、最大 {size} を読み込みます",
        "plan_over_limit": "（{limit} を超える {count} 個は読み込みません）",
        "plan_largest": "。大きいもの:",
        "plan_hint": (
            "データを除外するには: Ctrl+C で止め、--exclude 'DIR/**' を付けて再実行してください"
        ),
        "plan_hint_snapshots": (
            "（作成したばかりのスナップショットも削除されます。"
            "--keep-snapshots で残せば --current-snapshot で使えます）"
        ),
        "plan_hint_copy": (
            "（作成したばかりの AMI のコピーも、スナップショットがあればそれも削除されます。"
            "--keep-snapshots で残せば --baseline-ami と --current-snapshot で使えます）"
        ),
        # --- --upload ---
        "no_such_bucket": "バケットがありません: {bucket}",
        "bucket_access_denied": (
            "バケット {bucket} にアクセスできません: アクセスが拒否されました"
            "（--upload には、バケットへの s3:ListBucket と、"
            "prefix の下への s3:PutObject が必要です）"
        ),
        "bucket_unreachable": "バケット {bucket} にアクセスできません: {error}",
        "upload_file_failed": (
            "{name} を s3://{bucket}/{key} にアップロードできませんでした: {error}"
        ),
        "uploading": "s3://{bucket}/{prefix}/ にアップロードします",
        "upload_failed": "{error}（出力は {outdir} にあります）",
        "uploaded_to": "s3://{bucket}/{prefix}/（{count} ファイル）",
        # --- the summary: what stands after the labels ---
        "unknown": "不明",
        "since_baseline": "（baseline 以降は {count}）",
        "modified_without_baseline": ("（どの行が変わったか、AMI によるものか手作業かは不明）"),
        "packages_installed": "インストール済み {count}",
        "package_changes_unknown": "（baseline からの変化は不明）",
        "package_entries_unreadable": "（一部のエントリは読めない）",
        "baseline_none": (
            "なし: AMI に元からあるファイルも手作業と一緒に並び、\n"
            "削除されたファイル・変更前のファイル・パッチは出力できない\n"
            "（古いバックアップを指定する: --baseline-snapshot, --baseline-ami）"
        ),
        "changed_between": "{first} から {last} UTC（各項目の最終変更）",
        "ami_files_too": "（AMI に元からあるファイルも含む）",
        "may_include_package_files": "（パッケージのファイルを含む可能性がある）",
        "deleted_unknown": "不明（baseline なし）",
        "edited_after_install": "（インストール後に編集されたファイル {count}）",
        "count_files": "{count} ファイル",
        "services_by_package": "（うちパッケージによるもの {count}）",
        "containers": "イメージ {images}、コンテナ {containers}、ボリューム {volumes}",
        "not_read": "{limit} を超える {count} ファイル",
        "not_read_package_files": "、うちパッケージのファイル {count}",
        "not_read_hint": "（--max-file-size none で読み込む）",
        "secrets": (
            '{count} ファイルに機密情報とみられる文字列がある（manifest の "secrets" を参照）'
        ),
        "to_review": (
            "パッケージのファイル {count} 個が、setuid・setgid・誰でも書き込める・"
            "初回起動より後に変更、のいずれか（manifest の package_files_to_review を参照）"
        ),
        "count_entries": "{count} エントリ",
        "patches_none": "なし（比較する baseline がない）",
        "skipped": "{count}（manifest の archives.skipped を参照）",
        "masked": (
            "機密情報とみられる文字列をマスクしたファイル {count}"
            "（--include-sensitive でそのまま入れる）"
        ),
        "snapshots_made": "{ids}（{fate}）",
        "kept": "保持",
        "deleted": "削除済み",
        "not_deleted": "未削除: 手動で削除してください",
        "warning": "警告: {code}{place}: {message}",
        "warnings_more": '警告: {code}: ほかに {count} 件（manifest の "warnings" を参照）',
        # --- report.txt ---
        "report_title": "ec2-byhand {version} のレポート（{time} UTC）",
        "report_note": (
            "以下は、上の件数の内訳。1 行に 1 項目で、用語は manifest.json のもの\n"
            "（status・problems・kind）。時刻は各項目の最終変更時刻（ctime、UTC）。\n"
            "[ ] の中は manifest にあるその項目の補足で、secrets は\n"
            "種類（行）。"
        ),
        "report_since_baseline": "baseline 以降",
        "report_in_baseline": "baseline の時点で同じ",
        "report_by_package": "パッケージによる",
        "report_below": "（配下に {count}）",
        # --- --help ---
        "help_description": (
            "サーバーに手動で加えられた変更を見つける: ディスクを起動元の AMI と比較し、\n"
            "manifest.json と変更されたファイルを --output に出力する。"
        ),
        "help_epilog": (
            "例: ec2-byhand --instance-id i-0123456789abcdef0 -o out/\n"
            "英語のメッセージにする: 環境変数 EC2_BYHAND_LANG=en"
        ),
        "help_group_options": "オプション",
        "help_help": "このヘルプを表示して終了する",
        "help_version": "バージョンを表示して終了する",
        "help_group_now": "現在のサーバー（いずれか 1 つ）",
        "help_instance_id": "このインスタンスの EBS ボリュームのスナップショットを作成して解析する",
        "help_current_snapshot": "現在のサーバーの EBS スナップショット",
        "help_current_image": "現在のサーバーの raw ディスクイメージ",
        "help_group_baseline": "比較対象の AMI（既定: インスタンスの起動元の AMI）",
        "help_baseline_ami": "起動元の AMI の代わりに、この AMI と比較する",
        "help_baseline_snapshot": "AMI の EBS スナップショット",
        "help_baseline_image": "AMI の raw ディスクイメージ",
        "help_no_baseline": "AMI と比較しない",
        "help_group_what": "何を変更とみなすか",
        "help_exclude": (
            "ノイズとして扱うパターンを追加する。パス全体と照合する。例: '/opt/app/**'"
            "（読み込みもしない）、'**/*.bak'（複数指定できる）"
        ),
        "help_include": "ノイズとして扱わないパターン。--exclude と同じ形式（複数指定できる）",
        "help_verify_checksums": (
            "ext4 / XFS v5 のメタデータのチェックサムを照合する。不一致は読み取りエラー"
        ),
        "help_group_output": "出力",
        "help_output": "manifest.json・report.txt・アーカイブを書くディレクトリ",
        "help_max_file_size": (
            "これより大きいファイルは読み込まない（既定: 1G。'none' ですべて読み込む）: "
            "manifest に sha256 が付かず、パッケージの記録と照合せず、アーカイブに入れない"
        ),
        "help_include_sensitive": (
            "機密情報を含む可能性のあるファイルの中身もアーカイブに入れ、アーカイブとパッチの中の"
            "機密情報とみられる文字列（パスワード・鍵・トークン）もマスクしない"
        ),
        "help_sensitive": (
            "このパスも機密情報として扱う: manifest には載せ、中身はアーカイブに入れない。"
            "例: '/opt/app/conf/prod.yml'（複数指定できる）"
        ),
        "help_no_archives": (
            "manifest.json と report.txt だけを書く（アーカイブとパッチは書かない）"
        ),
        "help_upload": (
            "出力を s3://bucket/prefix/<label>/<time>/ にもアップロードする。SSE-KMS で暗号化する。"
            "バケットは解析の前に確認する"
        ),
        "help_kms_key_id": "--upload に使う KMS の鍵（既定: aws/s3 の鍵）",
        "help_label": "manifest に記録する、現在のサーバーの名前",
        "help_force": "空でない出力先に書き込む。前回の実行の出力は置き換える",
        "help_quiet": "まとめを stdout に出力しない",
        "help_group_aws": "AWS",
        "help_region": "AWS のリージョン（既定: AWS の設定から）",
        "help_profile": "AWS のプロファイル名",
        "help_keep_snapshots": (
            "--instance-id が作成したスナップショットと、公開 AMI から作成したコピーを残す"
        ),
        "help_parallel": (
            "スナップショットのブロックを同時に取得する数（既定: {default}）: "
            "回線が遅ければ減らし、AWS 内から実行するなら増やす"
        ),
    },
}
LANGS = tuple(TEXTS)

# The labels of the summary. The longest of a language sets the column where the
# values start (row), so a new label needs no realigning of the others.
LABELS: dict[str, dict[str, str]] = {
    "en": {
        "manifest": "manifest",
        "report": "report",
        "current": "current",
        "baseline": "baseline",
        "changed_between": "changed between",
        "hand_placed": "hand-placed",
        "modified_package_files": "modified package files",
        "deleted": "deleted",
        "packages": "packages",
        "snaps": "snaps",
        "language_packages": "language packages",
        "package_scripts": "package scripts",
        "cloud_init": "cloud-init",
        "alternatives": "alternatives",
        "services": "services",
        "containers": "containers",
        "noise": "noise",
        "not_read": "not read",
        "secrets": "secrets",
        "to_review": "to review",
        "after": "after.tar.gz",
        "before": "before.tar.gz",
        "patches": "patches",
        "skipped": "skipped",
        "masked": "masked",
        "ebs_direct_api": "EBS direct API",
        "snapshots_made": "snapshots made",
        "copies_made": "AMI copies made",
        "uploaded": "uploaded",
    },
    "ja": {
        "manifest": "manifest",
        "report": "レポート",
        "current": "current",
        "baseline": "baseline",
        "changed_between": "変更の期間",
        "hand_placed": "手動で配置されたファイル",
        "modified_package_files": "変更されたパッケージファイル",
        "deleted": "削除されたファイル",
        "packages": "パッケージ",
        "snaps": "snap",
        "language_packages": "言語パッケージ",
        "package_scripts": "パッケージのスクリプト",
        "cloud_init": "cloud-init",
        "alternatives": "alternatives",
        "services": "サービス",
        "containers": "コンテナ",
        "noise": "ノイズ",
        "not_read": "読み込まなかったファイル",
        "secrets": "機密情報",
        "to_review": "要確認",
        "after": "after.tar.gz",
        "before": "before.tar.gz",
        "patches": "パッチ",
        "skipped": "アーカイブ対象外",
        "masked": "マスク済み",
        "ebs_direct_api": "EBS direct API",
        "snapshots_made": "作成したスナップショット",
        "copies_made": "作成した AMI のコピー",
        "uploaded": "アップロード先",
    },
}

# The language now. One for the whole process, not a context variable: progress is
# also reported from the threads that fetch blocks ahead, which would not see one.
_lang = "en"


@contextlib.contextmanager
def language(lang: str) -> Iterator[None]:
    """Inside this, msg() and row() speak `lang` ("en" or "ja"); afterwards, what they
    spoke before.

    この中では msg() と row() が `lang`（"en" か "ja"）で話す。出ると元の言語に戻る。
    """
    global _lang
    if lang not in LANGS:
        raise ValueError(f"not a language of the messages: {lang!r} (one of {', '.join(LANGS)})")
    before, _lang = _lang, lang
    try:
        yield
    finally:
        _lang = before


def language_from_environment() -> str:
    """The language the environment asks for: EC2_BYHAND_LANG if set, else the locale
    (LC_ALL, LC_MESSAGES, LANG, then what the OS says). Japanese when that names it
    ("ja", "ja_JP.UTF-8", Windows' "Japanese_Japan"), English for anything else.

    環境が求める言語: EC2_BYHAND_LANG があればそれ、無ければロケール（LC_ALL・LC_MESSAGES・
    LANG、その次に OS の設定）。日本語を指していれば（"ja"、"ja_JP.UTF-8"、Windows の
    "Japanese_Japan"）日本語、それ以外はすべて英語。
    """
    names = [os.environ.get(name) for name in (ENV, "LC_ALL", "LC_MESSAGES", "LANG")]
    asked = next((name for name in names if name), None)
    if asked is None:
        try:
            asked = locale.getlocale()[0]
        except ValueError:  # a locale name Python does not know
            asked = None
    return "ja" if (asked or "").lower().startswith("ja") else "en"


def msg(key: str, /, **values: Any) -> str:
    """The message `key` in the language now, its {...} filled in from `values`.

    今の言語のメッセージ `key`。{...} は `values` で埋める。
    """
    return TEXTS[_lang][key].format(**values)


def width(text: str) -> int:
    """How many columns a terminal gives `text`: two for each full-width character.

    端末が `text` に使う桁数。全角の文字は 1 つで 2 桁。
    """
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def label(key: str, /) -> str:
    """The label `key` of the summary in the language now, as report.txt heads a
    section with it.

    今の言語の、まとめの見出し `key`。report.txt が節の見出しに使う。
    """
    return LABELS[_lang][key]


def row(key: str, value: str, /) -> str:
    """One row of the summary: the label `key`, a colon, and `value` from the column
    where every row's value starts (after the longest label of the language, its colon
    and a space). Further lines of `value` start in that column too.

    まとめの 1 行: 見出し `key`、コロン、そして全行で同じ桁から始まる `value`。その桁は、その
    言語でいちばん長い見出しとコロンと空白 1 つの後ろ。`value` の 2 行目以降も同じ桁から始める。
    """
    labels = LABELS[_lang]
    column = max(width(label) for label in labels.values()) + 2
    head = labels[key] + ":"
    indent = " " * column
    return head + " " * (column - width(head)) + value.replace("\n", "\n" + indent)


# A piece of text that stays on one line: a word of ASCII, or one other character, each
# with the opening brackets before it and the closing punctuation and spaces after it.
_UNBREAKABLE = re.compile(r"[（「]*(?:[!-~]+|[^ -~])[、。）」:]* *")


def wrap(text: str, columns: int) -> list[str]:
    """`text` in lines of at most `columns` columns as width() counts them. textwrap
    counts characters and breaks at spaces only, which Japanese has none of: it can be
    broken between any two characters, but not before closing punctuation or after an
    opening bracket.

    `text` を、width() で数えて `columns` 桁までの行に分ける。textwrap は文字数で数え、空白で
    しか折り返さないが、日本語に空白は無い: どの文字の間でも折り返せる。ただし閉じる記号と
    句読点の前、開き括弧の後ろでは折り返さない。
    """
    lines: list[str] = []
    line = ""
    for piece in _UNBREAKABLE.findall(" ".join(text.split())):
        if line and width((line + piece).rstrip()) > columns:
            lines.append(line.rstrip())
            line = ""
        line += piece
    if line.strip():
        lines.append(line.rstrip())
    return lines
