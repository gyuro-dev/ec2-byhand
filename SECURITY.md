# Security Policy

English | [日本語](#セキュリティポリシー)

## Supported versions

Security fixes are made for the latest release only.

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues, discussions or pull requests.

Report them privately through GitHub instead: open the repository's **Security** tab and choose **Report a vulnerability**. Include the version, the steps to reproduce, and the impact you expect.

This is a personal project maintained on a best-effort basis. We will acknowledge your report as soon as we can, keep you updated on the fix, and credit you in the advisory if you wish.

## What to keep in mind when using ec2-byhand

**The outputs hold copies of a server's files.** manifest.json, report.txt, the archives and the patches describe and contain what was found on the disk, files that only root could read on the server among them. Keep the output directory, and the bucket `--upload` writes to, as protected as the server itself.

**Masking is a help, not a guarantee.** Paths that usually hold secrets are left out of the archives, and secret-like strings in text files are masked, by a fixed list of paths and of forms (see the README). A secret written in another form, in a binary file, or in a file over 1 MiB is archived as it is. Look at what you are about to share; `--sensitive GLOB` and `--exclude GLOB` keep more out, and `--no-archives` writes no file contents at all.

**It needs few permissions; give it no more.** [docs/iam-policy.json](docs/iam-policy.json) is the least a run needs: it can create snapshots, read snapshot blocks, and delete only the snapshots it tagged itself. `--instance-id` creates snapshots and deletes them at the end; a run that is killed leaves them behind (the README says how to find them).

**The disk it reads is untrusted input.** The parsers are read-only and never execute anything from the disk, and names from the disk are escaped before they are printed or used as file names. A report of a disk image or snapshot that makes ec2-byhand crash, hang, write outside its output directory or print raw control characters is welcome as a vulnerability report.

---

## セキュリティポリシー

[English](#security-policy) | 日本語

### 対象の版

セキュリティの修正は、最新の版にだけ行います。

### 脆弱性の報告

脆弱性は、公開の issue・discussion・pull request には書かないでください。

GitHub の非公開の報告を使ってください。リポジトリの **Security** タブから **Report a vulnerability** を選びます。\
版、再現の手順、想定される影響を書いてください。

個人のプロジェクトのため、できる範囲で対応します。\
報告を受け取ったらできるだけ早く返事をし、修正の状況をお知らせします。\
希望があれば、公開する advisory に報告者としてお名前を載せます。

### 使うときに気をつけること

**出力にはサーバーのファイルの写しが入ります。**\
manifest.json・report.txt・アーカイブ・パッチには、ディスクにあったものの一覧と中身が入ります。サーバー上では root しか読めないファイルも含みます。\
出力先のディレクトリと、`--upload` のアップロード先のバケットは、サーバー自体と同じ水準で保護してください。

**マスクは補助であって、保証ではありません。**\
機密情報を含む可能性の高いパスはアーカイブに入れず、テキストファイルの中の機密情報とみられる文字列はマスクします。どちらも、決まったパスと形式の一覧に基づきます（README を参照）。\
別の形式で書かれた機密情報、バイナリファイルの中の機密情報、1 MiB を超えるファイルの中の機密情報は、そのままアーカイブに入ります。\
共有する前に中身を確認してください。`--sensitive GLOB` と `--exclude GLOB` で、入れないものを追加できます。`--no-archives` ならファイルの中身は一切書きません。

**必要な権限はわずかです。それ以上は与えないでください。**\
[docs/iam-policy.json](docs/iam-policy.json) が実行に必要な最小限です: スナップショットの作成、スナップショットのブロックの読み取り、このツールがタグを付けたスナップショットの削除だけができます。\
`--instance-id` はスナップショットを作成し、最後に削除します。強制終了された実行のものは残ります（探し方は README にあります）。

**読むディスクは、信頼できない入力として扱っています。**\
パーサーは読むだけで、ディスクの中のものを実行しません。ディスクから来た名前は、表示する前とファイル名に使う前にエスケープします。\
ディスクイメージやスナップショットで ec2-byhand が異常終了する・止まらなくなる・出力先の外に書く・制御文字をそのまま表示する、という報告は、脆弱性の報告として歓迎します。
