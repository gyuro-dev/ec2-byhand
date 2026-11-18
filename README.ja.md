# ec2-byhand

[English README](README.md)

EC2 インスタンス（または EBS スナップショット）を起動元の AMI と比べ、**起動後に手動で追加・変更された箇所の一覧**と、**そのファイルの実物（変更後・変更前・差分のパッチ）**を出力する CLI ツール。

サーバーへのログインもエージェントも不要。EBS スナップショットを直接読むので、稼働中の本番サーバーに負荷をかけない。

## クイックスタート

```bash
pip install ec2-byhand

# 比較対象を指定する: バックアップのスナップショットと比べる
ec2-byhand --instance-id i-0123456789abcdef0 --baseline-snapshot snap-0123456789abcdef0 -o out/

# 比較対象を指定しない: 起動元の AMI と比べる
ec2-byhand --instance-id i-0123456789abcdef0 -o out/
```

どちらも、スナップショットを作り、比較対象と比べ、作ったスナップショットを消す。結果は `out/` に出る。

比較対象を指定しない場合の補足: 起動元が Amazon Linux や Ubuntu などの**公開 AMI** のとき、そのスナップショットは AWS の制限で直接読めない。
そこで、スナップショットを作るのと並行して AMI を自分のアカウントにコピーし、最後にコピーを消す（[詳しく](#比較対象baselineの選び方)）。

```text
out/
├── report.txt      一覧（人向け）: 追加・変更されたファイルやパッケージを 1 行ずつ
├── manifest.json   一覧（プログラム向け）: 同じ内容の JSON
├── after.tar.gz    ファイルの実物（現在）: 手動で追加・変更されたファイル。権限や所有者もそのまま
├── before.tar.gz   ファイルの実物（AMI 時点）: 変更前・削除前のファイル
└── patches/        差分のパッチ: 設定ファイルなどの書き換えた箇所（patch / git apply で適用できる）
```

Python 3.12 以上が必要。Python が古い環境（CloudShell、Amazon Linux 2023）では、`uv tool install --python 3.12 ec2-byhand` で専用の Python ごと入れられる。\
認証情報とリージョンは AWS CLI と同じ設定から取る（[必要な権限](#permissions)）。

**料金と時間の目安**: 実測で約 0.03 USD、3〜4 分（ボリューム 3 本で計 117 GiB、ファイル約 5.5 万個の Amazon Linux 2023。一覧だけを出す実行で 4.5 GiB を読んだ）。\
料金は主に EBS direct API の読み出しで、1,000 ブロック（約 500 MiB）あたり 0.003 USD ほど。スナップショットの保管料金は、実行中の数分ぶんだけ。\
読む量と時間は、ボリュームの大きさではなくファイルの量で決まる。初めてスナップショットを取るボリュームでは、その完了待ちが加わる。データのディレクトリは `--exclude` で外せる。

## 取り出せるもの

ログやキャッシュのように自動で変わるもの（`/var/log`、`/tmp`、`/var/cache` など）は除く。

| 対象 | 例 | 一覧に出ること | 取り出せるファイル |
|---|---|---|---|
| **手動で配置されたファイル** | `/opt/myapp/`、`/etc/myapp.conf`、スクリプト、systemd の unit、cron | パス・種別・権限・ハッシュ・最終変更時刻 | after.tar.gz に現在のファイル。書き換えたものは before.tar.gz と patches/ にも |
| **手動で変更されたパッケージファイル** | `/etc/ssh/sshd_config`、`/etc/nginx/nginx.conf`、権限を変えたコマンド | どのパッケージのものか、何が変わったか（中身・権限・所有者） | after.tar.gz に現在のファイル、before.tar.gz に AMI 時点のファイル、patches/ に差分 |
| **削除されたファイル** | AMI にはあって今は無いファイルやディレクトリ | 消えたパスと、その配下の件数 | before.tar.gz に削除前のファイル |
| **あとから入れた OS パッケージ** | `dnf install nginx`、`apt install jq` | 追加・削除・更新されたパッケージとバージョン、実行したコマンド | （一覧だけ） |
| **pip / npm のパッケージ** | `pip install`、`npm install`（グローバルもアプリの中も） | パッケージ名とバージョン、インストール後に書き換えたファイル | 書き換えたファイルを after.tar.gz に |
| **サービスの有効・無効** | `systemctl enable myapp`、`systemctl disable ...` | 有効・無効・mask にしたサービス（パッケージによるものと手作業を区別する） | 自作の unit や drop-in は after.tar.gz に |
| **コンテナ** | Docker / Podman / containerd | 追加・削除されたイメージ、コンテナ、ボリューム | （一覧だけ。`/etc/docker` などの設定は、ほかのファイルと同じ扱い） |

- **対応環境**: Amazon Linux 2 / 2023、RHEL 系（rpm）、Ubuntu / Debian（dpkg）。ファイルシステムは ext4・XFS・LVM・vfat。
- **機密情報の扱い**: 秘密鍵（`id_rsa`、`*.pem`）、`/etc/shadow`、`.env` などは一覧に `[sensitive]` と出し、既定ではアーカイブに中身を入れない。テキストの中のパスワードやトークンも `***MASKED***` に置き換える（`--include-sensitive` で解除）。

### 出力例

`out/report.txt` には、見つけた変更が 1 行ずつ並ぶ（抜粋）。

```text
手動で配置されたファイル (17)
  added     2026-10-24 13:10  /etc/myapp.conf
  added     2026-10-24 13:10  /etc/systemd/system/myapp.service
  modified  2026-10-24 13:10  /opt/legacy/change.txt [changed: sha256]
  added     2026-10-24 13:10  /opt/myapp/bin/run.sh
  added     2026-10-24 13:10  /root/.ssh/id_rsa [sensitive]

変更されたパッケージファイル (10)
  2026-10-24 13:11  /etc/profile  (setup: content, size) [baseline 以降] [config]
  2026-10-24 13:11  /usr/bin/alias  (bash: mode) [baseline 以降]

パッケージ (3)
  added       tree.x86_64  1.8.0-6.amzn2023.0.2  (dnf: install -q -y tree)
```

`added` は AMI 以降に追加されたもの、`modified` は変更されたもの。その次は最終変更時刻（UTC）。

画面には、件数のまとめが出る（例）。

```text
manifest:                     out/manifest.json
レポート:                     out/report.txt
baseline:                     ami-0123456789abcdef0 /dev/xvda=snap-0aaaa1111bbbb2222c
変更の期間:                   2026-10-24 13:10 から 2026-10-24 13:11 UTC（各項目の最終変更）
手動で配置されたファイル:     17
変更されたパッケージファイル: 10（baseline 以降は 6）
削除されたファイル:           1
パッケージ:                   インストール済み 110, +3 -0 ^0 v0
言語パッケージ:               5
サービス:                     1
ノイズ:                       628
after.tar.gz:                 22 エントリ
before.tar.gz:                8 エントリ
パッチ:                       2
```

| 行 | 意味 |
|---|---|
| 手動で配置されたファイル | どのパッケージのものでもなく、AMI 以降に増えた・変わったパス |
| 変更されたパッケージファイル | パッケージがインストールしたときと違うファイル（かっこ内は AMI 以降に変わった数） |
| 削除されたファイル | AMI にはあって今は無い、手動で配置されていたパス |
| パッケージ | インストール済みの数と、AMI 以降の追加（+）・削除（-）・アップグレード（^）・ダウングレード（v） |
| ノイズ | 一覧に出さなかったパスの数。[一覧に出るもの・出ないもの](#scope)を参照 |

<a id="scope"></a>

## 一覧に出るもの・出ないもの

**出るもの**: 上の表のもの。ほかに、cloud-init が初回起動で書いたもの、パッケージのスクリプトが作ったもの、alternatives、snap が、それぞれの見出しで出る。

**既定で出ないもの（ノイズ）**: 稼働中のサーバーで、人が触らなくても変わるもの。まとめには数だけが出て、規則ごとの内訳は manifest の `noise` にある。

| 規則 | 例 |
|---|---|
| ログ | `/var/log/**`（手動で作ったディレクトリは出る）、systemd のジャーナル |
| 一時ファイル・実行時のファイル | `/tmp`、`/var/tmp`、`/var/run`、`/run` |
| パッケージ管理の状態とキャッシュ | `/var/lib/rpm`、`/var/lib/dpkg`、`/var/cache` |
| システムが作り直すもの | `/etc/machine-id`、`/etc/ld.so.cache`、`/etc/ssh/ssh_host_*`、`/var/lib/cloud`、`*.pyc` |
| シェルやエディタの履歴 | `.bash_history`、`.viminfo`、`~/.cache` |
| コンテナの中身 | `/var/lib/docker`、`/var/lib/containers`（一覧は `containers` に出る） |
| エージェントの状態 | SSM Agent の `/var/lib/amazon` |

`--include GLOB` で規則より優先して一覧に出し、`--exclude GLOB` で除外を追加できる。\
人が手動で変更した可能性のあるもの（`/etc/hosts`、crontab、`/etc/alternatives` など）は、ノイズにしていない。

**一覧には出るが、中身を入れないもの**:

- 機密情報を含む可能性のあるパスと、機密情報とみられる文字列（上の「機密情報の扱い」）。パスには `*.key` や `.aws/credentials` も入る。
- 1 GiB を超えるファイル（`--max-file-size` で変えられる）と、スワップファイル。

出力にはサーバーのファイルの写しが入る。[SECURITY.md](SECURITY.md) も読んでほしい。

**解析しないもの**:

- /etc/fstab がマウントしないボリューム（警告で知らせる）と、インスタンスストア。
- コンテナのイメージの層。

## 使い方

### 対象の指定

指定するのは 2 つ: **現在のサーバー**と、**比較対象（baseline）**。

```bash
# EC2 インスタンス: スナップショットを作って、起動元の AMI と比べる
ec2-byhand --instance-id i-0123456789abcdef0 -o out/

# 既にあるスナップショット同士
ec2-byhand --current-snapshot snap-aaa snap-bbb --baseline-snapshot snap-ccc -o out/

# 手元の raw ディスクイメージ（EBS ボリュームごとに 1 ファイル）
ec2-byhand --current-image server-root.img server-data.img --baseline-image ami-root.img -o out/
```

| | 現在のサーバー | 比較対象（baseline） |
|---|---|---|
| インスタンス | `--instance-id` | 既定で起動元の AMI（公開 AMI は[コピーして使う](#比較対象baselineの選び方)） |
| AMI | | `--baseline-ami` |
| スナップショット | `--current-snapshot` | `--baseline-snapshot` |
| ディスクイメージ | `--current-image` | `--baseline-image` |
| 比べない | | `--no-baseline` |

`--no-baseline` では、AMI に元からあるファイルも結果に入る。`ec2-byhand --help` も同じ区分で表示する。

### 主なオプション

| オプション | 説明 |
|---|---|
| `--exclude GLOB` | 除外するパスを追加する。`'DIR/**'` なら読み込みもしない（時間と API 課金の節約） |
| `--include GLOB` | ノイズの規則より優先して一覧に出す |
| `--max-file-size SIZE` | これより大きいファイルは読まない（既定 `1G`、`none` で全部読む） |
| `--sensitive GLOB` | 機密情報として扱うパスを追加する |
| `--include-sensitive` | 機密情報を含むファイルの中身も入れ、機密情報とみられる文字列もマスクしない |
| `--no-archives` | manifest.json と report.txt だけを書く |
| `--upload s3://bucket/prefix` | 出力を S3 にもアップロードする |
| `--keep-snapshots` | 作ったスナップショットと、公開 AMI のコピーを残す |
| `--profile` / `--region` | AWS の設定を上書きする |
| `--parallel N` | スナップショットのブロックを同時に取得する数（既定 32） |
| `--verify-checksums` | ext4 / XFS v5 のメタデータのチェックサムを照合する |

パターンは絶対パス全体と比べる（`'/opt/app/**'`、`'**/*.bak'`）。

<a id="permissions"></a>

### 必要な権限

[docs/iam-policy.json](docs/iam-policy.json) が、実行に必要な最小限（実機で確認済み）。削除できるのは、このツールがタグを付けたスナップショットと AMI のコピーだけ。\
`ec2:CopyImage` が無いと、公開 AMI が baseline のときはエラーになり、手で実行する `copy-image` のコマンドが表示される。\
既定の `aws/ebs` の鍵で暗号化したスナップショットは、追加の権限は不要。カスタマー管理キーなら、そのキーポリシーで `kms:Decrypt` を許可する。\
`--upload` には [docs/iam-policy-upload.json](docs/iam-policy-upload.json) を追加する（BUCKET と PREFIX は自分のものに置き換える）。

### 表示言語

メッセージ・まとめ・`--help` は英語と日本語で表示できる。`EC2_BYHAND_LANG=ja`（または `=en`）で選ぶ。\
無ければロケール（`LC_ALL`・`LC_MESSAGES`・`LANG`、その次に OS の設定）で決まり、日本語以外はすべて英語になる。\
manifest.json はプログラムが読むデータなので、どちらでも英語。そこから来る警告の本文も、まとめの中で英語のまま出る。

## 詳細

### スナップショットの扱い

スナップショットの完了待ちに上限は無く（大きなボリュームの最初のスナップショットは数時間かかることがある）、数分おきに進捗を表示する。\
途中で止めた実行（Ctrl+C、SIGTERM、端末や SSH の切断）は、終了時に自分が作ったスナップショットと AMI のコピーを削除する。\
強制終了された実行のものは `ec2-byhand=<インスタンス ID>`（AMI のコピーとそのスナップショットは `ec2-byhand=<コピー元の AMI>`）のタグ付きで残る。\
`aws ec2 describe-snapshots --owner-ids self --filters Name=tag-key,Values=ec2-byhand` と `aws ec2 describe-images --owners self --filters Name=tag-key,Values=ec2-byhand` で一覧を取得できる。

### 比較対象（baseline）の選び方

**バックアップを baseline に**: 同じサーバーの古いスナップショット（手動で取得したもの、DLM のものなど）も baseline に使える。\
`--instance-id i-... --baseline-snapshot snap-<バックアップ>` でそのバックアップ以降の作業、\
`--current-snapshot snap-<新しい方> --baseline-snapshot snap-<古い方>` で 2 つのバックアップの間の作業が出る。\
cloud-init が初回起動時に行ったことはバックアップにも入っているので、結果には出なくなる。

**公開 AMI**: 公開 AMI のスナップショットは EBS direct API で読めない（AWS は `Public snapshots are not supported` と返す）。\
そこで、baseline が公開 AMI（起動元の AMI、または `--baseline-ami`）のときは、同じリージョンで自分のアカウントにコピーし、コピーのスナップショットを読む。\
`--instance-id` では、スナップショットを作るのと並行してコピーする。コピーとそのスナップショットは、作ったスナップショットと同じく最後に消す（`--keep-snapshots` で残せば、次からは `--baseline-ami` で使える）。\
Red Hat の RHEL の AMI はコピーできない（`You do not have permission to access the storage of this ami`）ので、`--no-baseline` を使う。

**dpkg（Ubuntu / Debian）**: dpkg は権限・所有者・リンク先を記録しないので、baseline のファイルと比べるのは、両側で同じバージョンのパッケージのファイルだけ。\
それ以外のパッケージ（baseline がなければ全部）は、setuid・setgid・誰でも書き込めるファイルを manifest の `package_files_to_review` に挙げる。sudo などの正規のものも含む、目で確認するための一覧。\
baseline がないときは `dpkg-metadata-unverified` の警告でもそれを伝える。\
あわせて、ctime がパッケージをインストールした時刻とインスタンスの初回起動（cloud-init のログから）の両方より後で、apt の実行の中でもないパッケージのファイルを `changed-since-boot` として挙げる。手動で chmod・chown すると、この痕跡が残る。

### データボリューム

`--instance-id` は全 EBS ボリュームのスナップショットを作るが、解析するのは /etc/fstab がマウントするものだけ。\
ファイルシステムがあるのにマウントされないボリュームは `unmounted-volume` の警告で知らせる。\
開けないボリューム（LVM のメタデータの破損、読めない種類の LV）は `unreadable-volume` の警告で知らせる。\
fstab の `UUID=`、`LABEL=`、LVM の名前は常に解決できる。\
`/dev/xvdf`・`/dev/sdf` は、デバイス名が分かるときに解決できる: `--instance-id` と `--baseline-ami`、それに ID で渡したスナップショットがそのインスタンスのボリュームのものであるとき\
（`--instance-id i-... --baseline-snapshot snap-<ルートのバックアップ> snap-<データのバックアップ>`。元のボリュームは DescribeSnapshots で分かる）。\
`/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol...` は、そのボリュームのスナップショットならどれでも解決できる。ディスクイメージと、`--instance-id` なしのスナップショットにはデバイス名が無いので、こうした行は `unresolved-mount` になる。\
`/dev/nvme1n1` の番号はどのボリュームかを示さない。条件（種別とパーティション番号）に合う未マウントのボリュームが 1 つだけならそれをマウントして `inferred-mount` の警告を出し、複数あれば `unresolved-mount` にする。\
解析しない大きなボリュームがあるなら、ルートだけスナップショットを取って `--current-snapshot` で渡すと待たずに済む。

### 出力の補足

report.txt には、manifest.json に無いことは書かない。\
各項目には、最終変更時刻 `ctime` が付く（カーネルが付ける時刻で、`touch` では変えられない）。まとめには、手作業がいつからいつの間に行われたかを出す。\
ACL（`setfacl`）・ケーパビリティ（`setcap`）などの拡張属性もパスの一部として比べる: それだけが変わっても報告し（`changed: xattrs`）、付いている属性の名前を `xattrs` に出す。値はアーカイブに入る。\
SELinux のラベルも比べる: `chcon` は `changed: selinux` として出て、今のラベルが付く。片側にしかラベルが無いとき（SELinux の有効・無効を切り替えた）は、パスごとの変更とは数えない。\
パッケージのファイルの拡張属性（`/usr/bin/node` への `setcap`、`/var/www` への `setfacl` など）は、baseline に同じ版のパッケージがあるときだけ baseline と比べる（`problems: xattrs`）。パッケージ自身のスクリプトが付けるものがあり、アップグレードで付け直されるため。パッケージのファイルの SELinux のラベルは比べない。\
サーバー上で root しか読めないファイルの写しも入るので、Linux と macOS では実行した本人だけが読める。Windows では出力先フォルダのアクセス権で守ること。

### 大きなファイル・大きなサーバー

`--max-file-size` を超えるファイルは sha256 が付かず、アーカイブにも入らない。baseline との比較はサイズと mtime で判定する。\
上限を超えたパッケージや pip のファイルは記録のハッシュとも照合しない（`content-not-verified` の警告）。上限のために読まなかった数はまとめに出る。\
中身を読み始める前に、どのパッケージにも属さないファイルをどれだけ読むかを stderr に出す。1 GiB 以上なら大きいファイルも挙げるので、データディレクトリが混じっていたらそこで Ctrl+C して `--exclude` を追加する\
（`--instance-id` では作ったばかりのスナップショットも、公開 AMI のコピーも消える。`--keep-snapshots` で残せば `--current-snapshot` と `--baseline-ami` で実行し直せる）。

メモリは両側のファイル数に比例して増える。目安は片側 1 パスあたり 1.5〜1.8 KB（実測: 両側 30 万ファイルずつで ext4 0.9 GB、XFS 1.0 GB。両側 100 万ファイルずつなら 3 GB ほど）。\
数百万ファイルあるなら、データのディレクトリを `--exclude 'DIR/**'` で外す。外したディレクトリは走査もしない（`--include` があるときは全体を読む）。

### S3 へのアップロード

`--upload s3://bucket/prefix` は、実行が書いたファイルだけをアップロードする（report.txt も含む。`-o` にあるほかのものは対象外）。\
保存先は `prefix/<ラベル>/<時刻>/`（ラベルはインスタンスやスナップショットの ID か `--label`、時刻は UTC）で、実行ごとに別なので上書きしない。\
どのオブジェクトも SSE-KMS（aws/s3 の鍵か `--kms-key-id KEY`）で暗号化し、S3 側で SHA-256 を検証する。大きなファイルは分割して送り、manifest.json は最後に送る。\
バケットは解析の前に確認する。カスタマー管理キー（`--kms-key-id`）を使うなら、その鍵で `kms:GenerateDataKey` と、分割して送るファイルのための `kms:Decrypt` も許可する。\
アップロードに失敗しても出力は `-o` に残り、終了コードは 1 になる。

### 機密情報とみられる文字列

報告する 1 MiB 以下のテキストファイルから、秘密鍵、AWS のアクセスキー、GitHub・Slack のトークン、URL に埋め込んだパスワード、\
`password`・`secret`・`token`・`api_key` などへの値の代入を探す。形は `key = 値`、`key: 値`、`'key' => '値'`、`define('KEY', '値')`、`<key>値</key>`（`${DB_PASSWORD}` のような参照、パス、`getenv(...)` のような呼び出しは除く）。\
キーと値を空白だけで区切る形（redis の `requirepass`）は検出しないので、そうしたファイルは `--sensitive` で指定する。manifest には種類と行だけを書き、値は書かない。\
マスクした箇所は `archives.masked` に一覧が出る。スワップファイルは常に読まない（中身は設定ではなくメモリ）。

### npm

アプリの `node_modules` もグローバルも `language_packages` にまとめる。\
各パッケージは、サーバーの npm キャッシュ（`~/.npm/_cacache`）にある自分の tarball と照合する。tarball は lockfile が記録する integrity で、グローバルに入れたものはキャッシュの索引から探す。\
このとき `modified` と `missing` は確定（`verified_by: npm-cache`）で、何もダウンロードしない。\
tarball が無いとき（ほかからコピーした node_modules、消したキャッシュ）は、npm がファイルごとのハッシュを持たないので、インストールより 10 分以上あとに更新されたファイルを、手動で編集した候補として `edited_after_install` に挙げ、after.tar.gz に入れる。\
こちらは時刻からの推定なので確実ではない。編集のあとに `npm install` を実行すると基準の時刻が動き、その編集は見つからない。

### コンテナ

Docker（`/var/lib/docker`）・Podman（`/var/lib/containers` と、各ユーザーの rootless の `~/.local/share/containers`）・containerd（`/var/lib/containerd`）は、\
そこに自分の状態を置き、手動では編集しない（設定は `/etc/docker`・`/etc/containers`・`/etc/containerd` で、こちらは通常どおり検出する）。\
その下のファイルは一覧にもアーカイブにも出さず、イメージの層は読みもしない。代わりに manifest の `containers` に、エンジンごとにイメージ（名前と ID）、\
コンテナ（名前・イメージ・作成日時。パスワードを含みがちな環境変数は読まない）、ボリューム（ファイル数と容量）を挙げる。baseline があれば、増えた・消えた・変わったものだけ。\
rootless の Podman のものには `user`、containerd のものには `namespace` が付く（Docker 自身の名前空間 `moby` は Docker に任せる）。

### サービス

`services` の `/etc/systemd/system` の各リンクに、パッケージによるものか（`by_package`）が付く。deb-systemd-helper の記録がある（Debian・Ubuntu）か、\
dnf / yum / apt の実行中に作られたリンクがパッケージによるもので、その実行が `transaction` に入る。`apt install nginx` が nginx を有効にしたのはパッケージ、あとの `systemctl enable`・`disable`・`mask` は手作業。\
消えたリンクは、指していた unit ごと消えたときだけパッケージのもの。\
パッケージが有効にしたあと手動で無効にしたサービス（`apt install apache2` のあと `systemctl disable apache2`）は `disabled` として出す。新しいサーバーでは有効になってしまうため。\
Debian・Ubuntu はパッケージが有効にしたものを記録している。rpm は、baseline 以降に入ったパッケージについて、preset と unit の `[Install]` から計算する。

### snap

Ubuntu の snap は `snaps` にまとめる。snapd 自身の状態（`/var/lib/snapd/state.json`）から、名前・種類・リビジョン・チャネル・イメージに入っていたか（`seeded`）、\
手動で入れたものはそれをした snapd の操作（`via`）を読む。baseline があれば、増えた・消えた・更新されたものだけ。\
snap に付いてくるもの（`.snap` ファイル、`/snap/<名前>`、snapd が書く unit、`/var/snap/<名前>` の空のディレクトリ）は手作業に含めない。`/var/snap/<名前>` に置かれたものは含める。

### cloud-init

AMI のスナップショットは初回起動の前なので、そのとき cloud-init が書くもの（既定のユーザーのホーム、`sudoers.d`、`authorized_keys`、ホスト名、ネットワークの設定）は、\
どのインスタンスでも手作業に見えてしまう。cloud-init 自身のログ `/var/log/cloud-init.log` には、書いたファイルと追加したユーザーが時刻付きで残る。\
ctime がその書き込みの時間帯に入るファイルは、`hand_placed` ではなく manifest の `cloud_init` にモジュールごとに挙げる。アーカイブには入れる（user-data の `write_files` は利用者自身の設定なので）。\
cloud-init が書き換えたパッケージのファイルは `modified_package_files` に残し、`cloud_init` の印を付ける。\
あとで手動や `runcmd` のスクリプトで変更したものは ctime が後になるので、手作業に残る（`authorized_keys` に足した鍵、ホームに置いたファイルなど）。\
cloud-init が動いたのにログが無ければ何も振り分けず、警告 `cloud-init-log-missing` を出す。

## 仕組み

```
手動で配置・変更されたもの
  = 現行スナップショットのファイル
  − AMI 時点から未変更のファイル
  − パッケージ（rpm/dpkg）が所有し、ハッシュが一致するファイル
  − 自動生成ノイズ（ログ・キャッシュ等）
```

- ディスクは **EBS direct API** でブロック単位に読み、マウントしない
- ext4 / XFS / LVM は**ユーザースペースで解析する**
- パッケージ DB もスナップショットから読む（サーバーで rpm コマンドを実行しない）
- AMI が消えていても「パッケージ管理外 + ハッシュ不一致」で大半は特定できる

## Python から使う

```python
from diskread import FileDevice
from ec2_byhand import manifest
from ec2_byhand.analyze import analyze
from ec2_byhand.cli import open_disks

with FileDevice("current.img") as cur, FileDevice("ami.img") as ami:
    m = analyze(open_disks({"disk0": cur}, "current"), open_disks({"disk0": ami}, "ami"))
manifest.write(m, "manifest.json")
```

`open_disks` はパーティション・LVM・fstab を解決して組み上げる。複数ディスクのサーバーは全部を渡す（`{"disk0": root, "disk1": data}`）。

## 開発

```bash
uv sync
uv run pytest
```

CI と同じ確認（ruff・mypy・対応する Python ごとのテスト）をまとめて実行する。

```bash
bash scripts/check.sh
```

`bash scripts/check.sh 3.13` で、指定したバージョンだけを確認する。結果は reports/check/ に残る（まず summary.txt を見る）。

CLI のテストは YAML のケース（[tests/casebook_cli.yaml](tests/casebook_cli.yaml) と\
[tests/casebook_verify.yaml](tests/casebook_verify.yaml)、[pytest-casebook](https://pypi.org/project/pytest-casebook/) で実行）。\
`uv run pytest --casebook-html=reports/casebook.html` でテスト仕様書（HTML の表）が出る。\
期待値を変えたら `uv run pytest --casebook-update` で golden（tests/golden/casebook_*/）を作り直し、差分をレビューする。

EBS direct API の経路は、AWS アカウント無しで [moto](https://github.com/getmoto/moto) 相手に通しで動かせる。

```bash
uv run --group integration pytest tests/test_integration_moto.py
```

ゴールデンイメージをスナップショットとして流し込み、出力をイメージ直読みの結果と比べる。\
moto のブロックは 512 バイト（EBS は 512 KiB）なので 1 分ほどかかる。`integration` グループが無ければ skip。\
ブロックトークンの期限切れ・ページネーション・スロットリング・暗号化スナップショットは再現されないので、そこは実アカウントが要る。

ゴールデンイメージは WSL（root）で作る。必要なパッケージ: `gdisk` `lvm2` `xfsprogs` `acl` `dosfstools`。\
XFS の一部のケース（AL2023 / Fedora の mkfs 既定値）は Docker を使う。`tests/golden/out/` に出力され、git には含めない。

```bash
wsl -u root -- bash tools/golden/build_partition.sh tests/golden/out
wsl -u root -- bash tools/golden/build_lvm.sh tests/golden/out
wsl -u root -- bash tools/golden/build_fs.sh tests/golden/out
wsl -u root -- bash tools/golden/build_dirty.sh tests/golden/out
wsl -u root -- bash tools/golden/build_system.sh tests/golden/out
wsl -u root -- bash tools/golden/build_vfat.sh tests/golden/out
# パッケージ DB とバージョン比較の正解（Docker）
wsl -u root -- bash tools/golden/build_pkgdb.sh tests/golden/out
wsl -u root -- bash tools/golden/build_vercmp.sh tests/golden/out
wsl -u root -- bash tools/golden/build_verify.sh tests/golden/out
# XFS v4 は WSL のカーネルでマウントできないため AlmaLinux 8 の VM で作る（qemu-system-x86 qemu-utils cloud-image-utils が必要）
wsl -u root -- bash tools/golden/fetch_almalinux8.sh
wsl -u root -- bash tools/golden/vm_almalinux8.sh tests/golden/out xfs-v4 xfs-v4-noftype xfs-v4-1k
```

イメージが無ければ、ゴールデンテストは skip される。

## ドキュメント

- [SECURITY.md](SECURITY.md) — 脆弱性の報告の方法と、出力を扱うときに気をつけること
- [CHANGELOG.md](CHANGELOG.md) — バージョンごとの変更

## ライセンス

MIT。[LICENSE](LICENSE) を参照。
