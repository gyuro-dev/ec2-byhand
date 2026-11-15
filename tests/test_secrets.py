"""Secret-like strings (found, flagged in the manifest, masked in the archives and
patches) and the user's own sensitive paths (--sensitive GLOB)."""

from __future__ import annotations

import tarfile
from pathlib import Path

import pytest
from memfs import MemFs

from diskread.source import SystemSource
from ec2_byhand.analyze import Snapshot, analyze
from ec2_byhand.archive import ArchiveOptions, write_outputs
from ec2_byhand.secrets import MASK, SCAN_MAX_BYTES, find_secrets, mask
from ec2_byhand.sensitive import Sensitive

CONFIG = b"""[db]
host = db.internal
password = hunter2-for-real
password_file = /etc/app/db.pass
user_password = ${DB_PASSWORD}
url = postgresql://app:s3cret-pw@db.internal/app
[aws]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
KEY = (
    b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
    b"b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n"
    b"-----END OPENSSH PRIVATE KEY-----\n"
)


def test_what_is_found_and_what_is_not() -> None:
    found = find_secrets(CONFIG)
    assert [(f.kind, f.line) for f in found] == [
        ("password", 3),
        ("url-password", 6),
        ("aws-access-key", 8),
        ("aws-secret-key", 9),
    ]
    assert [CONFIG[f.start : f.end] for f in found][:2] == [b"hunter2-for-real", b"s3cret-pw"]
    assert [f.kind for f in find_secrets(KEY)] == ["private-key"]


@pytest.mark.parametrize(
    "text",
    [
        b"PasswordAuthentication no\n",  # sshd_config: a setting, not a secret
        b"max_password_length = 64\n",
        b"token_ttl: 3600\n",
        b"password: ${SECRET}\n",
        b"password = %(db_pass)s\n",
        b"password: <your password here>\n",
        b"password=\n",
        # Code, not values: what stands unquoted after the key is a call or a lookup.
        b"password = get_password()\n",
        b'password = os.environ["DB_PASSWORD"]\n',
        b"'password' => env('DB_PASSWORD', ''),\n",  # Laravel's config/database.php
        b"'password' => $password,\n",
        b"$password = trim($_POST['password']);\n",
        b"protected $hidden = ['password', 'remember_token'];\n",
        b"define('DB_PASSWORD', getenv('DB_PASSWORD'));\n",
        b"<password>${db.password}</password>\n",
        b"token,name,email\n",
    ],
)
def test_settings_and_references_are_not_secrets(text: bytes) -> None:
    assert find_secrets(text) == []


@pytest.mark.parametrize(
    "text",
    [
        b"define( 'DB_PASSWORD', 'hunter2-for-real' );\n",  # wp-config.php
        b'define("AUTH_KEY", "hunter2-for-real");\n',
        b"    'password' => 'hunter2-for-real',\n",  # a PHP array
        b'  :password => "hunter2-for-real",\n',  # a Ruby hash
        b'$password = "hunter2-for-real";\n',
        b"$db_password='hunter2-for-real';\n",
        b"<password>hunter2-for-real</password>\n",
        b"  <db.password>hunter2-for-real</db.password>\n",
        b'password = "get(hunter2-for-real"\n',  # quoted: a value, whatever it looks like
    ],
)
def test_the_forms_of_php_ruby_and_xml(text: bytes) -> None:
    (found,) = find_secrets(text)
    assert found.kind == "password"
    assert text[found.start : found.end].strip(b"get(") == b"hunter2-for-real"
    assert b"hunter2" not in mask(text, [found])


def test_binary_and_large_files_are_not_scanned() -> None:
    assert find_secrets(b"\0password = hunter2-for-real\n") == []
    assert find_secrets(b"password = hunter2-for-real\n".ljust(SCAN_MAX_BYTES + 1, b"#")) == []


def test_masking_keeps_the_shape() -> None:
    out = mask(CONFIG, find_secrets(CONFIG))
    assert b"password = " + MASK + b"\n" in out
    assert b"postgresql://app:" + MASK + b"@db.internal/app" in out
    assert b"password_file = /etc/app/db.pass" in out  # a path: left alone
    assert out.count(b"\n") == CONFIG.count(b"\n")
    assert b"hunter2" not in out
    assert b"EXAMPLEKEY" not in out


def _server() -> tuple[MemFs, MemFs]:
    before, after = MemFs(), MemFs()
    before.add_file("/opt/app/app.ini", b"[db]\npassword = old-secret-value\n")
    after.add_file("/opt/app/app.ini", b"[db]\npassword = new-secret-value\nport = 5432\n")
    after.add_file("/opt/app/conf/prod.yml", b"debug: false\n")
    after.add_file("/home/appuser/.ssh/deploy", KEY)
    return before, after


def _run(tmp_path: Path, opts: ArchiveOptions, sensitive: Sensitive | None = None) -> dict:
    before, after = _server()
    now, ami = SystemSource.from_fs(after), SystemSource.from_fs(before)
    m = analyze(Snapshot("now", now), Snapshot("ami", ami), sensitive=sensitive)
    m["archives"] = write_outputs(m, now, ami, tmp_path, opts)
    return m


def _member(tmp_path: Path, archive: str, name: str) -> bytes:
    with tarfile.open(tmp_path / archive) as tar:
        f = tar.extractfile(name)
        assert f is not None
        return f.read()


def test_flagged_in_the_manifest_and_masked_in_the_archives(tmp_path: Path) -> None:
    m = _run(tmp_path, ArchiveOptions())
    items = {h["path"]: h for h in m["hand_placed"]}
    assert items["/opt/app/app.ini"]["secrets"] == [{"kind": "password", "line": 2}]
    assert items["/home/appuser/.ssh/deploy"]["secrets"] == [{"kind": "private-key", "line": 2}]
    assert "secrets" not in items["/opt/app/conf/prod.yml"]
    assert m["summary"]["files_with_secrets"] == 2

    after = _member(tmp_path, "after.tar.gz", "opt/app/app.ini")
    before = _member(tmp_path, "before.tar.gz", "opt/app/app.ini")
    assert after == b"[db]\npassword = " + MASK + b"\nport = 5432\n"
    assert before == b"[db]\npassword = " + MASK + b"\n"
    assert b"BEGIN OPENSSH PRIVATE KEY" in _member(
        tmp_path, "after.tar.gz", "home/appuser/.ssh/deploy"
    )
    patch = (tmp_path / "patches" / "opt/app/app.ini.diff").read_text(encoding="utf-8")
    assert "secret-value" not in patch
    assert "+port = 5432" in patch
    assert {(x["archive"], x["path"]) for x in m["archives"]["masked"]} == {
        ("after", "/opt/app/app.ini"),
        ("after", "/home/appuser/.ssh/deploy"),
        ("before", "/opt/app/app.ini"),
    }


def test_include_sensitive_keeps_them(tmp_path: Path) -> None:
    m = _run(tmp_path, ArchiveOptions(include_sensitive=True))
    assert b"new-secret-value" in _member(tmp_path, "after.tar.gz", "opt/app/app.ini")
    assert m["archives"]["masked"] == []


def test_a_users_own_sensitive_path(tmp_path: Path) -> None:
    mine = Sensitive(("/opt/app/conf/**",))
    m = _run(tmp_path, ArchiveOptions(sensitive=mine), sensitive=mine)
    items = {h["path"]: h for h in m["hand_placed"]}
    assert items["/opt/app/conf/prod.yml"]["sensitive"] is True
    skipped = {(s["archive"], s["path"]): s["reason"] for s in m["archives"]["skipped"]}
    assert skipped[("after", "/opt/app/conf/prod.yml")] == "sensitive"
    assert Sensitive(("**/.env.example",)).match("/srv/.env.example")  # the user's word wins
