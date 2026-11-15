"""The line between the two packages, kept by tests: an import or a name that crosses
it shows up in no other check. diskread must stay usable without AWS or ec2_byhand."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

from diskread import BytesDevice
from diskread.system import Volume, resolve_spec

SRC = Path(__file__).parent.parent / "src"
DISKREAD = sorted((SRC / "diskread").rglob("*.py"))
# What only an AWS-aware program has reason to name. Prose may mention EBS as the reason
# for a design, so docstrings and comments do not count; code does.
AWS_WORDS = re.compile(r"amazon|(?<![a-z])ebs(?![a-z])|xvd|ec2|boto|(?<![a-z])aws(?![a-z])", re.I)


def _code_words(tree: ast.Module) -> Iterator[str]:
    """Every name and string of the code, leaving docstrings out."""
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            first = node.body[0] if node.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in docstrings:
                yield node.value
        elif isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, ast.Attribute):
            yield node.attr
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            yield node.name
        elif isinstance(node, ast.arg):
            yield node.arg
        elif isinstance(node, ast.alias):
            yield node.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module


def _imports(path: Path) -> set[str]:
    out = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
    return out


@pytest.mark.parametrize("path", DISKREAD, ids=lambda p: p.relative_to(SRC).as_posix())
def test_diskread_does_not_import_ec2_byhand_or_aws(path: Path) -> None:
    roots = {name.split(".")[0] for name in _imports(path)}
    assert not roots & {"ec2_byhand", "boto3", "botocore"}


@pytest.mark.parametrize("path", DISKREAD, ids=lambda p: p.relative_to(SRC).as_posix())
def test_diskread_code_knows_nothing_of_aws(path: Path) -> None:
    words = _code_words(ast.parse(path.read_text(encoding="utf-8")))
    assert [w for w in words if AWS_WORDS.search(w)] == []


def test_the_check_would_see_a_name_or_string_but_not_a_docstring() -> None:
    def found(source: str) -> list[str]:
        return [w for w in _code_words(ast.parse(source)) if AWS_WORDS.search(w)]

    assert found('"""About EBS volumes."""\n# and EBS here\n') == []
    assert found('X = "/dev/xvdf"\n') == ["/dev/xvdf"]
    assert found("def ebs_device(): pass\n") == ["ebs_device"]


@pytest.mark.parametrize(
    "path", sorted((SRC / "ec2_byhand").rglob("*.py")), ids=lambda p: p.relative_to(SRC).as_posix()
)
def test_ec2_byhand_goes_through_the_filesystem_protocol(path: Path) -> None:
    readers = ("diskread.fs.ext4", "diskread.fs.xfs", "diskread.fs.fat")
    assert not [name for name in _imports(path) if name.startswith(readers)]


@pytest.mark.parametrize("name", ["noise", "archive", "langpkgs"])
def test_modules_unrelated_to_packages_do_not_need_the_package_code(name: str) -> None:
    imports = _imports(SRC / "ec2_byhand" / f"{name}.py")
    assert not {n for n in imports if n.startswith("ec2_byhand.packages")}


def test_diskread_alone_does_not_read_ec2_device_names() -> None:
    disk = Volume("/dev/xvdf", BytesDevice(bytes(512)), serial="vol0aaa")
    assert resolve_spec("/dev/sdf", [disk]) is None
    assert resolve_spec("/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_vol0aaa", [disk]) is None


def test_the_caller_can_pass_what_it_knows_about_device_names() -> None:
    disk = Volume("data", BytesDevice(bytes(512)))
    asked = []

    def resolver(spec: str, volumes: list[Volume]) -> Volume | None:
        asked.append(spec)
        return disk

    assert resolve_spec("LABEL=x", [disk], resolver) is None  # the disks answer this one
    assert resolve_spec("/dev/whatever", [disk], resolver) is disk
    assert asked == ["/dev/whatever"]
