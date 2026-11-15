#!/usr/bin/env bash
# The checks of CI, run here in a way that can be repeated (Linux, WSL, macOS, Git Bash
# on Windows): ruff, mypy, and the tests under each supported Python.
#
#   scripts/check.sh            # Python 3.12 to 3.15, one after another
#   scripts/check.sh 3.13       # the versions named
#
# - Dependencies come from uv.lock as it is (uv sync --frozen).
# - Each Python gets a virtual environment of its own ($EC2_BYHAND_VENVS/py<version>,
#   .venvs by default), so that one does not disturb another, nor the project's .venv.
# - With the integration group (moto: the S3 upload and the EBS direct APIs run against
#   it) where it installs; a Python it has no wheels for yet runs without, and the
#   summary says so (those tests skip).
# - Results are kept in reports/check/: summary.txt names the OS, uv, the commit and
#   the result of each step; the output of each is beside it.
# - The golden images (tests/golden/out, built by tools/golden/*.sh) are used when they
#   are there; without them the tests that need one are skipped, as in CI.
# - Exits 1 if anything failed.
set -uo pipefail

cd "$(dirname "$0")/.."
PYTHONS=("$@")
[ ${#PYTHONS[@]} -eq 0 ] && PYTHONS=(3.12 3.13 3.14 3.15)
VENVS="${EC2_BYHAND_VENVS:-.venvs}"
OUT="reports/check"
SUMMARY="$OUT/summary.txt"
export PYTHONIOENCODING=utf-8
export EC2_BYHAND_LANG=en  # as tests/conftest.py does: the tests read English

rm -rf "$OUT"
mkdir -p "$OUT"
{
  echo "# ec2-byhand: results of the checks"
  echo "date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "os:     $(uname -srm)"
  [ -r /etc/os-release ] && echo "distro: $(. /etc/os-release && echo "$PRETTY_NAME")"
  echo "uv:     $(uv --version)"
  echo "commit: $(git rev-parse --short HEAD 2>/dev/null)$(git diff --quiet 2>/dev/null || echo ' (with uncommitted changes)')"
  echo "golden: $(ls tests/golden/out/*.img 2>/dev/null | wc -l | tr -d ' ') images"
  echo
} > "$SUMMARY"

failed=0

# ruff does not depend on the Python version: once.
if uv run --frozen ruff check . > "$OUT/ruff.txt" 2>&1 && uv run --frozen ruff format --check . >> "$OUT/ruff.txt" 2>&1; then
  echo "ruff      : ok" >> "$SUMMARY"
else
  echo "ruff      : FAILED ($OUT/ruff.txt)" >> "$SUMMARY"
  failed=1
fi

# mypy (strict), with the Python of the project's own environment: once.
if uv run --frozen mypy > "$OUT/mypy.txt" 2>&1; then
  echo "mypy      : ok" >> "$SUMMARY"
else
  echo "mypy      : FAILED ($OUT/mypy.txt)" >> "$SUMMARY"
  failed=1
fi

for py in "${PYTHONS[@]}"; do
  name="py${py}"
  dir="$OUT/$name"
  mkdir -p "$dir"
  export UV_PROJECT_ENVIRONMENT="$VENVS/$name"
  export UV_PYTHON="$py"  # not the one .python-version names

  moto=""
  if ! uv sync --frozen --group integration --python "$py" > "$dir/setup.txt" 2>&1; then
    moto=" (without moto)"
    if ! uv sync --frozen --python "$py" >> "$dir/setup.txt" 2>&1; then
      echo "$(printf '%-10s' "$name"): FAILED (no environment: $dir/setup.txt)" >> "$SUMMARY"
      failed=1
      continue
    fi
  fi
  version=$(uv run --no-sync python -c "import sys; print(sys.version.split()[0])")
  uv run --no-sync pytest -p no:cacheprovider -q --junitxml="$dir/junit.xml" > "$dir/tests.txt" 2>&1
  tests=$?
  result="ok"
  if [ $tests -ne 0 ]; then
    result="FAILED (exit $tests: $dir/tests.txt)"
    failed=1
  fi
  echo "$(printf '%-10s' "$name"): $result  [python $version$moto] $(tail -n 1 "$dir/tests.txt" | tr -d '=')" >> "$SUMMARY"
done

cat "$SUMMARY"
exit $failed
