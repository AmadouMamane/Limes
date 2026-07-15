#!/usr/bin/env bash
# limes gate — ruff + ruff format --check + mypy --strict + pytest, naming the
# tree it judged (ADR 0026 lineage). A green pass whose tree moved underneath it
# is VOID (exit 3) — unusable is not the same as failed (exit 1).
set -o pipefail
UV="${UV:-uv}"

fingerprint() { { git ls-files -s; git diff; git diff --cached; } 2>/dev/null | shasum -a 256 | cut -c1-16; }

show_tree() {
  echo "  worktree: $(pwd)"
  echo "  branch:   $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '(none)')"
  echo "  HEAD:     $(git rev-parse --short HEAD 2>/dev/null || echo '(no commit yet)')"
  echo "  dirty:    $([ -n "$(git status --porcelain 2>/dev/null)" ] && echo yes || echo no)"
  echo "  digest:   $(fingerprint)"
}

if [ "${1:-}" = "--tree" ]; then
  show_tree
  exit 0
fi

echo "== limes gate — the tree BEFORE =="
show_tree
before="$(fingerprint)"

rc=0
echo "== ruff check =="          ; "$UV" run ruff check .          || rc=1
echo "== ruff format --check ==" ; "$UV" run ruff format --check . || rc=1
echo "== mypy --strict =="       ; "$UV" run mypy                  || rc=1
echo "== pytest =="              ; "$UV" run pytest -q             || rc=1

echo "== limes gate — the tree AFTER =="
show_tree
after="$(fingerprint)"

if [ "$before" != "$after" ]; then
  echo "VOID (exit 3): the tree moved under the gate — $before -> $after"
  exit 3
fi
if [ "$rc" != "0" ]; then
  echo "GATE RED (exit 1)"
  exit 1
fi
echo "GATE GREEN on tree $after"
