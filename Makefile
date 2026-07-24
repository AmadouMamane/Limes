# limes — developer gate.
#
# Inherited discipline (ADR 0026, Tessera): a verdict names the tree it judged.
# `make gate` prints the tree fingerprint before and after the run and refuses
# (VOID, exit 3) if the tree moved underneath it. The logic lives in
# scripts/gate.sh so it is robust to the macOS default make (3.81, no .ONESHELL).
.DEFAULT_GOAL := help
UV ?= uv

.PHONY: help sync fmt gate tree eval

help:
	@echo "limes targets:"
	@echo "  make sync   — uv sync (install deps into .venv)"
	@echo "  make fmt    — ruff format + ruff check --fix"
	@echo "  make gate   — ruff + ruff format --check + mypy --strict + pytest, naming the tree it judged"
	@echo "  make tree   — print the tree fingerprint the gate would judge"
	@echo "  make eval   — run every admitted detector's harness; write the dated matrices"

sync:
	$(UV) sync

fmt:
	$(UV) run ruff format .
	$(UV) run ruff check --fix .

gate:
	@UV="$(UV)" bash scripts/gate.sh

tree:
	@UV="$(UV)" bash scripts/gate.sh --tree

# Every admitted detector, not just the first one. A matrix that stops being
# regenerated stops being evidence, and ADR 0003 admits detectors on their
# matrices — so the target has to grow with ADMITTED, and does.
eval:
	$(UV) run python -m limes.eval.harness --write
	$(UV) run python -m limes.eval.egress_harness pii-egress --write
