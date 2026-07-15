## What this changes

A short description, and the motivation. Link any issue or ADR.

## Checklist

- [ ] `make gate` is green locally (ruff + ruff format --check + mypy --strict + pytest).
- [ ] Commits follow **Conventional Commits** (`feat:`, `fix:`, `docs:`, …).
- [ ] Structural change? It references or adds an ADR under `docs/decisions/`.
- [ ] I have signed the [CLA](CLA.md) (required before a first merge).

## If this adds or changes a detector (ADR 0003)

- [ ] Positive corpus added / updated.
- [ ] Benign corpus added / updated.
- [ ] Null control measured (vs unplugged **and** vs block-everything).
- [ ] Confusion matrix regenerated (`make eval`) and committed under `eval/matrices/`.
- [ ] The two numbers are in the PR description below.

**The two numbers:** attacks blocked = `…`, legitimate traffic killed = `…`.
