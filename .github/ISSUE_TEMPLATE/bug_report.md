---
name: Bug report
about: A defect in the limes engine, a detector, or a transport
title: "bug: "
labels: bug
---

**Do not use this for security vulnerabilities.** See
[SECURITY.md](../../SECURITY.md) for private reporting.

## What happened

A clear description of the bug.

## Reproduce

Minimal steps or a code snippet. If it involves a detector verdict, include the
input and the `Verdict` / `Evidence` you observed.

```python
# minimal repro
```

## Expected

What you expected instead (e.g. `Deny` with evidence, `CannotSay`, `Allow`).

## Environment

- limes version / commit:
- Python version:
- OS:

## Which layer (best guess)

- [ ] Core (verdict algebra, evidence chain)
- [ ] Detector / policy
- [ ] Transport
- [ ] Eval harness
- [ ] Docs
