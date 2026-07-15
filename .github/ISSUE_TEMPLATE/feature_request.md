---
name: Feature request
about: Propose a new detector, policy, or transport (the core never grows)
title: "feat: "
labels: enhancement
---

## What and why

What capability is missing, and the problem it solves.

## Which layer (ADR 0004)

A new capability is a plugin, never a change to the core.

- [ ] Detector (new detection capability)
- [ ] Policy (new rules for an existing detector)
- [ ] Transport (new integration surface — MCP, HTTP, …)
- [ ] Something that seems to need a core change → it needs a new ADR; say why

## If this is a detector: the admission rule (ADR 0003)

A detector ships only with its **two numbers**. Sketch how you would measure it:

- **Positive corpus** — the attacks it catches:
- **Benign corpus** — legitimate traffic it must not kill:
- **Null control** — how it beats doing nothing, and how it avoids block-everything:

A detector without a benign corpus and a null control will not be admitted,
however easy it looks.
