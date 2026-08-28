# 12. The egress leg scans for injection: tool poisoning and indirect injection are server→host attacks

Date: 2026-08-28

## Status

Accepted. Admits one detector (`injection-egress`) under ADR 0003 and adds one
guarded method to the MCP proxy's outbound seam (`tools/list`). Closes a blind
spot the README has carried since v0.1: case `42_email_zeroclick` is listed
among the injection detector's residual misses as "an *egress* attack, the
wrong detector; an egress detector is future work". This is that detector.

## Context

The proxy guards two directions asymmetrically. Host→server tool calls are
inspected for injection; server→host traffic is inspected for *data leaving*
(PII, secrets) — but not for *instructions arriving*. Two published attack
families live exactly there:

1. **Tool poisoning** (Invariant Labs, 2025): a hostile or compromised MCP
   server hides directives in its **tool descriptions** — `<IMPORTANT>` blocks
   telling the model to read `~/.ssh/id_rsa` and pass it as a side parameter,
   instructions to conceal steps from the user, shadowing instructions aimed at
   *other* tools. The description reaches the model at `tools/list`, which the
   proxy forwards as **faithful pass-through**, uninspected: the shipped
   `injection` detector answers only on the inbound leg, and the listing never
   crosses the outbound guard because `tools/list` is not a guarded method.
2. **Indirect injection in tool results**: a fetched web page, an email, a
   retrieved document that says "ignore previous instructions". The result
   *does* cross the outbound seam — but the detectors wired there today look
   for card numbers and API keys, not directives.

In both cases the payload is content the agent's model will read, delivered on
the server→host leg — in limes's vocabulary, the **egress leg**. mcp-scan
(Invariant) analyses tool descriptions statically; nothing in the shipped
proxy mediates them live.

## Decision

**One detector, `injection-egress`, on the outbound leg — same machinery as
`pii-egress` and `secrets-egress`.** Rules are data in `egress.yaml` (one file,
one hash); the shared scan produces exact spans; the corpus is synthetic by
construction (ADR 0009), graded on `located` offsets, admitted with a benign
corpus of lookalikes, a null control and a per-category matrix (ADR 0003).
Four rule categories:

- `injection:hidden-tag` — `<IMPORTANT>` / `<HIDDEN>` / `<SECRET>` blocks,
  **case-sensitive**: the published attacks shout their markers, and the
  lowercase `<important>` admonition of an ordinary fetched document must not
  fire.
- `injection:override` — "ignore previous instructions" (en/fr/de) and
  embedded `SYSTEM:` directives, the family Tessera case 08 hides in a quoted
  payee name.
- `injection:concealment` — "do not tell the user", « ne le mentionne pas à
  l'utilisateur », „erwähne … nicht": a legitimate tool has no reason to ask
  the model to hide anything from its principal.
- `injection:exfiltration` — a directive verb within reach of a sensitive
  source (`.ssh`, `id_rsa`, `credentials`, `.env`, API keys, the conversation
  history, passwords).

**The proxy screens `tools/list` responses**: `tools/list` joins `tools/call`
and `resources/read` in the outbound seam's guarded methods. Nothing else in
the transport changes — the canonical payload walk already reaches every
description string, the kind-based egress policy already dispositions the
findings (kind `injection` is not declared `redact` anywhere, so it falls to
the blocking default: a poisoned listing does not reach the host), and every
decision lands on the same chain. A deployment that wired no outbound detector
keeps exact pass-through, as before.

**Known, measured limit — mention versus use.** A rule cannot tell an article
*about* prompt injection from an injection: a fetched security blog quoting
"ignore previous instructions" will be flagged. That benign case is in the
corpus, and if the rules kill it, the matrix publishes it with its cause
rather than rounding it away (ADR 0003) — narrowing the rule until the quote
survives would also let the attack hide behind quoting, which is the wrong
trade for a guard. The v0.1 scope is `tools/list` and the already-guarded
results; `prompts/*` listings and resource *descriptions* are declared out of
scope, not silently covered.

## Consequences

- The residual-miss family documented since v0.1 (`42_email_zeroclick` — an
  egress attack) now has the right detector on the right leg.
- A poisoned tool description is refused before the model ever reads it; the
  refusal carries the exact span, on the chain.
- The registry, entry points, Makefile eval, admission enforcer and frontier
  perimeter each gain one entry — the admission path exercised twice before.
- The proxy's "faithful pass-through" table shrinks by one method, and the
  README says so where it said the opposite.
