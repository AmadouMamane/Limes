# 8. Mask styles are per-kind and verified; reversible tokenisation is out

Date: 2026-07-24

## Status

Accepted. Extends ADR 0006 (egress redaction is a transport behaviour). Changes
no core, no pipeline, no detector — it is a richer rendering of the same masking
the transport already does.

## Context

ADR 0006's mask is a fixed token: a matched region becomes `[REDACTED:<kind>]`,
carrying the kind and nothing else. That is the right default — it leaks neither
the value nor its shape — but it is blunt. A response that says "your card
`•••• 4242` was charged" is more useful than one that says "your card
`[REDACTED:pii]` was charged", and revealing the last four digits of a card is a
PCI-DSS convention precisely because it is safe: four digits do not reconstruct
sixteen. Some UIs, too, validate a *shape* — sixteen digits in four groups — and
break on a token that is not shaped like the field.

So the deployment, not the core, should be able to choose *how* a masked region
is rendered, per kind, the same way it already chooses *whether* a kind is masked
at all. The risk is obvious: a style that reveals part of the value can reveal too
much. "Last four" of a value that is only four characters long reveals all of it;
"keep the shape, replace the digits" over a value that was already all zeros
changes nothing. A masking that keeps too much is not a masking, and forwarding it
while recording it as `redact` would be the one lie the audit trail cannot afford.

## Decision

**1. A `mask_style` per kind, in the policy, default `full`.**

```yaml
on_egress_finding:
  by_kind:
    pii: redact
  mask_style:      # optional; a kind with no entry masks `full`
    pii: last4
```

Three styles:

- `full` — the ADR 0006 token `[REDACTED:<kind>]`. **The default, byte-for-byte
  unchanged**, so every v0.3 deployment behaves identically.
- `last4` — reveal the last four characters, mask the rest (`••••4242`). A value
  of **four characters or fewer reveals nothing** (four bullets), so a short
  secret can never be shown whole by asking for its "last four".
- `format_preserving` — keep the length and the separators, replace every digit
  with `0` and every letter with `x` (`0000 0000 0000 0000`).

The style lives in `limes/transports/redaction.py`, on the `Masking`: the
rendering is a pure function of the original bytes and the style. A region where
two kinds' spans overlapped and merged renders `full`, because two per-kind styles
cannot both govern the same bytes.

**2. Every mask is verified by re-derivation, and an unverified one blocks.**
`conceals_all(content, redaction)` checks, for every masked region, that the
sensitive original is not recoverable from its rendering. `full` always conceals;
`last4` conceals by construction; `format_preserving` conceals unless the value
was already all placeholders. When a mask does *not* conceal, the transport falls
closed to the block it was standing in for — on both the in-process leg and the
proxies. This is the same discipline ADR 0006 already applied structurally (the
MCP bridge re-derives the sanitised payload and compares it to the plan); this
adds the content-level check the styled masks need.

**3. The style is recorded, the bytes are not.** Each masking's annotation gains a
`style` field, alongside the kind marker `token` (which stays `[REDACTED:<kind>]`
for every style). So a record names *how* a region was rendered without ever
quoting *what* it rendered — not even the four digits `last4` revealed in the
content itself.

**4. Anti-scope.** Deterministic masks only. **No reversible tokenisation** — that
needs a keystore and is a different feature (a separate increment, if ever). **No
format-preserving *encryption*** — FPE needs a cipher, and its point is
reversibility, which a redaction must not have. `format_preserving` here is a
deterministic shape-preserving *mask*, not a cipher: it cannot be undone because
it keeps no bits of the original digit, only that a digit was there.

## Consequences

- A deployment can trade a little legibility for a little exposure, per kind, with
  eyes open — and cannot accidentally trade away the whole value, because the
  verification blocks a mask that kept too much.
- The core is untouched; the frontier ratchet still shows it byte-identical to
  v0.1. This is a transport rendering, the third thing ADR 0004 says may grow.
- `last4` here is generic (the last four characters of the matched text), not
  data-type-aware: it does not special-case an IBAN to reveal its country code, or
  a card to reveal its first six. A subkind-aware style is future work, absent
  rather than half-built.
- Proven on the in-process leg and on both proxies (stdio and HTTP), each against
  real processes, and the record carries the style with none of the masked bytes.
