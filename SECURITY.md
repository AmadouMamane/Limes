# Security policy

limes is a security tool; we take vulnerabilities in it seriously.

## Supported versions

limes is pre-1.0 and alpha. Security fixes land on `main` and in the next
tagged release. There is no back-port guarantee before 1.0.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions.**

Use GitHub's private vulnerability reporting instead: open the
[Security tab](https://github.com/AmadouMamane/Limes/security) of this repository
and click **"Report a vulnerability"**. This creates a private advisory visible
only to the maintainers.

Please include:

- a description of the vulnerability and its impact;
- the affected version or commit;
- steps to reproduce — a minimal proof of concept if possible;
- any suggested remediation.

## What to expect

- We aim to acknowledge a report within a few days.
- We will confirm the issue, assess its severity, and keep you informed of
  progress toward a fix.
- We practice coordinated disclosure: please give us a reasonable window to ship
  a fix before public disclosure. We will credit you unless you prefer to remain
  anonymous.

## Scope — read this before reporting

What ships, and is therefore in scope: **four admitted detectors** —
`injection` on the inbound leg, and `pii-egress`, `secrets-egress` and
`injection-egress` on the outbound one — reached through **three transports**: the
in-process guard, the MCP stdio proxy (`limes proxy`) and the MCP Streamable HTTP
proxy (`limes proxy-http`). On the proxies the outbound seam screens the results
of `tools/call`, `resources/read`, `tools/list` and `prompts/get`, and the
`sampling/createMessage` and `elicitation/create` requests a server makes of the
host (ADR 0024); the threat model names what crosses uninspected, by decision, and the chain declares it the first time each kind crosses (ADR 0028). An image, an audio clip or a binary resource in a guarded message is a declared blind spot, blocked by default (ADR 0028). `limes check` is the CLI, and the leg selects its
detectors there too (ADR 0018): the inbound leg runs `injection`, the outbound
leg runs all three egress detectors — outbound scanning over the CLI is shipped,
active, and in scope.

What the README's "What limes does not do" declares *out* of scope, because it
was never claimed: generic high-entropy secret scanning, any PII category beyond
the five a checksum or a format can separate from ordinary prose, and any
classifier layer (ADR 0013 frames one; it is not implemented).

- A prompt-injection variant the detector **misses** is a **corpus gap**, tracked
  in the open through the eval harness. That is expected, adversarial growth
  (ADR 0003) — not a vulnerability in the engine. The best way to report one is a
  pull request that adds the case to the corpus with its measurement.
- A flaw in the **engine** *is* a vulnerability: a `CannotSay` silently treated as
  `Allow`, an `Allow` constructed without evidence, a redacted span that leaks the
  raw payload, a hash-chain that verifies a tampered record, a `__bool__` that
  does not raise, a rule whose cost is not linear in the content at the declared
  budget (ADR 0023), a message that reaches a peer without the decision the
  README promises for it (ADR 0024), a `CannotSay` whose cause is `fault` or
  `refused` forwarded under any `on_cannot_say` policy (ADR 0026), an `Allow` on
  a leg no detector read (ADR 0027), an image or binary block counted as
  inspected text (ADR 0028), a declared blind spot forwarded under a policy that
  did not open every family it carries, or a shipped limit raised under the
  wrong family (ADR 0029). Please report these privately.
