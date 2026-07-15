# Security policy

limes is a security tool; we take vulnerabilities in it seriously.

## Supported versions

limes is pre-1.0 (v0.1, alpha). Security fixes land on `main` and in the next
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

limes v0.1 is an **in-process** guard with a single **inbound** injection
detector. The perimeter is stated honestly in the README: v0.1 has no MCP proxy,
no PII or secrets detector, and no egress detection.

- A prompt-injection variant the detector **misses** is a **corpus gap**, tracked
  in the open through the eval harness. That is expected, adversarial growth
  (ADR 0003) — not a vulnerability in the engine. The best way to report one is a
  pull request that adds the case to the corpus with its measurement.
- A flaw in the **engine** *is* a vulnerability: a `CannotSay` silently treated as
  `Allow`, an `Allow` constructed without evidence, a redacted span that leaks the
  raw payload, a hash-chain that verifies a tampered record, a `__bool__` that
  does not raise. Please report these privately.
