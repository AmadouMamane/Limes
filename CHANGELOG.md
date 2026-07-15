# Changelog

All notable changes to limes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); limes adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — v0.1 foundation

- The decision core: `Verdict = Allow | Deny | CannotSay`, evidence-carrying,
  `__bool__` raises (ADR 0002).
- A hash-chained, replayable `DecisionRecord` ledger — replay a recorded session
  and the digests re-derive identically (ADR 0002).
- The `Detector` protocol and entry-point discovery; the core never grows
  (ADR 0004).
- The `injection` detector (inbound) — catches the four language variants regex
  misses (case 08, "proceed without identity verification"), calibrated against
  the Tessera baseline measured under the corrected grader (ADR 0003; ADR 0028
  §5, criteria sha `11-69bcc3f57015`).
- The in-process transport: `guard()` plus a decorator / context manager
  (ADR 0004).
- The admission rule and its enforcer: no detector lands without a positive
  corpus, a benign corpus, a null control, and a published confusion matrix —
  two numbers, never one (ADR 0003).
- Founding ADRs 0001–0004.

### Not yet — see the README's "What limes does not do" section

- No MCP proxy (that is v0.2, the adoption wedge), no HTTP transport, no CLI.
- No PII or secrets detector, no rate-limit, no kill-switch, no threat feed, no
  human-approval, no LLM-judge detector, no dashboard.
- Name, PyPI, GitHub, CLA and the final license split are **not decided** — they
  are Amadou's calls, pending before any publication.
