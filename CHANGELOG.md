# Changelog

All notable changes to limes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); limes adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — v0.2, the MCP stdio proxy (ADR 0005)

- **A second transport, and nothing else.** `limes proxy` / `limes-proxy` sits
  between an MCP host and an MCP server on stdio: a server to one, a client to
  the other. An MCP host adopts limes by wrapping the command it already runs —
  one line of JSON, no code. `docs/design/mcp-proxy-v0.2.md` is the design note,
  with its deviations listed.
- **Faithful pass-through** of everything it does not guard — `initialize`,
  `tools/list`, `prompts/*`, capabilities, notifications, unknown methods and
  unknown fields — in both directions, ids preserved. The host sees the wrapped
  server's real capabilities.
- **A refusal is a tool result, not a transport error.** A blocked `tools/call`
  comes back as `CallToolResult(isError=True)` carrying the reason and the
  redacted evidence in `_meta.limes`, so an agent degrades instead of crashing.
  The one exception is a refused response on a method with no `isError`
  affordance (`resources/read`), which gets JSON-RPC code `-32001`.
- **Fail-closed on `CannotSay`**, overridable only explicitly
  (`--on-cannot-say allow`, or `on_cannot_say:` in the policy file). A proxy that
  cannot load its policy exits `2` rather than running unguarded.
- **Decision records** as JSONL — the same shape the in-process transport emits,
  plus an `mcp` annotation outside the hashed core — to **stderr** by default
  (stdout is the host's JSON-RPC channel) or `--record FILE`. A recorded session
  replays to byte-identical digests.
- **The outbound seam is wired and empty.** limes ships no egress detector, so
  responses pass through untouched and unrecorded; the pipeline is *not* run over
  zero detectors, which would answer `Allow` with no witness.
- **The `mcp` SDK is an optional extra** (`pip install 'limes[mcp]'`, pinned
  `>=1.28,<2`); the core keeps its single dependency.
- **Measured overhead**, never asserted: median ~0.6 ms added per guarded
  `tools/call` (macOS arm64, Python 3.12.4, n=200, 256-byte payload).
  `uv run python -m limes.transports.mcp.bench`.

### Unchanged — the core did not grow

The verdict algebra, the ledger, the detector protocol, the pipeline, the
`injection` detector and their tests are **byte-identical to v0.1**. A ratchet
compares them against the v0.1 commit, refuses any new file outside the
transport, refuses `mcp` in `[project].dependencies`, and refuses any core module
importing the SDK. All four were seen red under deliberate mutation.

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
