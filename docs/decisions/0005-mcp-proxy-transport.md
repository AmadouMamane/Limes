# 5. The MCP stdio proxy is a transport

Date: 2026-07-23

## Status

Accepted.

## Context

limes v0.1 could only guard code that imported it. That is the wrong shape for
adoption: the people who most need a guard between an agent and its tools are
running Claude Desktop, Cursor or Claude Code against third-party MCP servers,
and they will not fork either side to get one.

MCP's stdio transport makes the wedge available: a process can sit between the
host and the server, look like a server to one and a client to the other, and
relay everything. An MCP host adopts limes by editing one line of JSON. It adopts
neither Tessera nor limes' Python API.

The proxy-guardrail idea is not new, and the README says so with links verified
on the day of the commit (see *Prior art* below). What limes adds is not the
proxy: it is that **every tool call becomes a decision that carries its
evidence** — refused or allowed, hash-chained, replayable, presentable to an
auditor — and that the decision comes from the *same core* as the in-process
transport, so a `Deny` re-derives identically whichever way it was reached.

## Decision

### 1. It is a transport, and the core does not grow (ADR 0004)

The proxy lives entirely in `src/limes/transports/mcp/`. It **imports**
`limes.transports.in_process.Guard` (hence `limes.guard.decide`), the verdict
algebra and the `Ledger`; it modifies none of them, and it **adds no detector**.

This is enforced, not asserted. `tests/unit/mcp/test_boundary.py` compares the
*bytes* of every file that existed at the v0.1 commit against the working tree
and fails on any change outside a declared allowlist; two core modules whose
prose had to be corrected are allowed to change their **docstring only**, and
that is checked by comparing their ASTs with the module docstring stripped. All
four of those ratchets were seen red under a deliberate mutation before this ADR
was written — a ratchet never seen red is not a ratchet.

### 2. A refusal is a tool result, never a JSON-RPC error

A blocked `tools/call` comes back as a `CallToolResult` with `isError: true`,
carrying the reason in its text content and the evidence in `_meta.limes`
(chain digest, policy hash, content hash, redacted spans). The request `id` is
preserved, so the host's pending call resolves instead of hanging.

The reason is behavioural. An agent that receives a *failed tool result* reads
it, explains it, and tries something else — the degradation MCP was designed
for. A JSON-RPC error reads as a broken transport, and hosts treat it as a
crashed server. A guard that takes the session down every time it does its job
will be uninstalled.

The one exception, and it is a *narrower* rule rather than a softer one: a
refusal on the **response** to a method that has no `isError` affordance (today,
`resources/read`) is returned as a JSON-RPC error with the implementation-defined
code `-32001`. Substituting a refusal *into* resource contents would be a lie
about what the resource says, which is worse than an error.

### 3. `CannotSay` fails closed, and only an operator may change that

A detector that could not look produces `CannotSay`, and the transport blocks —
`on_cannot_say` defaults to `deny`. It is overridable in the policy file or with
`--on-cannot-say allow`, but never implicitly: a witness that cannot see may
never report "ok" (ADR 0002). The refusal says so in as many words and carries
*no* evidence, because there is none — rather than an evidence block that would
read like a look that never happened.

Any other failure of the guard also stops the session. There is deliberately no
degraded mode: a proxy that cannot load its policy exits `2` rather than becoming
a pass-through that an operator believes is guarding them.

### 4. The outbound seam is wired, and empty

The relay inspects the *results* of `tools/call` and `resources/read` on an
**outbound** leg that runs the same pipeline and enforces the same way. limes
ships **no egress detector**, so that leg is configured with zero detectors, and
with zero detectors the relay passes the response through *untouched and
unrecorded*.

It specifically does **not** call `decide()` over an empty detector list. That
call returns an `Allow` whose evidence names no witness — the exact shape of a
false "ok", written into the ledger as though something had looked. An unwatched
leg is a blind spot; it is declared in the README, not simulated in the chain.
A test installs a detector on that seam and proves it is really run and enforced,
which is what makes "wired" a fact rather than a comment.

### 5. `mcp` is an optional extra, never a core dependency

`pip install limes` keeps exactly one dependency (PyYAML). The proxy is
`pip install 'limes[mcp]'`. Both console scripts (`limes`, `limes-proxy`) ship
with the base package and, without the extra, print a one-line install hint and
exit `2` rather than raising `ImportError` from a script that should not have
existed. A ratchet asserts `mcp` is absent from `[project].dependencies` and that
no module outside `transports/mcp/` imports `mcp` or `anyio`.

The SDK is pinned `>=1.28,<2`. Verified 2026-07-23: `mcp` 1.28.1 (2026-06-26) is
the latest **stable** release and the line the SDK's own README calls
production-ready; 2.0.0b2 is a pre-release targeting a newer specification.
v0.2 is built and measured against 1.28.1, which negotiates protocol version
`2025-11-25`. Moving to the 2.x line is a separate change with its own
measurement, not a silent range widening.

### 6. Records go to stderr by default, not stdout

The v0.2 design note proposed "stdout JSONL by default". **That is wrong for this
transport, and shipping it would have been a self-inflicted bug**: in a stdio
proxy, stdout *is* the JSON-RPC channel to the host, so a record written there
desynchronises the very session it documents. The default is stderr;
`--record FILE` appends to a file. This is the one deliberate deviation from the
design note, and it is the reason the note is committed to `docs/design/` with
its deviations listed rather than quietly rewritten.

### 7. The clock is injected, so a session replays

`Evidence.observed_at` is data, never `now()` (ADR 0002). The transport supplies
it through a `clock` seam that defaults to UTC now; a replay injects a frozen
clock and re-derives byte-identical digests. The emitted JSONL carries exactly
the fields of `DecisionRecord` — the same shape the in-process transport produces
— plus an `mcp` annotation (method, tool, request id, action) that sits outside
the hashed core and therefore cannot alter a digest.

## Anti-scope (refused, even where easy)

stdio only — no HTTP/SSE and no anticipatory skeleton for it. No new detector.
No dashboard, rate limit, kill switch, human approval, config UI. One host↔server
pair per process; no multiplexing. Object *keys* and non-string scalars in tool
arguments are not inspected — a declared blind spot, listed in the README.

## Consequences

- Adoption costs one line of JSON in a host config, and nothing else.
- The claim "the same core, two transports" is now testable, and tested: the same
  corpus case that the in-process guard refuses is refused here, and the real
  server's own journal proves it never received it.
- **Measured cost**, on the machine that ran it and never asserted: one guarded
  `tools/call` adds a **median of ~0.6 ms** (two runs: +0.61 ms and +0.67 ms;
  p95 +0.95 ms and +0.63 ms) over the same call made directly — macOS arm64,
  Python 3.12.4, n=200 calls, 256-byte payload, default configuration.
  Reproduce with `uv run python -m limes.transports.mcp.bench`.
- The `limes` console script now exists, with exactly one subcommand. That is a
  surface to defend: a second subcommand is a new decision, not a convenience.

## Prior art

Verified on 2026-07-23, one by one, before this file was committed.

- [MCP Inspector](https://github.com/modelcontextprotocol/inspector) — the
  official "visual testing tool for MCP servers" (MIT): a developer tool for
  testing and debugging, not a runtime guard.
- [mcpsnoop](https://github.com/kerlenton/mcpsnoop) — "Wireshark for MCP. A
  transparent proxy that shows every real tool call between your AI client and
  your MCP servers, live in your terminal" (MIT). The same wrapping shape limes
  uses; it observes, it does not refuse.
- [mcp-proxy](https://github.com/sparfenyuk/mcp-proxy) — "a bridge between
  Streamable HTTP and stdio MCP transports" (MIT). A transport bridge, with no
  inspection.
- [mcp-scan](https://pypi.org/project/mcp-scan/) (Invariant Labs) — **has been
  renamed**: PyPI now states "this package has been renamed to snyk-agent-scan",
  and the repository presents [Snyk Agent Scan](https://github.com/invariantlabs-ai/mcp-scan),
  "security scanner for AI agents, MCP servers and agent skills" (Apache-2.0),
  which analyses configurations and tool descriptions rather than mediating live
  traffic. Earlier write-ups describe mcp-scan as a real-time monitoring proxy;
  that is **not** what either page says today, so limes does not repeat it.
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) — the
  official SDK this transport is built on.
