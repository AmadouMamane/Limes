# 7. The MCP Streamable HTTP transport reuses the decision; only the wire is new

Date: 2026-07-24

## Status

Accepted. Instances ADR 0004 (core / detectors / transports) a third time, after
the in-process guard (v0.1) and the MCP stdio proxy (ADR 0005). Reuses the
egress-redaction behaviour of ADR 0006 unchanged.

## Context

limes claims a transport-agnostic decision core: the *same* verdict, evidence and
chain whether the guard is called in-process or across a proxy. Two transports
made that claim testable; a third — over HTTP, the other wire MCP actually runs
on — is what makes it *true* rather than merely repeated. The current MCP HTTP
transport is **Streamable HTTP** (protocol `2025-11-25`): a single endpoint that
takes JSON-RPC over `POST`, streams server→client messages back over SSE, and
tracks a session with an `Mcp-Session-Id` header. (The older HTTP+SSE transport
is deprecated; limes does not implement it.)

The risk in a third transport is that it re-implements the decision — inbound
inspection, the outbound seam, redaction, the ledger — and the three copies
drift. That would defeat the entire point: a `Deny` that re-derives *differently*
depending on how it was reached is not one guard behind three doors, it is three
guards.

The stdio proxy already factored the decision out of the wire. Its `Relay` reads
and writes `SessionMessage` over four in-memory streams and knows nothing about
pipes; the stdio `serve()` only *feeds* it stdio streams. So the HTTP transport
needs no new decision at all — it needs new streams.

Both halves of the HTTP plumbing are the SDK's own:

- host-facing, the SDK's `StreamableHTTPSessionManager` owns session routing by
  `Mcp-Session-Id`, the SSE stream, and session cleanup, and hands an "app" a
  pair of `SessionMessage` streams per session;
- server-facing, the SDK's `streamable_http_client` opens one upstream connection
  and yields the same pair of streams.

## Decision

**1. New module `limes/transports/mcp/http.py`. No change to the core, the
pipeline, the detectors, or the stdio proxy's decision.** The frontier ratchet
(`tests/unit/test_frontier.py`) proves the core is byte-identical to v0.1; a
dedicated ratchet (`tests/unit/mcp/test_http.py`) proves this module *reuses* the
decision rather than copying it: `http.Relay is bridge.Relay`, and the module's
source contains no `rule`, `rule_egress`, `_screen_result`, `_inspect_call` or
`_masked_response` definition of its own.

**2. The decision is the stdio `Relay`, unchanged.** A small seam, `_ProxyApp`,
stands in for the MCP server the session manager expects. It is not a server: it
implements only the two methods the manager calls (`create_initialization_options`
and `run`), and its `run` opens the upstream client and drives a fresh `Relay`
per host session between the manager's host-facing streams and the upstream
client's streams. One host session, one upstream session, one decision chain. The
seam is handed to the manager through a `cast` — the manager's `app` is typed as
its own `Server`, and the two methods it actually touches are all `_ProxyApp`
provides; the end-to-end test is the proof the runtime contract holds.

**3. Only HTTP plumbing is new, and even that is mostly the SDK's.** limes adds
the Starlette app (a lifespan that runs the session manager, a mount that routes
every MCP request to it), the config, the CLI, and the seam above. Session
routing, SSE, and the `Mcp-Session-Id` handshake are the SDK's.

**4. The dependency is the `http` extra, and it happens to add nothing over
`mcp`.** `pip install 'limes[http]'` pulls `mcp` plus a pinned `uvicorn`; since
`mcp` already depends on `starlette` and `uvicorn`, `limes[http] ⊇ limes[mcp]`.
The extra exists so the intent (`I want the HTTP proxy`) is a declared gesture,
and so the pin is explicit rather than transitive. The core still installs with
one dependency; the frontier ratchet still forbids `mcp` from the core deps.

**5. Anti-scope (v1).** Streamable HTTP only. One host↔upstream pair per session.
No host authentication beyond what the SDK's transport enforces, and no upstream
credentials forwarded — the upstream connection uses the SDK's default client
(a `--header`/upstream-auth surface is future work, and is *absent* rather than
stubbed, so nothing reads as guarded that is not). No multiplexing. A decision
chain is per host session, so under HTTP one process may hold several independent
chains — honest, and unlike stdio where one process is one session.

## Consequences

- The "transport-agnostic core" claim is now proven on the two wires MCP runs on.
  An injection re-derives the same evidence over stdio and over HTTP because it is
  the same `Relay`; the end-to-end test drives real processes and real HTTP for
  transparency, blocking (with its unproxied control), redaction (with its
  control), and a fixed-clock replay to identical digests.
- **Measured, not asserted.** One guarded `tools/call` over HTTP adds a **median
  ~3.3–3.9 ms** over the same call made directly (two runs: +3.88 / +3.30 ms
  median, +5.36 / +3.72 ms p95; macOS arm64, Python 3.12.4, n=200, 256-byte
  payload, default config). That is materially more than the stdio proxy's
  ~0.6 ms, and expectedly so: the HTTP proxy makes a *second* full HTTP round trip
  to the upstream, where stdio pipes bytes between two local processes. Reproduce:
  `uv run python -m limes.transports.mcp.bench_http`.
- Egress redaction (ADR 0006) works over HTTP with no new code: the same `Relay`
  masks the same offsets, and the masked result crosses the SSE stream as a normal
  result annotated in `_meta`.
- The session manager can be created only once per instance; the app builds a
  fresh manager per process, which is correct for a one-pairing-per-process proxy.
