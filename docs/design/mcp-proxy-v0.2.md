# Design note — the MCP stdio proxy (v0.2)

> Written 2026-07-23, before the implementation. Kept here **as written**, with a
> final section listing where the shipped transport deviates from it and why. A
> design note that is silently rewritten to match the code proves nothing; one
> that carries its own corrections is a record. The binding decisions are in
> [ADR 0005](../decisions/0005-mcp-proxy-transport.md).

## 1. What it is

A stdio proxy that slips **between an MCP host and an MCP server**: to the host
it looks like a server, to the server it looks like a client. It relays the whole
JSON-RPC 2.0 conversation faithfully and **inspects** only the messages that
carry guardable content — refusing a `tools/call` whose arguments trip the core's
pipeline, with the evidence.

Any MCP host (Claude Desktop, Cursor, Claude Code, …) puts limes in front of its
servers **without a line of code**, and without adopting Tessera.

The differentiating property, carried to the transport: **every tool call an
agent emits becomes provable** — refused or allowed, each decision produces a
chained, replayable `DecisionRecord`.

## 2. Positioning

The MCP proxy-guardrail already exists; limes does not invent it. What no one
else assembles is the verdict that carries its proof (serialisable, hash-chained,
replayable), the admission rule (no detector without a published eval corpus and
null control), and **the same decision core as the in-process transport** — one
machine, two transports, so a `Deny` re-derives identically either way.

The verified prior-art list lives in the README and in ADR 0005, with the date it
was checked. It is re-verified before each commit that touches it; between the
writing of this note and the implementation, one of the four projects had been
renamed and re-scoped, which is exactly why the rule exists.

## 3. Architecture

- New transport module `src/limes/transports/mcp/`: a host-facing stdio MCP
  server, a server-facing stdio MCP client, and the bridge between them. Console
  entry points `limes proxy` and `limes-proxy`. **The core is not touched** — the
  proxy imports `guard()` and the types, it does not modify them, and a test
  proves the diff outside the transport (plus entry points and docs) is empty.
- The `mcp` SDK is an **optional extra** (`limes[mcp]`), never a core dependency.
- Composition: preserve JSON-RPC `id`s; relay requests, responses **and**
  notifications, in both directions.

## 4. The interception points

| Message | Direction | limes |
|---|---|---|
| `tools/call` (request) | host → server | **inbound** pipeline over the arguments (`injection` today). Verdict below. |
| result of `tools/call`, `resources/read` | server → host | **outbound** pipeline (seam wired; **empty** until an egress detector exists — honest, not simulated). |
| `initialize`, `tools/list`, `prompts/*`, capabilities, notifications, everything else | ↔ | **faithful pass-through**, unmodified. The host sees the wrapped server's real capabilities. |

Verdict handling on an inbound `tools/call`:

- **`Allow(evidence)`** → forward. `DecisionRecord` emitted.
- **`Deny(reason, evidence)`** → **do not forward**. Return a `CallToolResult`
  with **`isError: true`** carrying the reason and the evidence id — **not** a
  JSON-RPC transport error. `DecisionRecord` emitted.
- **`CannotSay(blind_spot)`** → **fail closed by default** (treated as `Deny`),
  overridable by policy (`on_cannot_say: deny|allow`, default `deny`).

Every decision — allow, deny, cannot-say — emits a serialisable `DecisionRecord`
to a sink. A test replays a recorded proxied session and re-derives the same
hashes.

## 5. Configuration — the adoption wedge

From:

```json
{ "mcpServers": { "files": { "command": "mcp-server-filesystem", "args": ["/data"] } } }
```

to:

```json
{ "mcpServers": { "files": {
    "command": "uvx",
    "args": ["limes-proxy", "--policy", "~/.limes/policy.yaml", "--", "mcp-server-filesystem", "/data"]
} } }
```

Everything after `--` is the real server's command, launched verbatim.

## 6. Anti-scope

stdio only (no HTTP/SSE, no anticipatory skeleton) · no new detector · no
dashboard, rate limit, kill switch, human approval, config UI · one host↔server
pair per process. The core does not grow.

## 7. Definition of done

`make gate` green, naming the tree it judged · transparency proven against a real
server · blocking proven, including that the real server never received the call ·
fail-closed proven both ways · evidence replayable · frontier proven · README
(drop-in snippet, "what it does not do", verified prior art) · ADR 0005 · every
number measured, never asserted.

---

## 8. Deviations of the shipped transport from this note

Three, each deliberate. ADR 0005 carries the full reasoning.

1. **Records go to stderr by default, not stdout.** §4 of this note said "stdout
   JSONL by default". In a stdio proxy stdout *is* the JSON-RPC channel to the
   host: a record written there corrupts the session it documents. Default is
   stderr; `--record FILE` appends to a file.

2. **A refused *response* on a method with no `isError` affordance is a JSON-RPC
   error.** The "never a JSON-RPC error" rule is right for `tools/call`, whose
   `isError` lets an agent degrade gracefully. `resources/read` has no such
   field, and substituting a refusal into resource contents would lie about what
   the resource says — so it gets a JSON-RPC error with the
   implementation-defined code `-32001`.

3. **The empty outbound seam emits no record at all.** "Wired but empty" cannot
   mean "runs the pipeline with zero detectors": that returns an `Allow` whose
   evidence names no witness, i.e. a pass written into the chain as if something
   had looked. With no egress detector the leg is a pure pass-through, and the
   blind spot is declared in the README instead.

Two smaller notes on the same honesty axis:

- The SDK is pinned `>=1.28,<2`. 1.28.1 is the latest **stable** release
  (verified 2026-07-23) and the version every published number was measured
  against; the 2.x line is still pre-release and targets a newer specification.
- What the inbound pipeline inspects is **the string values** of the tool
  arguments, walked in canonical order (sorted keys), joined by newlines. Object
  *keys* and non-string scalars are not inspected. That is a declared blind spot,
  listed in the README, not an oversight.
