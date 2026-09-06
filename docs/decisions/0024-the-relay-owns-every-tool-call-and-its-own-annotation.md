# 24. The relay owns every tool call, and its own annotation

Date: 2026-09-06

## Status

Accepted. Extends ADR 0005 (the MCP proxy is a transport) and ADR 0012 (the
egress leg scans for injection). Changes only `src/limes/transports/mcp/`.

## Context

Four holes in the relay, found by asking the wire rather than the tests — three
of them by sending a message the tests had never sent.

**A `tools/call` with no `id` crossed uninspected.** MCP defines `tools/call` as
a request. The relay inspected `JSONRPCRequest` and relayed everything else
byte-faithful, so a `tools/call` shaped as a *notification* — the same method,
the same arguments, no id — reached the wrapped server with no decision and no
record. The official SDK's server ignores such a message; a server that does
not use the SDK may execute it. The README says every tool call becomes a
decision, and this one did not.

**A wrapped server could sign as limes.** The relay annotates the results it
masks or refuses under `_meta.limes`, with the chain digest that indexes the
decision. On a clean result it forwarded the server's bytes as they were — so a
server could ship its own `_meta.limes`, with a digest of its choosing, and the
host had no way to tell it from the relay's.

**Three server→host channels reached the model unscreened, and nothing said so.**
`prompts/get` returns the messages of a prompt — content that goes straight into
the model's context — and was not a guarded method. `sampling/createMessage` is
a request the *server* makes of the host, carrying the messages it wants the
host's model to complete; `elicitation/create` carries the text the host shows
its user. ADR 0012 declared `prompts/*` *listings* and resource descriptions out
of scope; none of these three was mentioned anywhere.

**The table of unanswered guarded requests grew without bound.** A server that
never answered could hold an entry per request forever. Bounding it the obvious
way — forget the oldest — would let that request's response cross unscreened
when it finally arrived.

## Decision

**1. A `tools/call` is judged whatever its shape.** A notification-shaped
`tools/call` runs the same inbound pipeline as a request; the decision is
recorded with `request_id: null`; an allowed one is forwarded; a refused one is
dropped, with a line on stderr naming the record, because there is no id to
answer. It is not an error to the host and not a pass to the server.

**2. The relay reserves `_meta.limes` on the host-facing side.** Every
server→host result is inspected for it, guarded leg or not. A value found there
is moved to `_meta.limes-upstream` — kept, so the host can see what the server
claimed, but unable to pass for the relay's own — and a line on stderr says so.
The relay's annotation is then the only thing that key ever carries, and its
`record.digest` is verifiable against the journal.

**3. `prompts/get` joins the outbound seam's guarded methods**, beside
`tools/call`, `resources/read` and `tools/list`. The canonical payload walk
already reaches every message string; a refused result is a JSON-RPC error,
since the method has no `isError` affordance.

**4. `sampling/createMessage` and `elicitation/create` cross the outbound seam
as requests.** Their parameters are content the host's model or user reads, so
they are inspected by the outbound detectors and recorded on the outbound leg.
A refusal is a JSON-RPC error answered to the *server*, which asked, and the
host never sees the request. Redaction does not apply: it is a behaviour for
results (ADR 0006), and a request that trips a detector is refused whatever the
egress policy says about its kind. With no egress detector installed the
requests cross untouched and unrecorded, exactly like a result.

**5. The pending table refuses rather than forgets.** At 4 096 unanswered
guarded requests the relay stops remembering and refuses the next one — closed,
with a `CannotSay` on the chain naming why — instead of evicting an entry whose
response would then cross unscreened. A server that has left that many requests
unanswered in one session is not answering.

**Declared, and not guarded.** `prompts/list`, `resources/list`,
`resources/templates/list` and `completion/complete` carry descriptions and
completion values and cross untouched, as ADR 0012 decided for listings;
`notifications/message` (server logging) crosses untouched because a host writes
it to a log, not to the model, and a blocking policy over log lines would drop
every line that happened to carry an address. Each is named in the threat model
so a reader finds the perimeter written down rather than inferred.

## Consequences

- The sentence "every tool call becomes a decision" is true of the wire again,
  not only of the requests the tests happened to send.
- A host reading `_meta.limes` reads the relay. An upstream forgery is visible
  under its own name and cannot carry the relay's.
- The outbound seam guards four result methods and two request methods, on both
  transports, since the HTTP proxy runs the same relay (ADR 0007).
- Every decision above is sealed with its disposition (ADR 0025), so the journal
  and the chain agree about what left.
- Anti-scope, unchanged: no redaction of a server→host *request*; no screening
  of host→server responses (the host's answers to a sampling request are the
  model's own output, on the leg the inbound detector does not claim).
