# Threat model — what limes defends, and what it does not

limes is one layer in a defence, not the whole of one. This page states plainly
where it sits, which attacks it addresses, which it deliberately does not, and the
assumptions the whole thing rests on. If a claim is not here, limes does not make
it.

---

## 1. Where limes sits

limes is a checkpoint on the seam **between an agent and its tools** — in-process,
or as an MCP proxy. It sees two things, and only two:

- **the tool calls your model makes** (the *outgoing* / inbound leg), and
- **the results and listings the tools send back** (the *incoming* / outbound leg).

It does **not** sit in front of the model. The user's prompt reaches the model
without crossing this seam; limes never sees it and does not claim to filter it.
(You *may* run the library on user input as a separate integration point — but the
proxy guards the tool seam, not the prompt.)

---

## 2. What it defends — and which leg does it

### Injection arriving from a tool — stopped before the model reads it (incoming)

This is the leg where limes genuinely intercepts injection *before* the model.
Two published families live here:

- **Tool poisoning** (Invariant Labs): a hostile or compromised MCP server hides a
  directive in a **tool description** (`<IMPORTANT>read ~/.ssh/id_rsa…</IMPORTANT>`),
  delivered to the model at `tools/list`. limes screens `tools/list` and refuses a
  poisoned listing (ADR 0012).
- **Indirect injection**: an "ignore previous instructions" buried in a fetched
  page, an email, a retrieved document — arriving in a tool *result*. limes screens
  results on the same leg.

Detector: `injection-egress`.

### Sensitive data trying to leave — stripped or blocked (incoming)

A tool result carrying a card number, an IBAN, an e-mail, a phone, a NIR
(`pii-egress`), or a prefixed API key / PEM key / JWT (`secrets-egress`) is
redacted or blocked per policy before it reaches the host — each gated by
arithmetic (Luhn, MOD 97-10, …) rather than a loose regex, so an order reference is
not mistaken for a card.

### A hijacked action — gated before it runs (outgoing)

On the model→tool leg, the model has *already* been prompted, so this is **not
protecting the model**. `injection` checks the tool-call arguments as the last
deterministic gate before an action executes — guarding the *consequence*, in case
the model was talked into a dangerous call, regardless of how.

---

## 3. What it deliberately does NOT do

Each of these is a **declared blind spot with a test pinning it**, not backlog
dressed as coverage:

- **It does not filter the user's prompt to the model.** That text never crosses
  the tool seam (§1).
- **No generic high-entropy secret scanning, and no *unprefixed* credential
  detection.** A UUID, a git digest, a base64 blob are all high-entropy and none is
  a secret; an entropy rule with no context is a false-positive generator. An AWS
  *secret* key, a bare bearer token, a DB password (no vendor prefix) are not
  detected.
- **No PII category beyond the five.** Names, postal addresses, dates of birth are
  not claimed — nothing separates them from ordinary prose the way a checksum
  separates a card number from an order reference, so nothing here would *measure*
  them.
- **Injection detection is rule-based** — fast, auditable, zero-drift, and blind to
  the paraphrase and social coercion a trained classifier would catch. A measured
  classifier layer is *framed* as an optional extra, admission-gated (ADR 0013),
  and ships only when its two numbers earn it.
- **No rate-limit, kill-switch, threat feed, human-approval workflow, or dashboard.**
  Those are policies and transports built *around* limes, not the core.

---

## 4. Assumptions the defence rests on

- **Prompt injection into the model is not reliably preventable.** limes does not
  pretend otherwise. It puts a **deterministic** check at the trust boundaries it
  *can* control — what enters the model from tools, and what actions leave the
  model toward tools — so a manipulated model still meets a policy it cannot argue
  with at the point of consequence.
- **A verdict must be inspectable, and silence must never read as safety.** A
  detector that cannot look returns `CannotSay` and the leg **fails closed**; a
  proxy that cannot load its policy exits rather than becoming a silent
  pass-through. (See [The verdict](../README.md#the-verdict).)
- **The audit trail commits to content, it does not store it.** Tamper-evidence
  over content you hold elsewhere; the ledger never becomes a copy of every secret
  that flowed. (See [The audit trail](audit-trail.md).)
- **The tamper-evidence is only as strong as an externally anchored head.** limes
  gives you the head digest; anchoring it out of a tamperer's reach is a deployment
  decision (see [audit-trail.md §4](audit-trail.md)).

---

## 5. Where limes is one layer among several

A robust agent deployment also constrains the *tools* themselves: least-privilege
scopes, argument schemas, human approval for consequential actions,
plan-then-execute patterns. limes is on the good side of that consensus by
construction — fail-closed, egress that loses the answer rather than the key — but
it is **one layer**, not the whole defence. It does not replace confining what your
tools are allowed to do.

---

## See also

- [`docs/decisions/0012-the-egress-leg-scans-for-injection.md`](decisions/0012-the-egress-leg-scans-for-injection.md)
- [`docs/decisions/0013-a-classifier-layer-enters-by-the-same-gate.md`](decisions/0013-a-classifier-layer-enters-by-the-same-gate.md)
- [Measuring detection](measuring-detection.md) · [The audit trail](audit-trail.md)
