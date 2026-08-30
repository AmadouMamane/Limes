# 18. The leg selects its detectors, in every transport including the CLI

Date: 2026-08-30

## Status

Accepted. Closes a hole in `limes check` that ADR 0004's usage-surface rule made
easy to miss.

## Context

`limes check` is described, correctly, as *the same pipeline from the command
line*. It reuses `decide` unchanged and adds a usage surface, not a decision
(ADR 0004).

It did not run the same detectors.

`limes check` built one `InjectionDetector` and used it on whichever leg
`--direction` named. On `--direction inbound` that is right. On
`--direction outbound` it ran the inbound detector against a tool result — a
detector that, by construction, never inspects that leg — and printed:

```
[ALLOW] observed by 1 detector(s), 0 findings
exit 0
```

That output is worse than an error. It is an `Allow`, whose entire contract in
this project is that it *names what looked at the content* (ADR 0002), on content
nothing capable of judging it had looked at. The three detectors that actually
guard the outbound leg — `pii-egress` (v0.5), `secrets-egress` (v0.6),
`injection-egress` (v0.8) — were unreachable from the command line, so the
documented CI use ("scan this tool output before you trust it") returned a clean
sheet over an unscanned card number.

The help text said so honestly — *"this command wires the injection detector
only"* — and honest documentation of a hole is still a hole. Worse, it was the
kind ADR 0026's lineage exists to forbid: a witness reporting "ok" about
something it could not see.

## Decision

**The leg selects its detectors, and it selects the same ones in every
transport.**

| `--direction` | detectors |
|---|---|
| `inbound` | `injection` |
| `outbound` | `pii-egress`, `secrets-egress`, `injection-egress` |

That is exactly the set the MCP proxies deploy on each leg, so "the same pipeline
from the command line" becomes true rather than nearly true. A future admitted
detector joins its leg here for free, because the set is derived from the leg and
not listed at each call site.

Two consequences follow, and both are deliberate.

**Evidence names the whole set.** With more than one detector on a leg, no single
detector's `policy_hash` describes the rules that ran, so the recorded hash is the
digest of the set — each detector's id with its own policy hash, joined. An
`Allow` from the outbound leg now reads *"observed by 3 detector(s)"*, and the
hash beside it identifies which three and under which rules.

**`check` reports a verdict; it does not transform.** Redaction is a transport
behaviour (ADR 0006): a masked-and-forwarded response is something a proxy does.
A scanner that silently rewrote its input would be a different tool, and one
whose exit code no longer *is* the verdict.

`--policy` keeps its meaning — the injection policy, for the inbound leg. The
egress rules are data too (`egress.yaml`, packaged), and pointing this flag at
both would make one option mean two files.

## Amendment discovered while writing the end-to-end proof

`limes check` was not the only transport with an empty leg. Writing the test that
proves a poisoned `tools/list` is refused — the claim this project leads with —
found that **`serve()` defaulted its outbound detectors to `()`, and the console
entry point passed none**. Its docstring even said so: *"Empty by default, and
the console entry point never passes any — limes ships no egress detector."*

That sentence was true at v0.4. `pii-egress` landed in v0.5, `secrets-egress` in
v0.6, `injection-egress` in v0.8. For three releases the shipped proxy ran with
nothing on the leg the README described it guarding, and the CLI's own help
repeated the stale claim (*"limes ships no egress detector, so nothing exercises
this today"*).

Every unit test passed. They all constructed the bridge themselves and handed it
detectors, so none of them ever exercised the default — which is exactly the
shape of hole a unit test cannot see and an end-to-end test finds on its first
run.

So the rule above is transport-wide, not CLI-specific: **`serve()` installs every
admitted egress detector unless a caller overrides.** The override survives,
including `()` for a deliberately unguarded leg, because the transparency tests
use it to prove exact pass-through and a default that swallowed that distinction
would make them unable to say what they say. The set is *derived* from
`ADMITTED`, so a detector admitted tomorrow reaches this transport without
anybody remembering; a test pins what the derivation yields, so it cannot
silently select nothing.

## Consequences

- `echo "$TOOL_OUTPUT" | limes check --direction outbound -` does what its
  documentation always claimed: exit 1 on a card number, an API key, or an
  instruction smuggled into a tool result; exit 0 on ordinary content.
- The removed sentence — *"the egress detectors run in the proxy transports, not
  here"* — was the accurate description of a defect. It is gone because the
  defect is.
- One behaviour change for anyone who scripted `--direction outbound`: it used to
  exit 0 on everything, because nothing was looking. It now returns a verdict. A
  pipeline that depended on the old silence was depending on a bug.
- Nothing in the core moved. This is a usage surface selecting from the admitted
  set, which is what ADR 0004 says a usage surface may do.
