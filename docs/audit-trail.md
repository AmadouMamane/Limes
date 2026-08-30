# The audit trail — evidence, the ledger, and how to verify it

Every limes decision is recorded, and the record is designed to be **checked
later by someone who does not trust the recorder**. This page explains exactly
what is stored, what is *not*, and the three things you can prove from it.

The short version: the ledger is a **tamper-evident log**, not a database and not
a copy of your traffic. It **commits** to the content that flowed — with a hash —
and lets you prove that content later, but it never stores the content itself.

---

## 1. What is recorded, per decision

One decision is one `DecisionRecord`. It has exactly six fields:

| field | example | what it is |
|---|---|---|
| `seq` | `1` | 0-based position in the chain — this *is* the record's index |
| `direction` | `outbound` | which leg the decision was made on (`inbound` / `outbound`) |
| `actor` | `"alice"` | the caller's asserted identity (`null` if anonymous) |
| `verdict_fingerprint` | *(JSON string, below)* | the *what and why* of the decision — all as hashes |
| `prev_hash` | `9020a692…` | the digest of the **previous** record (`0000…` for the first) |
| `digest` | `586d8b16…` | `SHA-256` of this record's core — what seals it |

The `verdict_fingerprint` is a canonical JSON string. Expanded, a real one looks
like this (an outbound decision that masked a card number):

```json
{
  "evidence": {
    "content_sha": "66850244dbc8…",          // SHA-256 of the whole inspected content
    "observed_at": "2026-08-30T10:00:00Z",    // a full ISO-8601 instant, caller-supplied
    "policy_hash": "d81baf67343c…",           // which policy decided
    "spans": [
      { "start": 6, "end": 25,                // WHERE a rule fired (offsets)
        "label": "pii:pan",
        "sha": "9219e0affa4b…" }              // SHA-256 of the matched value — never the value
    ],
    "witnesses": [ { "id": "pii-egress", "version": "0.1.0" } ]
  },
  "kind": "deny",
  "reason": "1 rule match(es) on outbound content: pii:pan"
}
```

**What is deliberately *not* stored:** the raw content (`"Carte 4242 4242 4242
4242…"`) and the raw matched value (the card number). Only their SHA-256
(`content_sha`, `spans[].sha`) and the **offsets** that locate the match. The
ledger can say *"at offsets 6–25 there was a value whose hash is 9219e0af…"*
without ever writing the card down. That is what lets an audit log exist without
becoming a liability that leaks every secret it ever saw.

> **The MCP proxy adds one annotation.** When limes runs as a proxy, each JSONL
> line carries the six record fields **plus** an `mcp` object — `method`, `tool`,
> `request_id`, `action` (`forward`/`redact`/`block`), and `redaction` (kinds,
> offsets, token — never the masked text). This annotation is **outside** the
> hashed core and cannot change a digest; it exists to correlate a record with a
> specific call (see §5).

---

## 2. The two hashes, and the chain

Two independent hashes do two different jobs.

**`content_sha` commits to the content.** It is `SHA-256` of the exact bytes that
were inspected. Because it lives inside `verdict_fingerprint`, which is hashed
into `digest`, the content commitment is itself sealed by the chain.

**`digest` + `prev_hash` chain the records.** Each record's `digest` is computed
over its own core *and the previous record's digest*:

```
digest_N = SHA-256( { seq: N, direction, actor,
                      verdict: <fingerprint_N>,
                      prev_hash: digest_{N-1} } )
```

So the records form a linked chain:

```
  GENESIS(0000…) ◄─prev─ record 0 [digest 9020a692…]
                          ◄─prev─ record 1 [digest 586d8b16…]
                                   ◄─prev─ record 2 [digest …]
```

Appending is **O(1)**: a new record reads only the previous digest (a 64-hex
string), hashes its own small core, and is done. The history is never re-hashed.
Yet `digest_N` transitively depends on *every* prior record — because it includes
`digest_{N-1}`, which includes `digest_{N-2}`, and so on. The head digest is a
commitment to the entire past, built one hash at a time.

---

## 3. Proving what content a decision was about

A hash is one-way, so you never *reverse* it. You **re-present** the content and
re-hash it. Verification is: *"here is the content I claim was processed"* → hash
it → compare to the stored `content_sha`.

```
claim: record 0 was about "Vire 500 EUR vers le compte de Paul"
  SHA-256("Vire 500 EUR vers le compte de Paul") = e861bede8a6d…
  == record 0 content_sha (e861bede8a6d…) ?        → yes, proven

forged claim: "Vire 5000 EUR vers le compte de Paul" (amount inflated)
  SHA-256("Vire 5000 EUR vers le compte de Paul") = 59efc521a244…
  == record 0 content_sha (e861bede8a6d…) ?        → no, exposed
```

The irreversibility is exactly what makes this sound: no one can craft a
*different* content that hashes to the same value.

There are **three levels** of verification, needing progressively more:

1. **Sequence integrity — needs no content at all.** `Ledger.verify()` recomputes
   each `digest` from the stored fields and checks that every `prev_hash` links to
   the previous digest. It proves no record was inserted, deleted, reordered or
   altered. The records are self-contained; the content is not required.

2. **Content binding — needs the content.** Hash the content you hold and match it
   to a record's `content_sha` (above). This proves *which* content a given
   decision concerned.

3. **Full replay — needs content + policy + timestamp.** The decision core is
   **pure**: no wall clock, no randomness — `observed_at` is passed in, never read
   from `now()`. So with the content, the `policy_hash`'s policy, and the recorded
   `observed_at`, you can **re-run the whole pipeline and reproduce every digest
   byte-for-byte**. Not just "the hash matches" — the entire chain regenerates
   identically.

---

## 4. Detecting tampering

Suppose someone edits a stored record — changes `actor` from `alice` to
`mallory`, or inflates an amount (which changes `content_sha`). Recomputing that
record's `digest` yields a different value:

```
digest_0 original            = 9020a692…
digest_0 recomputed (mallory) = 3d0a2bd9…   ← different
but record 1's prev_hash      = 9020a692…   ← still points at the original
```

The link is **broken**, and `verify()` reports `broken_at` that index. To hide the
edit, the tamperer must recompute the forged record's digest, rewrite the *next*
record's `prev_hash`, recompute *its* digest, and so on — **rewrite the entire
tail.**

That is expensive but not impossible for someone who fully controls the log file.
The final lock is **external**: keep a copy of the **head** (the most recent
digest) out of the tamperer's reach — published to a counterparty, timestamped,
appended to a WORM store, the way a Certificate Transparency log is anchored. At
audit time, replay the chain: if the recomputed head ≠ the externally anchored
head, tampering is proven.

> limes gives you the head (`Ledger.head`, or the last JSONL line's `digest`).
> **Anchoring it externally is your deployment's decision** — limes does not do it
> for you.

---

## 5. Finding a specific decision

The ledger is an **ordered log, not a queryable database** — this is deliberate
(the core stays tiny, one runtime dependency). `seq` *is* the index, but you do
not know a decision's `seq` in advance; you **locate** the record by filtering on
a field.

```python
recs = guard.ledger.records()          # ordered by seq

# all of alice's decisions — usually several, so this alone is ambiguous
alice = [r for r in recs if r.actor == "alice"]

# THE specific decision, pinpointed by the content you kept elsewhere
import hashlib, json
target = "Vire 500 EUR vers Paul"
h = hashlib.sha256(target.encode("utf-8", "surrogatepass")).hexdigest()
def content_sha_of(r): return json.loads(r.verdict_fingerprint)["evidence"]["content_sha"]
hit = next(r for r in recs if content_sha_of(r) == h)   # -> the record; hit.seq is its index
```

The join key between *a real-world request* and *a ledger record* is something
**you keep in your own logs**:

- **`content_sha`** — hash the content you retained, find the matching record;
- **`request_id`** — the proxy's JSONL `mcp.request_id` (the JSON-RPC id) ties a
  record to one specific call; if your app logged "transfer X was request 47",
  find `mcp.request_id == 47`;
- **`observed_at`** — the timestamp, if you know roughly when;
- **`seq`** — once known, `records()[seq]` is direct.

At scale, build **your own index** as you consume the JSONL — a table
`request_id → seq` (or `content_sha → seq`) in your database. The ledger stays a
pure append-only log; the index is a layer you add over it.

**`observed_at` is a full ISO-8601 instant** — date, time and timezone, e.g.
`2026-08-30T13:49:06.844689+00:00` (the CLI and proxy default to microsecond
UTC). It is a caller-supplied string, stored verbatim and sealed into the chain,
so it cannot be back-dated on a past record without breaking the links.

---

## 6. Where records live

- **In memory** — the `Ledger` is a list of records for the life of the process,
  reachable any time via `guard.ledger.records()` and `guard.ledger.head`.
- **Durably** — the **proxy** writes each record as one JSONL line, to **stderr by
  default** (never stdout, which is the host's JSON-RPC channel) or to a file with
  `--record FILE`, append-only. The **in-process library does not persist on its
  own**: you serialise `records()` (via `dataclasses.asdict`) wherever you want.

---

## 7. How it scales

- **Writing is O(1)** and cheap — one `SHA-256` over the content plus one over a
  small fixed-size record core. The chain is not the bottleneck; detectors and I/O
  are (a guarded MCP call adds ~0.6 ms over stdio, dominated by the round trip).
- **A hash chain is inherently sequential.** Record `N+1` needs record `N`'s
  digest, so a *single global* chain cannot be written concurrently by many
  instances without a serialization point. limes sidesteps this by keeping **one
  chain per session/process** — you shard the proof by session, each chain
  independently verifiable. You do not get one global total order across the fleet
  (and you cannot, from a hash chain, without a single writer).
- **`verify()` is O(n)** — it replays every link from genesis. Fine as an
  occasional audit; there is no Merkle checkpoint to verify a suffix cheaply.
- **The in-memory ledger grows unbounded** for the life of a process. For a
  long-lived, high-volume session this needs care (keep only the head in memory,
  stream the rest); for ordinary sessions it is a non-issue. Durable output is
  append-only JSONL; **rotation and retention are the operator's job**, not
  built in.

---

## 8. What the audit trail deliberately does *not* do

- **It does not store your content** — only hashes and offsets. If no one retained
  the content, you keep proof *of the decision* (how many, in what order, which
  verdict, which policy, when), and a way to validate any content later presented
  — but the ledger will not hand the content back.
- **It does not anchor the head for you** — external anchoring (§4) is a
  deployment choice.
- **It is not a query engine** — locating and indexing (§5) live in your layer.
