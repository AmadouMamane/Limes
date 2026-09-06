# 28. The guard says what it cannot read

Date: 2026-09-06

## Status

Accepted. Amends ADR 0004's frontier for `src/limes/guard.py` (one keyword
argument), `src/limes/policy.py` and `src/limes/detectors/policy.yaml` (an
optional `locales` declaration) and `src/limes/detectors/injection.py` (the
readability screen), each re-pinned in `tests/unit/test_frontier.py`. Adds one
module to the detector perimeter (`src/limes/detectors/readability.py`). Extends
ADR 0024's list of what the relay does not inspect from prose to the chain.

## Context

ADR 0002's rule is that a witness that cannot see may never report "ok". By
0.13.0 the detectors honoured it for the two limits they knew how to name —
size and encoding — and answered "nothing found" over several kinds of content
no rule had read a word of:

- **an image, an audio clip or a binary resource in a tool result.** The
  payload walk (ADR 0005) swept the base64 as if it were prose, matched nothing
  in it, and the result passed as inspected. The host's model reads the text in
  a picture; a text guard cannot; a picture is therefore exactly where a
  directive hides from limes while reaching the model.
- **a payload that is mostly base64, hex or a serialised blob** — a file's
  bytes returned encoded, a data URL. Same shape, one level down: the model may
  decode it, the rules cannot. The corpus already recorded one instance as a
  documented miss (`11_prompt_injection_base64`, where the encoded directive is
  short and sits inside readable prose, and stays a miss under this record).
- **words split by invisible characters.** A zero-width space inside `ignore`
  defeats every override rule; a zero-width joiner inside a card number defeats
  the Luhn rule's shape.
- **another script, or a declared language the rules do not cover.** The
  injection rules are French, German and English. Cyrillic prose matched none
  of them and was "clean"; and `Context.locale`, carried since v0.1, was read
  by no detector at all.

And the relay forwarded a dozen kinds of message it never inspects —
`initialize`, `prompts/list`, `resources/list`, `completion/complete`,
notifications, errors — declared in the threat model (ADR 0024) and invisible in
the journal. An auditor reading only the chain saw nothing where the guard had
read nothing, and could not tell that from a session in which nothing crossed.

## Decision

**The payload walk names what it leaves out.** `payload.derive()` returns the
readable text *and* one sentence per binary block it did not derive text from: a
content block whose `type` is `image` or `audio` (its `data`), and a resource
carrying `blob` — embedded, or returned by `resources/read`. The block's other
fields (media type, URI, name) are text and are read. `leaves()` and
`redact_payload()` skip the same strings, so the offsets and the masking cannot
drift, and a binary block is copied through untouched.

**The core accepts the caller's blind spots.** `decide(..., blind_spots=())`
takes those sentences and aggregates them exactly like a detector's declared
limit: a finding dominates them; otherwise the verdict is `CannotSay` with
cause `DECLARED`. `Guard.verdict`, `check` and `check_egress` pass them through.
The relay hands them over for every payload it inspects — a `tools/call`'s
arguments, a guarded result, a server's `sampling/createMessage`, whose
messages may carry images.

**Every admitted detector runs a readability screen after its rules found
nothing** (`limes.detectors.readability`), and raises `DetectorBlind` — a
declared limit — when:

- **most of the content is opaque encoded runs**: runs of the base64 /
  base64url / hex alphabet at least 100 characters long carrying both a digit
  and a letter cover at least half of a content at least 200 characters long.
  A git SHA-1, a sha256, a UUID and a JWT segment sit below the run length; a
  run of letters alone (a DNA fragment, a placeholder) or digits alone (a
  number the shape rules already read) does not count;
- **an invisible format character is wedged inside a word or a number**: a
  character of Unicode category `Cf` whose neighbours are both alphanumeric, at
  least one of them ASCII — so an emoji sequence keeps its joiners and a
  Persian word keeps its non-joiners. The **soft hyphen is excepted**: extracted
  web text carries hyphenation hints inside ordinary words, and blocking every
  scraped page would teach the operator to switch the guard off. A directive
  split with a soft hyphen is therefore a documented miss, stated here rather
  than found later;
- for a **word-reading** detector only (`injection`, `injection-egress`): at
  least half of at least 40 letters are outside the Latin script, or the caller
  declared a `locale` whose language the policy does not list under `locales`.
  The shape-reading detectors (`pii-egress`, `secrets-egress`) skip this part: a
  card number has no language, and the PII rules find one under Cyrillic prose.

The screen runs **after** the rules so that a finding always dominates: a key
inside a base64 dump is a key found, a directive in an English sentence under
Cyrillic prose is a directive found. Every measure is one linear pass.

**The policies declare their languages.** `policy.yaml` and the
`injection-egress` block of `egress.yaml` declare `locales: [fr, de, en]`; the
key is optional and read by one function both loaders share. A caller that
declares a locale the policy does not list gets a blind spot rather than a
"clean" the rules could not have earned. `None` declares nothing, and nothing
is inferred from it.

**The relay declares on the chain what it forwards unread.** The first time
each kind of uninspected message crosses in a session — keyed by direction and
method, with a peer's responses and errors under `(response)` and `(error)` —
the relay appends a `CannotSay` with cause `DECLARED` and disposition `forward`
and emits it to the journal like any record. It is a declaration, not a ruling:
the message is forwarded by design, so it does not pass through `rule()`, and
the blind spot says so in words. The set is bounded (`DECLARED_METHODS_LIMIT`,
64 kinds); a peer inventing method names without end gets a line on stderr
rather than a ledger that grows with its vocabulary. An outbound leg with no
detector wired declares the same way, per kind of response, which is how ADR
0027's pass-through stops being silent.

## Consequences

- **A tool result carrying an image is blocked by default.** That is the
  fail-closed doctrine applied to content the guard was pretending to read. An
  operator whose tools return screenshots accepts it knowingly with
  `on_cannot_say: allow`, which since ADR 0026 opens exactly the declared kind
  and nothing else; the record still says the image was not inspected. The
  README says this loudly, because it is the one behaviour change here that an
  ordinary deployment will meet on day one — a file-reading tool that returns
  base64 meets the opaque-run screen the same way.
- No published matrix number moves. Every harness counted `Deny` only; a vector
  that is now `CannotSay` was "not blocked" before and is "not blocked" now.
  The external secrets bench, which calls the detectors directly, now treats a
  declared blind spot as neither a hit nor a kill and **names** the vectors it
  happens to (eight gitleaks vectors that are mostly one long token), so the
  number is read with them.
- The journal of a proxy session now begins with the declaration that
  `initialize` crossed unread, and carries one line per kind of message the
  guard never read. Counts in three end-to-end tests that pinned "N decisions"
  became shape assertions that separate decisions from declarations.
- `Context.locale` finally does something, and only when a caller sets it.
- Three ratchets hold all of this
  (`tests/unit/ratchets/test_the_guard_says_what_it_cannot_read.py` and its
  two siblings), each seen red under a named mutation of the new code before
  this record was written.
