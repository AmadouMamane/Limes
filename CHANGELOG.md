# Changelog

All notable changes to limes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); limes adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.1] - 2026-08-30

**Two documents still carried a version number, and one of them was already
wrong.** Found by looking at the rendered 0.9.0 page on TestPyPI rather than at
the source — which is the point of a rehearsal.

### Fixed

- `SECURITY.md` said "limes is pre-1.0 (v0.8, alpha)" in a 0.9.0 release. The
  previous fix had reset that counter from v0.1 to v0.8 instead of removing it.
  A policy document does not need to repeat a number the distribution metadata
  already carries, and every release would have had to remember to update it, so
  the number is gone: "limes is pre-1.0 and alpha."
- Two README headings named the release they described — `What's in the box
  (v0.8.0)` and `What limes does NOT do (v0.8)` — and were stale for the same
  reason. Both now describe the current state without dating it, with their table
  of contents anchors rewired. The remaining `(v0.1)`, `(v0.2)`, `(v0.5)` … in
  section titles are deliberate and stable: they say *when a capability landed*,
  which does not change.

0.9.0 was uploaded to TestPyPI as the release rehearsal and is not on PyPI. Its
number is spent, so the rehearsed artifact and the published one stay the same
thing — which is the whole reason to rehearse.

## [0.9.0] - 2026-08-30

**The release audit, and the two amendments it forced.** Nothing on the decision
path changed: `decide`, the verdict algebra, the evidence chain and all four
detectors are byte-identical. What changed is what the package *claimed* about
itself, what its CI was actually able to check, and — under two new ADRs — the
one attribute a published library must have and the rule its own ratchets must
obey. Every finding below was measured on the artifact or on the running CI,
never inferred.

The minor bump rather than a patch is `limes.__version__`: a name added to the
public surface is a minor, and this project does not round its own numbers down.

### Fixed

- **`pyyaml>=6.0` named a version nobody could install.** PyYAML 6.0 publishes no
  wheel for cp312, cp313 or cp314, so on every Python limes supports it fell back
  to its sdist — and that build dies under Cython 3 (`'build_ext' object has no
  attribute 'cython_sources'`). `uv pip install --resolution lowest limes` simply
  failed. The floor is now `>=6.0.1`, the first release that installs and runs on
  3.12, 3.13 and 3.14 — measured on all three. Still exactly one runtime
  dependency.
- **CI had been red on every push since v0.1, and the badge said so where nobody
  read it.** `actions/checkout` fetches depth 1 by default, and
  `tests/unit/test_frontier.py` compares today's bytes against the v0.1 commit
  read out of git history — which a shallow checkout cannot produce. 16 red runs;
  the one green run was v0.1 itself, where the comparison was trivially true. The
  gate was green locally the whole time, because a normal clone has the history.
  The checkout now fetches the full history, so the frontier ratchet actually runs
  where it was supposed to.
- **The package's own docstring predated three of its four detectors.**
  `limes/__init__.py` still said "Still not shipped: an egress detector … or any
  detector beyond `injection`" while shipping `pii-egress`, `secrets-egress` and
  `injection-egress` and declaring all four as entry points. That is what
  `help(limes)` printed. Prose only; the module's code is byte-identical, and the
  ratchet asserts it.
- **The security policy described a limes that has not existed since v0.2.**
  `SECURITY.md`'s scope said "limes v0.1 is an in-process guard with a single
  inbound injection detector … no MCP proxy, no PII or secrets detector, and no
  egress detection" — telling a security researcher that three transports and
  three detectors were out of scope. It now names what ships. (One half of this
  is not fixable in the repository: the document points reporters at GitHub's
  private vulnerability reporting, which is **disabled** on the repository, so
  the button it names does not exist. A maintainer has to enable it.)
- **Six README links pointed at repository-relative paths**, which resolve on
  GitHub and 404 on a PyPI project page (`LICENSE`, `docs/decisions/`,
  `CONTRIBUTING.md`, `CLA.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`). All absolute
  now. The diagram is pinned to a commit rather than to `main`: a PyPI description
  is frozen at upload, the image it fetches is not.

### Changed

- **A ratchet reports its own blind spot, and never an assertion its missing tool
  satisfies** (ADR 0015). The type-level ratchet asserted `returncode != 0` to
  mean "mypy rejected `Allow()`" — and `python -m mypy` exits non-zero when mypy
  is *not installed*, so the assertion was satisfied by mypy's own absence. Only
  a second assertion on the message text stood between that ratchet and a green
  over a hole. Presence is now resolved with `find_spec` before any exit code is
  read, and its absence is a named skip.
- **The frontier ratchet reports a blind spot instead of a verdict when it cannot
  see** (ADR 0026). `_git` already skipped when git could not answer; `_v0_1_bytes`
  asserted instead, which is why `pytest` from an unpacked sdist printed 27 reds
  that said nothing about the code — exactly what a downstream packager runs. Now:
  no history at all (an sdist ships none) declares itself unseen; a *truncated*
  history is a misconfiguration and gets one loud red naming the fix; and with the
  history present, a v0.1 object git refuses to produce is still red.
- **CI runs the whole gate on 3.12, 3.13 and 3.14.** `requires-python = ">=3.12"`
  was true — measured, 404 tests green on each — and had no witness. Those Pythons
  are now classifiers too.
- No `License :: OSI Approved ::` classifier: PEP 639 makes it mutually exclusive
  with the `license = "Apache-2.0"` expression, which is the authoritative one.

### Added

- **`limes.__version__`** (ADR 0014). A published library is asked its version by
  every bug report and by `SECURITY.md` itself, which wants "the affected version
  or commit" first. `limes --version` answered; `import limes; limes.__version__`
  raised `AttributeError`. It is now *read* from the installed distribution's
  metadata — the same single source the CLI reads, so the two cannot disagree and
  no version literal enters the source tree. From an uninstalled source tree it
  is `"0+unknown"`, a PEP 440 local version that sorts below every release: a
  blind spot named, not an exception escaping out of `import limes`.
- `.github/workflows/release.yml` — build and publish by Trusted Publishing
  (OIDC), so no long-lived token exists on any machine. It re-runs the full gate
  on the tag rather than trusting that the commit was green when it landed, and
  refuses to publish when the tag and `pyproject.toml` name different versions.
- **A pin must record what the code determines, never what an interpreter
  renders.** The first implementation of ADR 0014's code pin was a sha256 of
  `ast.dump(...)`; the CI matrix introduced in this same release killed it on its
  first run — `ast.dump` is a debugging representation that gains fields between
  CPython releases, so the pin was green on 3.12 and red on 3.13 and 3.14 over a
  byte-identical file. The constant now holds the authorised code itself, parsed
  on both sides by the same interpreter and compared as a multiset. A single-
  Python CI would have carried that silently to the first user on 3.13.
- Three decision records: **ADR 0014** (the package names its own version, from
  the one place it is written), **ADR 0015** (a ratchet reports its own blind
  spot), and **ADR 0016** (Apache-2.0 throughout — ADR 0004 left its licence
  split as an explicitly unratified *lean*, "before any publication", and
  publication is now the thing happening; a distribution declares its licence
  once, and the wheel ships the corpus). ADRs 0001-0004 are untouched: per
  ADR 0001 the founding contract is superseded by a new record, never rewritten.
- `.gitleaks.toml` — the eleven findings on this repository are all synthetic
  detection material, verified one by one; they are exempted file by file, with
  what each holds, and never by a wildcard over `tests/`. A real key in a new test
  still rings (checked by mutation).

## [0.8.0] - 2026-08-28

**A fourth detector closes the third corner: instructions arriving on the way
out.** The proxy inspected inbound tool calls for injection and outbound results
for data leaving; it did not inspect outbound content for injection *arriving* —
the corner tool poisoning and indirect injection live in.

### Added — `injection-egress`

- Poisoned tool descriptions (`tools/list`) and indirect injection in tool
  results, on the server→host leg. Four rule categories — attack-marker tags
  (case-sensitive), override directives (fr/de/en + embedded `SYSTEM:`),
  concealment, exfiltration (a directive verb within reach of a named sensitive
  source). Rules are data in `egress.yaml` like every other detector.
- **16/16 located, 1/14 benign killed, F1 0.97** over the synthetic corpus, per
  category: hidden_tag 3/3, override 5/5, concealment 4/4, exfiltration 4/4. The
  one false positive is a security article quoting the attack string (mention vs
  use), published with its cause (ADR 0003). Dated matrix:
  `eval/matrices/injection_egress.md`. No baseline ships elsewhere; the null
  control is the baseline.
- `tools/list` joins the outbound seam's guarded methods (ADR 0012): a poisoned
  listing is refused before the model reads it, on the chain; a clean listing
  crosses untouched; a deployment with no outbound detector keeps exact
  pass-through. Proven by two relay tests and the existing e2e suite.

### Added — ADR 0013 (frame only)

- A measured classifier layer for inbound injection is framed as an optional
  `limes[ml]` extra, admission-gated, core dependency count unchanged. It ships
  only when its two numbers earn admission — authorised, not presumed. No code
  yet.

### Changed

- The proxy's "faithful pass-through" now excludes `tools/list` when an egress
  detector is wired. The inbound detector's residual-miss list reframes
  `42_email_zeroclick` from "future work" to "caught outbound by
  injection-egress".

## [0.7.0] - 2026-08-28

**The one honest limit of v0.5/v0.6 is closed: a crash is not a verdict.**

### Fixed

- `limes.guard.decide` no longer raises `UnicodeEncodeError` on content carrying
  unpaired surrogates. The content digest is total over `str` (ADR 0011,
  `surrogatepass`), so the detector's refusal to guess — already correct since
  v0.5 — now reaches the caller as `CannotSay`, which the egress leg turns into
  **block**. On every string that encodes to UTF-8 the digest is byte-identical
  to before, so ledgers keep their hashes.

### Changed

- The frontier ratchet pins `guard.py` to the sha256 of its post-ADR bytes
  instead of byte-identity to v0.1 — the single authorised amendment, recorded
  in `AMENDED` with two guards: an entry must name a core file and that file
  must actually differ from v0.1. Every other core file remains pinned to v0.1.
- The tests that pinned the crash now pin the verdict, in the same file.

## [0.6.0] - 2026-07-24

**Two detectors became three, and the README's "1 detector" is now honestly
"3".** `secrets-egress` completes the outbound leg: personal data was v0.5, and
credentials are what actually ends a company's week.

### Added — `secrets-egress`

- **Prefixed API keys** (AWS `AKIA`/`ASIA`… , OpenAI `sk-`/`sk-proj-`, GitHub
  `gh[pousr]_`, Stripe `[sr]k_(live|test)_`, Google `AIza`, Slack `xox[baprse]-`),
  **PEM private-key blocks**, and **JWTs**. Rules are data in
  `src/limes/detectors/egress.yaml` like every other rule.
- **15/15 located, 0/20 benign killed, F1 1.00** over the synthetic corpus, per
  category: AWS 2/2, OpenAI 2/2, GitHub 2/2, Stripe 2/2, Google 1/1, Slack 2/2,
  PEM 2/2, JWT 2/2. Dated matrix: `eval/matrices/secrets_egress.md`.
- **No baseline, and the report says so.** Tessera's guard policy declares
  `tools`, `prompt_injection` and `pii` and nothing else — checked, not assumed —
  so nothing comparable ships elsewhere and the **null control is the baseline**.
  A test asserts that exactly one of the two egress detectors has a ported
  baseline, so neither an invented comparison nor a silently dropped one passes.
- **A PEM finding spans the whole block**, never the armour line: a finding that
  located only `-----BEGIN … PRIVATE KEY-----` would be masked to exactly that and
  would forward the key material underneath it. An unterminated block swallows to
  the end of the content. `CERTIFICATE` and `PUBLIC KEY` armour is not matched.
- **A JWT is decided by its header, not its shape.** Three dot-separated
  base64url segments is also `limes.detectors.egress_policy`, `backup.tar.gz` and
  `1.2.3`; the claim is entirely that the first segment decodes to a JSON object
  declaring `alg`.
- **End to end over stdio and HTTP**: one policy file, two dispositions —
  `pii: redact` keeps the answer with the card masked, `secret: block` loses the
  answer rather than let a key leave — each with its unproxied control run.

### Not added, deliberately — generic high-entropy scanning

A UUID, a git digest, a `sha256:` image pin and a base64 blob are all
high-entropy and none is a secret. An entropy rule with no context is a
false-positive generator that teaches its operator to switch the detector off, so
it is **deferred** and all of those live in the benign corpus as lookalikes
instead. The consequence — an *unprefixed* credential (AWS secret access key,
database password, bare bearer token) is not detected — is a declared blind spot
with a test pinning it, stated in the README rather than implied away.

### Changed — the enforcers grew with the second detector

- ADR 0009's corpus rules now cover both corpora, plus one the secrets corpus
  needs: every credential-shaped string must visibly say `EXAMPLE` (or be AWS's
  own published documentation key), and every PEM body must base64-decode to
  placeholder text. A contributor pasting the value that caused a bug is the
  failure mode; this is what stops it being a live key in a public repository.
- The frontier ratchet gained an **anti-phantom** check: a perimeter entry naming
  a path that exists neither at v0.1 nor on disk now fails, because such an entry
  reads as "covered" and covers nothing (ADR 0026). One had already crept in
  while writing this release, and this is what found it.

### The ratchets, seen red

27 deliberate mutations, each **asserted to have actually applied** before its
verdict was believed — a mutation that silently fails to apply runs the test on
the original tree and reports green, which is "I did not look" wearing the
costume of "nothing is wrong". That happened once during this work and is why the
check exists. All 27 red: 13 core files by byte identity, three perimeter
widenings, three registry mutations, three corpus-rule violations, three detector
validators removed, the grader's own located-span test, and a new file outside
every perimeter.

### Unchanged — the core still did not grow

Byte-identical to v0.1 (`86bf21dd`). `pip install limes` still has exactly one
dependency.

## [0.5.0] - 2026-07-24

**One detector became two.** v0.4 shipped the outbound machinery and nobody to
feed it: limes knew how to mask a finding and produced none, so "egress
redaction" masked nothing out of the box and every end-to-end proof used a test
double. `pii-egress` closes that. It is admitted the same way `injection` was,
and the admission — not the regex — is the work (ADR 0003).

### Added — `pii-egress`, the first outbound detector

- **Five fixed categories, each gated by arithmetic**: PAN (ISO/IEC 7812 Luhn),
  IBAN (ISO 13616 MOD 97-10), e-mail, telephone (FR / DE / E.164, digit count in
  range), NIR (control key `97 − (body mod 97)`, with Corsica's `2A`/`2B`
  substituted). The shapes are **data** — `src/limes/detectors/egress.yaml` — and
  each rule *names* its check from a closed registry; an unknown validator is a
  load error, never a rule that matches a shape and vouches for nothing
  (ADR 0004).
- **Measured against the null control and against Tessera's shipping output
  guard**, over the same corpus with the same grader: limes locates **32/32**
  where the ported `apply_output_guard` baseline locates 21/32, and kills **1/26**
  benign lookalikes where the baseline kills 15/26. Per category, all five at
  full recall. Dated matrix: `eval/matrices/pii_egress.md`, via `make eval`.
- **The grader reads offsets, not text.** A positive case declares the exact
  substring that must be spanned, and a finding counts only when its
  `[start, end)` reproduces it there. `block-everything` is therefore *flagged* on
  32/32 and *located* on 0/32 — no token a case handed the detector can pass for
  evidence that the detector found something.
- **A benign corpus of lookalikes** is half the corpus: 16-digit order references
  failing Luhn, IBAN-shaped internal identifiers failing MOD 97-10, truncated
  addresses, dates, versions, UUIDs, git digests, NIRs with a wrong key. It is
  what measures precision, and it is the half that is tempting to skip.
- **The one false positive is published with its cause and its refused fix**:
  `pii:pan` fires on eighteen digits inside an IBAN-shaped reference that pass
  Luhn by coincidence. Suppressing PAN candidates behind an IBAN head would fix
  it and would let a real card hide behind `DE12 ` — the wrong trade for a guard.
- **`retry_trim`**: a candidate that fails its check may be retried after dropping
  its trailing group, because prose runs an IBAN into the next word
  (`…0130 00 EUR`). It can only ever shorten, and every shortened candidate must
  pass the same check.
- **Fail-closed, with a declared budget.** Beyond `max_content_chars` (200 000)
  the detector raises `DetectorBlind`, the core answers `CannotSay`, and the
  egress leg blocks. An unbounded sweep over an unbounded tool result is a
  denial-of-service surface; "I stopped looking" is auditable data, not silence.
- **End to end, over stdio *and* HTTP**, against real processes, each with the
  unproxied control run that shows the server does return the card in the clear
  (`tests/integration/egress/test_pii_egress_e2e.py`). The masked bytes are
  identical over both transports.
- **Zero raw value in any record.** A test sweeps the entire corpus through the
  verdict fingerprint, the chain record, the redaction annotation and the JSONL a
  proxy actually writes, and asserts the values appear in none of them.

### Added — ADR 0009: the egress corpus is synthetic, admission is per category

- Every value is synthetic **by construction**: published processor test PANs,
  documentation IBANs, RFC 2606 reserved domains, phone ranges reserved for
  fiction, NIR keys recomputed over fictional identities. Enforced by the
  *loader* (a file may only declare `provenance: synthetic`) and by tests that
  refuse any Luhn-valid number that is not a published test vector and any
  address off a reserved domain.

### Changed — the admission enforcer, and the frontier ratchet

- `tests/unit/test_admission_rule.py` no longer asserts "there is exactly one
  detector" — which said nothing about a *second* one being measured. It now
  iterates `ADMITTED` and refuses any member whose positive corpus, benign
  corpus, beaten null control or published matrix it cannot produce. A detector
  added to the tuple without a corpus turns it red, naming the detector.
- The frontier ratchet grew from one perimeter to **three** — transports,
  detectors, admission surface — because ADR 0004 names three places a capability
  may land. The anti-widening check now polices all three: adding
  `src/limes/detectors/` to the detector perimeter to silence a red would turn
  the anti-widening test red instead, naming `injection.py` and its policy. The
  registry itself is held to a stronger witness than byte-identity: it may gain
  an import and a tuple entry and **nothing else** — no branch, no call, no
  function — so no detector can ever be registered conditionally.
- `make eval` now writes every admitted detector's matrix, not just the first.

### Unchanged — the core still did not grow

The verdict algebra, the ledger, the detector protocol, the pipeline, the
`injection` detector, its policy and its harness are **byte-identical to v0.1**
(`86bf21dd`), and the ratchet was seen red under eight deliberate mutations
before being believed green. `pip install limes` still has exactly one
dependency: the detector is rules plus arithmetic, and cost nothing.

### Known limitation, found by this work

`limes.guard.decide` hashes the inspected content *after* running the detectors,
so content carrying unpaired surrogates raises `UnicodeEncodeError` before the
detector's blind spot can be rendered as `CannotSay`. It fails loudly and never
open — nothing is forwarded — but it is a crash rather than a verdict. Fixing it
means editing the core, which ADR 0004 does not allow from a detector. Pinned by
a test rather than left to be rediscovered.

## [0.4.0] - 2026-07-24

The first tagged version. Nothing was published before, so the whole surface —
three transports, one detector, egress redaction with mask styles, and the CLI —
arrives as 0.4.0. Pre-1.0 by choice: the surface is complete, the field use that
earns a 1.0 is not.

### Added — the command-line surface: `limes check`

- **A third way to use limes**, after the library and the proxy: `limes check
  [--policy P] [--direction inbound|outbound] [--json] [FILE|-]` runs the same
  pipeline over a file or stdin, no server. **The exit code is the verdict** (0
  allow, 1 deny, 3 cannot-say), so a CI step gates on it. `--json` emits the
  canonical verdict fingerprint plus the chain record — no new evidence format.
  `limes` becomes a dispatcher (`check` | `proxy` | `proxy-http`) that keeps
  `check` free of the `mcp` extra.

### Added — the third transport: MCP Streamable HTTP (ADR 0007)

- **The same guard on the other wire MCP runs on.** `limes proxy-http --upstream
  URL --port N` speaks MCP Streamable HTTP to host and server; the relay between
  is the *same* one the stdio proxy runs — same verdict, evidence, chain,
  redaction. Only the plumbing is new, and most of it is the SDK's session
  manager. Proven transparent, blocking, redacting and replayable against real
  processes. `pip install 'limes[http]'` pins the ASGI server.
- **Measured overhead**, never asserted: median ~3.3–3.9 ms per guarded
  `tools/call` — more than stdio's ~0.6 ms, a second HTTP round trip to the
  upstream. `uv run python -m limes.transports.mcp.bench_http`.

### Added — mask styles for egress redaction (ADR 0008)

- **Per-kind rendering of a masked region**, in the policy: `mask_style: { pii:
  last4 }`. `full` (the default, unchanged), `last4` (`••••4242`, the PCI-DSS
  convention; a value of four characters or fewer reveals nothing),
  `format_preserving` (keep the shape, replace the content). Every style is
  verified by re-derivation — the transport confirms the sensitive value is gone
  and blocks otherwise — and the style is recorded in the evidence, never the
  masked bytes. Deterministic masks only: no reversible tokenisation, no
  format-preserving encryption.

### Unchanged — the core still did not grow

- The verdict algebra, the ledger, the detector protocol, the pipeline, the
  `injection` detector and their tests are byte-identical to the v0.1 commit. The
  frontier ratchet asserts it, and a dedicated ratchet asserts the HTTP transport
  reuses the stdio relay rather than copying it. Every claim was seen red under a
  deliberate mutation.

### Added — v0.3, egress redaction (ADR 0006)

- **A transport behaviour, not a fourth verdict.** When a detector fires on the
  outbound leg, the transport blocks by default; under
  `on_egress_finding: redact` it overwrites the matched offsets with a fixed
  token and forwards the rest. Declared per kind (`pii: redact`,
  `secret: block`) in the policy file the transport already reads, or with
  `--on-egress-finding` for the default. Both transports honour it.
- **Nothing was added to the core.** Evidence has carried `start`/`end` for every
  match since v0.1; those are the coordinates the masker needs. No new field, no
  new verdict, no new detector.
- **A masked forward is a normal result** — a `CallToolResult` without
  `isError` — with `_meta.limes` naming what was masked, at which offsets, under
  which chain record, and never the masked text. The token `[REDACTED:<kind>]` is
  the in-band annotation an agent reads.
- **The chain still records a `Deny`.** Content that left masked is not recorded
  as allowed; the record's `mcp.action` reads `redact`.
- **The masking is verified before it is sent.** The sanitised payload is
  re-derived and compared to the plan applied to the flat content; a
  disagreement blocks, as do a refusal with no located span and offsets that do
  not fit the content. Nothing is clamped.
- **`serve(config, outbound=[...])`** lets an embedder install their own outbound
  detectors. The console entry point never passes any.

### Unchanged — the core still did not grow

- `tests/unit/test_frontier.py` (which supersedes `tests/unit/mcp/test_boundary.py`)
  asserts the core, the pipeline, the detectors and their tests are byte-identical
  to the v0.1 commit, *and* that the named core list is not covered by the
  transport allowlist — so widening the allowlist cannot buy silence. Six
  mutations were each seen red.

### Known limitation

- **limes still ships no egress detector**, so out of the box nothing is ever
  masked: ADR 0003 forbids shipping a detector without an eval corpus and a null
  control. The proofs use doubles that live in `tests/`. Told to mask with an
  empty outbound leg, the proxy says so on stderr.

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

### Not yet at v0.1 — see the later versions above and the README

- No MCP proxy (that arrives in v0.2, the adoption wedge), no HTTP transport and
  no CLI (both in the 0.4.0 line).
- No PII or secrets detector, no rate-limit, no kill-switch, no threat feed, no
  human-approval, no LLM-judge detector, no dashboard — most of these are scope,
  not backlog (see the README's "What limes does not do").
- The PyPI name `limes` was **verified available** on 2026-07-24
  (`pypi.org/simple/limes/` → 404). The name, GitHub org, CLA and the final
  license split remain Amadou's calls, pending before any publication.

[0.9.1]: https://github.com/AmadouMamane/Limes/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/AmadouMamane/Limes/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/AmadouMamane/Limes/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/AmadouMamane/Limes/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/AmadouMamane/Limes/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/AmadouMamane/Limes/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/AmadouMamane/Limes/releases/tag/v0.4.0
