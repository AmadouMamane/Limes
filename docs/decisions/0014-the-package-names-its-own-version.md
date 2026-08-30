# 14. The package names its own version, from the one place it is written

Date: 2026-08-30

## Status

Accepted. Amends ADR 0004's frontier for exactly one file
(`src/limes/__init__.py`), and does so the way ADR 0011 did: by naming the
change, pinning its result, and leaving every other core file where it was.

## Context

limes is being published. From the day it is on an index, the first question
asked of it is *which version is this?* — by every bug report, by every
dependency audit, and above all by `SECURITY.md`, which asks a reporter for "the
affected version or commit" before it asks for anything else.

The command line answers that question: `limes --version` and `limes-proxy
--version` both read `importlib.metadata.version("limes")`. The library does
not:

```python
>>> import limes; limes.__version__
AttributeError: module 'limes' has no attribute '__version__'
```

That is the form the answer is asked for in practice — a maintainer triaging a
report asks the reporter to paste `limes.__version__`, not to find a shell with
the console script on its PATH. A library that cannot say its own name and
number makes the reporter guess, and a guessed version in a security advisory is
worse than no version.

Adding it is not free, and that is the point of this record. `src/limes/__init__.py`
sits in the frontier ratchet's `DOCSTRING_ONLY` list: its prose may be corrected
— it had to be, twice — but its **code** is asserted byte-for-byte identical to
v0.1, through the AST. ADR 0004 forbids a quiet edit to the core, and correctly:
the debt stayed open for exactly that reason rather than because anybody judged
the missing attribute acceptable. This ADR is the authorisation.

## Decision

**`limes.__version__` exists, and it is *read*, never written.**

```python
try:
    __version__ = version("limes")
except PackageNotFoundError:
    __version__ = "0+unknown"
```

Three properties, each load-bearing:

- **One source.** The value comes from the installed distribution's metadata —
  the same source `limes --version` already reads. No version literal enters the
  source tree; `pyproject.toml` remains the only place the number is written, so
  `limes.__version__` and `limes --version` cannot disagree, and neither can go
  stale against the wheel a user actually installed. A second literal would have
  been a second source, and this project has already paid for one of those.
- **It does not raise.** Imported from a source tree that is not an installed
  distribution, `importlib.metadata` raises `PackageNotFoundError`. Letting that
  escape would make `import limes` fail because the package could not name
  itself — a crash where a blind spot is the honest answer, which is ADR 0011's
  lesson applied one layer out. The fallback is `"0+unknown"`: a valid PEP 440
  local version that sorts below every release and cannot be misread as one.
- **It is not the core growing.** No capability, no dependency
  (`importlib.metadata` is standard library, so `pip install limes` still pulls
  exactly PyYAML), no branch on the decision path, and nothing added to the
  verdict algebra. `decide`, `Verdict`, `Evidence`, `DecisionRecord` and the
  `Detector` protocol are untouched, and `__all__` is unchanged. What the module
  gained is the ability to state which build of itself is answering — the one
  thing a plugin, a policy or a transport cannot supply on its behalf.

**The frontier keeps its ratchet, with one named delta.**
`src/limes/__init__.py` stays in `DOCSTRING_ONLY` — its prose must remain free to
be corrected, which is the whole reason that list exists — and its **code** is
held in `tests/unit/test_frontier.py` to *v0.1's statements plus the authorised
ones*, recorded in `DECLARED_CODE_DELTA` beside a reference to this ADR. The
constant holds the authorised code **itself**, not a hash of it, so a reader sees
what was permitted without leaving the file. Any statement added, removed or
edited beyond it is red, exactly as before; what moved is the reference, once,
with its authorisation written down.

The first implementation of that pin was a sha256 of `ast.dump(...)`, and the CI
matrix this release also introduced killed it on its first run: `ast.dump` is a
debugging representation, not a stable format — it gains fields between CPython
releases — so the pin was **green on 3.12 and red on 3.13 and 3.14 over a
byte-identical file**. A witness must not record a value that depends on the
interpreter reading it; it reports on the interpreter instead of on the code.
The check now parses both sides in the same process, which is precisely why the
older docstring comparison never had the problem, and compares them as a
multiset — a reformatting is not drift, an edit is.

`DECLARED_CODE_DELTA` carries the same two guards `AMENDED` carries, for the same
reason: an entry must name a file the ratchet already treats as prose-only, and
that file's code must genuinely differ from v0.1. An entry violating the first
would be a perimeter by another name; one violating the second would be a phantom
nobody can audit (ADR 0026 of Tessera, inherited). A third guard is specific to
holding code rather than a digest: a delta that parses to no statement at all is
refused, since it would read as an authorisation while authorising nothing.

## Consequences

- `limes.__version__` and `limes --version` report the same string, always,
  because they read the same metadata.
- A security report can carry an exact version without the reporter guessing,
  which is what `SECURITY.md` asks for.
- From an uninstalled source tree the attribute reads `"0+unknown"` rather than
  raising. That string is deliberately not a version anybody could ship: if it
  ever appears in a bug report, the report is about a checkout, not a release.
- One more pinned constant in the frontier ratchet. The cost is that a future
  code change to `src/limes/__init__.py` must be declared there deliberately —
  which is the intended cost, not a side effect.
- A rule this ADR paid for and leaves behind: **a pin records something the code
  determines, never something an interpreter renders.** The CI matrix found it in
  one run; a single-Python CI would have carried it silently to the first user on
  3.13.
