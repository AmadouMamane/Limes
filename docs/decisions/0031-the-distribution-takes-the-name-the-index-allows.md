# 31. The distribution takes the name the index allows

Date: 2026-10-15

## Status

Accepted. Amends ADR 0014's one declared code delta in `src/limes/__init__.py`
— the distribution whose metadata names the build — and re-declares it in
`tests/unit/test_frontier.py` with the new literal beside a reference to this
record, which is ADR 0014's own rule for moving it. Nothing else in the core
moves.

## Context

Everything in this project was called `limes`: the import, the console script,
the entry-point group, the distribution. On 2026-10-15 the first upload to PyPI
was refused on the last of those:

```
400 The name 'limes' isn't allowed.
See https://pypi.org/help/#project-name for more information.
```

That is PyPI's third kind of unavailable name. Not registered by someone else
(PEP 541 would apply), not too close to an existing one, but *explicitly
prohibited by the administrators*. The index answers `404` for such a name
exactly as it does for a free one, which is what the pre-release check of
2026-07-24 read as "available" (CHANGELOG, 0.1.0): a `404` says nobody has the
name, not that anybody may have it. TestPyPI keeps its own list, so the 0.13.0
rehearsal there proved nothing about PyPI. The release workflow had already
run the gate on the tag and built the artifacts; the refusal came from the
index, after everything this repository can check was green.

Two ways out. Ask the administrators to release the name: days or weeks, no
guarantee, and a project nobody can install meanwhile. Or rename the
distribution, and only the distribution.

## Decision

**The distribution is `limes-guard`. Everything else keeps its name.**

| Surface | Name | Moves? |
|---|---|---|
| distribution: `pip install …` and its extras | `limes-guard`, `limes-guard[mcp]`, `limes-guard[http]` | yes |
| import | `limes` | no |
| console scripts | `limes`, `limes-proxy` | no |
| entry-point group (ADR 0004) | `limes.detectors` | no |
| policies, their hashes, the verdict algebra | — | no |

The one place the *code* names the distribution is ADR 0014's lookup,
`importlib.metadata.version("limes")`: once in `src/limes/__init__.py`, once
behind each `--version` flag. It now reads `version("limes-guard")`. The string
names the distribution, not the package, and the distribution is what changed.

A lookup through `importlib.metadata.packages_distributions()` would have
avoided the literal. It would also have made the package's version depend on
whichever distribution happens to provide `limes` on `sys.path`, and a version
that can name a build other than the one it ships is the drift ADR 0014 exists
to prevent. The literal stays; it is the distribution's name, written once more
than before, in the one module that is allowed to say it.

**0.17.0 stays tagged as it is.** The tag names a tree whose metadata says
`limes`; publishing a different tree under that number is the traceability
failure the release workflow was built to refuse ("the tag and the version must
be the same number"). The renamed tree is 0.17.1, and 0.17.1 is the first
version on PyPI.

## Consequences

- `pip install limes-guard` installs `import limes`. The README says so once,
  beside the install block; the install hints in the CLI's error messages say
  `limes-guard[mcp]` and `limes-guard[http]`; past ADRs and changelog entries
  keep the name they were written with, because a record is not edited in place
  (ADR 0001).
- A user who types `pip install limes` gets whatever PyPI's prohibition returns,
  never this project. Nothing can be done about that from here.
- ADR 0014's claim holds unchanged: one source for the version, read from the
  installed distribution's metadata. The metadata merely belongs to a
  distribution with a different name. `limes.__version__`, `limes --version` and
  `limes-proxy --version` still cannot disagree.
- Should the administrators ever release `limes`, taking it would be a second
  rename for no capability. The name stays `limes-guard`.
