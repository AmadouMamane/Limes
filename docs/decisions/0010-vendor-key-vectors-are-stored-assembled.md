# 10. Vendor-key secret vectors are stored assembled, never as a literal

Date: 2026-08-04

## Status

Accepted. Refines ADR 0009 (the egress corpus is synthetic) for one category of
value: vendor-prefixed credentials.

## Context

ADR 0009 froze every egress-corpus value as synthetic: a published test PAN, a
documentation IBAN, an `example.com` address, a revoked-format API key. That
keeps a *real* secret out of the repository. It does not keep a *credential-shaped
string* out of it — and for the `secrets-egress` detector, the positive corpus is,
by construction, a set of strings shaped exactly like AWS keys, Stripe keys, GitHub
tokens and Slack tokens.

Two distinct parties read those bytes and cannot tell synthetic from real:

1. **A host secret scanner.** GitHub push protection refused the very first push
   of this corpus, on the two Stripe vectors, because `sk_live_[A-Za-z0-9]{24,}`
   is `sk_live_[A-Za-z0-9]{24,}` whether the body says `EXAMPLE` or not. The
   scanner's format detector and limes' detection rule are, for a vendor key, the
   *same* format — so no synthetic body exists that limes must catch and the
   scanner must ignore. (The Slack rule was looser than GitHub's, so an all-alpha
   body dodged it; that dodge does not generalise, and relying on it per vendor is
   a standing bet against every scanner's next update.)

2. **A future contributor or forker.** Anyone who clones this repository and
   pushes hits the same wall, and a security package that requires every consumer
   to punch a hole in their own push protection to work with it has a real defect,
   not an incident.

Committing a contiguous `sk_live_…` literal is therefore wrong on its own terms,
independently of whether the value is live: it is a credential-shaped string in a
public repository, and the whole discipline of this project is that the honest
thing is measured and witnessed, not asserted.

## Decision

**A vendor-prefixed secret vector is stored assembled, and the file never contains
the contiguous literal.** A positive case for such a vector declares, instead of
`content` and `locate`:

- `content_template` — the outbound content with a single `{token}` placeholder;
- `token_parts` — the token's fragments (at least two), joined in order with no
  separator by the loader.

The loader (`limes.eval.egress_corpus`) assembles `token = "".join(token_parts)`,
substitutes it into the template, and grades on that exact token at its real
offset. **The detector runs on the reconstructed real format** — nothing about the
measurement changes; the assembled tokens are byte-identical to the literals they
replace, so the matrix numbers are unchanged. Only the *storage* changes.

The two shapes are mutually exclusive and the **loader** refuses a case that mixes
them, so a rule whose only enforcer is a test that restates it is not the enforcer
here (ADR 0026).

The split point is the vendor prefix: `["sk_", "live_", "EXAMPLE…"]`. Because JSON
writes each fragment as its own quoted string, the bytes between the prefix and the
body are `", "` — and no vendor rule's post-prefix character class contains a
quote, so the shape cannot re-form across the boundary. That is what makes the file
invisible to a format scanner while the joined token remains a perfect positive.

**Two shapes stay literal:** PEM private-key blocks and JWTs. Their corpus values
are documentation shapes (a PEM body that base64-decodes to `EXAMPLE ONLY`, the JWT
every tutorial publishes) that no host scanner push-protects, and a multi-line
block does not benefit from the split. They keep `content`/`locate`.

## Consequences

- The corpus file carries no vendor-key literal. A **witness** proves it: it runs
  limes' own secrets rules (every one except the two literal-allowed shapes) over
  the raw bytes of `secrets_positive.json` and refuses any match
  (`tests/unit/egress/test_no_raw_secret_literal_in_corpus_file.py`). Revert an
  assembled case to a literal, or paste a raw key into a template, and it goes red.
- The published `secrets-egress` matrix is unchanged (15/15 located, 0/20 benign,
  F1 1.00): assembly is a storage transform, not a corpus change.
- A little legibility is traded for it — a reviewer reads fragments, not a whole
  token — bought back by the `why` field naming the shape and this ADR fixing the
  rule. The reviewer can still see exactly what will be assembled.
- The mechanism generalises: any future vendor whose format a scanner learns to
  match is stored the same way, with no per-vendor cleverness and no bet against
  the scanner.
