# 9. The egress corpus is synthetic, and admission is per category

Date: 2026-07-24

## Status

Accepted.

## Context

ADR 0003 says no detector lands without a positive corpus, a benign corpus, a
null control and a published matrix. For `injection` that was safe: an attack
prompt is a sentence somebody wrote, and publishing it is the point.

An **egress** detector inverts the problem. Its positive corpus is, by
definition, a set of card numbers, IBANs, e-mail addresses, social-security
numbers and API keys. A corpus of *real* ones would be a data breach committed
by the security tool, in a public repository, for ever — and it would be
committed by exactly the well-meaning act of reproducing a bug with the value
that caused it.

There is a second, quieter problem. A single F1 over five categories hides which
one is broken. A PII detector at 0.90 that finds every e-mail and no IBAN is not
a detector at 0.90; it is a working e-mail rule shipped next to a dead IBAN rule,
and the aggregate is what let it ship.

## Decision

**Every value in an egress corpus is synthetic by construction.** Not
"anonymised", not "from a staging environment" — synthetic:

| category | what a positive case may carry |
|---|---|
| card number | a published processor test PAN (`4242…`, `4111…`, Amex `3782…`) |
| IBAN | an ECBS / national documentation example |
| e-mail | an RFC 2606 reserved domain (`example.com`, `example.org`, …) |
| telephone | a range reserved for fiction (`+1 202 555 01xx`, Ofcom `020 7946 0xxx`) |
| NIR | a fictional identity whose control key was **recomputed**, never observed |
| API key | a documentation or revoked key **format** (`AKIAIOSFODNN7EXAMPLE`) |
| private key | the PEM armour, with no usable key material |
| JWT | a self-signed token over fictional claims |

This costs nothing, because what is being measured is the detection of a
**shape and its checksum** — and a checksum does not know whether the account
exists. It prevents a whole class of accident.

**The rule is enforced, not documented.** Three enforcers, because a constraint
whose only witness is this page is a decoration:

1. every corpus file declares `"provenance": "synthetic"`, and the *loader*
   refuses any other value (`limes/eval/egress_corpus.py`) — asked of the loader,
   not restated in a test (ADR 0026);
2. `tests/unit/egress/test_corpus_is_synthetic.py` refuses any Luhn-valid card
   number that is not one of the published test vectors, and any e-mail address
   not on a reserved domain;
3. the same file refuses a case with no stated `why` — a vector with no recorded
   origin is a vector nobody can confirm is synthetic.

**Admission is per category.** Each egress detector publishes recall *per
category* alongside the aggregate, and each benign lookalike declares the
category it `mimics`, so a false positive is attributed to the rule whose
precision it cost. A category with no positive cases and no lookalikes is not
admitted, and therefore is not claimed.

**The grader reads offsets, not text.** A positive case declares the exact
substring that must be spanned; a finding counts only when its `[start, end)`
reproduces that substring at that offset. This is the egress form of ADR 0003's
corrected-grader rule: no token the case handed the detector may be mistaken for
evidence that the detector found something. Its teeth are visible in every
matrix — `block-everything` is *flagged* on 100 % of cases and *located* on 0 %.

## Consequences

- The corpus can be published, forked and quoted in an issue without a legal
  review. That is what makes it able to grow adversarially, which ADR 0003
  requires of it.
- limes cannot claim detection of anything that has no synthetic vector. Free-text
  names, postal addresses and dates of birth are therefore **not** claimed: not
  because they do not matter, but because nothing here would measure them.
- A category is exactly as real as its two numbers. The per-category table is the
  place a reader finds out which ones are, and the "what still fails, and why"
  section is where the misses are named with their cause rather than rounded away.
- The residual false positives are published with **what actually fired, on which
  bytes**, generated from the detector rather than transcribed — so the matrix
  stays true when the rules change.
