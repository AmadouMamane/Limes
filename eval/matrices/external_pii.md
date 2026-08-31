# limes `pii-egress` — against document contexts it did not write

Generated 2026-08-31 from **presidio-research** (MIT, commit `70ff860bed29`, <https://github.com/data-privacy-stack/presidio-research>) — 42 sentence templates vendored by value into `eval/corpus/presidio/` (ADR 0021). limes does not depend on presidio-research; the corpus is a copy, reproducible with `scripts/vendor_presidio_corpus.py`.

**Strength of this number.** external contexts, author-cleared synthetic values — the DOCUMENTS are third-party, the VALUES are limes's own already-admitted vectors (ADR 0009 forbids any other kind). Strictly weaker than garak, where the attack itself is foreign. Labelled wherever published.

**Read both sides of every row.** A recall column alone is satisfied by blocking everything; a false-positive column alone is satisfied by blocking nothing. `block-everything` is on the table for exactly that reason.

| configuration | values located (dev) | values located (holdout) | matched control: checksum-invalid decoy | matched control: value removed | out-of-scope slots (declared) |
|---|---|---|---|---|---|
| unplugged (null control) | 0/185 (0.0%) | 0/104 (0.0%) | 0/289 (0.0%) | 0/39 (0.0%) | 0/5 (0.0%) |
| block-everything | 0/185 (0.0%) | 0/104 (0.0%) | 289/289 (100.0%) | 39/39 (100.0%) | 5/5 (100.0%) |
| tessera-pii baseline (apply_output_guard) | 137/185 (74.1%) | 79/104 (76.0%) | 171/289 (59.2%) | 0/39 (0.0%) | 0/5 (0.0%) |
| **limes pii-egress** | 185/185 (100.0%) | 104/104 (100.0%) | 6/289 (2.1%) | 0/39 (0.0%) | 0/5 (0.0%) |

- **values located** — the exact synthetic vector, at its own offsets, inside a third-party sentence. The *documents* are presidio-research's; the *values* are limes's own already-admitted ones, because ADR 0009 forbids any other kind.
- **checksum-invalid decoy** — the same sentence, the value replaced by a same-shape twin whose Luhn / MOD 97-10 / E.164 check fails. limes says its precision comes from the checksum; this column is where that claim is paid for.
- **value removed** — the same sentence with the value replaced by a neutral phrase. A detector firing here has learnt the sentence, not the value.
- **out-of-scope slots** — templates carrying `{{ssn}}`, `{{us_driver_license}}` or `{{ip_address}}`, which limes has never claimed. Measured so the perimeter is a number rather than a sentence.

## Per category

| category | located | decoys killed |
|---|---|---|
| **email** | 30/30 (100.0%) | 0 |
| **iban** | 27/27 (100.0%) | 6 |
| **pan** | 133/133 (100.0%) | 0 |
| **phone** | 99/99 (100.0%) | 0 |

## Where the misses are

- No template loses a value. Over 42 third-party sentence contexts, the detector's recall does not depend on the prose around the value — which is the claim this corpus exists to test, and the one it supports.

**Decoys killed:** 6. Named, not rounded away: `t012_iban_04_decoy`, `t012_iban_05_decoy`, `t028_iban_04_decoy`, `t028_iban_05_decoy`, `t036_iban_04_decoy`, `t036_iban_05_decoy`

## The two numbers

- **Values located (dev):** 185/185 (100.0%).
- **Values located (holdout):** 104/104 (100.0%).
- **matched control: checksum-invalid decoy:** 6/289 (2.1%) killed.
- **matched control: value removed:** 0/39 (0.0%) killed.
- **out-of-scope slots (declared):** 0/5 (0.0%) killed.
- **Power of the false-positive claim:** n=333, alpha=0.05, minimum detectable effect ~= 0.015 (of 333 benign inputs flipped (one-sided exact sign test)).

## The protocol

Split by **template**, never by materialised case: one template becomes as many cases as its category has vectors, so splitting the cases would put the same template on both sides and a rule written on `dev` would score on `holdout` by identity rather than by generalisation. A test asserts no template appears on both sides.

Splits scored here: `dev`, `holdout`.

