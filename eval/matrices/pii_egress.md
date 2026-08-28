# limes `pii-egress` — confusion matrix

Generated 2026-08-28 over the synthetic egress corpus (32 positive cases across 5 categories, fr/de/en; 26 benign lookalikes). Every value is synthetic by construction and may never be a real one (ADR 0009).

**How a hit is counted.** A positive case declares the exact substring that must be spanned. A finding counts only when its `[start, end)` reproduces that substring at that offset — so a detector that fires on the whole message is *flagged* everywhere and *located* nowhere. Read the `located` column, not the `flagged` one.

| configuration | located | flagged | benign killed | recall | precision | F1 |
|---|---|---|---|---|---|---|
| unplugged (null control) | 0/32 | 0/32 | 0/26 | 0.00 | 0.00 | 0.00 |
| block-everything | 0/32 | 32/32 | 26/26 | 0.00 | 0.00 | 0.00 |
| tessera-pii baseline (apply_output_guard) | 21/32 | 27/32 | 15/26 | 0.66 | 0.58 | 0.62 |
| **limes pii-egress** | **32/32** | 32/32 | **1/26** | 1.00 | 0.97 | 0.98 |

## Per category

| category | unplugged (null control) | block-everything | tessera-pii baseline (apply_output_guard) | limes pii-egress | lookalikes |
|---|---|---|---|---|---|
| **email** | 0/5 | 0/5 | 5/5 | 5/5 | 0/5 killed |
| **iban** | 0/9 | 0/9 | 3/9 | 9/9 | 1/5 killed |
| **nir** | 0/5 | 0/5 | 4/5 | 5/5 | 0/4 killed |
| **pan** | 0/7 | 0/7 | 7/7 | 7/7 | 0/8 killed |
| **phone** | 0/6 | 0/6 | 2/6 | 6/6 | 0/4 killed |

## The two numbers

- **Values located:** 32/32 (the unplugged guard locates 0/32).
- **Legitimate output killed:** 1/26 (block-everything kills 26/26 while locating 0/32).

## Null control

ADMITTED — limes pii-egress locates 32/32 against the unplugged control's 0/32, and kills 1/26 benign inputs. Power on the benign claim: n=26, alpha=0.05, minimum detectable effect ~= 0.192 (of 26 benign inputs flipped (one-sided exact sign test)). A smaller false-positive rate than that would be invisible here — grow the benign corpus.

## Baseline

limes pii-egress beats tessera-pii baseline (apply_output_guard): 32/32 located against 21/32, 1/26 benign killed against 15/26. It adds no false positive the baseline does not already make.

## What still fails, and why

Nothing in this corpus. That is a statement about this corpus, not about the world: the corpus grows adversarially (ADR 0003).

## False positives — what fired, and what it cost

- `iban_like_off_by_one_de` (mimics **iban**) — One digit away from the German documentation IBAN — only MOD 97-10 separates them.
  - Content: `Referenz DE89 3704 0044 0532 0130 01 wurde storniert.`
  - What actually fired: `pii:pan` on `3704 0044 0532 0130 01`, `pii:phone` on `0532 0130 01`

