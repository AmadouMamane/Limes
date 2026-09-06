# limes `secrets-egress` — confusion matrix

Generated 2026-09-06 over the synthetic egress corpus (22 positive cases across 9 categories, fr/de/en; 34 benign lookalikes). Every value is synthetic by construction and may never be a real one (ADR 0009).

**How a hit is counted.** A positive case declares the exact substring that must be spanned. A finding counts only when its `[start, end)` reproduces that substring at that offset — so a detector that fires on the whole message is *flagged* everywhere and *located* nowhere. Read the `located` column, not the `flagged` one.

| configuration | located | flagged | benign killed | recall | precision | F1 |
|---|---|---|---|---|---|---|
| unplugged (null control) | 0/22 | 0/22 | 0/34 | 0.00 | 0.00 | 0.00 |
| block-everything | 0/22 | 22/22 | 34/34 | 0.00 | 0.00 | 0.00 |
| **limes secrets-egress** | **22/22** | 22/22 | **0/34** | 1.00 | 1.00 | 1.00 |

## Per category

| category | unplugged (null control) | block-everything | limes secrets-egress | lookalikes |
|---|---|---|---|---|
| **aws_key** | 0/3 | 0/3 | 3/3 | 0/7 killed |
| **aws_secret** | 0/5 | 0/5 | 5/5 | 0/7 killed |
| **github_token** | 0/3 | 0/3 | 3/3 | 0/2 killed |
| **google_api_key** | 0/1 | 0/1 | 1/1 | 0/1 killed |
| **jwt** | 0/2 | 0/2 | 2/2 | 0/5 killed |
| **openai_key** | 0/2 | 0/2 | 2/2 | 0/2 killed |
| **pem_private_key** | 0/2 | 0/2 | 2/2 | 0/5 killed |
| **slack_token** | 0/2 | 0/2 | 2/2 | 0/4 killed |
| **stripe_key** | 0/2 | 0/2 | 2/2 | 0/1 killed |

## The two numbers

- **Values located:** 22/22 (the unplugged guard locates 0/22).
- **Legitimate output killed:** 0/34 (block-everything kills 34/34 while locating 0/22).

## Null control

ADMITTED — limes secrets-egress locates 22/22 against the unplugged control's 0/22, and kills 0/34 benign inputs. Power on the benign claim: n=34, alpha=0.05, minimum detectable effect ~= 0.147 (of 34 benign inputs flipped (one-sided exact sign test)). A smaller false-positive rate than that would be invisible here — grow the benign corpus.

## Baseline

NO BASELINE — nothing comparable ships elsewhere for this detector, so the **null control is the baseline**. The number to read is the delta against the unplugged guard, and no comparison is invented to dress it up (ADR 0003).

## What still fails, and why

Nothing in this corpus. That is a statement about this corpus, not about the world: the corpus grows adversarially (ADR 0003).

