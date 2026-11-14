# SentinelX Risk Model

> Model version **1.0.0** · implemented in `security-engine/sentinelx_security/risk.py`
> · applied by `apps/api/app/services/risk.py`.

SentinelX ranks findings with a **deterministic, versioned and explainable** score
from 0 to 100. The same inputs always produce the same score, every score is
stored with its model version, weights and factor breakdown, and no machine
learning or opaque heuristics are involved.

## 1. Formula

```
base      = CVSS base score x 10            (CVE findings with an NVD score)
          = severity default                (all other findings)
adjusted  = base x confidence x asset criticality x asset exposure
score     = clamp(adjusted + KEV + EPSS x EPSS points + exposure window, 0, 100)
```

| Factor | Source | Default weight |
|--------|--------|----------------|
| Severity default | Finding severity when no CVSS exists | critical 95 · high 80 · medium 55 · low 30 · info 5 |
| Confidence | Finding confidence | tentative x0.8 · firm x1.0 · confirmed x1.1 |
| Asset criticality | Asset inventory | low x0.7 · medium x1.0 · high x1.15 · critical x1.3 |
| Asset exposure | Asset inventory | external x1.0 · internal x0.75 · unknown x0.9 |
| Known exploited | CISA KEV catalog | +20 points |
| Exploit prediction | FIRST EPSS probability (0–1) | + probability x 15 points |
| Exposure window | Days since first seen | +3 after 30 days · +7 after 90 days |

Bands: **critical ≥ 80 · high ≥ 60 · medium ≥ 40 · low ≥ 15 · info < 15**.

CVSS is the preferred base for CVE findings (v4.0 when NVD provides it, else
v3.1, NVD's *Primary* score over the CNA's). Other findings (TLS, headers, DNS,
ZAP, Nuclei) use the severity default, because those tools do not produce CVSS.

## 2. Worked example

Apache 2.4.49 detected on an internet-facing asset of medium criticality,
correlated with CVE-2021-41773 (CVSS 9.8, in CISA KEV, EPSS 0.97):

| Factor | Effect | Points |
|--------|--------|--------|
| base | CVSS 9.8 | 98.0 |
| confidence | tentative x0.8 | −19.6 |
| asset criticality | medium x1.0 | 0.0 |
| asset exposure | external x1.0 | 0.0 |
| known exploited | +20 | +20.0 |
| exploit prediction | 0.97 x 15 | +14.6 |
| clamp | 0–100 | −13.0 |
| **score** | | **100 (critical)** |

The stored explanation reads: *"Critical risk (100/100): starts at 98 from CVSS
9.8; known exploited +20.0, confidence −19.6, exploit prediction +14.6."*

## 3. When scores change

Scores are recomputed whenever an input changes, and a history row is written
only when the score, band or model version actually moves:

| Trigger | Recorded as |
|---------|-------------|
| A scan creates or updates the finding | `scan` |
| An intelligence refresh re-correlates the finding | `correlation` |
| Asset criticality or exposure is edited | `asset_updated` |
| CVE data, KEV or EPSS changes | `intel_updated` |
| An administrator changes the weights | `weights_changed` |
| Daily maintenance (exposure window grows) | `daily` |

Status is **not** a risk input: a suppressed finding (`false_positive`,
`accepted_risk`) or a `resolved` one keeps its score for the record but no
longer counts toward the project posture.

## 4. Project posture

```
posture = worst + (100 − worst) x 0.5 x mean(next 4 worst scores) / 100
```

computed over open and acknowledged findings. The posture is never lower than the
worst issue, rises when several serious issues coexist, and is not diluted or
inflated by long tails of informational findings. A snapshot is stored per
project per day (on every scan, triage, rescoring and by the daily task) and the
last 30 days are shown as a trend.

## 5. Configuration and governance

* Weights are platform-wide, edited by administrators (`settings:manage`) on the
  **Risk Model** page or via `PUT /api/v1/risk/weights`; each weight has enforced
  bounds, and every change is audited with old and new values and triggers an
  immediate rescore of all findings.
* `POST /api/v1/risk/weights/reset` restores the defaults.
* Changing the *formula* (not the weights) requires a new `MODEL_VERSION`; scores
  computed under an older version are visible as such and are replaced by the
  daily rescoring.

## 6. Limitations

* CVSS and EPSS describe the vulnerability, not your environment; compensating
  controls are expressed by triage (`accepted_risk`) or asset context, not inside
  the score.
* Version-based CVE findings are `tentative` (x0.8) because distributions backport
  fixes; confirm and mark them `confirmed`/`false_positive` to sharpen the ranking.
* EPSS is fetched only for CVEs referenced by active findings.
