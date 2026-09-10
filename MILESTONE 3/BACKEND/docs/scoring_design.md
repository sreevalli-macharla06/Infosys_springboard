# M2 Hybrid Scoring Engine — Design Contract
**Version:** 1.1.0 (Phase 5A corrections applied)  
**Phase:** 5B — Implementation Complete  
**Milestone:** 2 — AI-Based Threat Detection & Anomaly Analysis Engine  
**Status:** IMPLEMENTED — v1.1.0

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Layer 1 — Isolation Forest Signal](#2-layer-1--isolation-forest-signal)
3. [Layer 2 — Random Forest Signal](#3-layer-2--random-forest-signal)
4. [Layer 3 — Security Rule Engine](#4-layer-3--security-rule-engine)
5. [Score Combination Formula](#5-score-combination-formula)
6. [Verdict Thresholds](#6-verdict-thresholds)
7. [Explainable Reason Schema](#7-explainable-reason-schema)
8. [Prediction Output Contract](#8-prediction-output-contract)
9. [Edge Cases](#9-edge-cases)
10. [Test Scenarios](#10-test-scenarios)
11. [Assumptions & Known Limitations](#11-assumptions--known-limitations)

---

## 1. Architecture Overview

```
Incoming Event (POST /predict payload)
              │
              ▼
   engineer_features_single_event()
   (fetch user history from MongoDB, derive aggregates)
              │
              ▼
   preprocessor.pkl → X  (1 × 16 encoded feature matrix)
              │
    ┌─────────┴──────────────────────────────┐
    │                                        │
    ▼                                        ▼
if_model.pkl                          clf_model.pkl
IsolationForest                       RandomForest
decision_function()                   predict_proba()
    │                                        │
    ▼                                        ▼
IF Raw Score                          Class Probabilities
(lower = more anomalous)              (10 classes, sum=1)
    │                                        │
    ▼                                        ▼
anomaly_normalized [0–100]            rf_score [0–100]
(higher = more anomalous)             (higher = more confident)
    │                                        │
    └──────────────┬─────────────────────────┘
                   │
                   ▼
         Security Rule Engine
         (evaluate raw event fields)
                   │
                   ▼
         rule_score [0–100]
                   │
    ┌──────────────┴──────────────────┐
    │                                 │
    ▼                                 │
Score Combination                     │
final_confidence =                    │
  0.50 × anomaly_normalized           │
+ 0.40 × rule_score                   │
+ 0.10 × rf_score                     │
                   │                  │
                   ▼                  │
         Verdict Thresholds           │
         Normal / Suspicious / Critical
                   │
                   ▼
         Prediction Output
         (verdict, confidence, threat_type,
          anomaly_label, reasons, ...)
```

### Conceptual Separation

| Concept | Question | Primary Source |
|---|---|---|
| **Anomaly** | "Does this look unusual?" | Isolation Forest (Layer 1) |
| **Threat Type** | "What category does this resemble?" | Random Forest (Layer 2) |
| **Risk / Verdict** | "How concerning is this overall?" | Hybrid combination (all three layers) |

These three concepts are **not interchangeable** and must not be conflated in API responses or UI presentation.

---

## 2. Layer 1 — Isolation Forest Signal

### 2.1 Raw Score Source

```
raw_score = IsolationForest.decision_function(X)[0]
```

**Score semantics:**
- Lower raw score → more anomalous (shorter average isolation path)
- Higher raw score → more normal (longer average isolation path)
- Decision boundary ≈ 0.0

### 2.2 Training Distribution Reference (empirically measured, locked)

These constants are derived from the fitted `if_model.pkl` applied to the full 10,000-event M1 training set and are stored alongside the artifact.

| Constant | Symbol | Value |
|---|---|---|
| Training minimum score | `IF_SCORE_MIN` | **−0.06650378** |
| Training maximum score | `IF_SCORE_MAX` | **+0.11269725** |
| Training score range   | `IF_SCORE_RANGE` | **0.17920103** |
| Suspicious mean score  | — | −0.01661746 |
| Normal mean score      | — | +0.05148798 |

These reference constants must be **hardcoded into `scoring_service.py`** (not recomputed per-request). They represent the stable normalization reference for all future inference calls.

### 2.3 Normalization Formula

```
anomaly_normalized = clip(
    (IF_SCORE_MAX − raw_score) / IF_SCORE_RANGE × 100,
    0,
    100
)
```

Where:
- `IF_SCORE_MAX` = 0.11269725
- `IF_SCORE_RANGE` = 0.17920103
- `clip(x, 0, 100)` clamps the result to [0, 100]

**Verification:**

| raw_score | anomaly_normalized | Interpretation |
|---|---|---|
| −0.06650378 (training min) | 100.0 | Maximally anomalous |
| +0.11269725 (training max) | 0.0 | Maximally normal |
| 0.00000000 (zero boundary) | ≈ 62.9 | Slightly above midpoint |
| −0.01661746 (Suspicious mean) | ≈ 71.9 | Typical suspicious event |
| +0.05148798 (Normal mean) | ≈ 34.5 | Typical normal event |

**Scores outside the training range** (possible for novel inference data):
- `raw_score > IF_SCORE_MAX` → anomaly_normalized clipped to **0** (less anomalous than anything seen in training — treat as extremely normal)
- `raw_score < IF_SCORE_MIN` → anomaly_normalized clipped to **100** (more anomalous than anything seen in training — treat as maximally anomalous)

Both cases are handled by the `clip()` operation.

### 2.4 Anomaly Label

In addition to the continuous normalized score, retain the model's binary label for rule evaluation and output:

```
anomaly_label = "Suspicious" if raw_prediction == -1 else "Normal"
```

The `anomaly_label` is **not** used as the final verdict. It is included in the prediction output and may produce an explanation-only model-signal entry in the `reasons` list (see Section 7.2), but it does **not** contribute points to `rule_score`.

---

## 3. Layer 2 — Random Forest Signal

### 3.1 Performance Context

> **Critical Design Note (from Phase 4.5):**  
> The RF classifier achieves ~9.85% accuracy on the M1 test set, which is statistically indistinguishable from the random-chance baseline of 10.0% for 10 balanced classes. The MI between all contract features and `event_type` is ≈ 0.  
> The RF is used **only as a weak secondary soft signal**, not as a primary confidence source.

### 3.2 Outputs Used

```python
proba_vector   = clf_model.predict_proba(X)[0]   # shape: (10,)
predicted_type = clf_model.predict(X)[0]          # str: event_type label
top_prob       = proba_vector.max()               # float ∈ [0.117, 0.782] empirically
```

Observed training-distribution top-probability range:
- `min`: 0.117 (barely above random chance)
- `max`: 0.782 (high-confidence prediction)
- `mean`: 0.312 (typical prediction)

### 3.3 RF Score Normalization

The RF score is normalized relative to the random-chance baseline for 10 classes (1/10 = 0.10):

```
rf_score = clip(
    (top_prob − RANDOM_BASELINE) / (1.0 − RANDOM_BASELINE) × 100,
    0,
    100
)
```

Where `RANDOM_BASELINE = 1 / n_classes = 0.10`.

**Verification:**

| top_prob | rf_score | Interpretation |
|---|---|---|
| 0.10 (random chance) | 0 | No useful signal |
| 0.12 (slightly above chance) | 2.2 | Negligible signal |
| 0.31 (empirical mean) | 23.3 | Weak but non-zero |
| 0.78 (empirical max) | 75.6 | Moderately confident |
| 1.00 (hypothetical perfect) | 100.0 | Maximum |

Even at the empirical maximum top-probability of 0.782, `rf_score = 75.6`, contributing at most **7.56 points** to `final_confidence` (at weight 0.10). This is intentional.

### 3.4 Threat Type Assignment

The predicted threat type is **always** reported as:

```
threat_type = clf_model.predict(X)[0]   # e.g. "Brute Force"
```

It is labeled in API responses as `"predicted_threat_type"` with an explicit `"rf_confidence"` field showing `top_prob`, so consumers understand its reliability level.

### 3.5 RF Confidence Note Thresholds

These thresholds are applied identically in all sections of this document and in the implementation:

| Condition | `rf_confidence_note` |
|---|---|
| `top_prob < 0.15` | `"low"` |
| `0.15 <= top_prob < 0.50` | `"moderate"` |
| `top_prob >= 0.50` | `"high"` |

When `top_prob < 0.15`:
- `rf_score` ≤ 5.6 (contributes ≤ 0.56 points to final score)
- The `reasons` list does **not** include an RF-based entry
- `predicted_threat_type` is still returned but explicitly marked `rf_confidence_note = "low"`

---

## 4. Layer 3 — Security Rule Engine

### 4.1 Rule Evaluation Inputs

All rules evaluate fields available from the **enriched event dict** (post-`engineer_features_single_event()`):

| Input field | Source |
|---|---|
| `malware_flag` | M1 event field (0/1) |
| `failed_login_attempts` | M1 event field (int) |
| `severity_score` | M1 event field (1=Low, 2=Medium, 3=High, 4=Critical) |
| `cvss_score` | M1 event field (float, 0.0–10.0) |
| `impossible_travel_flag` | Derived by `engineer_features_single_event()` |
| `after_hours_flag` | Derived (hour < 8 or hour >= 18) |
| `anomaly_label` | From IF output ("Normal" / "Suspicious") |
| `status_flag` | M1 event field (0/1) |

### 4.2 Rule Definitions

Each rule is evaluated independently. Points from multiple rules **accumulate**; the total is capped at 100 before weighting.

---

#### RULE_MALWARE
| Property | Value |
|---|---|
| **Rule ID** | `RULE_MALWARE` |
| **Condition** | `malware_flag == 1` |
| **Points** | **50** |
| **Reason text** | `"Malware activity detected on this event"` |
| **Severity tag** | `Critical` |
| **Affects verdict** | Yes |
| **Affects explanation** | Yes — always shown when triggered |

---

#### RULE_FAILED_LOGINS_HIGH
| Property | Value |
|---|---|
| **Rule ID** | `RULE_FAILED_LOGINS_HIGH` |
| **Condition** | `failed_login_attempts >= 15` |
| **Points** | **40** |
| **Reason text** | `"Excessive failed login attempts ({n})"` |
| **Severity tag** | `High` |
| **Affects verdict** | Yes |
| **Affects explanation** | Yes |

---

#### RULE_FAILED_LOGINS_MED
| Property | Value |
|---|---|
| **Rule ID** | `RULE_FAILED_LOGINS_MED` |
| **Condition** | `8 <= failed_login_attempts < 15` |
| **Points** | **20** |
| **Reason text** | `"Elevated failed login attempts ({n})"` |
| **Severity tag** | `Medium` |
| **Affects verdict** | Yes |
| **Affects explanation** | Yes |
| **Note** | Mutually exclusive with `RULE_FAILED_LOGINS_HIGH` (only highest tier applies) |

---

#### RULE_IMPOSSIBLE_TRAVEL
| Property | Value |
|---|---|
| **Rule ID** | `RULE_IMPOSSIBLE_TRAVEL` |
| **Condition** | `impossible_travel_flag == 1` |
| **Points** | **45** |
| **Reason text** | `"Impossible travel detected: country changed within {window}h window"` |
| **Severity tag** | `Critical` |
| **Affects verdict** | Yes |
| **Affects explanation** | Yes |

---

#### RULE_CRITICAL_SEVERITY
| Property | Value |
|---|---|
| **Rule ID** | `RULE_CRITICAL_SEVERITY` |
| **Condition** | `severity_score >= 4` |
| **Points** | **35** |
| **Reason text** | `"Event carries Critical severity rating"` |
| **Severity tag** | `Critical` |
| **Affects verdict** | Yes |
| **Affects explanation** | Yes |

---

#### RULE_HIGH_SEVERITY
| Property | Value |
|---|---|
| **Rule ID** | `RULE_HIGH_SEVERITY` |
| **Condition** | `severity_score == 3` |
| **Points** | **20** |
| **Reason text** | `"Event carries High severity rating"` |
| **Severity tag** | `High` |
| **Affects verdict** | Yes |
| **Affects explanation** | Yes |
| **Note** | Mutually exclusive with `RULE_CRITICAL_SEVERITY` |

---

#### RULE_HIGH_CVSS
| Property | Value |
|---|---|
| **Rule ID** | `RULE_HIGH_CVSS` |
| **Condition** | `cvss_score >= 9.0` |
| **Points** | **30** |
| **Reason text** | `"Critical CVSS vulnerability score ({score})"` |
| **Severity tag** | `Critical` |
| **Affects verdict** | Yes |
| **Affects explanation** | Yes |

---

#### RULE_MEDIUM_CVSS
| Property | Value |
|---|---|
| **Rule ID** | `RULE_MEDIUM_CVSS` |
| **Condition** | `7.0 <= cvss_score < 9.0` |
| **Points** | **15** |
| **Reason text** | `"High CVSS vulnerability score ({score})"` |
| **Severity tag** | `High` |
| **Affects verdict** | Yes |
| **Affects explanation** | Yes |
| **Note** | Mutually exclusive with `RULE_HIGH_CVSS` |

---

#### RULE_AFTER_HOURS
| Property | Value |
|---|---|
| **Rule ID** | `RULE_AFTER_HOURS` |
| **Condition** | `after_hours_flag == 1` |
| **Points** | **10** |
| **Reason text** | `"Activity occurred outside business hours (hour={hour})"` |
| **Severity tag** | `Low` |
| **Affects verdict** | Yes — as a minor modifier (10 points to rule_score, which feeds the 40% rule component) |
| **Affects explanation** | Yes — always shown when triggered |

---

#### IF Anomaly — Explanation-Only Signal (NOT a scored rule)

> **Design rationale (Correction 2):** The Isolation Forest anomaly signal already contributes **50% of the final confidence score** via `anomaly_normalized`. Adding it again as a rule would double-count the same signal. Therefore there is **no `RULE_IF_ANOMALY`** in the rule engine.
>
> The IF anomaly is represented in two ways:
> 1. **Quantitatively** — through `anomaly_normalized` (0–100) in the 50%-weighted score component.
> 2. **Qualitatively** — through a model-signal explanation entry in `reasons` when `anomaly_label == "Suspicious"` (see Section 7.2).
>
> This explanation entry has `"points": 0` and does **not** increase `rule_score`.

---

### 4.3 Rule Score Computation

```
raw_rule_points = sum(points of all triggered SCORED rules)
rule_score      = min(raw_rule_points, 100)
```

Only the 9 scored rules listed above contribute to `raw_rule_points`. The IF anomaly explanation entry (Section 4.2, final block) always has `points = 0` and is excluded from this sum.

The cap at 100 ensures the rule component cannot exceed its maximum contribution to the final score regardless of how many rules fire simultaneously.

### 4.4 Mutual Exclusion

The following rule pairs are mutually exclusive — only the **highest-severity tier** applies:

| Group | Rules | Resolution |
|---|---|---|
| Failed Logins | `RULE_FAILED_LOGINS_HIGH` (40pt) + `RULE_FAILED_LOGINS_MED` (20pt) | Apply only highest tier |
| Severity | `RULE_CRITICAL_SEVERITY` (35pt) + `RULE_HIGH_SEVERITY` (20pt) | Apply only highest tier |
| CVSS | `RULE_HIGH_CVSS` (30pt) + `RULE_MEDIUM_CVSS` (15pt) | Apply only highest tier |

---

## 5. Score Combination Formula

### 5.1 Component Weights

| Component | Symbol | Weight | Max Contribution |
|---|---|---|---|
| Isolation Forest anomaly | `W_IF` | **0.50** | **50 points** |
| Security rule engine | `W_RULE` | **0.40** | **40 points** |
| Random Forest soft signal | `W_RF` | **0.10** | **10 points** |
| **Total** | | **1.00** | **100 points** |

### 5.2 Final Formula

```
final_confidence = round(
    W_IF   × anomaly_normalized
  + W_RULE  × rule_score
  + W_RF    × rf_score,
  1                           ← round to 1 decimal place
)
```

```
final_confidence = round(
    0.50 × anomaly_normalized
  + 0.40 × rule_score
  + 0.10 × rf_score,
  1
)
```

Output range: **[0.0, 100.0]**

### 5.3 Weight Rationale

- **IF at 50%:** The Isolation Forest is the only model with a well-grounded signal in this dataset. It detects structural outliers in the feature space independent of `event_type` labels. It is the most reliable M2 signal.
- **Rules at 40%:** Explicit domain-knowledge rules (malware, failed logins, impossible travel, CVSS) are directly interpretable and reliable. They are weighted nearly as heavily as the IF signal because they express unambiguous security semantics.
- **RF at 10%:** The RF classifier was empirically shown to perform near random chance on the M1 dataset. A 10% cap ensures its contribution is a tie-breaker / soft nudge at most, never a primary driver. Even at the empirical top-prob maximum of 0.782, the RF contributes at most ~7.6 points.

### 5.4 Worked Example — Critical Event

| Component | Value | Calculation | Points |
|---|---|---|---|
| IF raw score | −0.055 (very anomalous) | (0.1127 − (−0.055)) / 0.1792 × 100 = 93.6 | 0.50 × 93.6 = **46.8** |
| Rules: malware_flag=1 (50), failed_logins=18 (40) | raw=90, capped=90 | — | 0.40 × 90 = **36.0** |
| RF top_prob=0.28 | (0.28−0.10)/0.90 × 100 = 20.0 | — | 0.10 × 20.0 = **2.0** |
| **Final** | | | **84.8 → Critical** |

### 5.5 Worked Example — Normal Event

| Component | Value | Calculation | Points |
|---|---|---|---|
| IF raw score | +0.095 (very normal) | (0.1127 − 0.095) / 0.1792 × 100 = 9.9 | 0.50 × 9.9 = **4.9** |
| Rules: no rules fire | raw=0 | — | 0.40 × 0 = **0.0** |
| RF top_prob=0.13 | (0.13−0.10)/0.90 × 100 = 3.3 | — | 0.10 × 3.3 = **0.3** |
| **Final** | | | **5.2 → Normal** |

---

## 6. Verdict Thresholds

```
final_confidence ∈ [ 0.0,  34.9] → verdict = "Normal"
final_confidence ∈ [35.0,  64.9] → verdict = "Suspicious"
final_confidence ∈ [65.0, 100.0] → verdict = "Critical"
```

### 6.1 Threshold Rationale

| Threshold | Rationale |
|---|---|
| **0–34.9 = Normal** | Below 35 points: the IF signal is in the lower 40% of the anomaly range AND few or no security rules fire. These events do not warrant escalation. |
| **35–64.9 = Suspicious** | Events in this range have moderate IF anomaly signal or at least one moderate security rule (e.g. elevated failed logins, High severity). Requires analyst attention. |
| **65–100 = Critical** | Events here require either: (a) very high IF anomaly signal, OR (b) at least one critical security rule (malware, impossible travel, critical CVSS), OR (c) multiple compounding signals. Immediate escalation. |

### 6.2 Verdict Override Rules

Two **hard override** conditions force the verdict regardless of the computed score:

| Condition | Override |
|---|---|
| `malware_flag == 1` | Minimum verdict: **Critical** (floor the score to 65.0 if below) |
| `impossible_travel_flag == 1` | Minimum verdict: **Suspicious** (floor the score to 35.0 if below) |

These overrides exist because these two signals are unambiguous security indicators that should never be silently classified as Normal by the scoring math.

---

## 7. Explainable Reason Schema

### 7.1 Individual Reason Object

```json
{
  "rule_id":  "RULE_MALWARE",
  "reason":   "Malware activity detected on this event",
  "points":   50,
  "severity": "Critical"
}
```

| Field | Type | Description |
|---|---|---|
| `rule_id` | string | Unique identifier from Section 4.2 |
| `reason` | string | Human-readable explanation tied to the specific observation |
| `points` | int | Rule points contributed (before final weighting) |
| `severity` | string | `"Critical"`, `"High"`, `"Medium"`, or `"Low"` |

### 7.2 Reason Generation Rules

- Reasons are generated **only** for rules that actually fired (condition evaluated to True).
- Reason text templates are interpolated with actual observed values (e.g. actual `failed_login_attempts` count).
- Generic AI-sounding reasons not tied to rule evidence are explicitly forbidden.
- Reasons are sorted by `points` descending in the response.
- **IF anomaly explanation entry:** If `anomaly_label == "Suspicious"`, one model-signal entry is appended to the reasons list with `points = 0` (it does not affect `rule_score`):
  ```json
  {
    "rule_id": "IF_ANOMALY_SIGNAL",
    "reason":  "Isolation Forest flagged this event as anomalous (normalized score: {anomaly_score})",
    "points":  0,
    "severity": "Medium"
  }
  ```
  This entry is purely explanatory. It communicates the IF model signal to API consumers and UI without double-counting it in the score.
- If no security rules fire **and** `anomaly_label == "Normal"`, the reasons list is **empty** `[]`.
- If no security rules fire **and** `anomaly_label == "Suspicious"`, the reasons list contains **only** the `IF_ANOMALY_SIGNAL` entry above.

---

## 8. Prediction Output Contract

### 8.1 Internal Result Structure

```python
PredictionResult = {
    # Identity
    "event_id":               str,           # passthrough from request

    # Final verdict
    "verdict":                str,           # "Normal" | "Suspicious" | "Critical"
    "confidence_score":       float,         # [0.0, 100.0], 1 decimal place

    # Threat classification (Layer 2 — RF, weak signal)
    "predicted_threat_type":  str,           # e.g. "Brute Force"
    "rf_top_probability":     float,         # [0.0, 1.0]
    "rf_confidence_note":     str,           # "low" | "moderate" | "high"

    # Anomaly signal (Layer 1 — IF)
    "anomaly_label":          str,           # "Normal" | "Suspicious"
    "anomaly_score":          float,         # [0.0, 100.0] normalized
    "anomaly_score_raw":      float,         # raw IF decision_function output

    # Rule engine
    "rule_score":             float,         # [0.0, 100.0] capped rule points
    "triggered_rules":        list[str],     # list of fired rule_ids

    # Explanations
    "reasons":                list[dict],    # list of reason objects (Section 7.1)

    # Model signals (for debugging / audit)
    "model_signals": {
        "if_anomaly_normalized":  float,     # [0.0, 100.0]
        "rf_score_normalized":    float,     # [0.0, 100.0]
        "rule_score":             float,     # [0.0, 100.0]
    }
}
```

### 8.2 Field Constraints

| Field | Type | Valid Range / Values |
|---|---|---|
| `verdict` | str | `"Normal"`, `"Suspicious"`, `"Critical"` |
| `confidence_score` | float | [0.0, 100.0], 1dp |
| `predicted_threat_type` | str | One of the 10 RF class labels |
| `rf_top_probability` | float | [0.0, 1.0] |
| `rf_confidence_note` | str | `"low"` if top_prob < 0.15, `"moderate"` if 0.15 ≤ top_prob < 0.50, `"high"` if top_prob ≥ 0.50 |
| `anomaly_label` | str | `"Normal"` or `"Suspicious"` |
| `anomaly_score` | float | [0.0, 100.0], normalized |
| `anomaly_score_raw` | float | unbounded; typically [−0.067, +0.113] |
| `rule_score` | float | [0.0, 100.0] |
| `triggered_rules` | list[str] | Subset of rule IDs from Section 4.2 |
| `reasons` | list[dict] | See Section 7.1; may be empty |

---

## 9. Edge Cases

| Scenario | Expected Behavior |
|---|---|
| **Missing optional fields** (e.g. `hour` absent) | Use default values: `hour=12` (business hours), `is_weekend=False`. Derived flags computed from defaults. Log a warning. |
| **Unknown protocol** | `OneHotEncoder(handle_unknown='ignore')` sets all protocol OHE columns to 0. Score proceeds normally. |
| **No historical user context** (`hist=[]`) | `events_per_user = 1`, `unique_destination_count = 1`, `impossible_travel_flag = 0`. These defaults represent a brand-new user with no prior history. |
| **`impossible_travel_flag` unavailable** | Default to `0`. Flag cannot be set without valid timestamps and prior history. |
| **RF probability unusually low** (`top_prob < 0.15`) | `rf_score` ≤ 5.6 (≤ 0.56 pts to final score). No RF-based reason entry generated. `rf_confidence_note = "low"`. Thresholds: `< 0.15` = low, `0.15–0.50` = moderate, `≥ 0.50` = high. |
| **Anomaly score outside training range** | `clip()` handles both directions: score < IF_MIN → anomaly_normalized = 100; score > IF_MAX → anomaly_normalized = 0. |
| **Model artifact unavailable** | `FileNotFoundError` raised by `model_loader.py` at startup; FastAPI lifespan fails to start. `POST /predict` is never reachable. Not handled at scoring level. |
| **Malformed event** (missing required fields) | Pydantic validation at the route level rejects the request with HTTP 422. Not handled in scoring_service.py. |
| **`severity_score` out of expected range** | Rules evaluate the raw value; if 0 ≤ value ≤ 4, normal evaluation. Values outside range are treated as if `severity_score = 0` (no severity rule fires). |

---

## 10. Test Scenarios

### Scenario 1 — Normal Low-Risk Event
**Inputs:** `malware_flag=0`, `failed_login_attempts=0`, `severity_score=1`, `cvss_score=2.5`, `after_hours_flag=0`, `impossible_travel_flag=0`, IF score ≈ +0.095  
**Rules fired:** None  
**Expected anomaly_normalized:** ≈ 10  
**Expected rule_score:** 0  
**Expected final_confidence:** ≈ 5–12  
**Expected verdict:** **Normal**  
**Reason list:** `[]`

---

### Scenario 2 — High Failed Logins Only
**Inputs:** `malware_flag=0`, `failed_login_attempts=18`, `severity_score=2`, `cvss_score=5.0`, IF score ≈ −0.020  
**Rules fired:** `RULE_FAILED_LOGINS_HIGH` (40pt)  
**Expected rule_score:** 40  
**Expected anomaly_normalized:** ≈ 74  
**Expected final_confidence:** ≈ 0.50×74 + 0.40×40 + RF ≈ 37 + 16 + RF ≈ 53–56  
**Expected verdict:** **Suspicious**

---

### Scenario 3 — Malware Detected
**Inputs:** `malware_flag=1`, `failed_login_attempts=2`, `severity_score=3`, `cvss_score=6.0`, IF score ≈ −0.030  
**Rules fired:** `RULE_MALWARE` (50pt), `RULE_HIGH_SEVERITY` (20pt) → raw = 70 → capped at 70  
**Expected rule_score:** 70  
**Verdict override:** `malware_flag=1` → minimum Critical (score floor 65)  
**Expected final_confidence:** ≈ 0.50×78 + 0.40×70 + RF ≈ 39 + 28 + RF ≈ 67–70  
**Expected verdict:** **Critical** (also forced by override)

---

### Scenario 4 — Critical Severity + High CVSS
**Inputs:** `malware_flag=0`, `failed_login_attempts=0`, `severity_score=4`, `cvss_score=9.5`, IF score ≈ −0.010  
**Rules fired:** `RULE_CRITICAL_SEVERITY` (35pt), `RULE_HIGH_CVSS` (30pt) → raw = 65  
**Expected rule_score:** 65  
**Expected anomaly_normalized:** ≈ 68  
**Expected final_confidence:** ≈ 0.50×68 + 0.40×65 + RF ≈ 34.0 + 26.0 + RF ≈ 60–63  
**Expected verdict:** **Suspicious** (close to Critical boundary)

> **Why Suspicious and not Critical?**  
> Critical severity (35pt) and a high CVSS score (30pt) are both strong security signals — together they push `rule_score` to 65 and contribute 26 points to the final score. However, the verdict is determined by the **hybrid formula**, not by any single component alone.  
> In this scenario the IF anomaly is only moderate (raw ≈ −0.010 → anomaly_normalized ≈ 68 → contributes 34 points). With no malware flag and no impossible-travel flag, neither hard override applies.  
> The combined score of ~60–63 sits just below the Critical threshold of 65.0.  
> **This is correct by design:** the scoring model requires the *combined weight* of anomaly + rules to reach 65, not just the rules alone. An event with critical indicators but a normal-range anomaly score is escalated to Suspicious for analyst review — not automatically to Critical — because the ML signal does not corroborate the severity rating in isolation.

---

### Scenario 5 — Impossible Travel
**Inputs:** `malware_flag=0`, `failed_login_attempts=1`, `impossible_travel_flag=1`, `severity_score=2`, IF score ≈ −0.015  
**Rules fired:** `RULE_IMPOSSIBLE_TRAVEL` (45pt)  
**Expected rule_score:** 45  
**Verdict override:** `impossible_travel_flag=1` → minimum Suspicious  
**Expected final_confidence:** ≈ 0.50×72 + 0.40×45 + RF ≈ 36 + 18 + RF ≈ 54–57  
**Expected verdict:** **Suspicious**

---

### Scenario 6 — Multiple Simultaneous Indicators
**Inputs:** `malware_flag=1`, `failed_login_attempts=16`, `impossible_travel_flag=1`, `severity_score=4`, `cvss_score=9.8`, IF score ≈ −0.060  
**Rules fired:** `RULE_MALWARE` (50), `RULE_FAILED_LOGINS_HIGH` (40), `RULE_IMPOSSIBLE_TRAVEL` (45), `RULE_CRITICAL_SEVERITY` (35), `RULE_HIGH_CVSS` (30) → raw = 200 → **capped at 100**  
**Expected rule_score:** 100  
**Expected anomaly_normalized:** ≈ 96  
**Expected final_confidence:** ≈ 0.50×96 + 0.40×100 + RF ≈ 48 + 40 + RF ≈ 88–92  
**Expected verdict:** **Critical**

---

### Scenario 7 — Highly Anomalous IF, No Rules
**Inputs:** `malware_flag=0`, `failed_login_attempts=0`, `severity_score=1`, `cvss_score=3.0`, IF score ≈ −0.064 (very anomalous)  
**Rules fired:** None (IF anomaly does not contribute rule points — Correction 2)  
**Expected rule_score:** 0  
**Expected anomaly_normalized:** (0.11270 − (−0.064)) / 0.17920 × 100 ≈ **97.6**  
**Expected rf_score:** assume typical mean top_prob ≈ 0.31 → (0.31−0.10)/0.90×100 ≈ 23.3  
**Expected final_confidence:** 0.50×97.6 + 0.40×0 + 0.10×23.3 = 48.8 + 0.0 + 2.3 ≈ **51.1**  
**Expected verdict:** **Suspicious**  
**Reason list:** One explanation-only entry — `{"rule_id": "IF_ANOMALY_SIGNAL", "reason": "Isolation Forest flagged this event as anomalous (normalized score: 97.6)", "points": 0, "severity": "Medium"}` — because `anomaly_label == "Suspicious"`.  
**Key observation (post-Correction 2):** Without `RULE_IF_ANOMALY` contributing 15 rule points, the final score drops from the original ~55–58 to ~51. The event remains firmly **Suspicious** — the IF anomaly signal alone (contributing 48.8 of the 50-point maximum from its 50% weight) is strong enough to reach Suspicious without any rule support. However, without a hard-override rule (malware or impossible travel), it cannot reach Critical on anomaly signal alone.

---

### Scenario 8 — Low RF Confidence, Moderate Rules
**Inputs:** `malware_flag=0`, `failed_login_attempts=9`, `severity_score=2`, `cvss_score=5.5`, IF score ≈ +0.020, RF top_prob = 0.12  
**Rules fired:** `RULE_FAILED_LOGINS_MED` (20pt)  
**Expected rf_score:** (0.12−0.10)/0.90×100 ≈ 2.2  
**Expected rule_score:** 20  
**Expected anomaly_normalized:** ≈ 51  
**Expected final_confidence:** ≈ 0.50×51 + 0.40×20 + 0.10×2.2 ≈ 25.5 + 8.0 + 0.2 ≈ 33.7  
**Expected verdict:** **Normal** (just below Suspicious threshold)  
**Key observation:** Low RF confidence contributes 0.22 points — negligible, as designed.

---

## 11. Assumptions & Known Limitations

### Assumptions

1. `preprocessor.pkl` is fitted on the full 10,000-event M1 training set and remains the production transformation artifact.
2. The IF score normalization reference constants (`IF_SCORE_MIN`, `IF_SCORE_MAX`) are **hardcoded** in `scoring_service.py` based on Phase 3 training measurements. They are not recomputed per request.
3. `impossible_travel_flag` is always 0 in M1 training data (all records `source_country = "India"`). This flag provides value only for geo-diverse live inference and rule-based scoring.
4. The MongoDB query for `historical_events` in `POST /predict` enforces `timestamp < incoming_event.timestamp` to maintain temporal causality.
5. The 10 RF event_type class labels match exactly: `['Brute Force', 'Failed Login', 'File Access', 'Login Success', 'Malware Detection', 'Phishing Email', 'Port Scan', 'Privilege Escalation', 'SQL Injection Attempt', 'USB Device Connected']`.

### Known Limitations

1. **RF performance at chance level:** The RF classifier cannot reliably distinguish between event_type categories from the available feature set. `predicted_threat_type` should be interpreted as "the most probable category according to the model given limited information," not as a confirmed classification. The `rf_confidence_note` field communicates this to API consumers.
2. **`impossible_travel_flag` = 0 in all training data:** The IF model learned no split on this feature from M1 training. The feature's security value is expressed through the rule engine (`RULE_IMPOSSIBLE_TRAVEL`, 45pt) rather than through the ML models.
3. **IF reference range hardcoded:** If a significantly different dataset is used for future retraining, `IF_SCORE_MIN` and `IF_SCORE_MAX` must be recomputed and updated.
4. **Synthetic M1 dataset:** The M1 dataset was synthetically generated. The scoring weights and thresholds are calibrated for M1 data characteristics. Real-world production deployment would require recalibration.
5. **No temporal drift detection:** The scoring service has no mechanism to detect if incoming events follow a fundamentally different distribution than training data.

---

*Document created: Phase 5A v1.0.0. Corrections applied: Phase 5A v1.1.0. Implementation (Phase 5B) completed.*
