# SentinelAI Security â€” Backend API

An enterprise-ready FastAPI backend for the SentinelAI AI-Assisted Threat Detection Dashboard (Milestones 1 & 2). It processes security telemetry, maps events to MITRE ATT&CK techniques, executes machine learning anomaly detection and threat classification, and serves real-time security predictions powered by MongoDB.

---

## Tech Stack

- **Core:** Python 3.9+
- **API Framework:** FastAPI, Uvicorn, Pydantic
- **Machine Learning:** Scikit-Learn (Isolation Forest, Random Forest), Joblib
- **Database:** MongoDB, PyMongo
- **Data Processing:** Pandas, NumPy
- **HTTP Client:** HTTPX

---

## Folder Structure

```
BACKEND/
â”œâ”€â”€ data/           # Source CSV datasets (security_events.csv, etc.)
â”œâ”€â”€ database/       # MongoDB connection manager, seeder, & prediction store
â”œâ”€â”€ docs/           # Architecture design docs (feature_selection.md, scoring_design.md, etc.)
â”œâ”€â”€ ml/             # ML pipeline modules (preprocessing, anomaly detection, classifier, training)
â”œâ”€â”€ models/         # Pydantic schemas & serialized production model artifacts (.pkl)
â”œâ”€â”€ routes/         # FastAPI REST API endpoints (events, stats, predictions, etc.)
â”œâ”€â”€ services/       # Core business logic (prediction_service, scoring_service, data_store)
â”œâ”€â”€ validation/     # Archived phase validation scripts
â”œâ”€â”€ main.py         # FastAPI application factory & route registration
â”œâ”€â”€ run.py          # Application entry point script
â””â”€â”€ requirements.txt
```

---

## Prerequisites & Quick Start

### Option 1 (Recommended) â€” Docker

```bash
docker compose up --build
```

Docker automatically starts MongoDB, initializes datasets, and launches the FastAPI server at `http://localhost:8000`.

### Option 2 â€” Local Development

**Requirements:** Python 3.9+, MongoDB running locally on port 27017

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run backend server
python run.py
```

Automatic database initialization:

- Seeds `security_events` with 10,000 M1 records when the collection is empty.
- Automatically populates `threat_predictions` for M2 when predictions are missing or incomplete.
- Ensures the required MongoDB indexes are available.

---

# Milestone 1 â€” Core Security Dashboard APIs

Milestone 1 implements baseline telemetry ingestion, security event querying, MITRE ATT&CK mapping, and executive security stats.

## M1 API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/events` | GET | List security events with severity & type filtering |
| `/events` | POST | Ingest a new security event |
| `/stats` | GET | Overview KPI summary metrics |
| `/threats` | GET | Threat counts grouped by attack type |
| `/vulnerabilities` | GET | System vulnerability (CVE) reports |
| `/threat-intel` | GET | Threat intelligence IOC records |

---


# Milestone 2 â€” AI Threat Detection & Anomaly Engine

Milestone 2 integrates an end-to-end Machine Learning pipeline, persistent prediction storage, hybrid explainable scoring, and specialized AI threat intelligence APIs.

## M2 End-to-End Architecture

```
Security Events Telemetry (10,000 Records)
                 â”‚
                 â–¼
     Causal Feature Engineering (12 Logical Features)
                 â”‚
                 â–¼
      ML Preprocessing (OneHotEncoder â†’ 16 Matrix Columns)
                 â”‚
                 â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                 â–¼                                 â–¼
   Isolation Forest (Unsupervised)    Random Forest (Supervised)
        (Contamination = 0.10)            (10 Threat Classes)
                 â”‚                                 â”‚
                 â–¼                                 â–¼
    Anomaly Score / Label (0â€“100)      Predicted Threat Type / Prob
                 â”‚                                 â”‚
                 â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                  â–¼
                     Hybrid Scoring Scorer Engine
            (50% IF + 40% Security Rules + 10% RF)
                                  â”‚
                                  â–¼
                 MongoDB Persistence (threat_predictions)
                                  â”‚
                                  â–¼
                       FastAPI REST Services
                                  â”‚
                                  â–¼
                    React Threat Detection Dashboard
```

---

## M2 Machine Learning Pipeline & Feature Design

### Feature Engineering (12 Logical Features â†’ 16 Encoded Matrix Columns)
The feature engineering pipeline transforms raw event JSON into a numeric vector ($X$) without data leakage:

1. **12 Logical Input Features (`LOGICAL_FEATURES`):**
   - **Authentication:** `failed_login_attempts` (brute force count), `status_flag` (0=Success/Failed, 1=Blocked/Detected)
   - **Vulnerability:** `cvss_score` (0.0â€“10.0 rating)
   - **Security Flags:** `severity_score` (1=Low â€¦ 4=Critical), `malware_flag` (binary alert)
   - **Time & Calendar:** `hour` (0â€“23), `is_weekend` (0/1)
   - **Categorical Network:** `protocol` (`HTTP`, `HTTPS`, `SSH`, `TCP`, `SMB`)
   - **Causal Behavior Aggregates:** `events_per_user`, `unique_destination_count`, `after_hours_flag` (outside 08:00â€“18:00), `impossible_travel_flag` (geo-anomaly indicator evaluated strictly on prior timestamps where $\text{history.timestamp} < \text{current.timestamp}$)

2. **16 Encoded Matrix Columns ($X$):**
   Categorical feature `protocol` is transformed via `OneHotEncoder(handle_unknown='ignore')`, expanding the 12 logical features into a 16-column numerical matrix fed directly into the model inference pipeline.

### Excluded Attributes & Safeguards
- **Direct Identifiers:** `event_id` (document key), `timestamp` (converted to `hour`/`is_weekend`/`after_hours` and used for causal ordering / source date aggregation, not as a direct ML split feature), `source_ip`, `destination_ip`, `username` (aggregated into user behavioral metrics).
- **Target & Post-Event Leakage:** `event_type` (supervised target label $y$ for Random Forest), `technique_id`, `technique_name`, `tactic` (direct 1:1 mappings from `event_type`), `risk_level`, `login_risk`, `threat_confidence` (synthetic post-event fields).
- **Zero-Variance Columns:** `source_country`, `destination_country`, `year`, `month` (100% constant `"India"`, `2025`, `8` across baseline dataset).

> [!NOTE]
> **Data Quality Note on `threat_indicator`**: The baseline dataset contains 10,000 events without a `threat_indicator` column. Feature selection explicitly uses verified telemetry attributes without creating synthetic columns or mutating original CSV datasets.

### Model Artifacts & Specifications

| Model Artifact | File Path | Version / Specs | Role |
|---|---|---|---|
| **Preprocessor** | `models/preprocessor.pkl` | v1.5.0 (`OneHotEncoder` for `protocol`; numerical features pass through without `StandardScaler`) | Encodes categorical variables; tree-based models invariant to numeric scaling |
| **Isolation Forest** | `models/if_model.pkl` | v1.0.0-phase3 (`n_estimators=200`, `contamination=0.10`) | Primary unsupervised anomaly detection (50% score weight) |
| **Random Forest** | `models/clf_model.pkl` | v1.1.0-phase4.6 (`n_estimators=100`, `max_depth=15`) | Secondary soft threat classification across 10 classes (10% score weight) |

### Offline Model Performance & Evaluation
- **Isolation Forest:** Configured with `n_estimators=200` and `contamination=0.10`. Successfully isolates 998 anomalies (10.0% rate) out of 10,000 baseline events, serving as the primary 50% weighted score contributor.
- **Random Forest Classifier:** Evaluated on an 80/20 train-test split across 10 threat classes (`test_accuracy = 0.1070`, `test_macro_f1 = 0.1047`). Performance is near the ~10% random chance baseline due to synthetic baseline telemetry characteristics for `event_type`.
  > **Scoring Architecture Safeguard:** Because Random Forest performance is constrained by synthetic dataset limits, RF is intentionally assigned a low 10% weight as a soft secondary signal in the hybrid scoring engine ($50\%\text{ IF} + 40\%\text{ Rules} + 10\%\text{ RF}$), ensuring overall Threat Index reliability is never compromised.

---

## Hybrid Confidence Scoring Model

The hybrid scoring engine combines unsupervised ML anomalies, deterministic security rules, and supervised soft classification into a unified 0â€“100 Threat Index:

$$\text{Hybrid Score} = (0.50 \times \text{IF Score}) + (0.40 \times \text{Rule Score}) + (0.10 \times \text{RF Score})$$

### Verdict Thresholds
- **Normal:** `[0.0, 34.9]`
- **Suspicious:** `[35.0, 64.9]`
- **Critical:** `[65.0, 100.0]`

Every prediction generates human-understandable **reasons** detailing triggered rules, model contributions, and severity breakdowns.

---

## MILESTONE API Endpoints

The M2 prediction engine exposes **8 REST API endpoints**:

| Endpoint | Method | Description |
|---|---|---|
| `/predict` | POST | Compute live ML prediction & score for an ingested security event |
| `/predictions` | GET | Query paginated prediction history feed (sorted newest first, filter by verdict/threat) |
| `/prediction-trend` | GET | Daily historical prediction volume aggregated by source event timestamp |
| `/top-predictions` | GET | Retrieve top N predictions sorted globally by `confidence_score` DESC |
| `/predictions/{prediction_id}` | GET | Retrieve a single detailed prediction document by prediction ID |
| `/anomalies` | GET | Query high-risk predictions (final hybrid verdict IN [`Suspicious`, `Critical`]). Note: `anomaly_label` = Isolation Forest raw signal; `verdict` = final hybrid assessment |
| `/threat-summary` | GET | Aggregated counts, average confidence, and backend-calculated percentage by threat category |
| `/model-performance` | GET | Return offline model metrics & live prediction distribution statistics |

Interactive Swagger Documentation: **http://localhost:8000/docs**

---

## MongoDB Persistence Design

- **Collection:** `threat_predictions` (10,000 persisted prediction documents)
- **Indexing:** Compound non-unique indexes on `(event_id, prediction_timestamp)`, `verdict`, `predicted_threat_type`, and `anomaly_label`.
- **Append-Oriented Storage:** Designed for append-only execution logging while maintaining 1:1 mapping with source `security_events`.

> [!IMPORTANT]
> **Data Lineage Note**: `security_events.timestamp` is the authoritative source occurrence date (`2025-08-01` to `2025-08-07`). To ensure trend analytics reflect historical telemetry rather than execution timestamps, `/prediction-trend` performs a `$lookup` join from `threat_predictions` to `security_events` on `event_id`.

---



# Milestone 3 — Risk Prioritization & Security Intelligence

Milestone 3 extends the SentinelAI platform from individual telemetry event predictions to prioritized, contextualized, and actionable security incidents. It introduces a deterministic 5-factor risk scoring engine, sliding-window event correlation, multi-stage attack chain detection, dynamic risk weight configuration, explainable correlation comparison, and an analyst feedback loop with audit tracking.

---

## M3 Architecture & Pipeline Flow

The incident generation pipeline processes each security event and its corresponding M2 threat prediction through seven sequential stages:

```
                  Security Event (M1) + Threat Prediction (M2)
                                       │
                                       ▼
                     1. Contextual Enrichment Pipeline
          (Asset Criticality + CVE/CVSS + MITRE ATT&CK + Threat Intel IOC)
                                       │
                                       ▼
                   2. Temporal Event Correlation Engine
             (15-Minute Sliding Window on IP / User / Asset Pivots)
                                       │
                                       ▼
                   3. Multi-Stage Attack Chain Detection
      (Chronological: Brute Force, Privilege Escalation, Data Exfiltration)
                                       │
                                       ▼
                   4. Deterministic 5-Factor Risk Engine
     (Threat Severity 25% + ML Conf 25% + Asset 20% + CVSS 20% + Intel 10%)
                                       │
                                       ▼
               5. Explainable Comparison & Advisory Guidance
    (Before vs After Correlation Delta = 0 + Tailored SOC Recommendations)
                                       │
                                       ▼
                   6. Deduplicated Incident Persistence
      (MongoDB `incidents` Collection with Unique `anchor_event_id` Index)
                                       │
                                       ▼
                 7. Incident Lifecycle & Analyst Feedback
      (Status History Audit Trail + Structured False Positive Feedback)
```

---

## 5-Factor Risk Scoring Engine

The core risk engine calculates a deterministic integer score clamped between 0 and 100:

$$\text{Risk Score} = \text{round}\Big(\sum_{i=1}^{5} w_i \times v_i\Big)$$

### Default Factor Weights & Normalization

| Factor | Key | Default Weight ($w_i$) | Value Normalization ($v_i \in [0, 100]$) | Description |
|---|---|---|---|---|
| **Threat Severity** | `threat_severity` | **0.25 (25%)** | Critical=100, High=75, Medium=50, Low=25 | Base event severity level |
| **ML Confidence** | `ml_confidence` | **0.25 (25%)** | Integer rounded from M2 model probability | Soft confidence score from M2 prediction |
| **Asset Criticality** | `asset_criticality` | **0.20 (20%)** | Critical=100, High=75, Medium=50, Low=25 | Criticality of target asset in `assets` |
| **Vulnerability CVSS**| `vulnerability_cvss` | **0.20 (20%)** | $\text{round}(\text{CVSS} \times 10)$ | Base CVSS v3 score from `vulnerabilities` |
| **Threat Intelligence**| `threat_intelligence` | **0.10 (10%)** | Critical=100, High=80, Medium=50, Low=25 | Reputational score of matching IOC |

### Precision & Rounding Rules
- Factor contributions preserve float precision (e.g., $90 \times 0.25 = 22.5$, $91 \times 0.25 = 22.75$, $98 \times 0.20 = 19.6$).
- The final score is rounded to an integer clamped between 0 and 100.
- **Mentor Acceptance Baseline (Score 93):** An event with Threat Severity=90, ML Confidence=91, Asset Criticality=100, CVSS=98, and Threat Intel=80 produces:
  $$22.5 + 22.75 + 20.0 + 19.6 + 8.0 = 92.85 \longrightarrow \mathbf{93} \quad (\text{Critical}, \text{CRITICAL\_IMMEDIATE})$$

### Risk Levels & Priority Mapping

| Score Range | Risk Level | Priority Rating | SLA / Analyst Action |
|---|---|---|---|
| **81 – 100** | `Critical` | `CRITICAL_IMMEDIATE` | Immediate containment and active threat hunting |
| **61 – 80** | `High` | `HIGH_IMMEDIATE` | Expedited triage within 30 minutes |
| **41 – 60** | `Moderate` | `HIGH` | Standard SOC review queue |
| **21 – 40** | `Medium` | `MEDIUM` | Scheduled review during shift |
| **0 – 20** | `Low` | `LOW` | Informational logging / automated monitoring |

---

## Threat Intelligence IOC Resolution Semantics

Threat intelligence matches against the `threat_intelligence` collection adhere to strict deterministic precedence rules:
1. **Source IP Precedence:** The event `source_ip` is checked first against `threat_intelligence.indicator_value`.
2. **Destination IP Fallback:** If `source_ip` yields no match, `destination_ip` is evaluated.
3. **Precedence Resolution:** If both IPs match records, `source_ip` takes precedence.
4. **Matched Field Tracking:** `ioc_matched_field` records `"source_ip"` or `"destination_ip"`.
5. **Non-Lossy Field Propagation:** All IOC metadata (`ioc_value`, `ioc_matched_field`, `ioc_type`, `ioc_confidence`, `ioc_severity`, `threat_name`, `threat_actor`) propagates without loss from enrichment through incident documents to API and UI.
6. **Clean State:** When no match exists, `ioc_status` is `"Clean"`, `ioc_value` is `None`, and the UI displays a clean "No Threat Intelligence Match" state.

---

## Event Correlation & Attack Chain Detection

- **Correlation Window:** Configurable sliding time window (default **15 minutes**).
- **Pivot Keys:** Events are correlated when sharing strong contextual identifiers: `username`, `source_ip`, or `asset_name`.
- **Chronological Attack Chains:** Detected when correlated events exhibit progressive attack tactics:
  - **Brute Force Chain:** $\ge 2$ failed login attempts followed by a subsequent `Login Success` on the same user/IP.
  - **Privilege Escalation Chain:** `Initial Access` (e.g. Web Exploit) followed chronologically by `Privilege Escalation`.
  - **Data Exfiltration Chain:** Initial access followed by discovery/lateral movement and outbound data exfiltration.
- **Zero Risk Inflation Philosophy:** Event correlation significantly enriches investigation context, visualizes attack progression, and provides related event timelines. It does **not** artificially increase the base 5-factor risk score ($\Delta = 0$), preventing double-counting and maintaining mathematical integrity.

---

## Advanced Milestone 3 Features

### 1. Dynamic Risk Weights
- Allows SOC administrators to adjust factor weights at runtime via REST API.
- **Validation Rules:** All 5 factor weights must be $\ge 0.0$ and $\le 1.0$, and must sum to exactly $1.0 \pm 0.001$.
- **Exact Zero-Value Handling:** Factors set to `0.0` (0%) remain exactly `0.0` and never fall back to default values on save, reload, or modal reopen.
- **Reset Endpoint:** `POST /api/v1/risk/weights/reset` restores factory defaults `(0.25, 0.25, 0.20, 0.20, 0.10)`.
- **Safety Invariant:** Dynamic weights apply only to new calculations; historical incident records are never recalculated.

### 2. Animated Attack Chain Visualization
- Reconstructs chronological adversary progression step-by-step.
- Provides interactive playback controls (play, pause, step forward/back, speed 0.5x/1x/2x, timeline scrubber).
- Renders MITRE tactic indicators, technique badges, and relative time deltas.

### 3. Risk Score Comparison (Before vs After Correlation)
- Renders an explicit Before vs After correlation comparison card.
- Displays `before_correlation` (base 5-factor score), `after_correlation` (base score), `change = 0`, and plain-English justification explaining that correlation expands contextual visibility without score inflation.

### 4. Analyst Feedback Loop & Incident Status Audit Trail
- Structured False Positive feedback modal allowing analysts to categorize false alarms using validated reasons:
  - *Benign administrative activity*, *Expected user behavior*, *Security scanner / automated tool*, *Incorrect threat classification*, *Incorrect enrichment*, *Excessive sensitivity*, *Other*.
- Submitting feedback automatically transitions incident lifecycle status to `False Positive`.
- **Comprehensive Audit Trail (`status_history`):** Every status transition records `{status, changed_by, changed_at, reason}` across incident initialization, analyst PATCH status updates, and False Positive feedback.

---

## Complete M3 REST API Reference

The Milestone 3 backend exposes **12 API endpoints** under `/api/v1/`:

### Core Intelligence APIs (7)

| Endpoint | Method | Request / Query | Response | Description |
|---|---|---|---|---|
| `/api/v1/risk/calculate` | POST | `{"event_id": "EVT000001"}` | `RiskCalculateResponse` | On-demand risk scoring, breakdown, attack chain, and comparison |
| `/api/v1/risk/high` | GET | `min_score=61, limit, skip` | Paginated list | High & Critical priority incidents queue (`total` = true count) |
| `/api/v1/risk/summary` | GET | None | `RiskSummaryResponse` | Executive KPI counts, risk distribution, and 30-day timeline trend |
| `/api/v1/incidents` | GET | `risk_level, threat_type, asset_name, department, mitre_technique, start_date, end_date, status, limit, skip` | Paginated list | 7-facet server-side filtered and paginated incident queue |
| `/api/v1/incidents/{incident_id}` | GET | Path: `incident_id` | `IncidentDocument` | Full incident details with breakdown, IOCs, chain, status history |
| `/api/v1/attack-chains` | GET | `limit, skip` | Paginated list | Incidents with multi-stage attack chains detected (`total` = true count) |
| `/api/v1/recommendations/{incident_id}`| GET | Path: `incident_id` | `List[Recommendation]` | Tailored, non-destructive advisory response recommendations |

### Advanced & Lifecycle APIs (5)

| Endpoint | Method | Request / Query | Response | Description |
|---|---|---|---|---|
| `/api/v1/incidents/{incident_id}/status` | PATCH | `{"status": "...", "changed_by": "...", "reason": "..."}` | `IncidentDocument` | Safely update lifecycle status and record audit entry in `status_history` |
| `/api/v1/incidents/{incident_id}/feedback` | POST | `{"reason": "...", "comment": "...", "analyst": "..."}` | `AnalystFeedbackRecord` | Submit structured False Positive feedback, transition status, and record audit |
| `/api/v1/incidents/{incident_id}/feedback` | GET | Path: `incident_id` | `List[AnalystFeedbackRecord]` | Retrieve historical analyst feedback reviews for an incident |
| `/api/v1/risk/weights` | GET | None | `RiskWeightsModel` | Retrieve currently active risk scoring factor weights |
| `/api/v1/risk/weights` | PUT | `RiskWeightsUpdateRequest` | `RiskWeightsModel` | Update dynamic factor weights (validates sum = 1.0 $\pm 0.001$, supports 0.0 weights) |
| `/api/v1/risk/weights/reset` | POST | None | `RiskWeightsModel` | Reset active risk weights back to default `(0.25, 0.25, 0.20, 0.20, 0.10)` |

---

## Testing & Verification

All M3 components are verified via automated test suites and live validation scripts:

```bash
# 1. Run unit & integration test suites (51 tests)
pytest -q tests/test_risk_engine.py tests/test_m3_backend.py

# 2. Run live validation scripts (requires backend running on port 8000)
python validation/validate_advanced_m3_features.py
python validation/test_status_lifecycle.py
python validation/validate_phase3_frontend_integration.py
python validation/validate_demo_ready.py
```


