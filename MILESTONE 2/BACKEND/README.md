# SentinelAI Security — Backend API

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
├── data/           # Source CSV datasets (security_events.csv, etc.)
├── database/       # MongoDB connection manager, seeder, & prediction store
├── docs/           # Architecture design docs (feature_selection.md, scoring_design.md, etc.)
├── ml/             # ML pipeline modules (preprocessing, anomaly detection, classifier, training)
├── models/         # Pydantic schemas & serialized production model artifacts (.pkl)
├── routes/         # FastAPI REST API endpoints (events, stats, predictions, etc.)
├── services/       # Core business logic (prediction_service, scoring_service, data_store)
├── validation/     # Archived phase validation scripts
├── main.py         # FastAPI application factory & route registration
├── run.py          # Application entry point script
└── requirements.txt
```

---

## Prerequisites & Quick Start

### Option 1 (Recommended) — Docker

```bash
docker compose up --build
```

Docker automatically starts MongoDB, initializes datasets, and launches the FastAPI server at `http://localhost:8000`.

### Option 2 — Local Development

**Requirements:** Python 3.9+, MongoDB running locally on port 27017

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run backend server
python run.py
```

Automatic database initialization seeds `security_events` (10,000 records) and indexes on first startup.

---

# Milestone 1 — Core Security Dashboard APIs

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


# Milestone 2 — AI Threat Detection & Anomaly Engine

Milestone 2 integrates an end-to-end Machine Learning pipeline, persistent prediction storage, hybrid explainable scoring, and specialized AI threat intelligence APIs.

## M2 End-to-End Architecture

```
Security Events Telemetry (10,000 Records)
                 │
                 ▼
     Causal Feature Engineering (12 Logical Features)
                 │
                 ▼
      ML Preprocessing (OneHotEncoder → 16 Matrix Columns)
                 │
                 ├─────────────────────────────────┐
                 ▼                                 ▼
   Isolation Forest (Unsupervised)    Random Forest (Supervised)
        (Contamination = 0.10)            (10 Threat Classes)
                 │                                 │
                 ▼                                 ▼
    Anomaly Score / Label (0–100)      Predicted Threat Type / Prob
                 │                                 │
                 └────────────────┬────────────────┘
                                  ▼
                     Hybrid Scoring Scorer Engine
            (50% IF + 40% Security Rules + 10% RF)
                                  │
                                  ▼
                 MongoDB Persistence (threat_predictions)
                                  │
                                  ▼
                       FastAPI REST Services
                                  │
                                  ▼
                    React Threat Detection Dashboard
```

---

## M2 Machine Learning Pipeline & Feature Design

### Feature Engineering (12 Logical Features → 16 Encoded Matrix Columns)
The feature engineering pipeline transforms raw event JSON into a numeric vector ($X$) without data leakage:

1. **12 Logical Input Features (`LOGICAL_FEATURES`):**
   - **Authentication:** `failed_login_attempts` (brute force count), `status_flag` (0=Success/Failed, 1=Blocked/Detected)
   - **Vulnerability:** `cvss_score` (0.0–10.0 rating)
   - **Security Flags:** `severity_score` (1=Low … 4=Critical), `malware_flag` (binary alert)
   - **Time & Calendar:** `hour` (0–23), `is_weekend` (0/1)
   - **Categorical Network:** `protocol` (`HTTP`, `HTTPS`, `SSH`, `TCP`, `SMB`)
   - **Causal Behavior Aggregates:** `events_per_user`, `unique_destination_count`, `after_hours_flag` (outside 08:00–18:00), `impossible_travel_flag` (geo-anomaly indicator evaluated strictly on prior timestamps where $\text{history.timestamp} < \text{current.timestamp}$)

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

The hybrid scoring engine combines unsupervised ML anomalies, deterministic security rules, and supervised soft classification into a unified 0–100 Threat Index:

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

