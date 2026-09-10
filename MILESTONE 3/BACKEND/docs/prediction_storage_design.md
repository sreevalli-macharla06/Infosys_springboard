# M2 Threat Predictions Storage Design
**Version:** 1.0.0  
**Phase:** 6B — Implementation Complete  
**Milestone:** 2 — AI-Based Threat Detection & Anomaly Analysis Engine  
**Status:** IMPLEMENTED

---

## Table of Contents

1. [Existing M1 Database Architecture Findings](#1-existing-m1-database-architecture-findings)
2. [Security Event & Prediction Document Relationship](#2-security-event--prediction-document-relationship)
3. [`threat_predictions` Document Schema](#3-threat_predictions-document-schema)
4. [Model Metadata & Versioning](#4-model-metadata--versioning)
5. [Index Design](#5-index-design)
6. [Future API Query Mapping](#6-future-api-query-mapping)
7. [Duplicate Strategy & Error Handling](#7-duplicate-strategy--error-handling)
8. [Example MongoDB Document](#8-example-mongodb-document)

---

## 1. Existing M1 Database Architecture Findings

Inspection of the Milestone 1 database modules (`mongo_db.py`, `seeder.py`, `data_store.py`, `schemas.py`) establishes the following foundational conventions:

| Component | Finding | Reference File |
|---|---|---|
| **Driver & Connection** | PyMongo `MongoClient` used synchronously (`MongoClient`). Single shared instance `mongo` connected at app startup. | `database/mongo_db.py` |
| **Database Name** | `threat_detection` | `database/mongo_db.py` |
| **Collection Access** | `mongo.get_database()[collection_name]` or `mongo.get_collection(name)` | `database/mongo_db.py` |
| **ObjectId Handling** | Auto-generated `_id` (`ObjectId`). M1 queries project `{"_id": 0}` to strip `ObjectId` for clean PyMongo/Pydantic/DataFrame serialization. | `services/data_store.py` |
| **Error Handling** | Raises `RuntimeError` on connection loss (`ConnectionFailure`, `ServerSelectionTimeoutError`). Startup fails fast if MongoDB is unreachable. | `database/mongo_db.py` |
| **Event Identification** | `event_id` is a string (e.g. `"EVT000001"`). Auto-generated sequentially (`EVT%06d`) if not provided. | `services/data_store.py` |
| **Timestamps** | Formatted string ISO-8601 (e.g., `"2025-08-01 06:00:00"` or UTC ISO string `"2026-08-10T22:40:00Z"`). | `database/seeder.py` |

---

## 2. Security Event & Prediction Document Relationship

The existing `security_events` collection remains the **unmodified source of truth** for raw M1 security telemetry.

```
┌──────────────────────────────────────┐          ┌──────────────────────────────────────────┐
│      security_events collection      │          │       threat_predictions collection      │
├──────────────────────────────────────┤          ├──────────────────────────────────────────┤
│ _id: ObjectId(...)                   │          │ _id: ObjectId(...)                       │
│ event_id: "EVT000185"  ◄─────────────┼──────────┼─ event_id: "EVT000185"                   │
│ timestamp: "2025-08-01 14:30:00"     │          │ prediction_timestamp: "2026-08-10T..."   │
│ source_ip: "192.168.1.100"           │          │ verdict: "Critical"                      │
│ destination_ip: "10.0.0.5"           │          │ confidence_score: 84.8                   │
│ username: "admin"                    │          │ predicted_threat_type: "SQL Inj. Attempt"│
│ event_type: "SQL Injection Attempt"  │          │ anomaly_label: "Suspicious"              │
│ severity: "Critical"                 │          │ anomaly_score: 93.6                      │
│ failed_login_attempts: 20            │          │ rule_score: 90.0                         │
│ malware_flag: 1                      │          │ reasons: [...]                           │
│ status_flag: 1                       │          │ model_metadata: {...}                    │
└──────────────────────────────────────┘          └──────────────────────────────────────────┘
```

- `threat_predictions` does **not** duplicate raw event attributes (IP addresses, department, etc.).
- It links to `security_events` via `event_id`.
- This ensures clean separation: `security_events` contains telemetry; `threat_predictions` contains AI analysis results.

---

## 3. `threat_predictions` Document Schema

MongoDB collection: `threat_predictions`

### Field Definitions & Data Types

| Field | BSON Type | Python Type | Description |
|---|---|---|---|
| `_id` | ObjectId | `ObjectId` | MongoDB primary key (auto-generated) |
| `prediction_id` | String | `str` | Deterministic unique string (`PRED_<event_id>_<timestamp>`) |
| `event_id` | String | `str` | Reference key linking to `security_events.event_id` |
| `prediction_timestamp` | String | `str` | UTC ISO-8601 string (`"YYYY-MM-DDTHH:MM:SSZ"`) of when prediction was computed |
| `verdict` | String | `str` | Final decision: `"Normal"`, `"Suspicious"`, or `"Critical"` |
| `confidence_score` | Double | `float` | Composite threat score `[0.0, 100.0]` (1 decimal place) |
| `predicted_threat_type` | String | `str` | RF Layer 2 predicted category (e.g. `"Brute Force"`) |
| `rf_top_probability` | Double | `float` | Top RF class probability `[0.0, 1.0]` |
| `rf_confidence_note` | String | `str` | Reliability note: `"low"`, `"moderate"`, or `"high"` |
| `anomaly_label` | String | `str` | IF Layer 1 binary output: `"Normal"` or `"Suspicious"` |
| `anomaly_score` | Double | `float` | Normalized IF score `[0.0, 100.0]` (higher = more anomalous) |
| `anomaly_score_raw` | Double | `float` | Raw `decision_function` output (e.g. `-0.055`) |
| `rule_score` | Double | `float` | Capped security rule score `[0.0, 100.0]` |
| `triggered_rules` | Array[String] | `list[str]` | List of fired rule IDs (e.g. `["RULE_MALWARE"]`) |
| `reasons` | Array[Object] | `list[dict]` | Structured array of explainable reason objects |
| `model_signals` | Object | `dict` | Breakdown of component normalized scores for debugging/UI |
| `model_metadata` | Object | `dict` | Locked model artifact & scoring engine versions |

---

## 4. Model Metadata & Versioning

Every prediction document includes a `model_metadata` sub-document capturing exact pipeline version strings:

```json
"model_metadata": {
  "preprocessor_version": "1.5.0",
  "if_model_version": "1.0.0-phase3",
  "clf_model_version": "1.1.0-phase4.6",
  "scoring_design_version": "1.1.0"
}
```

### Version String Definitions

| Metadata Field | Version String | Description |
|---|---|---|
| `preprocessor_version` | `"1.5.0"` | Preprocessing contract v1.5.0 (16 encoded features) |
| `if_model_version` | `"1.0.0-phase3"` | Isolation Forest (Phase 3, contamination=0.1, n_estimators=200, random_state=42) |
| `clf_model_version` | `"1.1.0-phase4.6"` | Random Forest Classifier (Phase 4.6, n_estimators=100, max_depth=15, random_state=42) |
| `scoring_design_version` | `"1.1.0"` | Hybrid Scoring Design Contract v1.1.0 (50/40/10 weighting + overrides) |

These version strings are static constants in the persistence service and are stored with every document to ensure full auditability if models are updated in future milestones.

---

## 5. Index Design

To ensure fast query execution for upcoming API endpoints, the following indexes are specified for `threat_predictions`:

| Index Keys | Direction | Type | Primary Purpose |
|---|---|---|---|
| `[("event_id", 1), ("prediction_timestamp", -1)]` | Compound | Non-Unique | `GET /predictions/{event_id}` (retrieves latest prediction for an event) |
| `[("prediction_timestamp", -1)]` | Single | Non-Unique | `GET /predictions` (chronological feed of predictions) |
| `[("verdict", 1), ("prediction_timestamp", -1)]` | Compound | Non-Unique | `GET /predictions?verdict=Critical` (filtering feed by threat severity) |
| `[("predicted_threat_type", 1)]` | Single | Non-Unique | `GET /threat-summary` (aggregations by predicted threat type) |
| `[("anomaly_label", 1), ("prediction_timestamp", -1)]` | Compound | Non-Unique | `GET /anomalies` (filtering specifically for anomalous events) |

### Duplicate Strategy Decision: Non-Unique `event_id`

`event_id` is **NON-UNIQUE** in `threat_predictions`.

**Rationale:**
- In an M2 monitoring system, an incoming event may be re-scored (e.g. if re-analyzed with updated historical window or batch re-evaluation).
- Treating `threat_predictions` as an **append-only audit log** preserves complete history.
- `GET /predictions/{event_id}` queries `{"event_id": event_id}` sorted by `prediction_timestamp: -1` and limited to 1 to always return the **most recent prediction**.

---

## 6. Future API Query Mapping

The schema directly supports all upcoming Milestone 2 endpoints:

| Endpoint | Target Collection | Primary Query / Aggregation |
|---|---|---|
| `POST /predict` | `threat_predictions` | Inserts new prediction document via `insert_one()` |
| `GET /predictions` | `threat_predictions` | `find(query, {"_id": 0}).sort("prediction_timestamp", -1).limit(limit)` |
| `GET /predictions/{event_id}` | `threat_predictions` | `find_one({"event_id": event_id}, {"_id": 0}, sort=[("prediction_timestamp", -1)])` |
| `GET /anomalies` | `threat_predictions` | `find({"anomaly_label": "Suspicious"}, {"_id": 0}).sort("prediction_timestamp", -1)` |
| `GET /threat-summary` | `threat_predictions` | `aggregate([{"$group": {"_id": "$predicted_threat_type", "count": {"$sum": 1}, "avg_confidence": {"$avg": "$confidence_score"}}}])` |
| `GET /model-performance` | `threat_predictions` | Summarizes `verdict` distributions, average `confidence_score`, and IF anomaly rate (`count(Suspicious) / count(total)`). |

---

## 7. Duplicate Strategy & Error Handling

| Scenario | Deterministic Behavior |
|---|---|
| **Same event predicted twice** | Stored as a new prediction document with a new `prediction_timestamp`. `GET /predictions/{event_id}` returns the latest document by sorting `prediction_timestamp: -1`. |
| **`event_id` does not exist in `security_events`** | Prediction proceeds on incoming payload; document recorded with supplied `event_id`. Warning logged. |
| **Malformed prediction result** | Validated via Pydantic model prior to insertion. Invalid results raise `ValueError` and are rejected before MongoDB call. |
| **MongoDB unavailable** | PyMongo raises `AutoReconnect` / `ServerSelectionTimeoutError`. Operation aborts; route returns HTTP 503. No partial writes. |

---

## 8. Example MongoDB Document

```json
{
  "_id": { "$oid": "66b7c2a1e4b0123456789abc" },
  "prediction_id": "PRED_EVT000185_1786349411",
  "event_id": "EVT000185",
  "prediction_timestamp": "2026-08-10T22:40:00Z",
  "verdict": "Critical",
  "confidence_score": 84.8,
  "predicted_threat_type": "SQL Injection Attempt",
  "rf_top_probability": 0.28,
  "rf_confidence_note": "moderate",
  "anomaly_label": "Suspicious",
  "anomaly_score": 93.6,
  "anomaly_score_raw": -0.055,
  "rule_score": 90.0,
  "triggered_rules": [
    "RULE_MALWARE",
    "RULE_FAILED_LOGINS_HIGH"
  ],
  "reasons": [
    {
      "rule_id": "RULE_MALWARE",
      "reason": "Malware activity detected on this event",
      "points": 50,
      "severity": "Critical"
    },
    {
      "rule_id": "RULE_FAILED_LOGINS_HIGH",
      "reason": "Excessive failed login attempts (18)",
      "points": 40,
      "severity": "High"
    },
    {
      "rule_id": "IF_ANOMALY_SIGNAL",
      "reason": "Isolation Forest flagged this event as anomalous (normalized score: 93.6)",
      "points": 0,
      "severity": "Medium"
    }
  ],
  "model_signals": {
    "if_anomaly_normalized": 93.6,
    "rf_score_normalized": 20.0,
    "rule_score": 90.0
  },
  "model_metadata": {
    "preprocessor_version": "1.5.0",
    "if_model_version": "1.0.0-phase3",
    "clf_model_version": "1.1.0-phase4.6",
    "scoring_design_version": "1.1.0"
  }
}
```

---

*Document created: Phase 6A. Implementation (Phase 6B) completed.*
