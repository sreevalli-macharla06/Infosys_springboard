# Milestone 3 Design — Risk Prioritization & Security Intelligence
**Project:** AI-Assisted Threat Detection Dashboard (Implemented System)
**Implementation Mode:** Solo Development

## 1. Objective
Milestone 3 answers: *How dangerous is the detected threat, which one should be investigated first, why, and what should the analyst consider doing?*

The system implements a deterministic, 5-factor risk scoring engine, correlates suspicious events into attack chains, and generates prioritized, explainable incidents. It strictly extends the existing M1/M2 foundation without modifying prior machine learning models or telemetry data.

## 2. Actual M2 Data Available & Count Semantics
The system consumes data from the existing MongoDB collections (`security_events`, `threat_predictions`, `assets`, `vulnerabilities`, `threat_intelligence`, `mitre_attack_mapping`). No artificial data was generated.

**Database Record Counts & Integrity:**
- `security_events`: Exactly 10,000 canonical security event documents.
- `threat_predictions`: 10,004 prediction documents generated during M2 training/evaluation.
- **Orphan Prediction Records:** There are 4 prediction records without corresponding canonical security events (an existing M2 data artifact).
- **Incident Eligibility Rule:** M3 processes predictions only when a corresponding valid security event exists in `security_events`. The 4 orphan predictions are safely skipped during incident generation.
- **Preservation Invariant:** M3 does NOT modify or delete M2 prediction or security event records; both datasets remain untouched.

## 3. M3 Input Data (M2 → M3 Pipeline Flow)
The incident generation pipeline processes each M2 `threat_prediction` (and its corresponding `security_event`) to construct an internal normalized incident record.
1. Event & Prediction Lookup (Anchor Event identified).
2. Contextual Enrichment (Asset, Vulnerability, MITRE, Threat Intel).
3. Sliding Window Correlation (15-minute window).
4. Attack Chain Progression Detection.
5. Deterministic 5-Factor Risk Scoring.
6. Diagnostic Explainability & Tailored Recommendations Generation.
7. MongoDB Incident Persistence (`incidents` collection).

## 4. Asset Criticality Enrichment
Enrichment resolves against the `assets` collection via `asset_name`.
Criticality is normalized deterministically to 0–100:
- **Critical:** 100
- **High:** 75
- **Medium:** 50
- **Low:** 25

## 5. Vulnerability / CVE Enrichment
Enrichment checks the `vulnerabilities` collection via `vulnerability_id` (CVE-XXX), falling back to event-level `cvss_score` if needed.
CVSS scores are normalized to 0–100 by multiplying by 10 (`cvss_norm = round(cvss_score * 10)`).

## 6. MITRE ATT&CK Enrichment
Event types map deterministically to MITRE techniques via the `mitre_attack_mapping` collection (e.g., `Brute Force` → `T1110`, `Credential Access`).

## 7. Threat Intelligence / IOC Enrichment
Indicators are matched against the `threat_intelligence` collection using a defined lookup precedence:
1. **source_ip** is checked first against `indicator_value`.
2. **destination_ip** is checked if no `source_ip` match exists.
3. If both match different records, `source_ip` takes precedence (documented behavior).
4. The `ioc_matched_field` attribute records which field produced the match (`"source_ip"` or `"destination_ip"`).

**Direct Field Mapping (No Inference or Conflation):**
- `threat_actor`: Mapped directly from `threat_intelligence.threat_actor` (e.g. `"Unknown"`, `"APT-Test-Group"`). It is NEVER derived from confidence or severity.
- `threat_name`: Mapped from `threat_intelligence.threat_name` (e.g. `"Web App Exploitation Campaign"`).
- `ioc_confidence`: Mapped from `threat_intelligence.confidence` (e.g. `"High"`, `"Critical"`).
- `ioc_severity`: Mapped from `threat_intelligence.severity`.
- `threat_score`: Normalized 0–100 score derived from confidence/severity for the risk formula.

## 8. Risk Score Engine & Dynamic Weights

### Mathematical Formulation
The risk engine evaluates a deterministic, 5-factor weighted model clamped between 0 and 100:

$$\text{Risk Score} = \text{round}\Big(\sum_{i=1}^{5} w_i \times v_i\Big)$$

where $v_i \in [0, 100]$ are normalized factor values and $w_i \ge 0$ are factor weights satisfying $\sum_{i=1}^{5} w_i = 1.0 \pm 0.001$.

### Default Weights
- **Threat Severity:** $w_1 = 0.25$ (25%)
- **ML Model Confidence:** $w_2 = 0.25$ (25%)
- **Asset Criticality:** $w_3 = 0.20$ (20%)
- **Vulnerability CVSS:** $w_4 = 0.20$ (20%)
- **Threat Intelligence:** $w_5 = 0.10$ (10%)

- Factor contributions preserve float precision (e.g., $90 \times 0.25 = 22.5$, $91 \times 0.25 = 22.75$, $100 \times 0.20 = 20.0$, $98 \times 0.20 = 19.6$, $80 \times 0.10 = 8.0$).
- The final score is rounded to an integer clamped between 0 and 100.

### Dynamic Risk Weights Configuration
- Administrators can override active weights via `PUT /api/v1/risk/weights` and restore factory defaults via `POST /api/v1/risk/weights/reset`.
- **Validation Rules:** Weights must sum to $1.0 \pm 0.001$, with each factor bounded in $[0.0, 1.0]$.
- **Zero-Value Safe Handling:** Factor weights configured as `0.0` (0%) remain exactly `0.0` and do NOT revert to default weights upon save, fetch, or modal reload (guaranteed via nullish coalescing `??`).
- **Isolation Invariant:** Dynamic weights apply strictly to active evaluations; historical persisted incidents are never mutated or recalculated.

## 9. Risk Classification and Priority
Risk bands and priority mapping:
- **0–20:** Low Risk (Priority: `LOW`)
- **21–40:** Medium Risk (Priority: `MEDIUM`)
- **41–60:** Moderate Risk (Priority: `HIGH`)
- **61–80:** High Risk (Priority: `HIGH_IMMEDIATE`)
- **81–100:** Critical Risk (Priority: `CRITICAL_IMMEDIATE`)

## 10. Event Correlation
Uses a configurable sliding time window (default 15 minutes) to associate independent security events sharing strong context pivots (`username`, `source_ip`, `destination_ip`, `asset_name`).

## 11. Attack Chain Detection & Schema
Identifies multi-stage attack progressions requiring meaningful chronological progression.

**Canonical Chain Types & Validation Rules:**
- **Brute Force Chain:** Requires $\ge 2$ failed/brute-force events + $\ge 1$ `Login Success` occurring AFTER failed attempts. Requires shared username or source_ip. Asset-only match is NOT sufficient.
- **Privilege Escalation Chain:** Requires `Initial Access` $\to$ `Privilege Escalation` in strict chronological order. Requires shared username or source_ip.
- **Data Exfiltration Chain:** Requires `Access Establishment` $\to$ `Discovery/Lateral Movement` (or multi-exfil) $\to$ `Exfiltration` in chronological order. Requires shared username or source_ip.

**Standardized Attack Chain Schema:**
- `attack_chain_id`: Deterministic identifier (e.g. `AC-INC-000058` or `AC-EVT000058`), never random UUIDs.
- `attack_chain_detected`: Boolean flag.
- `attack_chain_type`: Name of detected canonical chain.
- `confidence`: Deterministic correlation/chain detection confidence rating (`"High"` for $\ge 3$ stages / multi-pivot evidence, `"Medium"` for 2 stages). It represents *evidence strength*, NOT statistical probability of attack.
- `description`: Human-readable summary using detection terminology.
- `stages`: Chronologically ordered array of `AttackChainStage` items.
- `event_ids`: Array of participating event IDs.
- `timeline`: Stepper visualization payload.

**Terminology:** "Detected" is used (not "Confirmed" / "Proven") to reflect correlation-based detection.
**Anchor Invariant:** The incident anchor event must participate in the detected chain.

## 12. Correlation Impact & Risk Score Comparison (Before vs After)
- **Zero Score Inflation Philosophy:** Correlation significantly deepens contextual awareness, identifies attack chain progression, and maps related event topology. However, it does NOT artificially inflate or double-count the base 5-factor risk score ($\Delta = 0$).
- **Explainable Comparison Schema:** Every incident provides a `risk_score_comparison` payload:
  - `before_correlation`: Base 5-factor deterministic risk score.
  - `after_correlation`: Equals `before_correlation` ($\Delta = 0$).
  - `change`: `0`.
  - `change_reason`: Plain-English explanation detailing correlated event counts and attack chain findings without artificial inflation.
  - `related_events_count`: Number of correlated security events in the 15-minute sliding window.
  - `attack_chain_detected`: Flag indicating multi-stage progression.
  - `attack_chain_type`: Type of detected attack chain if present.

## 13. Explainable Risk Scoring
Every incident captures its exact factor `contribution` (as floats for precision) and generates human-readable diagnostic `reasons` explaining the score.

## 14. Response Recommendations
Generates advisory-only recommendations tailored to the threat type and attack chain (e.g., "Review authentication logs", "Isolate affected host"). Never performs destructive automated actions.

## 15. Incident Creation & Deduplication
Incidents are stored in the `incidents` MongoDB collection.
Identity is managed via `anchor_event_id` and an array of `event_ids`.
- **Database Invariant:** A unique index on `anchor_event_id` ensures exactly one incident per anchor event.
- The `event_ids` index is non-unique, permitting related events to legitimately appear in multiple incident correlation contexts.

## 16. Incident Lifecycle, Audit Trail & Analyst Feedback Loop
- **Supported Statuses:** `Open`, `Investigating`, `Resolved`, `False Positive`.
- **Comprehensive Status Audit Trail (`status_history`):**
  - Schema: `status`, `changed_by`, `changed_at`, and optional `reason`.
  - Automatically initialized on incident creation (`status: "Open"`, `changed_by: "System"`).
  - Appends an audit entry on every `PATCH /api/v1/incidents/{incident_id}/status` update.
  - Appends an audit entry whenever analyst feedback is submitted.
- **Analyst Feedback Loop (False Positive Review):**
  - Analysts mark false alarms using structured reasons: *Benign administrative activity*, *Expected user behavior*, *Security scanner / automated tool*, *Incorrect threat classification*, *Incorrect enrichment*, *Excessive sensitivity*, *Other*.
  - Submitting feedback via `POST /api/v1/incidents/{incident_id}/feedback` automatically transitions incident status to `False Positive`, logs the feedback record in MongoDB, and records the change in `status_history`.

## 17. M3 REST API Architecture
The M3 backend exposes **12 REST API endpoints** under `/api/v1/`:

### Core M3 Intelligence APIs (7)
1. `POST /api/v1/risk/calculate` — On-demand risk scoring & pipeline evaluation for any `event_id`.
2. `GET /api/v1/risk/high` — High/Critical risk spotlight with true database total count.
3. `GET /api/v1/risk/summary` — Aggregate KPI metrics, risk distributions, and 30-day trends.
4. `GET /api/v1/incidents` — Paginated incident queue with 7-facet server-side filtering.
5. `GET /api/v1/incidents/{incident_id}` — Full incident detail (breakdown, reasons, chain, recommendations, IOCs, audit history).
6. `GET /api/v1/attack-chains` — Multi-stage attack chain feed with true total count.
7. `GET /api/v1/recommendations/{incident_id}` — Tailored advisory response actions.

### Advanced Features & Lifecycle APIs (5)
8. `PATCH /api/v1/incidents/{incident_id}/status` — Lifecycle transition with `changed_by`, `reason`, and `status_history` logging.
9. `POST /api/v1/incidents/{incident_id}/feedback` — Structured False Positive feedback submission.
10. `GET /api/v1/incidents/{incident_id}/feedback` — Feedback review history for an incident.
11. `GET /api/v1/risk/weights` — Current active risk scoring weights.
12. `PUT /api/v1/risk/weights` & `POST /api/v1/risk/weights/reset` — Dynamic weight override and factory reset.

## 18. Frontend Architecture & Screens (React Dashboard)
1. **Risk Overview (`RiskOverview.jsx`):** 8 KPI summary cards, Doughnut risk distribution, Line trend chart, Priority spotlight table, and "Configure Risk Weights" modal trigger.
2. **Priority Incidents (`PriorityIncidents.jsx`):** Data table with 7 server-side filter facets (Risk Level, Threat Type, Asset, Department, MITRE Technique, Date Range, Lifecycle Status).
3. **Incident Investigation (`IncidentDetails.jsx`):** Comprehensive investigation view integrating:
   - Lifecycle Status Dropdown & Action Controls.
   - Risk Factor Breakdown (`RiskBreakdownCard.jsx`).
   - Risk Score Comparison (`RiskScoreComparisonCard.jsx`).
   - Integrated Security Intelligence Card (`SecurityIntelligenceCard.jsx`).
   - Animated Attack Chain Timeline (`AttackChainTimeline.jsx`) with playback controls.
   - Advisory Recommendations Panel (`RecommendationsPanel.jsx`).
   - Analyst Feedback Review (`AnalystFeedbackCard.jsx`).
   - Incident Lifecycle Audit Trail timeline.
   - Correlated Security Events timeline.
4. **Attack Chains Explorer (`AttackChains.jsx`):** Multi-stage progression feed with stage filters and asset details.
5. **Interactive Modals:** `RiskWeightConfigModal.jsx` (with zero-value safety) and `AnalystFeedbackModal.jsx`.

## 19. MongoDB Indexing
- `incident_id_1`: Unique index on `incident_id`.
- `anchor_event_id_1`: **Unique** index on `anchor_event_id` enforcing one incident per anchor.
- `risk_score_-1`, `risk_level_1`, `priority_1`, `status_1`, `asset_id_1`, `department_1`, `mitre_techniques_1`, `created_at_-1`: Performance indexes for 7-facet filtering and sorting.
- `event_ids_1`: Non-unique index for correlation lookups.

## 20. Backend Code Organization
- `risk/` — Pure domain logic: `risk_score.py`, `enrichment.py`, `correlation.py`, `recommendations.py`.
- `services/` — Orchestration: `incident_service.py`, `data_store.py`.
- `database/` — Persistence: `incident_repository.py`, `risk_weights_repository.py`, `mongo_db.py`, `prediction_store.py`.
- `routes/` — FastAPI endpoints: `risk_routes.py`, `incident_routes.py`, M1/M2 routes.
- `models/` — Pydantic schemas: `m3_schemas.py`.

## 21. Solo Development Implementation
Followed sequential build order: Backend Core $\to$ Correlation $\to$ Incidents $\to$ APIs $\to$ Frontend Integration $\to$ Hardening $\to$ Validation.

## 22. End-to-End Acceptance (Mentor Test)
Successfully validates the mentor target acceptance case:
- Threat Severity = 90 (weight 0.25 → 22.5)
- ML Confidence = 91 (weight 0.25 → 22.75)
- Asset Criticality = 100 (weight 0.20 → 20.0)
- Vulnerability CVSS = 98 (weight 0.20 → 19.6)
- Threat Intelligence = 80 (weight 0.10 → 8.0)
- **Total Sum:** $22.5 + 22.75 + 20.0 + 19.6 + 8.0 = 92.85 \to \mathbf{93}$ (`Critical`, `CRITICAL_IMMEDIATE`).

## 23. Testing Strategy
- Unit & integration tests in `tests/test_risk_engine.py` and `tests/test_m3_backend.py` (51 tests) using `pytest` and `mongomock`.
- Validates math precision, risk bands, deduplication, chronological attack chains, IOC source/destination precedence, zero weight factor support, and status history audit trail.

## 24. Known Limitations
- Data Exfiltration patterns are bounded by the fixed M2 event dataset sizes.
- Recommendations are static advisories rather than bidirectional SOAR playbooks.

## 25. Final Definition of Done
The system ingests M2 telemetry, executes deterministic 5-factor risk scoring, reconstructs chronological attack chains, stores deduplicated priority incidents in MongoDB, and serves them to the React frontend UI with granular filtering and rich visualizations, fully satisfying all Milestone 3 specifications.
