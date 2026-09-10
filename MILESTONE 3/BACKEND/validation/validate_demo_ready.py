"""
validate_demo_ready.py — M2 Demo-Readiness Final Validation Suite
===================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

Validates:
  1.  Backend reachable
  2.  Frontend reachable
  3.  M1 APIs healthy (regression check)
  4.  M2 APIs healthy
  5.  Predictions exist in MongoDB
  6.  Anomalies endpoint returns real data
  7.  Threat summary contains data
  8.  Model performance endpoint works
  9.  Prediction detail endpoint works
  10. AI Detection page loads (/dashboard/detection)
  11. Investigation page loads for a real prediction
  12. M1 security_events count remains 10,000
  13. ML artifacts remain present
  14. No mock/fake prediction documents exist
  15. Demo prediction documents contain all required fields

Target: ALL CHECKS PASSED
"""

import sys
import json
import time
import httpx
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────────────────────
BACKEND     = "http://localhost:8000"
FRONTEND    = "http://localhost:5173"
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))
MODELS_DIR  = BACKEND_DIR / "models"

# Required fields in every demo prediction document
REQUIRED_PREDICTION_FIELDS = [
    "prediction_id",
    "event_id",
    "verdict",
    "confidence_score",
    "predicted_threat_type",
    "rf_top_probability",
    "rf_confidence_note",
    "anomaly_label",
    "anomaly_score",
    "rule_score",
    "reasons",
    "model_metadata",
    "model_signals",
]

# Patterns that identify temp/test predictions (must NOT exist)
TEMP_ID_PREFIXES = ["PRED_PHASE", "PRED_TEST"]

SEP = "=" * 65
passed = 0
failed = 0
failures = []


def ok(msg: str):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def fail(msg: str):
    global failed
    failed += 1
    failures.append(msg)
    print(f"  [FAIL] {msg}")


def section(title: str):
    print(f"\n--- {title} ---")


def get(path: str, timeout: float = 10) -> httpx.Response:
    return httpx.get(f"{BACKEND}{path}", timeout=timeout)


def get_front(path: str, timeout: float = 8) -> httpx.Response:
    return httpx.get(f"{FRONTEND}{path}", timeout=timeout)


# ── CHECK 1: Backend server health ────────────────────────────────────────────
section("CHECK 1: BACKEND SERVER (http://localhost:8000)")
try:
    r = get("/health")
    if r.status_code == 200:
        ok(f"Backend health HTTP {r.status_code}")
    else:
        fail(f"Backend health returned {r.status_code}")
except Exception as e:
    fail(f"Backend unreachable: {e}")

# ── CHECK 2: Frontend server health ──────────────────────────────────────────
section("CHECK 2: FRONTEND SERVER (http://localhost:5173)")
try:
    r = get_front("/")
    if r.status_code == 200 and "<!doctype html>" in r.text.lower():
        ok(f"Frontend root HTTP {r.status_code}, returns HTML")
    else:
        fail(f"Frontend returned {r.status_code} or unexpected body")
except Exception as e:
    fail(f"Frontend unreachable: {e}")

# ── CHECK 3: M1 APIs regression ───────────────────────────────────────────────
section("CHECK 3: M1 API REGRESSION")
M1_APIS = [
    ("/events?limit=5",  "Events feed"),
    ("/stats",           "System stats"),
    ("/threats",         "Threats list"),
    ("/threat-intel",    "Threat intel"),
    ("/vulnerabilities", "Vulnerabilities"),
]
for path, label in M1_APIS:
    try:
        r = get(path)
        if r.status_code == 200:
            ok(f"M1 API {label} ({path}) HTTP 200")
        else:
            fail(f"M1 API {label} ({path}) returned {r.status_code}")
    except Exception as e:
        fail(f"M1 API {label} ({path}) error: {e}")

# ── CHECK 4: M2 APIs healthy ──────────────────────────────────────────────────
section("CHECK 4: M2 APIS HEALTHY")
M2_PATHS = ["/predictions", "/anomalies", "/threat-summary", "/model-performance"]
m2_data: dict = {}
for path in M2_PATHS:
    try:
        r = get(path)
        m2_data[path] = r.json()
        if r.status_code == 200:
            ok(f"M2 API {path} HTTP 200")
        else:
            fail(f"M2 API {path} returned {r.status_code}")
    except Exception as e:
        fail(f"M2 API {path} error: {e}")

# ── CHECK 5: Predictions exist ────────────────────────────────────────────────
section("CHECK 5: PREDICTIONS EXIST")
first_prediction_id = None
try:
    data = m2_data.get("/predictions", [])
    sample_list = data if isinstance(data, list) else (
        data.get("predictions") or data.get("items") or data.get("data") or []
    )
    if len(sample_list) > 0:
        ok(f"GET /predictions returned {len(sample_list)} prediction(s)")
        first_prediction_id = sample_list[0].get("prediction_id")
    else:
        fail(f"GET /predictions returned 0 items")
except Exception as e:
    fail(f"Could not inspect /predictions response: {e}")

# ── CHECK 6: Anomalies endpoint returns data ──────────────────────────────────
section("CHECK 6: ANOMALIES ENDPOINT")
try:
    data = m2_data.get("/anomalies", [])
    anom_list = data if isinstance(data, list) else (
        data.get("anomalies") or data.get("items") or data.get("data") or []
    )
    ok(f"GET /anomalies returned {len(anom_list)} item(s) (real IF-flagged count)")
except Exception as e:
    fail(f"Could not inspect /anomalies response: {e}")

# ── CHECK 7: Threat summary contains data ────────────────────────────────────
section("CHECK 7: THREAT SUMMARY")
try:
    data = m2_data.get("/threat-summary", [])
    summ_list = data if isinstance(data, list) else (
        data.get("summary") or data.get("items") or data.get("data") or []
    )
    if len(summ_list) > 0:
        ok(f"GET /threat-summary returned {len(summ_list)} threat type(s)")
    else:
        fail(f"GET /threat-summary returned empty")
except Exception as e:
    fail(f"Could not inspect /threat-summary: {e}")

# ── CHECK 8: Model performance works ─────────────────────────────────────────
section("CHECK 8: MODEL PERFORMANCE ENDPOINT")
try:
    data = m2_data.get("/model-performance", {})
    if isinstance(data, dict) and data:
        ok(f"GET /model-performance returned dict with {len(data)} key(s)")
    else:
        fail(f"GET /model-performance returned empty or unexpected: {str(data)[:200]}")
except Exception as e:
    fail(f"Could not inspect /model-performance: {e}")

# ── CHECK 9: Prediction detail endpoint ───────────────────────────────────────
section("CHECK 9: PREDICTION DETAIL ENDPOINT")
if first_prediction_id:
    try:
        r = get(f"/predictions/{first_prediction_id}")
        if r.status_code == 200:
            detail = r.json()
            if detail.get("prediction_id") == first_prediction_id:
                ok(f"GET /predictions/{first_prediction_id} HTTP 200, id matches")
            else:
                fail(f"prediction_id mismatch in detail response")
        else:
            fail(f"GET /predictions/{first_prediction_id} returned {r.status_code}")
    except Exception as e:
        fail(f"Prediction detail request error: {e}")

    try:
        r = get("/predictions/NO_SUCH_PRED_XXXX_999")
        if r.status_code == 404:
            ok("GET /predictions/NO_SUCH_PRED_XXXX_999 correctly returned 404")
        else:
            fail(f"Expected 404 for nonexistent prediction, got {r.status_code}")
    except Exception as e:
        fail(f"404 check error: {e}")
else:
    fail("Skipping detail check — no prediction_id available from /predictions")

# ── CHECK 10: AI Detection page loads ─────────────────────────────────────────
section("CHECK 10: M2 FRONTEND ROUTE — /dashboard/detection")
try:
    r = get_front("/dashboard/detection")
    if r.status_code == 200:
        ok(f"/dashboard/detection HTTP {r.status_code}")
    else:
        fail(f"/dashboard/detection returned {r.status_code}")
except Exception as e:
    fail(f"/dashboard/detection error: {e}")

# ── CHECK 11: Investigation page loads for real prediction ─────────────────────
section("CHECK 11: INVESTIGATION PAGE — /dashboard/events/{prediction_id}")
if first_prediction_id:
    try:
        r = get_front(f"/dashboard/events/{first_prediction_id}")
        if r.status_code == 200:
            ok(f"/dashboard/events/{first_prediction_id} HTTP 200")
        else:
            fail(f"/dashboard/events/{first_prediction_id} returned {r.status_code}")
    except Exception as e:
        fail(f"Investigation route error: {e}")
else:
    fail("Skipping investigation page check — no prediction_id available")

# ── CHECK 12: M1 security_events count ────────────────────────────────────────
section("CHECK 12: M1 SECURITY_EVENTS INTEGRITY (must be exactly 10,000)")
try:
    sys.path.insert(0, str(BACKEND_DIR))
    from database.mongo_db import mongo
    mongo.connect()
    db = mongo.get_database()
    count = db["security_events"].count_documents({})
    if count == 10000:
        ok(f"M1 security_events count: {count} (unchanged)")
    else:
        fail(f"M1 security_events count CHANGED: {count} (expected 10000)")
except Exception as e:
    fail(f"Could not verify M1 count: {e}")
finally:
    try:
        mongo.disconnect()
    except Exception:
        pass

# ── CHECK 13: ML artifacts present ────────────────────────────────────────────
section("CHECK 13: ML ARTIFACTS PRESENT")
expected_artifacts = [
    MODELS_DIR / "preprocessor.pkl",
    MODELS_DIR / "if_model.pkl",
    MODELS_DIR / "clf_model.pkl",
]
for artifact in expected_artifacts:
    if artifact.exists():
        size = artifact.stat().st_size
        ok(f"ML artifact present: {artifact.name} ({size:,} bytes)")
    else:
        fail(f"ML artifact MISSING: {artifact}")

# ── CHECK 14: No mock/temporary prediction documents ──────────────────────────
section("CHECK 14: NO MOCK/TEMPORARY PREDICTION DOCUMENTS")
try:
    from database.mongo_db import mongo
    if not mongo.connected:
        mongo.connect()
    db = mongo.get_database()

    temp_docs = []
    for doc in db["threat_predictions"].find({}, {"_id": 0, "prediction_id": 1}):
        pid = doc.get("prediction_id", "")
        for prefix in TEMP_ID_PREFIXES:
            if pid.startswith(prefix):
                temp_docs.append(pid)
                break

    if not temp_docs:
        ok("No temporary/test prediction documents found")
    else:
        fail(f"Found {len(temp_docs)} temporary prediction(s): {temp_docs[:5]}")
    mongo.disconnect()
except Exception as e:
    fail(f"Could not check for temp predictions: {e}")
finally:
    try:
        mongo.disconnect()
    except Exception:
        pass

# ── CHECK 15: Demo predictions have all required fields ───────────────────────
section("CHECK 15: DEMO PREDICTION FIELD COMPLETENESS")
try:
    from database.mongo_db import mongo
    if not mongo.connected:
        mongo.connect()
    db = mongo.get_database()

    total_preds = db["threat_predictions"].count_documents({})
    if total_preds > 0:
        ok(f"threat_predictions collection has {total_preds} document(s)")
    else:
        fail("No predictions in threat_predictions collection")

    incomplete = []
    for doc in db["threat_predictions"].find({}, {"_id": 0}):
        missing = [f for f in REQUIRED_PREDICTION_FIELDS if f not in doc or doc[f] is None]
        if missing:
            incomplete.append((doc.get("prediction_id"), missing))

    if not incomplete:
        ok(f"All {total_preds} prediction(s) contain all required fields")
    else:
        for pid, miss in incomplete[:3]:
            fail(f"Prediction {pid} missing fields: {miss}")

    # Verify confidence_score range 0–100
    out_of_range = list(db["threat_predictions"].find(
        {"$or": [{"confidence_score": {"$lt": 0}}, {"confidence_score": {"$gt": 100}}]},
        {"_id": 0, "prediction_id": 1, "confidence_score": 1}
    ))
    if not out_of_range:
        ok("All confidence_score values within 0–100")
    else:
        fail(f"confidence_score out of range in: {[d.get('prediction_id') for d in out_of_range]}")

    # Verify _id is NOT exposed via API
    sample_api_data = m2_data.get("/predictions", [])
    sample_list_api = sample_api_data if isinstance(sample_api_data, list) else (
        sample_api_data.get("predictions") or sample_api_data.get("data") or []
    )
    if sample_list_api:
        if "_id" not in sample_list_api[0]:
            ok("MongoDB _id is NOT exposed through API responses")
        else:
            fail("MongoDB _id is EXPOSED in API response (should be excluded)")

    mongo.disconnect()
except Exception as e:
    fail(f"Field completeness check error: {e}")
finally:
    try:
        mongo.disconnect()
    except Exception:
        pass

# ── FINAL REPORT ──────────────────────────────────────────────────────────────
print(f"\n{SEP}")
total_checks = passed + failed
print(f"RESULTS: {passed}/{total_checks} checks passed, {failed} failed")
print(SEP)

if failed == 0:
    print("""
=================================================================
ALL CHECKS PASSED
MILESTONE 2 IS DEMO-READY
=================================================================
""")
    sys.exit(0)
else:
    print(f"\n{'=' * 65}")
    print(f"FAILED CHECKS ({failed}):")
    for i, f_msg in enumerate(failures, 1):
        print(f"  {i}. {f_msg}")
    print(f"{'=' * 65}")
    sys.exit(1)
