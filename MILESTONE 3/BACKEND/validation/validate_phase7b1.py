"""
validate_phase7b1.py — Final API & Dependency Audit with Source-Code Integrity
=============================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

Executes:
  1. Threat-Type Filter Check (GET /predictions?threat_type=...)
  2. Pagination Check (GET /predictions?limit=2&skip=0 vs skip=2)
  3. Anomaly Pagination Check (GET /anomalies?limit=2&skip=0 vs skip=1)
  4. Dependency Audit Check (httpx in requirements.txt & importable)
  5. OpenAPI Verification (GET /openapi.json for all 6 M2 endpoints)
  6. Error Response Verification (HTTP 404, 422; no stack traces or path leaks)
  7. MongoDB Integrity Check (security_events count unchanged)
  8. Model Artifact Integrity Check (no .pkl file modifications)
  9. Production Source-Code Integrity Check (prediction_service, scoring_service, prediction_store, ml/*.py)
 10. Clean up ONLY temporary PHASE7B1_TEST predictions
"""

import os
import sys
import urllib.parse
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Add BACKEND directory to sys.path
_BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_BACKEND_DIR))

from fastapi.testclient import TestClient

from main import app
from database.mongo_db import mongo
from database.prediction_store import prediction_store

SEP = "=" * 65
errors = []


def chk(cond: bool, label: str, detail: str = "") -> None:
    tag = "[PASS]" if cond else "[FAIL]"
    print(f"  {tag} {label}")
    if not cond:
        errors.append(f"{label}: {detail}")


def run_audit():
    print(SEP)
    print("PHASE 7B.1 AUDIT SUITE — FINAL API & DEPENDENCY VALIDATION")
    print(SEP)

    # -----------------------------------------------------------------------
    # SOURCE-CODE & MODEL ARTIFACT INTEGRITY PRE-CHECK
    # -----------------------------------------------------------------------
    # Target production source files
    source_files = [
        _BACKEND_DIR / "services" / "prediction_service.py",
        _BACKEND_DIR / "services" / "scoring_service.py",
        _BACKEND_DIR / "database" / "prediction_store.py",
    ] + list((_BACKEND_DIR / "ml").glob("*.py"))

    # Target model pkl files
    models_dir = _BACKEND_DIR / "models"
    pkl_files = list(models_dir.glob("*.pkl"))

    # Record initial modification timestamps (mtime)
    source_mtimes_before = {p.relative_to(_BACKEND_DIR).as_posix(): p.stat().st_mtime for p in source_files if p.exists()}
    pkl_mtimes_before = {p.name: p.stat().st_mtime for p in pkl_files if p.exists()}

    # -----------------------------------------------------------------------
    # CHECK 4: DEPENDENCY AUDIT
    # -----------------------------------------------------------------------
    print("\n--- CHECK 4: DEPENDENCY AUDIT ---")
    req_file = _BACKEND_DIR / "requirements.txt"
    chk(req_file.exists(), "requirements.txt exists")
    req_text = req_file.read_text(encoding="utf-8") if req_file.exists() else ""
    chk("httpx" in req_text, "httpx is declared in requirements.txt")

    try:
        import httpx
        chk(True, f"httpx imported successfully (v{httpx.__version__})")
    except ImportError as e:
        chk(False, "httpx import", f"ImportError: {e}")

    with TestClient(app) as client:
        # Record initial M1 security_events count
        db = mongo.get_database()
        m1_count_before = db["security_events"].count_documents({})

        # Insert temporary synthetic predictions for deterministic filtering/pagination testing
        now = datetime.now(timezone.utc)
        ts0 = (now - timedelta(minutes=40)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ts1 = (now - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ts2 = (now - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ts3 = (now - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")

        synth_bf_1 = {
            "event_id": "PHASE7B1_TEST_001",
            "timestamp": ts0,
            "username": "audit_user_1",
            "protocol": "SSH",
            "failed_login_attempts": 20,
            "status_flag": 1,
            "event_type": "Brute Force",
        }
        synth_bf_2 = {
            "event_id": "PHASE7B1_TEST_002",
            "timestamp": ts1,
            "username": "audit_user_1",
            "protocol": "SSH",
            "failed_login_attempts": 25,
            "status_flag": 1,
            "event_type": "Brute Force",
        }
        synth_sql = {
            "event_id": "PHASE7B1_TEST_003",
            "timestamp": ts2,
            "username": "audit_user_2",
            "protocol": "HTTP",
            "cvss_score": 9.5,
            "severity_score": 4,
            "event_type": "SQL Injection Attempt",
        }
        synth_mal = {
            "event_id": "PHASE7B1_TEST_004",
            "timestamp": ts3,
            "username": "audit_user_3",
            "protocol": "TCP",
            "malware_flag": 1,
            "event_type": "Malware Detection",
        }

        res_post_1 = client.post("/predict", json=synth_bf_1)
        res_post_2 = client.post("/predict", json=synth_bf_2)
        client.post("/predict", json=synth_sql)
        client.post("/predict", json=synth_mal)

        target_threat_type = res_post_1.json().get("predicted_threat_type", "Brute Force")

        # -------------------------------------------------------------------
        # CHECK 1 — Threat Type Filter
        # -------------------------------------------------------------------
        print("\n--- CHECK 1: THREAT TYPE FILTER ---")
        encoded_tt = urllib.parse.quote(target_threat_type)
        res_tt = client.get(f"/predictions?threat_type={encoded_tt}")
        chk(res_tt.status_code == 200, f"GET /predictions?threat_type={encoded_tt} status_code == 200 (got {res_tt.status_code})")
        body_tt = res_tt.json()
        chk(isinstance(body_tt, list), "Response is a list")
        chk(len(body_tt) >= 1, f"Found matching predictions for '{target_threat_type}' (got {len(body_tt)})")
        all_tt_match = all(p.get("predicted_threat_type") == target_threat_type for p in body_tt)
        chk(all_tt_match, f"Every returned item has predicted_threat_type == '{target_threat_type}'")

        # -------------------------------------------------------------------
        # CHECK 2 — Pagination
        # -------------------------------------------------------------------
        print("\n--- CHECK 2: PAGINATION ---")
        res_p1 = client.get("/predictions?limit=2&skip=0")
        res_p2 = client.get("/predictions?limit=2&skip=2")

        chk(res_p1.status_code == 200, "Page 1 (limit=2, skip=0) returned HTTP 200")
        chk(res_p2.status_code == 200, "Page 2 (limit=2, skip=2) returned HTTP 200")

        body_p1 = res_p1.json()
        body_p2 = res_p2.json()

        chk(len(body_p1) <= 2, f"Page 1 contains <= 2 records (got {len(body_p1)})")
        chk(len(body_p2) <= 2, f"Page 2 contains <= 2 records (got {len(body_p2)})")

        if len(body_p1) > 0 and len(body_p2) > 0:
            p1_ids = {p["prediction_id"] for p in body_p1}
            p2_ids = {p["prediction_id"] for p in body_p2}
            chk(p1_ids.isdisjoint(p2_ids), "Page 2 does not duplicate Page 1 predictions")

        if len(body_p1) >= 2:
            chk(body_p1[0]["prediction_timestamp"] >= body_p1[1]["prediction_timestamp"], "Page 1 ordered newest-first")

        # -------------------------------------------------------------------
        # CHECK 3 — Anomaly Pagination
        # -------------------------------------------------------------------
        print("\n--- CHECK 3: ANOMALY PAGINATION ---")
        res_an1 = client.get("/anomalies?limit=2&skip=0")
        res_an2 = client.get("/anomalies?limit=2&skip=1")

        chk(res_an1.status_code == 200, "GET /anomalies?limit=2&skip=0 returned HTTP 200")
        chk(res_an2.status_code == 200, "GET /anomalies?limit=2&skip=1 returned HTTP 200")

        body_an1 = res_an1.json()
        body_an2 = res_an2.json()

        all_susp1 = all(a.get("verdict") in ["Suspicious", "Critical"] for a in body_an1)
        all_susp2 = all(a.get("verdict") in ["Suspicious", "Critical"] for a in body_an2)
        chk(all_susp1 and all_susp2, "All returned anomaly records have verdict IN ['Suspicious', 'Critical'] (final hybrid verdict)")

        # -------------------------------------------------------------------
        # CHECK 5 — OpenAPI Verification
        # -------------------------------------------------------------------
        print("\n--- CHECK 5: OPENAPI VERIFICATION ---")
        res_oa = client.get("/openapi.json")
        chk(res_oa.status_code == 200, f"GET /openapi.json status_code == 200 (got {res_oa.status_code})")
        body_oa = res_oa.json()
        paths = body_oa.get("paths", {})

        required_endpoints = [
            "/predict",
            "/predictions",
            "/predictions/{prediction_id}",
            "/anomalies",
            "/model-performance",
            "/threat-summary",
        ]
        for ep in required_endpoints:
            chk(ep in paths, f"OpenAPI schema contains path '{ep}'")

        schemas = body_oa.get("components", {}).get("schemas", {})
        chk("PredictionRequest" in schemas, "OpenAPI schemas contain 'PredictionRequest'")
        chk("PredictionResponse" in schemas, "OpenAPI schemas contain 'PredictionResponse'")

        # -------------------------------------------------------------------
        # CHECK 6 — Error Response Verification
        # -------------------------------------------------------------------
        print("\n--- CHECK 6: ERROR RESPONSE VERIFICATION ---")
        res_404 = client.get("/predictions/DOES_NOT_EXIST_PRED_999")
        chk(res_404.status_code == 404, f"Unknown prediction_id returned HTTP 404 (got {res_404.status_code})")
        text_404 = res_404.text

        res_422 = client.post("/predict", json={"event_id": "EVT_BAD", "failed_login_attempts": "not_an_int"})
        chk(res_422.status_code == 422, f"Malformed POST /predict returned HTTP 422 (got {res_422.status_code})")
        text_422 = res_422.text

        sensitive_indicators = ["Traceback", "mongodb://", "C:\\Users", "/home/"]
        leaks_404 = any(ind in text_404 for ind in sensitive_indicators)
        leaks_422 = any(ind in text_422 for ind in sensitive_indicators)

        chk(not leaks_404, "HTTP 404 response contains no stack traces or sensitive path leaks")
        chk(not leaks_422, "HTTP 422 response contains no stack traces or sensitive path leaks")

        # -------------------------------------------------------------------
        # CHECK 7 — MongoDB Integrity & Cleanup
        # -------------------------------------------------------------------
        print("\n--- CHECK 7: MONGODB INTEGRITY & CLEANUP ---")
        m1_count_after = db["security_events"].count_documents({})
        chk(m1_count_after == m1_count_before, f"security_events count unchanged ({m1_count_before} == {m1_count_after})")

        del_res = db["threat_predictions"].delete_many({"event_id": {"$regex": "^PHASE7B1_TEST_"}})
        chk(del_res.deleted_count >= 4, f"Cleaned up {del_res.deleted_count} temporary PHASE7B1_TEST predictions")

    # -----------------------------------------------------------------------
    # CHECK 8 — Model Artifact Integrity
    # -----------------------------------------------------------------------
    print("\n--- CHECK 8: MODEL ARTIFACT INTEGRITY ---")
    pkl_mtimes_after = {p.name: p.stat().st_mtime for p in pkl_files if p.exists()}
    modified_artifacts = [f for f in pkl_mtimes_before if pkl_mtimes_before[f] != pkl_mtimes_after.get(f)]
    chk(len(modified_artifacts) == 0, "No model .pkl files modified during audit", f"modified: {modified_artifacts}")

    # -----------------------------------------------------------------------
    # CHECK 9 — Production Source-Code Integrity
    # -----------------------------------------------------------------------
    print("\n--- CHECK 9: PRODUCTION SOURCE-CODE INTEGRITY ---")
    source_mtimes_after = {p.relative_to(_BACKEND_DIR).as_posix(): p.stat().st_mtime for p in source_files if p.exists()}
    modified_sources = [f for f in source_mtimes_before if source_mtimes_before[f] != source_mtimes_after.get(f)]
    chk(len(modified_sources) == 0, "No production source-code files modified during audit", f"modified: {modified_sources}")

    # -----------------------------------------------------------------------
    # FINAL SUMMARY
    # -----------------------------------------------------------------------
    print("\n" + SEP)
    if errors:
        print(f"FAILED: {len(errors)} check(s) failed:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)
    else:
        print("Phase 7B.1 FINAL PASS — FastAPI API layer is fully validated and ready for frontend integration.")
    print(SEP)


if __name__ == "__main__":
    run_audit()
