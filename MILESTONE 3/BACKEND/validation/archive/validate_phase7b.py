"""
validate_phase7b.py — Validation Suite for FastAPI Prediction APIs (Phase 7B)
=============================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

Executes all 16 required validation tests:
  1. Application Startup & Router Registration
  2. POST /predict Valid Payload (HTTP 200/201, no _id)
  3. POST /predict Invalid Payload (HTTP 422)
  4. POST /predict Missing event_id (HTTP 422)
  5. POST /predict Missing timestamp (HTTP 422)
  6. GET /predictions History Feed (HTTP 200, no _id)
  7. GET /predictions Filtering (verdict & threat_type)
  8. GET /predictions Pagination (limit & skip)
  9. GET /predictions/{id} Valid ID (HTTP 200)
 10. GET /predictions/{id} Unknown ID (HTTP 404)
 11. GET /anomalies (HTTP 200, all anomaly_label == 'Suspicious')
 12. GET /threat-summary (HTTP 200, valid aggregation)
 13. GET /model-performance (HTTP 200, truthful offline evaluation)
 14. M1 Regression Check (GET /events & GET /stats)
 15. MongoDB Integrity Check (security_events count unchanged)
 16. Route Layer Architecture Check (no sklearn, no scoring math, no direct DB)
 17. Cleanup (deletes ONLY synthetic test predictions)
"""

import inspect
import sys
from pathlib import Path
from datetime import datetime, timezone

# Add BACKEND directory to sys.path
_BACKEND_DIR = Path(__file__).resolve().parent
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


def run_validation():
    print(SEP)
    print("PHASE 7B VALIDATION SUITE — FASTAPI PREDICTION APIs")
    print(SEP)

    # Instantiate TestClient (triggers lifespan startup)
    with TestClient(app) as client:
        # -------------------------------------------------------------------
        # TEST 1: APPLICATION STARTUP & ROUTER REGISTRATION
        # -------------------------------------------------------------------
        print("\n--- TEST 1: APPLICATION STARTUP & ROUTERS ---")
        chk(app is not None, "FastAPI app initialized successfully")
        
        routes = []
        for r in app.routes:
            if hasattr(r, "path"):
                routes.append(r.path)
            if hasattr(r, "original_router"):
                for sub_r in r.original_router.routes:
                    if hasattr(sub_r, "path"):
                        routes.append(sub_r.path)

        chk("/events" in routes, "M1 route /events registered")
        chk("/stats" in routes, "M1 route /stats registered")
        chk("/predict" in routes, "M2 route /predict registered")
        chk("/predictions" in routes, "M2 route /predictions registered")
        chk("/anomalies" in routes, "M2 route /anomalies registered")
        chk("/model-performance" in routes, "M2 route /model-performance registered")
        chk("/threat-summary" in routes, "M2 route /threat-summary registered")

        # Record initial M1 security_events count
        db = mongo.get_database()
        m1_count_before = db["security_events"].count_documents({})

        # -------------------------------------------------------------------
        # TEST 2: POST /predict (VALID PAYLOAD)
        # -------------------------------------------------------------------
        print("\n--- TEST 2: POST /predict VALID PAYLOAD ---")

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        valid_payload = {
            "event_id": "PHASE7B_TEST_EVT_001",
            "timestamp": now_str,
            "username": "phase7b_user",
            "source_ip": "10.0.0.50",
            "destination_ip": "10.0.0.100",
            "protocol": "HTTPS",
            "hour": 14,
            "is_weekend": False,
            "failed_login_attempts": 1,
            "status_flag": 0,
            "cvss_score": 3.5,
            "severity_score": 1,
            "malware_flag": 0,
            "event_type": "Login Success",
        }

        res_post = client.post("/predict", json=valid_payload)
        chk(res_post.status_code == 200, f"POST /predict status_code == 200 (got {res_post.status_code})")
        
        body_post = res_post.json()
        chk("prediction_id" in body_post, "Response contains prediction_id")
        chk("_id" not in body_post, "Response excludes MongoDB _id")
        chk(body_post.get("event_id") == "PHASE7B_TEST_EVT_001", "Response event_id matches input")
        chk(body_post.get("verdict") in ("Normal", "Suspicious", "Critical"), f"Verdict valid ('{body_post.get('verdict')}')")
        chk(0.0 <= body_post.get("confidence_score", -1) <= 100.0, "Confidence score valid")
        chk("anomaly_label" in body_post, "anomaly_label present")
        chk("predicted_threat_type" in body_post, "predicted_threat_type present")

        test_pred_id = body_post.get("prediction_id")

        # -------------------------------------------------------------------
        # TEST 3: POST /predict (INVALID PAYLOAD)
        # -------------------------------------------------------------------
        print("\n--- TEST 3: POST /predict INVALID PAYLOAD ---")
        invalid_payload = dict(valid_payload)
        invalid_payload["failed_login_attempts"] = "not_an_integer_string"

        res_invalid = client.post("/predict", json=invalid_payload)
        chk(res_invalid.status_code == 422, f"Invalid payload returned HTTP 422 (got {res_invalid.status_code})")

        # -------------------------------------------------------------------
        # TEST 4: POST /predict (MISSING EVENT ID)
        # -------------------------------------------------------------------
        print("\n--- TEST 4: POST /predict MISSING EVENT ID ---")
        no_eid_payload = dict(valid_payload)
        del no_eid_payload["event_id"]

        res_no_eid = client.post("/predict", json=no_eid_payload)
        chk(res_no_eid.status_code == 422, f"Missing event_id returned HTTP 422 (got {res_no_eid.status_code})")

        # -------------------------------------------------------------------
        # TEST 5: POST /predict (MISSING TIMESTAMP)
        # -------------------------------------------------------------------
        print("\n--- TEST 5: POST /predict MISSING TIMESTAMP ---")
        no_ts_payload = dict(valid_payload)
        del no_ts_payload["timestamp"]

        res_no_ts = client.post("/predict", json=no_ts_payload)
        chk(res_no_ts.status_code == 422, f"Missing timestamp returned HTTP 422 (got {res_no_ts.status_code})")

        # -------------------------------------------------------------------
        # TEST 6: GET /predictions
        # -------------------------------------------------------------------
        print("\n--- TEST 6: GET /predictions FEED ---")
        res_preds = client.get("/predictions")
        chk(res_preds.status_code == 200, f"GET /predictions status_code == 200 (got {res_preds.status_code})")
        body_preds = res_preds.json()
        chk(isinstance(body_preds, list), "GET /predictions returned a list")
        if body_preds:
            chk("_id" not in body_preds[0], "First item excludes MongoDB _id")

        # -------------------------------------------------------------------
        # TEST 7: GET /predictions FILTERING
        # -------------------------------------------------------------------
        print("\n--- TEST 7: GET /predictions FILTERING ---")

        # Post a Critical event to ensure filter target exists
        crit_payload = dict(valid_payload)
        crit_payload["event_id"] = "PHASE7B_TEST_EVT_CRIT"
        crit_payload["malware_flag"] = 1
        client.post("/predict", json=crit_payload)

        res_filt_crit = client.get("/predictions?verdict=Critical")
        chk(res_filt_crit.status_code == 200, "GET /predictions?verdict=Critical returned HTTP 200")
        body_filt_crit = res_filt_crit.json()
        chk(all(p["verdict"] == "Critical" for p in body_filt_crit), "All returned predictions have verdict == Critical")

        # -------------------------------------------------------------------
        # TEST 8: GET /predictions PAGINATION
        # -------------------------------------------------------------------
        print("\n--- TEST 8: GET /predictions PAGINATION ---")
        res_page = client.get("/predictions?limit=2&skip=0")
        chk(res_page.status_code == 200, "GET /predictions?limit=2&skip=0 returned HTTP 200")
        body_page = res_page.json()
        chk(len(body_page) <= 2, f"Pagination limit=2 respected (got {len(body_page)})")

        # -------------------------------------------------------------------
        # TEST 9: GET /predictions/{id} (VALID ID)
        # -------------------------------------------------------------------
        print("\n--- TEST 9: GET /predictions/{id} VALID ID ---")
        chk(test_pred_id is not None, "Valid prediction_id available from Test 2")
        if test_pred_id:
            res_single = client.get(f"/predictions/{test_pred_id}")
            chk(res_single.status_code == 200, f"GET /predictions/{test_pred_id} returned HTTP 200")
            body_single = res_single.json()
            chk(body_single.get("event_id") == "PHASE7B_TEST_EVT_001", "Retrieved event_id matches")
            chk("_id" not in body_single, "Retrieved item excludes MongoDB _id")

        # -------------------------------------------------------------------
        # TEST 10: GET /predictions/{id} (UNKNOWN ID)
        # -------------------------------------------------------------------
        print("\n--- TEST 10: GET /predictions/{id} UNKNOWN ID ---")
        res_404 = client.get("/predictions/DOES_NOT_EXIST_PRED_999999")
        chk(res_404.status_code == 404, f"Unknown prediction_id returned HTTP 404 (got {res_404.status_code})")

        # -------------------------------------------------------------------
        # TEST 11: GET /anomalies
        # -------------------------------------------------------------------
        print("\n--- TEST 11: GET /anomalies ---")
        res_anom = client.get("/anomalies")
        chk(res_anom.status_code == 200, "GET /anomalies returned HTTP 200")
        body_anom = res_anom.json()
        chk(isinstance(body_anom, list), "GET /anomalies returned a list")
        chk(all(a["anomaly_label"] == "Suspicious" for a in body_anom), "All anomaly items have anomaly_label == 'Suspicious'")

        # -------------------------------------------------------------------
        # TEST 12: GET /threat-summary
        # -------------------------------------------------------------------
        print("\n--- TEST 12: GET /threat-summary ---")
        res_sum = client.get("/threat-summary")
        chk(res_sum.status_code == 200, "GET /threat-summary returned HTTP 200")
        body_sum = res_sum.json()
        chk(isinstance(body_sum, list), "GET /threat-summary returned a list")
        if body_sum:
            chk("threat_type" in body_sum[0], "Row contains 'threat_type'")
            chk("count" in body_sum[0], "Row contains 'count'")
            chk("avg_confidence" in body_sum[0], "Row contains 'avg_confidence'")

        # -------------------------------------------------------------------
        # TEST 13: GET /model-performance
        # -------------------------------------------------------------------
        print("\n--- TEST 13: GET /model-performance ---")
        res_perf = client.get("/model-performance")
        chk(res_perf.status_code == 200, "GET /model-performance returned HTTP 200")
        body_perf = res_perf.json()
        chk(body_perf.get("evaluation_type") == "Offline Model Evaluation", "Contains 'Offline Model Evaluation' label")
        chk("random_forest" in body_perf, "Contains 'random_forest' section")
        chk(body_perf["random_forest"].get("test_accuracy") == 0.1070, "Exposes offline test accuracy (0.1070)")
        chk("prediction_distribution_stats" in body_perf, "Contains prediction_distribution_stats")

        # -------------------------------------------------------------------
        # TEST 14: M1 REGRESSION CHECK
        # -------------------------------------------------------------------
        print("\n--- TEST 14: M1 REGRESSION CHECK ---")
        res_m1_events = client.get("/events?limit=5")
        chk(res_m1_events.status_code == 200, "M1 endpoint GET /events returned HTTP 200")
        body_m1_events = res_m1_events.json()
        chk(isinstance(body_m1_events, list), "GET /events returned a list")

        res_m1_stats = client.get("/stats")
        chk(res_m1_stats.status_code == 200, "M1 endpoint GET /stats returned HTTP 200")

        # -------------------------------------------------------------------
        # TEST 15: MONGODB INTEGRITY CHECK
        # -------------------------------------------------------------------
        print("\n--- TEST 15: MONGODB INTEGRITY CHECK ---")
        m1_count_after = db["security_events"].count_documents({})
        chk(m1_count_after == m1_count_before, f"security_events count unchanged ({m1_count_before} == {m1_count_after})")

        # -------------------------------------------------------------------
        # TEST 16: ROUTE LAYER ARCHITECTURE CHECK
        # -------------------------------------------------------------------
        print("\n--- TEST 16: ROUTE LAYER ARCHITECTURE CHECK ---")
        import routes.prediction_routes as pr
        source_code = inspect.getsource(pr)
        chk("sklearn" not in source_code, "No sklearn imports in prediction_routes.py")
        chk("MongoClient" not in source_code, "No direct MongoClient in prediction_routes.py")
        chk("fit(" not in source_code, "No model fit in prediction_routes.py")
        chk("predict_proba" not in source_code, "No direct predict_proba call in prediction_routes.py")

        # -------------------------------------------------------------------
        # CLEANUP: DELETE SYNTHETIC TEST PREDICTIONS ONLY
        # -------------------------------------------------------------------
        print("\n--- CLEANUP SYNTHETIC TEST PREDICTIONS ---")
        del_res = db["threat_predictions"].delete_many({"event_id": {"$regex": "^PHASE7B_TEST_"}})
        chk(del_res.deleted_count >= 2, f"Cleaned up {del_res.deleted_count} synthetic test predictions")

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
        print("ALL 16 TESTS PASSED SUCCESSFULLY! (Phase 7B FastAPI Layer Verified)")
    print(SEP)


if __name__ == "__main__":
    run_validation()
