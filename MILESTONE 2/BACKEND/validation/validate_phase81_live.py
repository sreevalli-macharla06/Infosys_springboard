"""
validate_phase81_live.py — End-to-End Live Verification Suite for Phase 8.1
==========================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

Verifies live running servers:
  Backend: http://localhost:8000
  Frontend: http://localhost:5173
"""

import sys
import json
import httpx
from pathlib import Path
from datetime import datetime, timezone

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

SEP = "=" * 65
errors = []

def chk(cond: bool, label: str, detail: str = "") -> None:
    tag = "[PASS]" if cond else "[FAIL]"
    print(f"  {tag} {label}")
    if not cond:
        errors.append(f"{label}: {detail}")

def run_live_verification():
    print(SEP)
    print("PHASE 8.1 LIVE END-TO-END VERIFICATION SUITE")
    print(SEP)

    client = httpx.Client(timeout=10.0)

    # 1. Backend Server Check
    print("\n--- STEP 1: BACKEND SERVER CHECK (http://localhost:8000) ---")
    try:
        res_h = client.get("http://localhost:8000/health")
        chk(res_h.status_code == 200, f"Backend health endpoint HTTP 200 (got {res_h.status_code})")
    except Exception as e:
        chk(False, "Backend server connect", str(e))

    # 2. Frontend Server Check
    print("\n--- STEP 2: FRONTEND SERVER CHECK (http://localhost:5173) ---")
    try:
        res_f = client.get("http://localhost:5173/")
        chk(res_f.status_code == 200, f"Frontend root HTTP 200 (got {res_f.status_code})")
        chk("SentinelAI" in res_f.text or "vite" in res_f.text.lower(), "Frontend index.html returned cleanly")
    except Exception as e:
        chk(False, "Frontend server connect", str(e))

    # 3. M1 Route Verification (Frontend Dev Server HTML serving)
    print("\n--- STEP 3: M1 ROUTE REGRESSION CHECK ---")
    m1_routes = [
        "/dashboard",
        "/dashboard/events",
        "/dashboard/threat-intel",
        "/dashboard/vulnerabilities",
        "/dashboard/analytics",
    ]
    for r in m1_routes:
        try:
            res = client.get(f"http://localhost:5173{r}")
            chk(res.status_code == 200, f"M1 route {r} returned HTTP 200")
        except Exception as e:
            chk(False, f"M1 route {r}", str(e))

    # 4. M1 Backend APIs Check
    print("\n--- STEP 4: M1 BACKEND APIs CHECK ---")
    m1_apis = [
        ("/events?limit=5", "Events feed"),
        ("/stats", "System stats"),
        ("/threats", "Threats list"),
        ("/threat-intel", "Threat intel"),
        ("/vulnerabilities", "Vulnerabilities list"),
    ]
    for endpoint, label in m1_apis:
        try:
            res = client.get(f"http://localhost:8000{endpoint}")
            chk(res.status_code == 200, f"M1 Backend API {label} ({endpoint}) returned HTTP 200")
        except Exception as e:
            chk(False, f"M1 Backend API {endpoint}", str(e))

    # 5. M2 Frontend Route Verification
    print("\n--- STEP 5: M2 FRONTEND ROUTE CHECK ---")
    m2_routes = [
        "/dashboard/detection",
        "/dashboard/events/PRED_TEST_999",
    ]
    for r in m2_routes:
        try:
            res = client.get(f"http://localhost:5173{r}")
            chk(res.status_code == 200, f"M2 route {r} returned HTTP 200")
        except Exception as e:
            chk(False, f"M2 route {r}", str(e))

    # 6. M2 Backend Real API Verification
    print("\n--- STEP 6: M2 BACKEND REAL APIs CHECK ---")
    m2_apis = [
        ("/predictions", "Predictions feed"),
        ("/anomalies", "Anomalies feed"),
        ("/threat-summary", "Threat summary"),
        ("/model-performance", "Model performance"),
    ]
    api_responses = {}
    for endpoint, label in m2_apis:
        try:
            res = client.get(f"http://localhost:8000{endpoint}")
            chk(res.status_code == 200, f"M2 API {label} ({endpoint}) returned HTTP 200")
            if res.status_code == 200:
                api_responses[endpoint] = res.json()
        except Exception as e:
            chk(False, f"M2 API {endpoint}", str(e))

    # Create 1 test prediction to ensure live data exists for detail testing
    print("\n--- STEP 7: POST /predict & GET /predictions/{id} CHECK ---")
    test_event = {
        "event_id": "PHASE81_LIVE_EVT_001",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "username": "live_test_user",
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.1",
        "protocol": "SSH",
        "failed_login_attempts": 15,
        "status_flag": 1,
        "cvss_score": 7.5,
        "severity_score": 3,
        "malware_flag": 0,
        "event_type": "Brute Force"
    }

    try:
        res_p = client.post("http://localhost:8000/predict", json=test_event)
        chk(res_p.status_code == 200, f"POST /predict returned HTTP 200 (got {res_p.status_code})")
        pred_data = res_p.json()
        pred_id = pred_data.get("prediction_id")
        chk(pred_id is not None, f"Prediction response contains prediction_id ({pred_id})")

        if pred_id:
            res_get = client.get(f"http://localhost:8000/predictions/{encode_param(pred_id)}")
            chk(res_get.status_code == 200, f"GET /predictions/{pred_id} returned HTTP 200")
            get_data = res_get.json()

            # Verify schema & fields
            chk(get_data.get("verdict") in ["Normal", "Suspicious", "Critical"], f"Verdict valid ('{get_data.get('verdict')}')")
            chk(isinstance(get_data.get("confidence_score"), (int, float)), "confidence_score is numeric")
            chk(isinstance(get_data.get("rf_top_probability"), (int, float)), "rf_top_probability is numeric")
            chk(get_data.get("rf_confidence_note") in ["low", "moderate", "high"], "rf_confidence_note valid")
            chk("reasons" in get_data and isinstance(get_data["reasons"], list), "reasons is a list")
            chk("model_metadata" in get_data and "preprocessor_version" in get_data["model_metadata"], "model_metadata present")

            # Check distinction between hybrid confidence score and RF top probability
            chk(get_data.get("confidence_score") != get_data.get("rf_top_probability"), "Hybrid confidence_score is distinct from rf_top_probability")

            # Verify IF_ANOMALY_SIGNAL points=0 if present
            if_reasons = [r for r in get_data.get("reasons", []) if r.get("rule_id") == "IF_ANOMALY_SIGNAL"]
            if if_reasons:
                chk(if_reasons[0].get("points") == 0, "IF_ANOMALY_SIGNAL reason has points == 0")
    except Exception as e:
        chk(False, "POST /predict & GET /predictions/{id}", str(e))

    # 8. Not Found 404 Check
    print("\n--- STEP 8: 404 NOT FOUND CHECK ---")
    try:
        res_404 = client.get("http://localhost:8000/predictions/DOES_NOT_EXIST_PRED_999")
        chk(res_404.status_code == 404, f"GET /predictions/DOES_NOT_EXIST_PRED_999 returned HTTP 404 (got {res_404.status_code})")
    except Exception as e:
        chk(False, "404 Not Found Check", str(e))

    # 9. Cleanup Synthetic Test Prediction
    print("\n--- STEP 9: CLEANUP & SUMMARY ---")
    try:
        from database.mongo_db import mongo
        mongo.connect()
        db = mongo.get_database()
        del_res = db["threat_predictions"].delete_many({"event_id": "PHASE81_LIVE_EVT_001"})
        chk(del_res.deleted_count >= 1, f"Cleaned up {del_res.deleted_count} live test prediction(s)")
        mongo.disconnect()
    except Exception as e:
        chk(False, "Cleanup test prediction", str(e))

    print("\n" + SEP)
    if errors:
        print(f"FAILED: {len(errors)} check(s) failed:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)
    else:
        print("PHASE 8.1 PASS — M2 frontend is verified end-to-end against the live backend.")
    print(SEP)

def encode_param(p: str) -> str:
    import urllib.parse
    return urllib.parse.quote(p, safe="")

if __name__ == "__main__":
    run_live_verification()
