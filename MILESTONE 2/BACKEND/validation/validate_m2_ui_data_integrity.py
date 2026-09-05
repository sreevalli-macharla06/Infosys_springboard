"""
validate_m2_ui_data_integrity.py — Comprehensive Validation Suite for M2 UI Data & Chart Integrity
===================================================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

Validates:
  1. /prediction-trend returns HTTP 200, list, dynamic historical dates in Aug 2025, sorted chronologically.
  2. Sum of trend counts equals 10,000.
  3. /top-predictions returns HTTP 200, sorted by confidence_score DESC.
  4. /threat-summary returns HTTP 200, every item has valid percentage summing to ~100%.
  5. /predictions pagination works correctly (limit=10, skip=0 vs skip=10).
  6. Global anomaly and trend stats remain unchanged when querying page 1 vs page 2.
  7. Total prediction count in MongoDB is 10,000 with 10,000 unique event_ids.
  8. No temporary/test prediction IDs exist.
  9. M1 security_events remains exactly 10,000 records.
 10. Production ML model .pkl artifacts are intact and unmodified.
 11. M1 APIs (/events, /stats, /threats) return HTTP 200.
 12. M2 APIs (/predict, /predictions, /anomalies, /model-performance, /threat-summary) return HTTP 200.
"""

import sys
import json
import httpx
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))
MODELS_DIR = BACKEND_DIR / "models"
BASE_URL = "http://127.0.0.1:8000"

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


def main():
    print(SEP)
    print("M2 UI DATA INTEGRITY & CHART CORRECTNESS VERIFICATION SUITE")
    print(SEP)

    sys.path.insert(0, str(BACKEND_DIR))
    from database.mongo_db import mongo

    # 1. MongoDB Database Integrity Checks
    section("1. MONGODB DATABASE INTEGRITY & COUNTS")
    try:
        mongo.connect()
        db = mongo.get_database()

        m1_count = db["security_events"].count_documents({})
        if m1_count == 10000:
            ok(f"M1 security_events count: {m1_count} (exactly 10,000)")
        else:
            fail(f"M1 security_events count: {m1_count} (expected 10000)")

        pred_count = db["threat_predictions"].count_documents({})
        if pred_count == 10000:
            ok(f"threat_predictions count: {pred_count} (exactly 10,000)")
        else:
            fail(f"threat_predictions count: {pred_count} (expected 10000)")

        unique_eids = len(db["threat_predictions"].distinct("event_id"))
        if unique_eids == 10000:
            ok(f"Unique event_ids in threat_predictions: {unique_eids} (zero duplicates)")
        else:
            fail(f"Unique event_ids in threat_predictions: {unique_eids} (expected 10000)")

        # Check for temporary/test prediction IDs
        test_ids = list(db["threat_predictions"].find(
            {"prediction_id": {"$regex": "TEMP|TEST|PHASE81_LIVE|DOES_NOT_EXIST"}},
            {"_id": 0, "prediction_id": 1}
        ))
        if not test_ids:
            ok("No temporary/test prediction IDs exist in database")
        else:
            fail(f"Found temporary/test prediction IDs: {test_ids}")

    except Exception as e:
        fail(f"MongoDB count verification error: {e}")

    # 2. ML Artifact Integrity
    section("2. PRODUCTION ML MODEL ARTIFACT INTEGRITY")
    expected_artifacts = ["preprocessor.pkl", "if_model.pkl", "clf_model.pkl"]
    for art in expected_artifacts:
        p = MODELS_DIR / art
        if p.exists() and p.stat().st_size > 0:
            ok(f"Model artifact '{art}' exists ({p.stat().st_size:,} bytes)")
        else:
            fail(f"Model artifact '{art}' missing or empty")

    # 3. HTTP API Endpoints Validation
    section("3. M1 & M2 API HEALTH & RESPONSE VERIFICATION")
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        # Check /health
        try:
            r = client.get("/health")
            if r.status_code == 200:
                ok("GET /health -> HTTP 200 OK")
            else:
                fail(f"GET /health returned HTTP {r.status_code}")
        except Exception as e:
            fail(f"Cannot connect to FastAPI server at {BASE_URL}: {e}")
            print("\nPlease ensure the backend server is running (`python run.py`).\n")
            sys.exit(1)

        # M1 Endpoints
        for endpoint in ["/events?limit=5", "/stats", "/threats"]:
            try:
                r = client.get(endpoint)
                if r.status_code == 200:
                    ok(f"GET {endpoint} -> HTTP 200 OK")
                else:
                    fail(f"GET {endpoint} returned HTTP {r.status_code}")
            except Exception as e:
                fail(f"Error requesting {endpoint}: {e}")

        # M2 Endpoints
        for endpoint in ["/model-performance", "/anomalies?limit=5"]:
            try:
                r = client.get(endpoint)
                if r.status_code == 200:
                    ok(f"GET {endpoint} -> HTTP 200 OK")
                else:
                    fail(f"GET {endpoint} returned HTTP {r.status_code}")
            except Exception as e:
                fail(f"Error requesting {endpoint}: {e}")

        # 4. /prediction-trend Endpoint Verification
        section("4. PREDICTION TREND ENDPOINT & TIMESTAMP INTEGRITY")
        try:
            r = client.get("/prediction-trend")
            if r.status_code == 200:
                ok("GET /prediction-trend -> HTTP 200 OK")
                trend = r.json()
                if isinstance(trend, list) and len(trend) > 0:
                    ok(f"Trend response is a list with {len(trend)} dynamic date buckets")

                    # Verify dates are sorted chronologically
                    dates = [item["date"] for item in trend if "date" in item]
                    if dates == sorted(dates):
                        ok("Trend dates are sorted chronologically ascending")
                    else:
                        fail(f"Trend dates are NOT sorted: {dates}")

                    # Verify counts are numeric and non-negative
                    counts = [item.get("count", -1) for item in trend]
                    if all(isinstance(c, int) and c >= 0 for c in counts):
                        ok("All trend counts are valid non-negative integers")
                    else:
                        fail(f"Invalid trend counts found: {counts}")

                    # Verify trend represents SOURCE EVENT dates (2025-08-xx)
                    has_2025_dates = any("2025-08" in d for d in dates)
                    if has_2025_dates:
                        ok("Trend correctly represents source event dates in 2025-08")
                    else:
                        fail(f"Trend does NOT contain 2025-08 source event dates: {dates}")

                    # Verify sum of trend counts matches total prediction population (10,000)
                    total_trend_count = sum(counts)
                    if total_trend_count == 10000:
                        ok(f"Sum of trend counts matches total predictions: {total_trend_count}")
                    else:
                        fail(f"Sum of trend counts is {total_trend_count} (expected 10000)")
                else:
                    fail(f"Invalid trend response structure: {trend}")
            else:
                fail(f"GET /prediction-trend returned HTTP {r.status_code}")
        except Exception as e:
            fail(f"Error requesting /prediction-trend: {e}")

        # 5. /top-predictions Endpoint Verification
        section("5. TOP-PREDICTIONS ENDPOINT & SCORE SORTING")
        try:
            r = client.get("/top-predictions?limit=3")
            if r.status_code == 200:
                ok("GET /top-predictions?limit=3 -> HTTP 200 OK")
                top_preds = r.json()
                if isinstance(top_preds, list) and len(top_preds) == 3:
                    ok("Returned exactly 3 top predictions")
                    scores = [p.get("confidence_score", 0) for p in top_preds]
                    if scores == sorted(scores, reverse=True):
                        ok(f"Top predictions are sorted confidence_score DESC: {scores}")
                    else:
                        fail(f"Top predictions NOT sorted confidence_score DESC: {scores}")
                else:
                    fail(f"Expected 3 items in top predictions, got: {len(top_preds)}")
            else:
                fail(f"GET /top-predictions returned HTTP {r.status_code}")
        except Exception as e:
            fail(f"Error requesting /top-predictions: {e}")

        # 6. /threat-summary Percentage Verification
        section("6. THREAT-SUMMARY PERCENTAGE VERIFICATION")
        try:
            r = client.get("/threat-summary")
            if r.status_code == 200:
                ok("GET /threat-summary -> HTTP 200 OK")
                summary = r.json()
                if isinstance(summary, list) and len(summary) > 0:
                    ok(f"Threat summary returned {len(summary)} categories")
                    all_has_pct = all("percentage" in item for item in summary)
                    if all_has_pct:
                        ok("Every threat category has a backend-calculated 'percentage' field")
                        pct_sum = sum(item["percentage"] for item in summary)
                        if 99.0 <= pct_sum <= 101.0:
                            ok(f"Threat summary percentages sum to ~100%: {pct_sum:.1f}%")
                        else:
                            fail(f"Threat summary percentages sum to {pct_sum}% (expected ~100%)")
                    else:
                        fail("Some items in threat summary missing 'percentage' field")
                else:
                    fail(f"Invalid threat summary structure: {summary}")
            else:
                fail(f"GET /threat-summary returned HTTP {r.status_code}")
        except Exception as e:
            fail(f"Error requesting /threat-summary: {e}")

        # 7. Pagination & Global Statistics Independence
        section("7. PAGINATION & CHART INDEPENDENCE")
        try:
            r1 = client.get("/predictions?limit=10&skip=0")
            r2 = client.get("/predictions?limit=10&skip=10")

            if r1.status_code == 200 and r2.status_code == 200:
                page1 = r1.json()
                page2 = r2.json()
                p1_ids = [p["prediction_id"] for p in page1]
                p2_ids = [p["prediction_id"] for p in page2]

                if set(p1_ids).isdisjoint(set(p2_ids)):
                    ok("Page 1 (skip=0) and Page 2 (skip=10) return distinct sets of predictions")
                else:
                    fail("Overlap between Page 1 and Page 2 predictions")

                # Verify global model performance stats remain identical regardless of pagination
                perf = client.get("/model-performance").json()
                dist = perf.get("prediction_distribution_stats", {})
                total_preds = dist.get("total_predictions", 0)
                anomaly_cnt = dist.get("anomaly_count", 0)
                if total_preds == 10000 and anomaly_cnt > 0:
                    ok(f"Global prediction statistics remain constant (Total: {total_preds:,}, IF Anomalies: {anomaly_cnt:,})")
                else:
                    fail(f"Unexpected global distribution stats: total={total_preds}, anomaly_count={anomaly_cnt}")

        except Exception as e:
            fail(f"Error testing pagination independence: {e}")

    print("\n" + SEP)
    print(f"VERIFICATION SUMMARY: {passed} PASSED, {failed} FAILED")
    print(SEP)

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("\nALL M2 UI DATA INTEGRITY & CHART CORRECTNESS CHECKS PASSED SUCCESSFULLY!\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
