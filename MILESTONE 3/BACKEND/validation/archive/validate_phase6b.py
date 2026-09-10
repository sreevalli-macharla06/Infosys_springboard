"""
validate_phase6b.py — Validation Suite for M2 Threat Prediction Store (Phase 6B)
=============================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

Executes:
  1. Connects to MongoDB via existing mongo.connect()
  2. Runs ensure_indexes()
  3. Inserts synthetic test predictions with identifiable event IDs (PHASE6B_TEST_*)
  4. Tests get_prediction_by_id() and get_latest_prediction_by_event_id()
  5. Tests list_predictions() with filtering, limit, skip, and newest-first sorting
  6. Tests list_anomalies()
  7. Tests get_threat_summary() aggregation
  8. Tests get_prediction_statistics()
  9. Validates no ObjectId is exposed
 10. CLEANS UP only the synthetic test documents from MongoDB
"""

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Add BACKEND directory to sys.path
_BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_BACKEND_DIR))

from database.mongo_db import mongo
from database.prediction_store import (
    ensure_indexes,
    insert_prediction,
    get_prediction_by_id,
    get_latest_prediction_by_event_id,
    list_predictions,
    list_anomalies,
    get_threat_summary,
    get_prediction_statistics,
    prediction_store,
    COLLECTION_NAME,
)

SEP = "=" * 65
errors = []


def chk(cond: bool, label: str, detail: str = "") -> None:
    tag = "[PASS]" if cond else "[FAIL]"
    print(f"  {tag} {label}")
    if not cond:
        errors.append(f"{label}: {detail}")


def run_validation():
    print(SEP)
    print("PHASE 6B VALIDATION SUITE — THREAT PREDICTION PERSISTENCE")
    print(SEP)

    # 1. Connect to MongoDB
    print("\n--- STEP 1: MONGODB CONNECTION ---")
    try:
        mongo.connect()
        chk(mongo.connected, "Connected to MongoDB via shared mongo instance")
    except Exception as e:
        chk(False, "Connected to MongoDB", f"Error: {e}")
        print("Failed to connect to MongoDB. Make sure MongoDB is running.")
        sys.exit(1)

    # 2. Ensure Indexes
    print("\n--- STEP 2: ENSURE INDEXES ---")
    try:
        ensure_indexes()
        coll = prediction_store.get_collection()
        index_info = coll.index_information()
        chk(len(index_info) >= 5, f"Indexes created (found {len(index_info)})")
    except Exception as e:
        chk(False, "Ensure indexes", f"Error: {e}")

    # 3. Insert Synthetic Prediction Documents
    print("\n--- STEP 3: INSERT SYNTHETIC PREDICTIONS ---")

    now = datetime.now(timezone.utc)
    t1 = (now - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    t2 = (now - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
    t3 = (now - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    t4 = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    synth_1 = {
        "event_id": "PHASE6B_TEST_EVT_001",
        "prediction_timestamp": t1,
        "verdict": "Normal",
        "confidence_score": 12.5,
        "predicted_threat_type": "File Access",
        "rf_top_probability": 0.18,
        "rf_confidence_note": "moderate",
        "anomaly_label": "Normal",
        "anomaly_score": 15.0,
        "anomaly_score_raw": 0.085,
        "rule_score": 0.0,
        "triggered_rules": [],
        "reasons": [],
        "model_signals": {"if_anomaly_normalized": 15.0, "rf_score_normalized": 8.9, "rule_score": 0.0},
    }

    synth_2 = {
        "event_id": "PHASE6B_TEST_EVT_002",
        "prediction_timestamp": t2,
        "verdict": "Suspicious",
        "confidence_score": 55.0,
        "predicted_threat_type": "Brute Force",
        "rf_top_probability": 0.30,
        "rf_confidence_note": "moderate",
        "anomaly_label": "Suspicious",
        "anomaly_score": 75.0,
        "anomaly_score_raw": -0.020,
        "rule_score": 40.0,
        "triggered_rules": ["RULE_FAILED_LOGINS_HIGH"],
        "reasons": [{"rule_id": "RULE_FAILED_LOGINS_HIGH", "reason": "Excessive failed logins", "points": 40, "severity": "High"}],
        "model_signals": {"if_anomaly_normalized": 75.0, "rf_score_normalized": 22.2, "rule_score": 40.0},
    }

    synth_3 = {
        "event_id": "PHASE6B_TEST_EVT_003",
        "prediction_timestamp": t3,
        "verdict": "Critical",
        "confidence_score": 85.0,
        "predicted_threat_type": "Malware Detection",
        "rf_top_probability": 0.45,
        "rf_confidence_note": "moderate",
        "anomaly_label": "Suspicious",
        "anomaly_score": 90.0,
        "anomaly_score_raw": -0.050,
        "rule_score": 70.0,
        "triggered_rules": ["RULE_MALWARE", "RULE_HIGH_SEVERITY"],
        "reasons": [{"rule_id": "RULE_MALWARE", "reason": "Malware activity", "points": 50, "severity": "Critical"}],
        "model_signals": {"if_anomaly_normalized": 90.0, "rf_score_normalized": 38.9, "rule_score": 70.0},
    }

    # Re-prediction for EVT_001 to test latest event lookup & multi-prediction
    synth_1_v2 = {
        "event_id": "PHASE6B_TEST_EVT_001",
        "prediction_timestamp": t4,
        "verdict": "Suspicious",
        "confidence_score": 48.0,
        "predicted_threat_type": "Brute Force",
        "rf_top_probability": 0.25,
        "rf_confidence_note": "moderate",
        "anomaly_label": "Suspicious",
        "anomaly_score": 65.0,
        "anomaly_score_raw": -0.010,
        "rule_score": 20.0,
        "triggered_rules": ["RULE_FAILED_LOGINS_MED"],
        "reasons": [{"rule_id": "RULE_FAILED_LOGINS_MED", "reason": "Elevated logins", "points": 20, "severity": "Medium"}],
        "model_signals": {"if_anomaly_normalized": 65.0, "rf_score_normalized": 16.7, "rule_score": 20.0},
    }

    inserted_1 = insert_prediction(synth_1)
    inserted_2 = insert_prediction(synth_2)
    inserted_3 = insert_prediction(synth_3)
    inserted_1_v2 = insert_prediction(synth_1_v2)

    chk("_id" not in inserted_1, "Inserted result excludes MongoDB _id")
    chk("prediction_id" in inserted_1, "prediction_id generated automatically")
    chk(inserted_1["prediction_id"].startswith("PRED_PHASE6B_TEST_EVT_001_"), "prediction_id has correct format")

    pred_id_1 = inserted_1["prediction_id"]

    # 4. Retrieve by prediction_id
    print("\n--- STEP 4: RETRIEVE BY PREDICTION_ID ---")
    retrieved_1 = get_prediction_by_id(pred_id_1)
    chk(retrieved_1 is not None, f"Retrieved prediction by ID '{pred_id_1}'")
    if retrieved_1:
        chk(retrieved_1["event_id"] == "PHASE6B_TEST_EVT_001", "event_id matches expected")
        chk(retrieved_1["verdict"] == "Normal", "verdict matches expected")
        chk("_id" not in retrieved_1, "Retrieved dict excludes ObjectId _id")

    # 5. Retrieve Latest by event_id
    print("\n--- STEP 5: RETRIEVE LATEST BY EVENT_ID ---")
    latest_evt1 = get_latest_prediction_by_event_id("PHASE6B_TEST_EVT_001")
    chk(latest_evt1 is not None, "Retrieved latest prediction for 'PHASE6B_TEST_EVT_001'")
    if latest_evt1:
        chk(latest_evt1["prediction_timestamp"] == t4, "Returned latest prediction (t4 > t1)")
        chk(latest_evt1["verdict"] == "Suspicious", "Returned latest verdict ('Suspicious')")

    # 6. List Predictions & Filtering
    print("\n--- STEP 6: LIST PREDICTIONS & FILTERING ---")
    all_preds = list_predictions(limit=100)
    test_preds = [p for p in all_preds if p["event_id"].startswith("PHASE6B_TEST_")]
    chk(len(test_preds) == 4, f"4 synthetic predictions returned in feed (found {len(test_preds)})")

    # Verify newest-first ordering
    if len(test_preds) >= 2:
        chk(
            test_preds[0]["prediction_timestamp"] >= test_preds[1]["prediction_timestamp"],
            "Predictions returned in newest-first order",
        )

    # Filter by verdict=Critical
    critical_preds = list_predictions(verdict="Critical", limit=100)
    test_critical = [p for p in critical_preds if p["event_id"].startswith("PHASE6B_TEST_")]
    chk(len(test_critical) == 1, "Verdict filter 'Critical' returned 1 matching test prediction")
    if test_critical:
        chk(test_critical[0]["event_id"] == "PHASE6B_TEST_EVT_003", "Matching event is EVT_003")

    # Filter by threat_type="Brute Force"
    bf_preds = list_predictions(threat_type="Brute Force", limit=100)
    test_bf = [p for p in bf_preds if p["event_id"].startswith("PHASE6B_TEST_")]
    chk(len(test_bf) == 2, "Threat type filter 'Brute Force' returned 2 matching test predictions")

    # Pagination test (limit=2, skip=1)
    page_preds = list_predictions(limit=2, skip=1)
    chk(len(page_preds) <= 2, f"Pagination limit=2 returned {len(page_preds)} predictions")

    # 7. List Anomalies
    print("\n--- STEP 7: LIST ANOMALIES ---")
    anomalies = list_anomalies(limit=100)
    test_anomalies = [a for a in anomalies if a["event_id"].startswith("PHASE6B_TEST_")]
    chk(len(test_anomalies) == 3, f"3 synthetic anomalies returned (found {len(test_anomalies)})")
    for a in test_anomalies:
        chk(a["anomaly_label"] == "Suspicious", "All anomaly results have anomaly_label == 'Suspicious'")

    # 8. Threat Summary Aggregation
    print("\n--- STEP 8: THREAT SUMMARY AGGREGATION ---")
    summary = get_threat_summary()
    chk(isinstance(summary, list), "get_threat_summary() returned a list")
    chk(len(summary) > 0, "Aggregation results present")
    for row in summary:
        chk("threat_type" in row, "Summary row contains 'threat_type'")
        chk("count" in row, "Summary row contains 'count'")
        chk("avg_confidence" in row, "Summary row contains 'avg_confidence'")

    # 9. Prediction Statistics
    print("\n--- STEP 9: PREDICTION STATISTICS ---")
    stats = get_prediction_statistics()
    chk(stats["total_predictions"] >= 4, f"total_predictions >= 4 (got {stats['total_predictions']})")
    chk("anomaly_rate" in stats, "stats contains 'anomaly_rate'")
    chk("average_confidence" in stats, "stats contains 'average_confidence'")

    # 10. CLEANUP (Delete ONLY synthetic test documents)
    print("\n--- STEP 10: CLEANUP SYNTHETIC TEST DOCUMENTS ---")
    del_result = coll.delete_many({"event_id": {"$regex": "^PHASE6B_TEST_"}})
    chk(del_result.deleted_count == 4, f"Cleaned up exactly 4 synthetic test documents (deleted {del_result.deleted_count})")

    # Verify M1 data intact
    events_coll = mongo.get_database()["security_events"]
    m1_count = events_coll.count_documents({})
    chk(m1_count > 0, f"M1 security_events intact ({m1_count:,} records)")

    # -----------------------------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------------------------
    print("\n" + SEP)
    if errors:
        print(f"FAILED: {len(errors)} check(s) failed:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)
    else:
        print("ALL TESTS PASSED SUCCESSFULLY! (Phase 6B Persistence Layer Fully Verified)")
    print(SEP)


if __name__ == "__main__":
    run_validation()
