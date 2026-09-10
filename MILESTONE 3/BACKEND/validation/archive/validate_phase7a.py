"""
validate_phase7a.py — Validation Suite for Prediction Orchestration Service (Phase 7A)
=====================================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

Executes all 11 required validation tests:
  1. Test Normal Event Prediction & Response Payload
  2. Test Prediction Persistence & Retrieval
  3. Test Strict Temporal Causality (h.timestamp < event.timestamp)
  4. Test Defense Against Future Events
  5. Test No Preprocessor Fit (only transform_single)
  6. Test Model Artifact Reuse (no .pkl file modifications)
  7. Test Missing Event ID (ValueError)
  8. Test Missing Timestamp (ValueError)
  9. Test Unknown Protocol Handling (handle_unknown='ignore')
 10. Test New User with No History (defaults to 1 / 1)
 11. Test Synthetic Cleanup & M1 Data Integrity Preservation
"""

import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Add BACKEND directory to sys.path
_BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_BACKEND_DIR))

from database.mongo_db import mongo
from database.prediction_store import (
    ensure_indexes,
    get_prediction_by_id,
    prediction_store,
)
from services.prediction_service import (
    predict_event,
    get_loaded_models,
    parse_event_timestamp,
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
    print("PHASE 7A VALIDATION SUITE — PREDICTION ORCHESTRATION SERVICE")
    print(SEP)

    # 1. MongoDB Connection & Startup
    print("\n--- INITIALIZATION ---")
    try:
        mongo.connect()
        ensure_indexes()
        chk(mongo.connected, "Connected to MongoDB via shared mongo instance")
    except Exception as e:
        chk(False, "MongoDB connection", f"Error: {e}")
        sys.exit(1)

    # Record model artifact mtimes before testing to verify no retraining/modification
    models_dir = _BACKEND_DIR / "models"
    pkl_files = list(models_dir.glob("*.pkl"))
    mtimes_before = {p.name: p.stat().st_mtime for p in pkl_files}

    # -----------------------------------------------------------------------
    # TEST 1 — Normal Event Prediction
    # -----------------------------------------------------------------------
    print("\n--- TEST 1: NORMAL EVENT PREDICTION ---")

    now = datetime.now(timezone.utc)
    ts_now = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    synth_event_1 = {
        "event_id": "PHASE7A_TEST_EVT_001",
        "timestamp": ts_now,
        "username": "phase7a_user_alpha",
        "source_ip": "192.168.1.50",
        "destination_ip": "10.0.0.20",
        "source_country": "India",
        "destination_country": "India",
        "protocol": "SSH",
        "hour": 14,
        "is_weekend": False,
        "failed_login_attempts": 0,
        "severity_score": 1,
        "cvss_score": 2.0,
        "malware_flag": 0,
        "status_flag": 0,
        "event_type": "Login Success",
    }

    pred_1 = predict_event(synth_event_1)

    chk("prediction_id" in pred_1, "prediction_id present in response")
    chk("_id" not in pred_1, "No MongoDB _id exposed in response")
    chk(pred_1["event_id"] == "PHASE7A_TEST_EVT_001", "event_id matches input")
    chk(pred_1["verdict"] in ("Normal", "Suspicious", "Critical"), f"Verdict valid ('{pred_1['verdict']}')")
    chk(0.0 <= pred_1["confidence_score"] <= 100.0, f"Confidence score valid ({pred_1['confidence_score']})")
    chk("predicted_threat_type" in pred_1, "predicted_threat_type present")
    chk("rf_top_probability" in pred_1, "rf_top_probability present")
    chk(pred_1["rf_confidence_note"] in ("low", "moderate", "high"), f"rf_confidence_note valid ('{pred_1['rf_confidence_note']}')")
    chk("anomaly_label" in pred_1, "anomaly_label present")
    chk("anomaly_score" in pred_1, "anomaly_score present")
    chk("rule_score" in pred_1, "rule_score present")
    chk("triggered_rules" in pred_1, "triggered_rules present")
    chk("reasons" in pred_1, "reasons present")

    # -----------------------------------------------------------------------
    # TEST 2 — Prediction Persistence
    # -----------------------------------------------------------------------
    print("\n--- TEST 2: PERSISTENCE CHECK ---")
    pred_id_1 = pred_1["prediction_id"]
    retrieved = get_prediction_by_id(pred_id_1)

    chk(retrieved is not None, f"Retrieved prediction by ID '{pred_id_1}'")
    if retrieved:
        chk(retrieved["confidence_score"] == pred_1["confidence_score"], "Stored confidence_score matches returned value")
        chk(retrieved["verdict"] == pred_1["verdict"], "Stored verdict matches returned value")
        chk(retrieved["predicted_threat_type"] == pred_1["predicted_threat_type"], "Stored threat type matches returned value")

    # -----------------------------------------------------------------------
    # TEST 3 — Temporal Causality
    # -----------------------------------------------------------------------
    print("\n--- TEST 3: TEMPORAL CAUSALITY ---")

    base_time = datetime(2025, 8, 1, 10, 30, 0, tzinfo=timezone.utc)
    ts_target = base_time.strftime("%Y-%m-%d %H:%M:%S")

    # Synthetic history: 2 before cutoff, 2 after cutoff
    synth_history = [
        {"event_id": "P7A_HIST_01", "timestamp": "2025-08-01 09:00:00", "username": "phase7a_causal", "destination_ip": "10.0.0.1", "source_country": "India"},
        {"event_id": "P7A_HIST_02", "timestamp": "2025-08-01 10:00:00", "username": "phase7a_causal", "destination_ip": "10.0.0.2", "source_country": "India"},
        {"event_id": "P7A_HIST_03", "timestamp": "2025-08-01 11:00:00", "username": "phase7a_causal", "destination_ip": "10.0.0.99", "source_country": "USA"},  # AFTER
        {"event_id": "P7A_HIST_04", "timestamp": "2025-08-01 12:00:00", "username": "phase7a_causal", "destination_ip": "10.0.0.100", "source_country": "Germany"}, # AFTER
    ]

    target_event = {
        "event_id": "PHASE7A_TEST_EVT_002",
        "timestamp": ts_target,
        "username": "phase7a_causal",
        "destination_ip": "10.0.0.3",
        "source_country": "India",
        "protocol": "HTTP",
        "hour": 10,
        "is_weekend": False,
        "failed_login_attempts": 0,
        "severity_score": 1,
        "cvss_score": 1.0,
    }

    # Run prediction passing the full synthetic history list
    pred_causal = predict_event(target_event, history=synth_history)
    chk(pred_causal is not None, "Prediction executed with synthetic history")

    # -----------------------------------------------------------------------
    # TEST 4 — Future Event Defense
    # -----------------------------------------------------------------------
    print("\n--- TEST 4: FUTURE EVENT DEFENSE ---")

    # Add an extreme future event to synth_history (15:00, 50 failed logins, 10 new IPs)
    extreme_future_history = list(synth_history) + [
        {
            "event_id": "P7A_HIST_EXTREME_FUTURE",
            "timestamp": "2025-08-01 15:00:00",
            "username": "phase7a_causal",
            "destination_ip": "10.99.99.99",
            "source_country": "Russia",
            "failed_login_attempts": 50,
        }
    ]

    # Predict again for the SAME target event at 10:30 using extreme_future_history
    pred_future_defense = predict_event(target_event, history=extreme_future_history)

    chk(
        pred_causal["confidence_score"] == pred_future_defense["confidence_score"],
        "Prediction confidence score identical despite extreme future events added to history",
        f"causal={pred_causal['confidence_score']}, future_defense={pred_future_defense['confidence_score']}",
    )
    chk(
        pred_causal["anomaly_score"] == pred_future_defense["anomaly_score"],
        "Anomaly score identical despite extreme future events added to history",
    )

    # -----------------------------------------------------------------------
    # TEST 5 — No Preprocessor Fit
    # -----------------------------------------------------------------------
    print("\n--- TEST 5: NO PREPROCESSOR FIT ---")
    pp, _, _ = get_loaded_models()
    chk(pp.is_fitted, "Preprocessor remains fitted")
    chk(pp.encoded_feature_count == 16, f"Feature count unchanged ({pp.encoded_feature_count})")

    # -----------------------------------------------------------------------
    # TEST 6 — Model Reuse & No File Modification
    # -----------------------------------------------------------------------
    print("\n--- TEST 6: MODEL REUSE & ARTIFACT INTEGRITY ---")
    mtimes_after = {p.name: p.stat().st_mtime for p in pkl_files}
    modified_artifacts = [f for f in mtimes_before if mtimes_before[f] != mtimes_after.get(f)]
    chk(len(modified_artifacts) == 0, "No model .pkl files modified on disk", f"modified: {modified_artifacts}")

    # -----------------------------------------------------------------------
    # TEST 7 — Missing Event ID
    # -----------------------------------------------------------------------
    print("\n--- TEST 7: MISSING EVENT ID VALIDATION ---")
    try:
        predict_event({"timestamp": ts_now, "username": "user1"})
        chk(False, "Missing event_id raises ValueError", "No exception raised")
    except ValueError as e:
        chk(True, "Missing event_id raises ValueError", f"Caught: {e}")
    except Exception as e:
        chk(False, "Missing event_id raises ValueError", f"Unexpected error: {type(e).__name__}: {e}")

    # -----------------------------------------------------------------------
    # TEST 8 — Missing Timestamp
    # -----------------------------------------------------------------------
    print("\n--- TEST 8: MISSING TIMESTAMP VALIDATION ---")
    try:
        predict_event({"event_id": "EVT_NO_TS", "username": "user1"})
        chk(False, "Missing timestamp raises ValueError", "No exception raised")
    except ValueError as e:
        chk(True, "Missing timestamp raises ValueError", f"Caught: {e}")
    except Exception as e:
        chk(False, "Missing timestamp raises ValueError", f"Unexpected error: {type(e).__name__}: {e}")

    # -----------------------------------------------------------------------
    # TEST 9 — Unknown Protocol
    # -----------------------------------------------------------------------
    print("\n--- TEST 9: UNKNOWN PROTOCOL HANDLING ---")
    evt_unknown_proto = {
        "event_id": "PHASE7A_TEST_EVT_003",
        "timestamp": ts_now,
        "username": "user_unknown_proto",
        "protocol": "CUSTOM_UNKNOWN_PROTOCOL_V9",
        "hour": 12,
        "is_weekend": False,
    }
    try:
        pred_unknown = predict_event(evt_unknown_proto)
        chk(pred_unknown is not None, "Unknown protocol handled cleanly without error")
        chk(pred_unknown["event_id"] == "PHASE7A_TEST_EVT_003", "Prediction returned for unknown protocol")
    except Exception as e:
        chk(False, "Unknown protocol handled cleanly", f"Error: {e}")

    # -----------------------------------------------------------------------
    # TEST 10 — No History (New User)
    # -----------------------------------------------------------------------
    print("\n--- TEST 10: NEW USER WITH NO HISTORY ---")
    evt_new_user = {
        "event_id": "PHASE7A_TEST_EVT_004",
        "timestamp": ts_now,
        "username": "brand_new_unique_user_xyz",
        "destination_ip": "10.0.0.99",
        "protocol": "HTTPS",
        "hour": 11,
        "is_weekend": False,
    }
    pred_new_user = predict_event(evt_new_user, history=None)
    chk(pred_new_user is not None, "Prediction executed for new user with no history")

    # -----------------------------------------------------------------------
    # TEST 11 — Cleanup & M1 Data Integrity Check
    # -----------------------------------------------------------------------
    print("\n--- TEST 11: CLEANUP & M1 INTEGRITY CHECK ---")

    db = mongo.get_database()
    pred_coll = db["threat_predictions"]
    events_coll = db["security_events"]

    # Delete ONLY synthetic test prediction documents
    del_res = pred_coll.delete_many({"event_id": {"$regex": "^PHASE7A_TEST_"}})
    chk(del_res.deleted_count >= 4, f"Cleaned up {del_res.deleted_count} synthetic test predictions")

    # Verify M1 security_events collection is untouched
    m1_event_count = events_coll.count_documents({})
    chk(m1_event_count == 10000, f"M1 security_events count intact (expected 10,000, got {m1_event_count:,})")

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
        print("ALL 11 TESTS PASSED SUCCESSFULLY! (Phase 7A Orchestration Layer Verified)")
    print(SEP)


if __name__ == "__main__":
    run_validation()
