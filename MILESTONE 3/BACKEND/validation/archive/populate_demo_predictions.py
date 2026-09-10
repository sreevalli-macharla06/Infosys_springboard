"""
populate_demo_predictions.py — Generate Real Demo Predictions for M2 Dashboard
===============================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

OBJECTIVE:
  Select ~25 representative M1 security events from MongoDB and run each
  through the REAL production prediction pipeline:

      M1 security_events
              ↓
      existing feature engineering / preprocessing
              ↓
      Isolation Forest
              ↓
      Random Forest
              ↓
      hybrid scoring service
              ↓
      prediction_service.predict_event()
              ↓
      prediction_store → MongoDB threat_predictions
              ↓
      FastAPI APIs → React Dashboard

SAFETY:
  - Reads M1 events; does NOT modify them.
  - Skips any event_id that already has a prediction in threat_predictions
    (idempotent — safe to re-run without creating duplicates).
  - Does NOT clean up created predictions (they are the intended demo dataset).
  - Does NOT manipulate model outputs, scores, or verdicts.
"""

import sys
import json
from pathlib import Path

# Ensure BACKEND root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from database.mongo_db import mongo
from services.prediction_service import predict_event

# ── How many representative events to select ──────────────────────────────────
TARGET_COUNT = 25

# ── Event types present in M1 (10 classes, aim for at least 2 per type) ──────
SAMPLE_QUERY_PIPELINE = [
    # Group by event_type, take up to 3 per group, then sample across groups
    {
        "$group": {
            "_id": "$event_type",
            "docs": {"$push": "$$ROOT"},
        }
    },
    {
        "$project": {
            "docs": {"$slice": ["$docs", 3]}
        }
    },
    {"$unwind": "$docs"},
    {"$replaceRoot": {"newRoot": "$docs"}},
    {"$project": {"_id": 0}},
]

SEP = "=" * 65


def build_event_payload(m1_doc: dict) -> dict:
    """
    Map an M1 security_events document to the prediction service payload.
    All fields the pipeline needs are directly present on the M1 document.
    """
    return {
        "event_id":            m1_doc.get("event_id"),
        "timestamp":           str(m1_doc.get("timestamp", "")),
        "username":            m1_doc.get("username", ""),
        "source_ip":           m1_doc.get("source_ip", ""),
        "destination_ip":      m1_doc.get("destination_ip", ""),
        "protocol":            m1_doc.get("protocol", "TCP"),
        "hour":                m1_doc.get("hour", 12),
        "is_weekend":          bool(m1_doc.get("is_weekend", False)),
        "failed_login_attempts": int(m1_doc.get("failed_login_attempts", 0)),
        "status_flag":         int(m1_doc.get("status_flag", 0)),
        "cvss_score":          float(m1_doc.get("cvss_score", 0.0)),
        "severity_score":      int(m1_doc.get("severity_score", 0)),
        "malware_flag":        int(m1_doc.get("malware_flag", 0)),
        "source_country":      m1_doc.get("source_country", "India"),
        "destination_country": m1_doc.get("destination_country", "India"),
        "event_type":          m1_doc.get("event_type", ""),
    }


def main():
    print(SEP)
    print("M2 DEMO PREDICTION POPULATION SCRIPT")
    print(SEP)

    # ── Connect to MongoDB ────────────────────────────────────────────────────
    mongo.connect()
    db = mongo.get_database()

    m1_count = db["security_events"].count_documents({})
    existing_pred_count = db["threat_predictions"].count_documents({})
    print(f"\nM1 security_events count : {m1_count}")
    print(f"Existing threat_predictions : {existing_pred_count}")
    assert m1_count == 10000, f"ABORT: M1 count changed ({m1_count} != 10000)"

    # ── Fetch set of existing prediction event_ids to skip duplicates ─────────
    existing_event_ids = set(
        d["event_id"]
        for d in db["threat_predictions"].find({}, {"_id": 0, "event_id": 1})
        if d.get("event_id")
    )
    print(f"Already-predicted event_ids : {len(existing_event_ids)}")

    # ── Sample representative M1 events (up to 3 per event_type) ─────────────
    sampled_docs = list(db["security_events"].aggregate(SAMPLE_QUERY_PIPELINE))
    print(f"Sampled M1 events (pre-dedup) : {len(sampled_docs)}")

    # Filter out already-predicted events
    to_predict = [
        d for d in sampled_docs
        if d.get("event_id") and d["event_id"] not in existing_event_ids
    ]
    # Trim to TARGET_COUNT
    to_predict = to_predict[:TARGET_COUNT]
    print(f"Events to predict now : {len(to_predict)}")

    if not to_predict:
        print("\nNothing to do — all sampled events already have predictions.")
        mongo.disconnect()
        return

    # ── Run each event through the production pipeline ────────────────────────
    print(f"\n{SEP}")
    print("RUNNING PRODUCTION PREDICTION PIPELINE")
    print(SEP)

    results = []
    skipped = 0
    for i, m1_doc in enumerate(to_predict, 1):
        event_payload = build_event_payload(m1_doc)
        eid = event_payload["event_id"]
        try:
            result = predict_event(event_payload)
            results.append(result)
            verdict  = result.get("verdict", "?")
            conf     = result.get("confidence_score", 0)
            tt       = result.get("predicted_threat_type", "?")
            anomaly  = result.get("anomaly_label", "?")
            print(f"  [{i:02d}] {eid:<12} | {verdict:<10} | {conf:5.1f}% | {tt:<28} | IF={anomaly}")
        except Exception as exc:
            skipped += 1
            print(f"  [{i:02d}] {eid:<12} | SKIPPED ({exc})")

    # ── Summary stats ─────────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("SUMMARY")
    print(SEP)

    total_now = db["threat_predictions"].count_documents({})
    anomaly_count = db["threat_predictions"].count_documents({"anomaly_label": "Suspicious"})
    m1_count_after = db["security_events"].count_documents({})

    print(f"\nPredictions created this run : {len(results)}")
    print(f"Skipped (errors)             : {skipped}")
    print(f"Total threat_predictions now : {total_now}")
    print(f"Anomalies (Suspicious)       : {anomaly_count}")
    print(f"M1 security_events (before)  : {m1_count}")
    print(f"M1 security_events (after)   : {m1_count_after}")
    assert m1_count_after == 10000, "INTEGRITY FAILURE: M1 count changed!"

    if results:
        scores = [r.get("confidence_score", 0) for r in results]
        avg_conf = sum(scores) / len(scores)
        print(f"Average confidence this run  : {avg_conf:.1f}%")

        verdict_dist: dict = {}
        tt_dist: dict = {}
        for r in results:
            v = r.get("verdict", "?")
            verdict_dist[v] = verdict_dist.get(v, 0) + 1
            tt = r.get("predicted_threat_type", "?")
            tt_dist[tt] = tt_dist.get(tt, 0) + 1
        print(f"Verdict distribution         : {verdict_dist}")
        print(f"Threat-type distribution     : {json.dumps(tt_dist, indent=4)}")

    print(f"\n{'=' * 65}")
    print("DEMO PREDICTION POPULATION COMPLETE")
    print(f"{'=' * 65}")

    mongo.disconnect()


if __name__ == "__main__":
    main()
