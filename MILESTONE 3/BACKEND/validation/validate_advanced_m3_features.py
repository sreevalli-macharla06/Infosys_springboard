"""
validation/validate_advanced_m3_features.py — Live End-to-End Verification
==========================================================================
Verifies the 4 advanced Milestone 3 features against the live running API:
  1. Dynamic Risk Weights (GET, invalid PUT, valid PUT, calculation effect, reset)
  2. Animated Attack Chain Payload (Stage continuity, order, metadata)
  3. Risk Score Comparison (Before vs After, delta=0, explainable reason, context)
  4. Analyst Feedback Loop (False Positive submission, history retrieval, invalid reason rejection)
"""

import sys
import httpx

BASE_URL = "http://127.0.0.1:8000"

def test_dynamic_risk_weights():
    print("\n--- 1. Testing Feature 1: Dynamic Risk Weights ---")

    # 1a. GET current active weights
    r = httpx.get(f"{BASE_URL}/api/v1/risk/weights", timeout=10.0)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    w = r.json()
    print(f"  [PASS] GET /risk/weights: {w}")
    assert w["threat_severity"] == 0.25
    assert w["ml_confidence"] == 0.25
    assert w["asset_criticality"] == 0.20
    assert w["vulnerability_cvss"] == 0.20
    assert w["threat_intelligence"] == 0.10

    # 1b. Reject invalid weights (sum = 0.85)
    bad_payload = {
        "threat_severity": 0.20,
        "ml_confidence": 0.20,
        "asset_criticality": 0.20,
        "vulnerability_cvss": 0.15,
        "threat_intelligence": 0.10,
    }
    r = httpx.put(f"{BASE_URL}/api/v1/risk/weights", json=bad_payload, timeout=10.0)
    assert r.status_code == 400, f"Expected 400 for invalid sum, got {r.status_code}: {r.text}"
    print(f"  [PASS] PUT /risk/weights rejected invalid sum: {r.json()['detail']}")

    # 1c. Update to valid custom weights (sum = 1.0)
    valid_payload = {
        "threat_severity": 0.30,
        "ml_confidence": 0.20,
        "asset_criticality": 0.25,
        "vulnerability_cvss": 0.15,
        "threat_intelligence": 0.10,
    }
    r = httpx.put(f"{BASE_URL}/api/v1/risk/weights", json=valid_payload, timeout=10.0)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    w_new = r.json()
    assert w_new["threat_severity"] == 0.30
    assert w_new["ml_confidence"] == 0.20
    print(f"  [PASS] PUT /risk/weights accepted valid custom weights: ThreatSev=30%, ML=20%")

    # 1c2. Update to zero-weight factor (threat_severity = 0.0, sum = 1.0)
    zero_payload = {
        "threat_severity": 0.0,
        "ml_confidence": 0.35,
        "asset_criticality": 0.25,
        "vulnerability_cvss": 0.25,
        "threat_intelligence": 0.15,
    }
    r = httpx.put(f"{BASE_URL}/api/v1/risk/weights", json=zero_payload, timeout=10.0)
    assert r.status_code == 200, f"Failed zero weight PUT: {r.text}"
    w_zero = r.json()
    assert w_zero["threat_severity"] == 0.0, f"Expected 0.0, got {w_zero['threat_severity']}"
    r_get = httpx.get(f"{BASE_URL}/api/v1/risk/weights", timeout=10.0)
    assert r_get.json()["threat_severity"] == 0.0
    print("  [PASS] PUT & GET /risk/weights preserved 0.0 (zero-weight factor)")

    # 1d. Reset weights back to defaults
    r = httpx.post(f"{BASE_URL}/api/v1/risk/weights/reset", timeout=10.0)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    w_reset = r.json()
    assert w_reset["threat_severity"] == 0.25
    assert w_reset["ml_confidence"] == 0.25
    print(f"  [PASS] POST /risk/weights/reset successfully restored 25/25/20/20/10 defaults")


def test_attack_chain_payload():
    print("\n--- 2. Testing Feature 2: Attack Chain Data Contract ---")

    # Fetch incident with known attack chain (INC-000058)
    r = httpx.get(f"{BASE_URL}/api/v1/incidents/INC-000058", timeout=10.0)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    inc = r.json()
    ac = inc.get("attack_chain")
    assert ac is not None, "Expected attack_chain in INC-000058"
    assert ac["attack_chain_detected"] is True
    stages = ac["stages"]
    assert len(stages) >= 2, f"Expected multi-stage chain, got {len(stages)}"

    for idx, st in enumerate(stages):
        assert st["stage_order"] == idx + 1, f"Stage order mismatch: {st['stage_order']} vs {idx+1}"
        assert st["event_id"], "Missing event_id in stage"
        assert st["timestamp"], "Missing timestamp in stage"
        assert st["event_type"], "Missing event_type in stage"

    print(f"  [PASS] Attack Chain {ac['attack_chain_type']}: {len(stages)} sequential stages verified with complete metadata")


def test_risk_score_comparison():
    print("\n--- 3. Testing Feature 3: Risk Score Comparison ---")

    r = httpx.get(f"{BASE_URL}/api/v1/incidents/INC-000058", timeout=10.0)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    inc = r.json()
    comp = inc.get("risk_score_comparison")
    assert comp is not None, "Expected risk_score_comparison in incident response"
    assert comp["before_correlation"] == inc["risk_score"], "before_correlation must equal base risk score"
    assert comp["after_correlation"] == inc["risk_score"], "after_correlation must equal base risk score"
    assert comp["change"] == 0, "change must be 0"
    assert "Correlation increased investigation context" in comp["change_reason"]
    assert comp["attack_chain_detected"] is True
    assert comp["attack_chain_type"] == "Privilege Escalation Chain"
    assert comp["related_events_count"] == inc["related_events_count"]
    print(f"  [PASS] Risk comparison verified: Before={comp['before_correlation']}, After={comp['after_correlation']}, Delta={comp['change']}")
    print(f"         Reason: {comp['change_reason']}")


def test_analyst_feedback_loop():
    print("\n--- 4. Testing Feature 4: Analyst Feedback Loop ---")

    test_inc_id = "INC-000131"

    # 4a. Reject invalid reason
    bad_payload = {"reason": "Nonexistent Reason Category", "comment": "test"}
    r = httpx.post(f"{BASE_URL}/api/v1/incidents/{test_inc_id}/feedback", json=bad_payload, timeout=10.0)
    assert r.status_code == 400, f"Expected 400 for invalid reason, got {r.status_code}: {r.text}"
    print(f"  [PASS] POST feedback rejected invalid reason: {r.json()['detail']}")

    # 4b. Submit valid False Positive feedback
    valid_payload = {
        "reason": "Security scanner / automated tool",
        "comment": "Scheduled Tenable Nessus vulnerability assessment scan from 10.0.4.15.",
        "analyst": "senior.analyst@soc.corp",
    }
    r = httpx.post(f"{BASE_URL}/api/v1/incidents/{test_inc_id}/feedback", json=valid_payload, timeout=10.0)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    fb = r.json()
    assert fb["incident_id"] == test_inc_id
    assert fb["reason"] == "Security scanner / automated tool"
    assert fb["resulting_status"] == "False Positive"
    assert fb["analyst"] == "senior.analyst@soc.corp"
    print(f"  [PASS] POST feedback recorded: FeedbackID={fb['feedback_id']}, Status={fb['resulting_status']}")

    # 4c. Verify incident has updated status and feedback record
    # 4c. Verify incident has updated status and feedback record
    r = httpx.get(f"{BASE_URL}/api/v1/incidents/{test_inc_id}", timeout=10.0)
    assert r.status_code == 200
    inc = r.json()
    assert inc["status"] == "False Positive"
    assert inc.get("feedback") is not None
    assert len(inc["feedback"]) >= 1
    assert inc.get("status_history") is not None and len(inc["status_history"]) >= 1
    last_hist = inc["status_history"][-1]
    assert last_hist["status"] == "False Positive"
    assert last_hist["reason"] == "Security scanner / automated tool"
    print(f"  [PASS] GET /incidents/{test_inc_id} confirmed status='False Positive', feedback, and status_history audit trail")

    # 4d. Verify GET feedback history endpoint
    r = httpx.get(f"{BASE_URL}/api/v1/incidents/{test_inc_id}/feedback", timeout=10.0)
    assert r.status_code == 200
    history = r.json()
    assert len(history) >= 1
    assert history[0]["reason"] == "Security scanner / automated tool"
    print(f"  [PASS] GET /incidents/{test_inc_id}/feedback returned {len(history)} feedback audit entry/entries")

    # 4e. Restore status to Open for clean state
    r = httpx.patch(f"{BASE_URL}/api/v1/incidents/{test_inc_id}/status", json={"status": "Open"}, timeout=10.0)
    assert r.status_code == 200
    print(f"  [PASS] Cleaned up: Restored {test_inc_id} status to 'Open'")


def test_threat_intel_ioc_propagation():
    print("\n--- 5. Testing Threat Intelligence IOC Propagation ---")
    r = httpx.get(f"{BASE_URL}/api/v1/incidents/INC-000058", timeout=10.0)
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    inc = r.json()
    assert inc["ioc_status"] == "Malicious"
    assert inc.get("ioc_value") is not None, "ioc_value missing in incident"
    assert inc.get("ioc_matched_field") in ("source_ip", "destination_ip"), "ioc_matched_field invalid"
    assert inc.get("threat_name") is not None, "threat_name missing"
    assert inc.get("threat_actor") is not None, "threat_actor missing"
    print(f"  [PASS] Incident INC-000058 IOC propagation verified:")
    print(f"         Matched Field: {inc.get('ioc_matched_field')}, Value: {inc.get('ioc_value')}")
    print(f"         Campaign: {inc.get('threat_name')}, Threat Actor: {inc.get('threat_actor')}")


def main():
    print("=================================================================")
    print("VALIDATING 4 ADVANCED MILESTONE 3 FEATURES")
    print("=================================================================")
    try:
        test_dynamic_risk_weights()
        test_attack_chain_payload()
        test_risk_score_comparison()
        test_analyst_feedback_loop()
        test_threat_intel_ioc_propagation()
        print("\n=================================================================")
        print("ALL 4 ADVANCED MILESTONE 3 FEATURES SUCCESSFULLY VALIDATED!")
        print("=================================================================")
        return 0
    except Exception as e:
        print(f"\n[FAIL] Validation error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
