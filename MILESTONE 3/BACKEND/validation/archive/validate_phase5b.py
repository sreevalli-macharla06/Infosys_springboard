"""
validate_phase5b.py — Validation Suite for Hybrid Scoring Service (Phase 5B)
========================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

Executes:
  1. All 8 deterministic scoring scenarios from scoring_design.md v1.1.0
  2. Boundary tests for RF confidence thresholds (0.149, 0.150, 0.499, 0.500)
  3. Anomaly normalization formula & clipping tests
  4. Hard-override tests (malware_flag=1, impossible_travel_flag=1)
"""

import sys
from pathlib import Path

# Add BACKEND directory to sys.path
_BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_BACKEND_DIR))

from services.scoring_service import (
    calculate_hybrid_score,
    compute_rf_signal,
    normalize_anomaly_score,
    IF_SCORE_MAX,
    IF_SCORE_MIN,
)

SEP = "=" * 65
errors = []


def chk(cond: bool, label: str, detail: str = "") -> None:
    tag = "[PASS]" if cond else "[FAIL]"
    print(f"  {tag} {label}")
    if not cond:
        errors.append(f"{label}: {detail}")


def run_tests():
    print(SEP)
    print("PHASE 5B VALIDATION SUITE — HYBRID SCORING SERVICE")
    print(SEP)

    # -----------------------------------------------------------------------
    # TEST GROUP 1: Anomaly Normalization
    # -----------------------------------------------------------------------
    print("\n--- TEST GROUP 1: ANOMALY NORMALIZATION & CLIPPING ---")

    n_min = normalize_anomaly_score(IF_SCORE_MIN)
    chk(abs(n_min - 100.0) < 1e-5, "IF_SCORE_MIN yields 100.0", f"got {n_min}")

    n_max = normalize_anomaly_score(IF_SCORE_MAX)
    chk(abs(n_max - 0.0) < 1e-5, "IF_SCORE_MAX yields 0.0", f"got {n_max}")

    n_below = normalize_anomaly_score(-0.150)
    chk(n_below == 100.0, "Raw score below MIN clipped to 100.0", f"got {n_below}")

    n_above = normalize_anomaly_score(0.250)
    chk(n_above == 0.0, "Raw score above MAX clipped to 0.0", f"got {n_above}")

    # -----------------------------------------------------------------------
    # TEST GROUP 2: RF Confidence Thresholds & Normalization
    # -----------------------------------------------------------------------
    print("\n--- TEST GROUP 2: RF CONFIDENCE THRESHOLDS ---")

    s_a, note_a = compute_rf_signal(0.149)
    chk(note_a == "low", "top_prob = 0.149 -> 'low'", f"got {note_a}")

    s_b, note_b = compute_rf_signal(0.150)
    chk(note_b == "moderate", "top_prob = 0.150 -> 'moderate'", f"got {note_b}")

    s_c, note_c = compute_rf_signal(0.499)
    chk(note_c == "moderate", "top_prob = 0.499 -> 'moderate'", f"got {note_c}")

    s_d, note_d = compute_rf_signal(0.500)
    chk(note_d == "high", "top_prob = 0.500 -> 'high'", f"got {note_d}")

    # -----------------------------------------------------------------------
    # TEST GROUP 3: Hard Overrides
    # -----------------------------------------------------------------------
    print("\n--- TEST GROUP 3: HARD OVERRIDES ---")

    # Malware flag override test on a low-score event
    low_event = {
        "event_id": "EVT_OVERRIDE_1",
        "malware_flag": 1,
        "failed_login_attempts": 0,
        "severity_score": 1,
        "cvss_score": 1.0,
    }
    res_malware = calculate_hybrid_score(
        event=low_event,
        if_raw_score=0.100,  # very normal
        if_anomaly_label="Normal",
        rf_predicted_type="File Access",
        rf_top_prob=0.12,
    )
    chk(
        res_malware["confidence_score"] >= 65.0,
        "malware_flag=1 floors score to >= 65.0",
        f"got {res_malware['confidence_score']}",
    )
    chk(
        res_malware["verdict"] == "Critical",
        "malware_flag=1 forces verdict == 'Critical'",
        f"got {res_malware['verdict']}",
    )

    # Impossible travel override test on a low-score event
    travel_event = {
        "event_id": "EVT_OVERRIDE_2",
        "malware_flag": 0,
        "impossible_travel_flag": 1,
        "failed_login_attempts": 0,
        "severity_score": 1,
        "cvss_score": 1.0,
    }
    res_travel = calculate_hybrid_score(
        event=travel_event,
        if_raw_score=0.100,  # very normal
        if_anomaly_label="Normal",
        rf_predicted_type="Login Success",
        rf_top_prob=0.12,
    )
    chk(
        res_travel["confidence_score"] >= 35.0,
        "impossible_travel_flag=1 floors score to >= 35.0",
        f"got {res_travel['confidence_score']}",
    )
    chk(
        res_travel["verdict"] in ("Suspicious", "Critical"),
        "impossible_travel_flag=1 forces verdict != 'Normal'",
        f"got {res_travel['verdict']}",
    )

    # -----------------------------------------------------------------------
    # TEST GROUP 4: 8 Scenarios from scoring_design.md
    # -----------------------------------------------------------------------
    print("\n--- TEST GROUP 4: 8 DESIGN CONTRACT SCENARIOS ---")

    # Scenario 1 — Normal Low-Risk Event
    evt1 = {
        "event_id": "EVT_SCENARIO_1",
        "malware_flag": 0,
        "failed_login_attempts": 0,
        "severity_score": 1,
        "cvss_score": 2.5,
        "after_hours_flag": 0,
        "impossible_travel_flag": 0,
    }
    res1 = calculate_hybrid_score(evt1, 0.095, "Normal", "File Access", 0.13)
    chk(res1["verdict"] == "Normal", "Scenario 1 verdict == Normal", f"got {res1['verdict']}")
    chk(5.0 <= res1["confidence_score"] <= 15.0, "Scenario 1 score in [5, 15]", f"got {res1['confidence_score']}")
    chk(res1["rule_score"] == 0.0, "Scenario 1 rule_score == 0.0", f"got {res1['rule_score']}")
    chk(len(res1["reasons"]) == 0, "Scenario 1 reasons == []", f"got {res1['reasons']}")

    # Scenario 2 — High Failed Logins Only
    evt2 = {
        "event_id": "EVT_SCENARIO_2",
        "malware_flag": 0,
        "failed_login_attempts": 18,
        "severity_score": 2,
        "cvss_score": 5.0,
        "after_hours_flag": 0,
        "impossible_travel_flag": 0,
    }
    res2 = calculate_hybrid_score(evt2, -0.020, "Suspicious", "Brute Force", 0.25)
    chk(res2["verdict"] == "Suspicious", "Scenario 2 verdict == Suspicious", f"got {res2['verdict']}")
    chk(52.0 <= res2["confidence_score"] <= 58.0, "Scenario 2 score in [52, 58]", f"got {res2['confidence_score']}")
    chk(res2["rule_score"] == 40.0, "Scenario 2 rule_score == 40.0", f"got {res2['rule_score']}")
    chk("RULE_FAILED_LOGINS_HIGH" in res2["triggered_rules"], "Scenario 2 has RULE_FAILED_LOGINS_HIGH")
    chk("RULE_FAILED_LOGINS_MED" not in res2["triggered_rules"], "Scenario 2 excludes RULE_FAILED_LOGINS_MED (mutex)")

    # Scenario 3 — Malware Detected
    evt3 = {
        "event_id": "EVT_SCENARIO_3",
        "malware_flag": 1,
        "failed_login_attempts": 2,
        "severity_score": 3,
        "cvss_score": 6.0,
        "after_hours_flag": 0,
        "impossible_travel_flag": 0,
    }
    res3 = calculate_hybrid_score(evt3, -0.030, "Suspicious", "Malware Detection", 0.35)
    chk(res3["verdict"] == "Critical", "Scenario 3 verdict == Critical", f"got {res3['verdict']}")
    chk(res3["confidence_score"] >= 65.0, "Scenario 3 score >= 65.0", f"got {res3['confidence_score']}")
    chk(res3["rule_score"] == 70.0, "Scenario 3 rule_score == 70.0 (50+20)", f"got {res3['rule_score']}")

    # Scenario 4 — Critical Severity + High CVSS
    evt4 = {
        "event_id": "EVT_SCENARIO_4",
        "malware_flag": 0,
        "failed_login_attempts": 0,
        "severity_score": 4,
        "cvss_score": 9.5,
        "after_hours_flag": 0,
        "impossible_travel_flag": 0,
    }
    res4 = calculate_hybrid_score(evt4, -0.010, "Suspicious", "SQL Injection Attempt", 0.22)
    chk(res4["verdict"] == "Suspicious", "Scenario 4 verdict == Suspicious", f"got {res4['verdict']}")
    chk(60.0 <= res4["confidence_score"] <= 64.9, "Scenario 4 score in [60, 64.9]", f"got {res4['confidence_score']}")
    chk(res4["rule_score"] == 65.0, "Scenario 4 rule_score == 65.0 (35+30)", f"got {res4['rule_score']}")

    # Scenario 5 — Impossible Travel
    evt5 = {
        "event_id": "EVT_SCENARIO_5",
        "malware_flag": 0,
        "failed_login_attempts": 1,
        "impossible_travel_flag": 1,
        "severity_score": 2,
        "cvss_score": 4.0,
        "after_hours_flag": 0,
    }
    res5 = calculate_hybrid_score(evt5, -0.015, "Suspicious", "Login Success", 0.20)
    chk(res5["verdict"] == "Suspicious", "Scenario 5 verdict == Suspicious", f"got {res5['verdict']}")
    chk(53.0 <= res5["confidence_score"] <= 58.0, "Scenario 5 score in [53, 58]", f"got {res5['confidence_score']}")
    chk(res5["rule_score"] == 45.0, "Scenario 5 rule_score == 45.0", f"got {res5['rule_score']}")

    # Scenario 6 — Multiple Simultaneous Indicators
    evt6 = {
        "event_id": "EVT_SCENARIO_6",
        "malware_flag": 1,
        "failed_login_attempts": 16,
        "impossible_travel_flag": 1,
        "severity_score": 4,
        "cvss_score": 9.8,
        "after_hours_flag": 0,
    }
    res6 = calculate_hybrid_score(evt6, -0.060, "Suspicious", "Brute Force", 0.45)
    chk(res6["verdict"] == "Critical", "Scenario 6 verdict == Critical", f"got {res6['verdict']}")
    chk(res6["rule_score"] == 100.0, "Scenario 6 rule_score == 100.0 (capped)", f"got {res6['rule_score']}")
    chk(88.0 <= res6["confidence_score"] <= 95.0, "Scenario 6 score in [88, 95]", f"got {res6['confidence_score']}")

    # Scenario 7 — Highly Anomalous IF, No Rules
    evt7 = {
        "event_id": "EVT_SCENARIO_7",
        "malware_flag": 0,
        "failed_login_attempts": 0,
        "severity_score": 1,
        "cvss_score": 3.0,
        "after_hours_flag": 0,
        "impossible_travel_flag": 0,
    }
    res7 = calculate_hybrid_score(evt7, -0.064, "Suspicious", "Port Scan", 0.31)
    chk(res7["verdict"] == "Suspicious", "Scenario 7 verdict == Suspicious", f"got {res7['verdict']}")
    chk(res7["rule_score"] == 0.0, "Scenario 7 rule_score == 0.0 (IF is NOT a rule)", f"got {res7['rule_score']}")
    chk(50.0 <= res7["confidence_score"] <= 53.0, "Scenario 7 score in [50, 53]", f"got {res7['confidence_score']}")
    
    # Check that IF_ANOMALY_SIGNAL is present with points = 0
    if_reasons = [r for r in res7["reasons"] if r["rule_id"] == "IF_ANOMALY_SIGNAL"]
    chk(len(if_reasons) == 1, "Scenario 7 has IF_ANOMALY_SIGNAL explanation entry")
    if if_reasons:
        chk(if_reasons[0]["points"] == 0, "IF_ANOMALY_SIGNAL points == 0")

    # Scenario 8 — Low RF Confidence, Moderate Rules
    evt8 = {
        "event_id": "EVT_SCENARIO_8",
        "malware_flag": 0,
        "failed_login_attempts": 9,
        "severity_score": 2,
        "cvss_score": 5.5,
        "after_hours_flag": 0,
        "impossible_travel_flag": 0,
    }
    res8 = calculate_hybrid_score(evt8, 0.020, "Normal", "Phishing Email", 0.12)
    chk(res8["verdict"] == "Normal", "Scenario 8 verdict == Normal", f"got {res8['verdict']}")
    chk(res8["rf_confidence_note"] == "low", "Scenario 8 rf_confidence_note == 'low'")
    chk(32.0 <= res8["confidence_score"] <= 34.9, "Scenario 8 score in [32, 34.9]", f"got {res8['confidence_score']}")

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
        print("ALL TESTS PASSED SUCCESSFULLY! (100% compliant with scoring_design.md v1.1.0)")
    print(SEP)


if __name__ == "__main__":
    run_tests()
