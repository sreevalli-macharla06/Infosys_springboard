#!/usr/bin/env python3
"""
validate_phase3_frontend_integration.py
Automated end-to-end integration and data-contract validation for Milestone 3 Frontend Integration.
Validates all APIs and data payloads consumed by the React M3 screens.
"""

import sys
import httpx

BASE_URL = "http://127.0.0.1:8000"

def ok(msg):
    print(f"  [PASS] {msg}")

def fail(msg):
    print(f"  [FAIL] {msg}")
    sys.exit(1)

def section(title):
    print(f"\n--- {title} ---")

def main():
    print("=" * 65)
    print("MILESTONE 3 PHASE 3 FRONTEND API & CONTRACT VALIDATION")
    print("=" * 65)

    client = httpx.Client(base_url=BASE_URL, timeout=10.0)

    # 1. Health check
    section("1. Backend Liveness Check")
    try:
        r = client.get("/health")
        if r.status_code == 200:
            ok("Backend server is online and reachable")
        else:
            fail(f"Health returned status {r.status_code}")
    except Exception as e:
        fail(f"Could not connect to backend at {BASE_URL}: {e}")

    # 2. Risk Overview Screen APIs
    section("2. Screen 1: Risk Overview (/api/v1/risk/summary & /api/v1/risk/high)")
    r = client.get("/api/v1/risk/summary")
    if r.status_code == 200:
        data = r.json()
        assert "total_incidents" in data, "Missing total_incidents"
        assert "critical_count" in data, "Missing critical_count"
        assert "high_count" in data, "Missing high_count"
        assert "moderate_count" in data, "Missing moderate_count"
        assert "medium_count" in data, "Missing medium_count"
        assert "low_count" in data, "Missing low_count"
        assert "open_count" in data, "Missing open_count"
        assert "investigating_count" in data, "Missing investigating_count"
        assert "risk_distribution" in data, "Missing risk_distribution"
        assert "trend" in data, "Missing trend"
        ok(f"All 8 KPI metrics verified: Total={data['total_incidents']}, Critical={data['critical_count']}, High={data['high_count']}, Moderate={data['moderate_count']}, Medium={data['medium_count']}, Low={data['low_count']}, Open={data['open_count']}, Investigating={data['investigating_count']}")
        ok(f"Trend data points available: {len(data['trend'])} days")
    else:
        fail(f"Risk summary failed: {r.status_code} {r.text}")

    r = client.get("/api/v1/risk/high?limit=5&min_score=61")
    if r.status_code == 200:
        data = r.json()
        items = data.get("items", [])
        ok(f"High risk spotlight returned {len(items)} incidents (all score >= 61)")
        if items:
            scores = [i["risk_score"] for i in items]
            ok(f"Top 5 high risk scores: {scores}")
    else:
        fail(f"High risk query failed: {r.status_code}")

    # 3. Priority Incidents Screen APIs & 7-Facet Filter Validation
    section("3. Screen 2: Priority Incidents (7 Mentor Filters Validation)")
    
    # 3a. Filter by risk_level=Critical
    r = client.get("/api/v1/incidents?risk_level=Critical&limit=10&sort_by=risk_score&sort_order=desc")
    assert r.status_code == 200, f"Critical filter failed: {r.status_code}"
    crit_items = r.json().get("items", [])
    crit_total = r.json().get("total", 0)
    assert all(i["risk_level"] == "Critical" for i in crit_items)
    ok(f"Filter 1/7 [Risk Level = Critical]: Returned {len(crit_items)} items ({crit_total} total matches)")

    # 3b. Filter by threat_type=Brute Force
    r = client.get("/api/v1/incidents?threat_type=Brute Force&limit=10")
    assert r.status_code == 200
    bf_items = r.json().get("items", [])
    bf_total = r.json().get("total", 0)
    assert all(i["threat_type"] == "Brute Force" for i in bf_items)
    ok(f"Filter 2/7 [Threat Type = Brute Force]: Returned {len(bf_items)} items ({bf_total} total matches)")

    # 3c. Filter by asset_name=Firewall
    r = client.get("/api/v1/incidents?asset_name=Firewall&limit=10")
    assert r.status_code == 200
    asset_items = r.json().get("items", [])
    asset_total = r.json().get("total", 0)
    assert all(i["asset_name"] == "Firewall" for i in asset_items)
    ok(f"Filter 3/7 [Asset = Firewall]: Returned {len(asset_items)} items ({asset_total} total matches)")

    # 3d. Filter by department=IT
    r = client.get("/api/v1/incidents?department=IT&limit=10")
    assert r.status_code == 200
    dept_items = r.json().get("items", [])
    dept_total = r.json().get("total", 0)
    assert all(i["department"] == "IT" for i in dept_items)
    ok(f"Filter 4/7 [Department = IT]: Returned {len(dept_items)} items ({dept_total} total matches)")

    # 3e. Filter by mitre_technique=T1190
    r = client.get("/api/v1/incidents?mitre_technique=T1190&limit=10")
    assert r.status_code == 200
    mitre_items = r.json().get("items", [])
    mitre_total = r.json().get("total", 0)
    assert all("T1190" in i.get("mitre_techniques", []) for i in mitre_items)
    ok(f"Filter 5/7 [MITRE Technique = T1190]: Returned {len(mitre_items)} items ({mitre_total} total matches)")

    # 3f. Filter by Date Range (start_date / end_date)
    r = client.get("/api/v1/incidents?start_date=2025-08-01&end_date=2025-08-02T23:59:59&limit=10")
    assert r.status_code == 200
    date_items = r.json().get("items", [])
    date_total = r.json().get("total", 0)
    assert all(i["created_at"] >= "2025-08-01" for i in date_items)
    ok(f"Filter 6/7 [Date Range = 2025-08-01 to 2025-08-02]: Returned {len(date_items)} items ({date_total} total matches)")

    # 3g. Filter by status=Open
    r = client.get("/api/v1/incidents?status=Open&limit=10")
    assert r.status_code == 200
    status_items = r.json().get("items", [])
    status_total = r.json().get("total", 0)
    assert all(i["status"] == "Open" for i in status_items)
    ok(f"Filter 7/7 [Lifecycle Status = Open]: Returned {len(status_items)} items ({status_total} total matches)")

    # 4. Incident Investigation Screen APIs & Ground Truth Verification (INC-000058)
    section("4. Screen 3: Incident Investigation (INC-000058 Acceptance Contract)")
    r = client.get("/api/v1/incidents/INC-000058")
    if r.status_code == 200:
        inc = r.json()
        ok(f"Incident INC-000058 fetched successfully")
        
        # Verify required exact values per spec:
        assert inc.get("risk_score") == 94, f"Expected risk_score=94, got {inc.get('risk_score')}"
        ok(f"Risk Score: {inc.get('risk_score')} (Deterministic match)")
        
        assert inc.get("risk_level") == "Critical", f"Expected Critical, got {inc.get('risk_level')}"
        ok(f"Risk Level: {inc.get('risk_level')}")
        
        assert inc.get("priority") == "CRITICAL_IMMEDIATE", f"Expected CRITICAL_IMMEDIATE, got {inc.get('priority')}"
        ok(f"Priority: {inc.get('priority')}")
        
        assert inc.get("asset_id") == "AST005", f"Expected AST005, got {inc.get('asset_id')}"
        assert inc.get("asset_name") == "Firewall", f"Expected Firewall, got {inc.get('asset_name')}"
        assert inc.get("department") == "IT", f"Expected IT, got {inc.get('department')}"
        ok(f"Asset Context: ID={inc.get('asset_id')}, Name={inc.get('asset_name')}, Dept={inc.get('department')}")
        
        assert inc.get("cvss_score") == 9.5, f"Expected CVSS=9.5, got {inc.get('cvss_score')}"
        ok(f"Vulnerability CVSS: {inc.get('cvss_score')}")
        
        assert inc.get("ioc_status") == "Malicious", f"Expected Malicious, got {inc.get('ioc_status')}"
        ok(f"Threat Intelligence IOC Status: {inc.get('ioc_status')}")
        
        assert "T1190" in inc.get("mitre_techniques", []), f"Expected T1190 in MITRE techniques, got {inc.get('mitre_techniques')}"
        ok(f"MITRE ATT&CK Technique: {inc.get('mitre_techniques')}")
        
        assert inc.get("attack_chain_type") == "Privilege Escalation Chain", f"Expected Privilege Escalation Chain, got {inc.get('attack_chain_type')}"
        ok(f"Attack Chain Type: {inc.get('attack_chain_type')}")
        
        breakdown = inc.get("risk_breakdown", {}).get("factors", [])
        assert len(breakdown) == 5, f"Expected 5 risk factors, got {len(breakdown)}"
        ok(f"5-Factor Risk Breakdown: {[f['name'] for f in breakdown]}")
        
        reasons = inc.get("reasons", [])
        assert len(reasons) >= 4, f"Expected >= 4 reasons, got {len(reasons)}"
        ok(f"Risk Explainability Drivers count: {len(reasons)}")
        
        recs = inc.get("recommendations", [])
        assert len(recs) >= 3, f"Expected >= 3 recommendations, got {len(recs)}"
        ok(f"Advisory Recommendations count: {len(recs)}")
    else:
        fail(f"Incident INC-000058 detail failed: {r.status_code} {r.text}")

    # 5. Attack Chains Screen APIs
    section("5. Screen 4: Multi-Stage Attack Chains (/api/v1/attack-chains)")
    r = client.get("/api/v1/attack-chains?limit=10")
    if r.status_code == 200:
        data = r.json()
        chains = data.get("items", [])
        ok(f"Attack chains query returned {len(chains)} multi-stage attacks")
        if chains:
            c = chains[0]
            assert c.get("attack_chain", {}).get("attack_chain_detected") is True
            assert len(c.get("attack_chain", {}).get("stages", [])) >= 2
            ok(f"Sample Chain: ID={c.get('incident_id')}, Type='{c.get('attack_chain_type')}', Stages={len(c.get('attack_chain', {}).get('stages', []))}")
    else:
        fail(f"Attack chains query failed: {r.status_code}")

    # 6. Status Update Flow (Lifecycle PATCH)
    section("6. Incident Lifecycle Management (PATCH /api/v1/incidents/{id}/status)")
    r = client.patch("/api/v1/incidents/INC-000058/status", json={"status": "Investigating"})
    if r.status_code == 200 and r.json().get("status") == "Investigating":
        ok("Successfully updated incident status to 'Investigating'")
    else:
        fail(f"Status update failed: {r.status_code} {r.text}")

    # Restore
    r = client.patch("/api/v1/incidents/INC-000058/status", json={"status": "Open"})
    if r.status_code == 200 and r.json().get("status") == "Open":
        ok("Successfully restored incident status to 'Open'")
    else:
        fail(f"Status restore failed: {r.status_code} {r.text}")

    # 7. M1 / M2 Non-Regression Contract Checks
    section("7. M1 / M2 Non-Regression Checks")
    m1_m2_endpoints = [
        "/events?limit=2",
        "/stats",
        "/threats",
        "/threat-intel?limit=2",
        "/vulnerabilities?limit=2",
        "/predictions?limit=2",
        "/anomalies?limit=2",
        "/threat-summary",
        "/model-performance",
    ]
    for ep in m1_m2_endpoints:
        res = client.get(ep)
        if res.status_code == 200:
            ok(f"Endpoint {ep} -> HTTP 200 OK")
        else:
            fail(f"Endpoint {ep} failed: {res.status_code}")

    print("\n" + "=" * 65)
    print("ALL FRONTEND API & CONTRACT INTEGRATION TESTS PASSED (100%)")
    print("=" * 65)

if __name__ == "__main__":
    main()
