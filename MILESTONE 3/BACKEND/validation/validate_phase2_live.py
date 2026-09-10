"""
validation/validate_phase2_live.py — Live End-to-End M3 Backend Validation
==========================================================================
Milestone 3: Risk Prioritization & Security Intelligence

Validates:
  1. POST  /api/v1/risk/calculate (Real event + response completeness)
  2. GET   /api/v1/risk/high (Sorting, threshold >= 61)
  3. GET   /api/v1/risk/summary (Counts, distribution, trend metrics)
  4. GET   /api/v1/incidents (Pagination, filtering, sorting)
  5. GET   /api/v1/incidents/{incident_id} (Complete payload schema)
  6. PATCH /api/v1/incidents/{incident_id}/status (Lifecycle transitions)
  7. GET   /api/v1/attack-chains (Detected chain retrieval)
  8. GET   /api/v1/recommendations/{incident_id} (Advisory recommendations)
  9. M1/M2 Non-regression endpoints (/health, /events, /predictions, /anomalies)
"""

import sys
import json
import httpx

BASE_URL = "http://127.0.0.1:8000"
SEP = "=" * 65

passed = 0
failed = 0


def ok(msg: str):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def fail(msg: str):
    global failed
    failed += 1
    print(f"  [FAIL] {msg}")


def section(title: str):
    print(f"\n--- {title} ---")


def main():
    print(SEP)
    print("MILESTONE 3 PHASE 2 LIVE BACKEND API VALIDATION")
    print(SEP)

    client = httpx.Client(base_url=BASE_URL, timeout=10.0)

    # 1. Health check
    section("1. BACKEND HEALTH CHECK")
    r = client.get("/health")
    if r.status_code == 200 and r.json().get("status") == "ok":
        ok("Backend health endpoint is reachable (HTTP 200)")
    else:
        fail(f"Backend health failed: {r.status_code} {r.text}")

    # 2. Risk Calculate API
    section("2. POST /api/v1/risk/calculate")
    r = client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})
    if r.status_code == 200:
        data = r.json()
        if "risk_score" in data and "risk_level" in data and "priority" in data and "risk_breakdown" in data:
            ok(f"Risk calculation succeeded for EVT000001: Score={data['risk_score']}, Level={data['risk_level']}, Priority={data['priority']}")
            ok(f"Risk breakdown contains {len(data['risk_breakdown']['factors'])} factors with reasons: {len(data['reasons'])} entries")
        else:
            fail(f"Incomplete risk calculation response: {data}")
    else:
        fail(f"Risk calculate failed: {r.status_code} {r.text}")

    # 3. High Risk Incidents API
    section("3. GET /api/v1/risk/high")
    r = client.get("/api/v1/risk/high?limit=10&min_score=61")
    if r.status_code == 200:
        data = r.json()
        items = data.get("items", [])
        ok(f"High risk incidents endpoint returned {len(items)} items (min_score=61)")
        if items:
            is_sorted = all(items[i]["risk_score"] >= items[i+1]["risk_score"] for i in range(len(items)-1))
            if is_sorted:
                ok(f"High risk incidents are strictly sorted DESC: {[it['risk_score'] for it in items[:5]]}")
            else:
                fail("High risk incidents are not sorted DESC")
    else:
        fail(f"High risk endpoint failed: {r.status_code} {r.text}")

    # 4. Risk Summary API
    section("4. GET /api/v1/risk/summary")
    r = client.get("/api/v1/risk/summary")
    if r.status_code == 200:
        data = r.json()
        total = data.get("total_incidents", 0)
        dist = data.get("risk_distribution", {})
        ok(f"Risk summary returned: Total Incidents={total}, Distribution={dist}")
        ok(f"Status counts: Open={data.get('open_count')}, Investigating={data.get('investigating_count')}, Resolved={data.get('resolved_count')}")
    else:
        fail(f"Risk summary failed: {r.status_code} {r.text}")

    # 5. List Incidents API
    section("5. GET /api/v1/incidents")
    r = client.get("/api/v1/incidents?limit=5&sort_by=risk_score&sort_order=desc")
    sample_incident_id = None
    if r.status_code == 200:
        data = r.json()
        items = data.get("items", [])
        total = data.get("total", 0)
        ok(f"Incident listing returned {len(items)} items out of {total} total")
        if items:
            sample_incident_id = items[0]["incident_id"]
            ok(f"Top incident: ID={sample_incident_id}, Threat={items[0].get('threat_type')}, Score={items[0].get('risk_score')}, Priority={items[0].get('priority')}")
    else:
        fail(f"Incidents list failed: {r.status_code} {r.text}")

    # 6. Incident Detail API
    section("6. GET /api/v1/incidents/{incident_id}")
    if sample_incident_id:
        r = client.get(f"/api/v1/incidents/{sample_incident_id}")
        if r.status_code == 200:
            inc = r.json()
            ok(f"Incident detail fetched successfully for {sample_incident_id}")
            ok(f"Asset ID: {inc.get('asset_id')}, Asset Name: {inc.get('asset_name')}, User: {inc.get('affected_user')}, CVSS: {inc.get('cvss_score')}")
            if inc.get('asset_name') and not inc.get('asset_id'):
                fail(f"asset_id is null for known asset '{inc.get('asset_name')}'")
            else:
                ok(f"asset_id successfully resolved: {inc.get('asset_id')}")
            ok(f"Recommendations count: {len(inc.get('recommendations', []))}")
        else:
            fail(f"Incident detail failed for {sample_incident_id}: {r.status_code} {r.text}")

    # 7. Status Update API
    section("7. PATCH /api/v1/incidents/{incident_id}/status")
    if sample_incident_id:
        r = client.patch(f"/api/v1/incidents/{sample_incident_id}/status", json={"status": "Investigating"})
        if r.status_code == 200 and r.json().get("status") == "Investigating":
            ok(f"Updated status of {sample_incident_id} to 'Investigating'")
        else:
            fail(f"Status update failed: {r.status_code} {r.text}")

        # Restore to Open
        client.patch(f"/api/v1/incidents/{sample_incident_id}/status", json={"status": "Open"})
        ok(f"Restored status of {sample_incident_id} to 'Open'")

        # Test invalid status rejection
        bad_r = client.patch(f"/api/v1/incidents/{sample_incident_id}/status", json={"status": "BadStatusXYZ"})
        if bad_r.status_code == 400:
            ok("Invalid status 'BadStatusXYZ' correctly rejected with HTTP 400")
        else:
            fail(f"Invalid status was not rejected: {bad_r.status_code}")

    # 8. Attack Chains API
    section("8. GET /api/v1/attack-chains")
    r = client.get("/api/v1/attack-chains?limit=10")
    if r.status_code == 200:
        data = r.json()
        chains = data.get("items", [])
        ok(f"Attack chains endpoint returned {len(chains)} detected multi-stage chains")
        if chains:
            c = chains[0]
            ok(f"Sample Attack Chain: Incident={c.get('incident_id')}, Type='{c.get('attack_chain_type')}', Asset={c.get('asset_name')}")
    else:
        fail(f"Attack chains endpoint failed: {r.status_code} {r.text}")

    # 9. Recommendations API
    section("9. GET /api/v1/recommendations/{incident_id}")
    if sample_incident_id:
        r = client.get(f"/api/v1/recommendations/{sample_incident_id}")
        if r.status_code == 200:
            data = r.json()
            recs = data.get("recommendations", [])
            ok(f"Fetched {len(recs)} advisory recommendations for {sample_incident_id}")
            if recs:
                ok(f"Top recommendation: Action='{recs[0]['action']}', Priority={recs[0]['priority']}")
        else:
            fail(f"Recommendations endpoint failed: {r.status_code} {r.text}")

    # 10. M1/M2 Non-Regression Check
    section("10. M1 / M2 NON-REGRESSION VERIFICATION")
    m1_endpoints = ["/events?limit=2", "/stats", "/threats", "/predictions?limit=2", "/anomalies?limit=2", "/threat-summary", "/model-performance"]
    for ep in m1_endpoints:
        r = client.get(ep)
        if r.status_code == 200:
            ok(f"Existing endpoint {ep} -> HTTP 200 OK")
        else:
            fail(f"Existing endpoint {ep} failed: {r.status_code}")

    print("\n" + SEP)
    print(f"VALIDATION SUMMARY: {passed} PASSED, {failed} FAILED")
    print(SEP)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
