"""
validation/test_status_lifecycle.py — Live validation of incident status lifecycle and CORS
==========================================================================================
Verifies:
  1. CORS OPTIONS preflight request allows PATCH
  2. Status transitions across all 4 valid statuses: Open -> Investigating -> Resolved -> False Positive -> Open
  3. Direct GET endpoint retrieves updated status
  4. Status query filter (/api/v1/incidents?status=...) includes updated incident
  5. Invalid status returns HTTP 400 Bad Request
  6. Non-existent incident ID returns HTTP 404 Not Found
"""
import httpx
import sys

BASE_URL = "http://localhost:8000"
INCIDENT_ID = "INC-000131"

headers_preflight = {
    "Origin": "http://localhost:5173",
    "Access-Control-Request-Method": "PATCH",
    "Access-Control-Request-Headers": "content-type",
}

patch_headers = {
    "Origin": "http://localhost:5173",
    "Content-Type": "application/json",
}

print("=" * 70)
print("INCIDENT STATUS LIFECYCLE & CORS INTEGRATION VALIDATION")
print("=" * 70)

with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
    # 1. Test CORS Preflight
    print("\n--- 1. CORS Preflight Check ---")
    opt = client.options(f"/api/v1/incidents/{INCIDENT_ID}/status", headers=headers_preflight)
    print(f"  OPTIONS /api/v1/incidents/{INCIDENT_ID}/status -> HTTP {opt.status_code}")
    allow_methods = opt.headers.get("access-control-allow-methods", "")
    print(f"  Access-Control-Allow-Methods: {allow_methods}")
    assert opt.status_code == 200, f"Expected 200, got {opt.status_code}"
    assert "PATCH" in allow_methods, f"PATCH not in allow_methods: {allow_methods}"
    print("  [PASS] Preflight allows PATCH method")

    # 2. Test All 4 Status Transitions
    print("\n--- 2. Lifecycle Transitions (All 4 Statuses) ---")
    statuses_to_test = ["Investigating", "Resolved", "False Positive", "Open"]
    for st in statuses_to_test:
        # A. PATCH update
        resp = client.patch(
            f"/api/v1/incidents/{INCIDENT_ID}/status",
            json={"status": st},
            headers=patch_headers,
        )
        assert resp.status_code == 200, f"Failed PATCH {st}: {resp.status_code} {resp.text}"
        doc = resp.json()
        assert doc["status"] == st, f"Status mismatch in PATCH response: {doc['status']} != {st}"
        assert "status_history" in doc and len(doc["status_history"]) > 0, "status_history missing in response"
        print(f"  [PASS] PATCH -> status='{st}' (HTTP 200, audit history entries: {len(doc['status_history'])})")

        # B. GET single incident verification
        get_resp = client.get(f"/api/v1/incidents/{INCIDENT_ID}")
        assert get_resp.status_code == 200
        assert get_resp.json()["status"] == st, f"GET status mismatch: {get_resp.json()['status']} != {st}"
        print(f"  [PASS] GET /{INCIDENT_ID} confirms status='{st}' (HTTP 200)")

        # C. Filter verification
        filter_resp = client.get(f"/api/v1/incidents?status={st}&limit=100")
        assert filter_resp.status_code == 200
        item_ids = [item["incident_id"] for item in filter_resp.json().get("items", [])]
        assert INCIDENT_ID in item_ids, f"{INCIDENT_ID} not found in filter query results for status='{st}'"
        print(f"  [PASS] GET /incidents?status={st} includes {INCIDENT_ID} (HTTP 200)")

    # 3. Test Invalid Status
    print("\n--- 3. Error Handling: Invalid Status ---")
    bad_resp = client.patch(
        f"/api/v1/incidents/{INCIDENT_ID}/status",
        json={"status": "InvalidStatusXYZ"},
        headers=patch_headers,
    )
    assert bad_resp.status_code == 400, f"Expected 400, got {bad_resp.status_code}"
    print(f"  [PASS] Invalid status rejected with HTTP 400: {bad_resp.json().get('detail')}")

    # 4. Test 404 for Non-Existent Incident
    print("\n--- 4. Error Handling: Non-Existent Incident ---")
    missing_resp = client.patch(
        "/api/v1/incidents/INC-NONEXISTENT-999/status",
        json={"status": "Investigating"},
        headers=patch_headers,
    )
    assert missing_resp.status_code == 404, f"Expected 404, got {missing_resp.status_code}"
    print(f"  [PASS] Non-existent incident returns HTTP 404: {missing_resp.json().get('detail')}")

print("\n" + "=" * 70)
print("ALL STATUS LIFECYCLE CHECKS PASSED (100%)")
print("=" * 70)
