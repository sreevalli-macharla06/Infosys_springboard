"""
Integration test — verifies the MongoDB-backed backend actually works,
using mongomock (a faithful pymongo-API-compatible in-memory implementation)
since a real mongod binary isn't installable in this sandbox.

This is NOT part of the delivered app — it's a one-time verification script.
Run: python3 test_mongo_integration.py
"""
import os
import sys
import pandas as pd
import mongomock

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

# 1. Build a pre-populated mock Mongo client (same loading logic as database/init_db.py)
mock_client = mongomock.MongoClient()
db = mock_client["threat_detection"]

collections = {
    "security_events": "security_events.csv",
    "assets": "assets.csv",
    "vulnerabilities": "vulnerabilities.csv",
    "threat_intelligence": "threat_intelligence.csv",
    "incident_history": "incident_history.csv",
    "mitre_attack_mapping": "mitre_attack_mapping.csv",
    "mitre_technique_catalog": "mitre_technique_catalog.csv",
}

print("=== Loading CSVs into mongomock (simulated MongoDB) ===")
for coll_name, csv_file in collections.items():
    df = pd.read_csv(os.path.join(DATA_DIR, csv_file))
    records = df.to_dict("records")
    db[coll_name].insert_many(records)
    print(f"  {coll_name}: {len(records)} documents")

# 2. Patch database.mongo_db.MongoClient BEFORE main.py's lifespan calls mongo.connect()
import database.mongo_db as mongo_db_module
mongo_db_module.MongoClient = lambda *args, **kwargs: mock_client

# also patch admin.command('ping') support check — mongomock supports this natively
mock_client.admin.command("ping")
print("\n=== mongomock ping successful (simulates real MongoDB connectivity check) ===")

# 3. Now import the app — this triggers route registration but not startup yet
from fastapi.testclient import TestClient
from main import app

print("\n=== Starting app (triggers mongo.connect() + store.load() via lifespan) ===")
with TestClient(app) as client:
    # health check
    r = client.get("/health")
    print(f"\nGET /health -> {r.status_code} | {r.json()}")
    assert r.status_code == 200
    assert r.json()["data_loaded"] is True

    # stats
    r = client.get("/stats")
    print(f"GET /stats -> {r.status_code} | {r.json()}")
    assert r.status_code == 200
    assert r.json()["total_events"] == 10000

    # events
    r = client.get("/events?limit=2")
    print(f"GET /events?limit=2 -> {r.status_code} | {len(r.json())} events returned")
    assert r.status_code == 200
    assert len(r.json()) == 2
    sample = r.json()[0]
    assert set(["id", "timestamp", "time", "eventType", "severity", "sourceIP", "destIP",
                "department", "status", "mitre", "riskScore"]) <= set(sample.keys())
    print(f"  sample event fields OK: {list(sample.keys())}")

    # events with severity filter
    r = client.get("/events?severity=Critical&limit=1")
    print(f"GET /events?severity=Critical -> {r.status_code} | severity={r.json()[0]['severity'] if r.json() else 'NONE'}")
    assert r.status_code == 200
    assert r.json()[0]["severity"] == "Critical"

    # threats
    r = client.get("/threats")
    print(f"GET /threats -> {r.status_code} | {len(r.json())} threat types")
    assert r.status_code == 200
    assert len(r.json()) > 0

    # threat intel
    r = client.get("/threat-intel?limit=2")
    print(f"GET /threat-intel -> {r.status_code} | {len(r.json())} IOCs")
    assert r.status_code == 200

    # vulnerabilities
    r = client.get("/vulnerabilities?limit=2")
    print(f"GET /vulnerabilities -> {r.status_code} | {len(r.json())} CVEs")
    assert r.status_code == 200

    # POST a new event (Task 9 write capability)
    new_event = {
        "timestamp": "2026-08-02T10:00:00",
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.5",
        "username": "test_user",
        "event_type": "Brute Force",
        "protocol": "SSH",
        "source_country": "India",
        "destination_country": "India",
        "device_name": "TestDevice-01",
        "os": "Linux",
        "event_status": "Blocked",
        "severity": "High",
        "failed_login_attempts": 5,
        "malware_detected": "No",
        "asset_name": "WebServer",
        "department": "IT",
    }
    r = client.post("/events", json=new_event)
    print(f"POST /events -> {r.status_code} | {r.json()}")
    assert r.status_code == 201
    assert r.json()["status"] == "created"

    # verify it's actually in the DB now
    count_after = db["security_events"].count_documents({})
    print(f"\nsecurity_events count after POST: {count_after} (was 10000, now +1)")
    assert count_after == 10001

    # verify the new event shows up in GET /events immediately (no restart needed)
    r = client.get("/events?limit=1")
    print(f"\nGET /events?limit=1 right after POST -> most recent event: {r.json()[0]['id']}")
    assert r.status_code == 200

    # CORS preflight check for POST (this was previously broken — allow_methods=["GET"] only)
    r = client.options(
        "/events",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
    )
    print(f"\nCORS preflight for POST /events -> {r.status_code} | "
          f"allow-methods: {r.headers.get('access-control-allow-methods')}")
    assert r.status_code == 200
    assert "POST" in r.headers.get("access-control-allow-methods", "")

print("\n" + "=" * 60)
print("ALL INTEGRATION CHECKS PASSED")
print("=" * 60)
