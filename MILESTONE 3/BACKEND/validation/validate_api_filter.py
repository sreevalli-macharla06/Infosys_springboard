"""
validation/validate_api_filter.py — Live API validation script for M2 predictions filtering.
===========================================================================================
Ad-hoc validation script checking live /predictions query parameters.
"""
import urllib.request
import json
import time


def check_filter(qs: str):
    try:
        req = urllib.request.Request(f"http://127.0.0.1:8000/predictions?{qs}")
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            print(f"  [PASS] {qs}: Total={data.get('total')}, Items={len(data.get('items', []))}")
            return True
    except Exception as e:
        print(f"  [FAIL] {qs}: Error={e}")
        return False


if __name__ == "__main__":
    print("=== LIVE PREDICTIONS API FILTER VALIDATION ===")
    queries = [
        "severity=Low&limit=2",
        "severity=High&limit=2",
        "verdict=Normal&limit=2",
        "verdict=Suspicious&severity=Medium&limit=2",
        "verdict=All&limit=2",
    ]
    for q in queries:
        check_filter(q)
    print("===============================================")
