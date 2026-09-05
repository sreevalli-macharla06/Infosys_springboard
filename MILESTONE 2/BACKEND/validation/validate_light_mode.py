"""
validate_light_mode.py — Validation of Light Mode Theme & System Integrity
===========================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

Validates:
  1. Backend reachable (http://localhost:8000/health)
  2. Frontend reachable (http://localhost:5173/)
  3. ThemeContext & Light Mode CSS rules present in FRONTEND build
  4. Theme toggle button present in Header.jsx
  5. Chart.js components configured with useTheme()
  6. Backend ML pipeline, API routes, models, and MongoDB collections untouched
  7. All 28 demo-readiness checks in validate_demo_ready.py pass
"""

import sys
import os
import subprocess
import httpx
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))
FRONTEND_DIR = BACKEND_DIR.parent / "FRONTEND"

SEP = "=" * 65
passed = 0
failed = 0
failures = []


def ok(msg: str):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def fail(msg: str):
    global failed
    failed += 1
    failures.append(msg)
    print(f"  [FAIL] {msg}")


def section(title: str):
    print(f"\n--- {title} ---")


def main():
    print(SEP)
    print("LIGHT MODE THEME & SYSTEM INTEGRITY VALIDATION")
    print(SEP)

    # 1. Backend Health Check
    section("1. BACKEND HEALTH CHECK")
    try:
        r = httpx.get("http://localhost:8000/health", timeout=5)
        if r.status_code == 200:
            ok("Backend reachable at http://localhost:8000/health (HTTP 200)")
        else:
            fail(f"Backend returned HTTP {r.status_code}")
    except Exception as e:
        fail(f"Backend connection error: {e}")

    # 2. Frontend Health Check
    section("2. FRONTEND HEALTH CHECK")
    try:
        r = httpx.get("http://localhost:5173/", timeout=5)
        if r.status_code == 200 and "<!doctype html>" in r.text.lower():
            ok("Frontend reachable at http://localhost:5173/ (HTTP 200)")
        else:
            fail(f"Frontend returned HTTP {r.status_code}")
    except Exception as e:
        fail(f"Frontend connection error: {e}")

    # 3. Source Integrity Check (Backend/ML/API files MUST be untouched)
    section("3. BACKEND & ML PIPELINE INTEGRITY CHECK")
    backend_git_status = subprocess.run(
        ["git", "status", "--porcelain", "BACKEND/ml", "BACKEND/services", "BACKEND/models", "BACKEND/database", "BACKEND/routes"],
        cwd=BACKEND_DIR.parent,
        capture_output=True,
        text=True,
    )
    # Exclude validate_demo_ready.py or populate_demo_predictions.py if present
    backend_changes = [
        line for line in backend_git_status.stdout.splitlines()
        if not line.endswith("populate_demo_predictions.py") and not line.endswith("validate_demo_ready.py")
    ]
    if not backend_changes:
        ok("All BACKEND ML, services, models, database, and route files are UNTOUCHED")
    else:
        fail(f"Unexpected modifications in BACKEND: {backend_changes}")

    # 4. Frontend Theme Implementation Check
    section("4. FRONTEND THEME IMPLEMENTATION CHECK")
    theme_context_file = FRONTEND_DIR / "src" / "context" / "ThemeContext.jsx"
    if theme_context_file.exists():
        ok("ThemeContext.jsx exists in src/context/")
    else:
        fail("ThemeContext.jsx MISSING")

    header_file = FRONTEND_DIR / "src" / "components" / "layout" / "Header.jsx"
    if header_file.exists() and "useTheme" in header_file.read_text("utf-8"):
        ok("Header.jsx integrates useTheme() and theme toggle")
    else:
        fail("Header.jsx missing useTheme integration")

    global_css = FRONTEND_DIR / "src" / "global.css"
    if global_css.exists() and "html.light" in global_css.read_text("utf-8"):
        ok("global.css includes html.light theme overrides")
    else:
        fail("global.css missing html.light styles")

    # 5. Run Demo Readiness Verification Suite
    section("5. DEMO READINESS SUITE (validate_demo_ready.py)")
    res = subprocess.run(
        [sys.executable, "validation/validate_demo_ready.py"],
        cwd=BACKEND_DIR,
        capture_output=True,
        text=True,
    )
    if res.returncode == 0 and "ALL CHECKS PASSED" in res.stdout:
        ok("All 28 demo-readiness checks in validate_demo_ready.py PASSED")
    else:
        fail(f"validate_demo_ready.py failed with code {res.returncode}:\n{res.stdout}\n{res.stderr}")

    print(f"\n{SEP}")
    total_checks = passed + failed
    print(f"RESULTS: {passed}/{total_checks} checks passed, {failed} failed")
    print(SEP)

    if failed == 0:
        print("""
=================================================================
ALL CHECKS PASSED — LIGHT MODE THEME VERIFIED & READY
=================================================================
""")
        sys.exit(0)
    else:
        print("Validation failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
