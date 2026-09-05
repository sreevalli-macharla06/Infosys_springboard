"""
Phase 2 Correction — Full Validation Suite
Verifies causal training aggregate fixes, training/inference alignment,
and all pipeline integrity checks.
Run from BACKEND/: python validate_phase2_correction.py
"""
import sys, os
sys.path.insert(0, '.')
# Silence lower-level loggers for clean output
import logging
logging.disable(logging.CRITICAL)

import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from ml.preprocessing import (
    load_training_dataframe,
    engineer_features_batch,
    engineer_features_single_event,
    prepare_training_data,
    SecurityEventPreprocessor,
    load_preprocessor,
    LOGICAL_FEATURES,
    IMPOSSIBLE_TRAVEL_WINDOW_HOURS,
)

SEP  = "=" * 65
SEP2 = "-" * 65
PASS = "[PASS]"
FAIL = "[FAIL]"

errors = []

def check(condition, label, detail=""):
    marker = PASS if condition else FAIL
    print(f"  {marker} {label}")
    if not condition:
        errors.append(f"{label}: {detail}")

# ============================================================
print(SEP)
print("TEST 1 — SYNTHETIC TEMPORAL-CAUSALITY VERIFICATION")
print(SEP)

# Build a minimal synthetic DataFrame: 1 user, 4 events in order
synth = pd.DataFrame([
    {"username": "alice", "timestamp": "2025-08-01 06:00:00",
     "destination_ip": "10.0.0.1", "source_country": "India",
     "event_id": "E001", "event_type": "Brute Force"},
    {"username": "alice", "timestamp": "2025-08-01 10:00:00",
     "destination_ip": "10.0.0.2", "source_country": "India",
     "event_id": "E002", "event_type": "Port Scan"},
    {"username": "alice", "timestamp": "2025-08-01 14:00:00",
     "destination_ip": "10.0.0.2", "source_country": "India",
     "event_id": "E003", "event_type": "File Access"},
    {"username": "alice", "timestamp": "2025-08-01 20:00:00",
     "destination_ip": "10.0.0.3", "source_country": "India",
     "event_id": "E004", "event_type": "Failed Login"},
])

from ml.preprocessing import (
    _derive_events_per_user_training,
    _derive_unique_destination_count_training,
)

epu  = _derive_events_per_user_training(synth)
udc  = _derive_unique_destination_count_training(synth)

print(f"\n  {'idx':>3} | {'timestamp':20s} | {'events_per_user':>15} | {'unique_dest_count':>17} | event_type (y)")
print(f"  {SEP2}")
for i, row in synth.iterrows():
    print(f"  {i:>3} | {row['timestamp']:20s} | {epu[i]:>15} | {udc[i]:>17} | {row['event_type']}")

# Expected: cumulative counts, not flat totals
check(list(epu.values) == [1, 2, 3, 4],
      "events_per_user is causally cumulative [1,2,3,4]",
      f"got {list(epu.values)}")
check(list(udc.values) == [1, 2, 2, 3],
      "unique_dest_count is causally cumulative [1,2,2,3]",
      f"got {list(udc.values)}")
check(epu[0] == 1,
      "First event does NOT receive future-event information (events_per_user=1)")
check(udc[0] == 1,
      "First event does NOT receive future-event information (unique_dest=1)")

# Confirm y label alignment — event_type must match original row
check(synth.loc[0, "event_type"] == "Brute Force",
      "y-label alignment preserved at idx=0 (Brute Force)")
check(synth.loc[3, "event_type"] == "Failed Login",
      "y-label alignment preserved at idx=3 (Failed Login)")

# ============================================================
print(f"\n{SEP}")
print("TEST 2 — REAL M1 DATASET: AGGREGATE RANGE & EVOLUTION")
print(SEP)

df_raw = load_training_dataframe()
df_eng = engineer_features_batch(df_raw)

epu_real = df_eng["events_per_user"]
udc_real = df_eng["unique_destination_count"]

print(f"\n  events_per_user:         min={epu_real.min()}, max={epu_real.max()}")
print(f"  unique_destination_count: min={udc_real.min()}, max={udc_real.max()}")

check(epu_real.min() == 1,
      "events_per_user minimum is 1 (first event for each user)")
check(epu_real.max() <= df_raw.groupby("username")["event_id"].transform("count").max(),
      "events_per_user maximum <= full-dataset per-user total (causal, not inflated)")
check(udc_real.min() == 1,
      "unique_dest_count minimum is 1 (first event for each user)")

# Verify values evolve over time for one user — not flat constants
print(f"\n  Chronological sample for user 'root' (first 8 events):")
df_raw_copy = df_raw.copy()
df_raw_copy["events_per_user"] = epu_real
df_raw_copy["unique_destination_count"] = udc_real
df_raw_copy["_ts"] = pd.to_datetime(df_raw_copy["timestamp"])

root_sample = (
    df_raw_copy[df_raw_copy["username"] == "root"]
    .sort_values("_ts")
    .head(8)[["timestamp", "destination_ip", "events_per_user", "unique_destination_count"]]
)
print(f"\n  {'timestamp':20s} | {'dest_ip':15s} | {'epu':>5} | {'udc':>5}")
print(f"  {'-'*60}")
for _, r in root_sample.iterrows():
    print(f"  {r['timestamp']:20s} | {r['destination_ip']:15s} | {r['events_per_user']:>5} | {r['unique_destination_count']:>5}")

# Confirm the first root event gets epu=1
first_root_epu = root_sample["events_per_user"].iloc[0]
check(first_root_epu == 1,
      f"First 'root' event has events_per_user=1 (got {first_root_epu})")

# Confirm values are NOT constant (old bug was flat constant)
root_epu_values = (
    df_raw_copy[df_raw_copy["username"] == "root"]
    .sort_values("_ts")["events_per_user"]
    .values
)
check(root_epu_values[0] != root_epu_values[-1],
      "events_per_user values EVOLVE over time for 'root' (not a flat constant)")

# ============================================================
print(f"\n{SEP}")
print("TEST 3 — TRAINING / INFERENCE DEFINITION CONSISTENCY")
print(SEP)

# Training: the 5th event for alice should have events_per_user=5
# Inference: len(4 historical) + 1 = 5
# These must match.
synth5 = pd.concat([synth, pd.DataFrame([{
    "username": "alice", "timestamp": "2025-08-01 22:00:00",
    "destination_ip": "10.0.0.4", "source_country": "India",
    "event_id": "E005", "event_type": "Malware Detection",
}])], ignore_index=True)

epu5 = _derive_events_per_user_training(synth5)
udc5 = _derive_unique_destination_count_training(synth5)

# Training value for 5th alice event (idx=4)
training_epu = epu5.iloc[4]
training_udc = udc5.iloc[4]

# Inference value: 4 historical events + current
hist4 = [
    {"timestamp": "2025-08-01 06:00:00", "destination_ip": "10.0.0.1", "source_country": "India"},
    {"timestamp": "2025-08-01 10:00:00", "destination_ip": "10.0.0.2", "source_country": "India"},
    {"timestamp": "2025-08-01 14:00:00", "destination_ip": "10.0.0.2", "source_country": "India"},
    {"timestamp": "2025-08-01 20:00:00", "destination_ip": "10.0.0.3", "source_country": "India"},
]
infer_event = {
    "username": "alice", "timestamp": "2025-08-01 22:00:00",
    "destination_ip": "10.0.0.4", "source_country": "India",
    "hour": 22, "is_weekend": False,
    "failed_login_attempts": 0, "status_flag": 0,
    "cvss_score": 5.4, "severity_score": 2, "malware_flag": 0,
    "protocol": "HTTP",
}
infer_enriched = engineer_features_single_event(infer_event, hist4)
inference_epu = infer_enriched["events_per_user"]
inference_udc = infer_enriched["unique_destination_count"]

print(f"\n  5th event for alice:")
print(f"    Training events_per_user   = {training_epu}  |  Inference events_per_user   = {inference_epu}")
print(f"    Training unique_dest_count = {training_udc}  |  Inference unique_dest_count = {inference_udc}")

check(training_epu == inference_epu,
      f"events_per_user: training={training_epu} == inference={inference_epu}")
check(training_udc == inference_udc,
      f"unique_dest_count: training={training_udc} == inference={inference_udc}")

# ============================================================
print(f"\n{SEP}")
print("TEST 4 — FULL PIPELINE: FIT, TRANSFORM, SAVE, LOAD")
print(SEP)

X_df, y = prepare_training_data()
print(f"\n  X_df shape: {X_df.shape}  |  y shape: {y.shape}  |  y classes: {y.nunique()}")
check(X_df.shape[0] == 10000, f"X_df has 10000 rows (got {X_df.shape[0]})")
check(X_df.shape[1] == len(LOGICAL_FEATURES), f"X_df has {len(LOGICAL_FEATURES)} logical columns")
check(len(y) == 10000, "y has 10000 labels")
check(y.nunique() == 10, f"y has 10 unique classes (got {y.nunique()})")

# Verify y-label alignment: original index must match
check(
    df_raw["event_type"].iloc[0] == y.iloc[0],
    "y[0] matches event_type of original first row (index alignment preserved)"
)

# Fit & transform
preprocessor = SecurityEventPreprocessor()
X_train = preprocessor.fit_transform(X_df)
print(f"\n  X_train.shape: {X_train.shape}")
print(f"  Logical feature count:  {preprocessor.logical_feature_count}")
print(f"  Encoded feature count:  {preprocessor.encoded_feature_count}")
print(f"  Encoded feature names:  {preprocessor.feature_names}")
check(X_train.shape == (10000, 16), f"X_train.shape is (10000, 16) (got {X_train.shape})")

# NaN / Inf
nan_count = int(np.isnan(X_train).sum())
inf_count = int(np.isinf(X_train).sum())
print(f"\n  NaN count: {nan_count}  |  Inf count: {inf_count}")
check(nan_count == 0, f"No NaNs in X_train (got {nan_count})")
check(inf_count == 0, f"No Infs in X_train (got {inf_count})")

# Save
artifact_path = preprocessor.save()
print(f"\n  preprocessor.pkl saved to: {artifact_path}")
print(f"  File size: {artifact_path.stat().st_size} bytes")
check(artifact_path.exists(), "preprocessor.pkl exists on disk")

# ============================================================
print(f"\n{SEP}")
print("TEST 5 — ARTIFACT LOAD & SINGLE-EVENT COMPATIBILITY")
print(SEP)

loaded = load_preprocessor()
X_reloaded = loaded.transform(X_df)
identical = np.allclose(X_train, X_reloaded)
print(f"\n  Reloaded transform identical: {identical}")
check(identical, "Loaded artifact produces identical transforms")

# Single-event inference
X_event = loaded.transform_single(infer_enriched)
print(f"  X_event.shape: {X_event.shape}")
check(X_event.shape == (1, 16), f"X_event shape is (1,16) (got {X_event.shape})")
check(X_train.shape[1] == X_event.shape[1],
      f"Training ({X_train.shape[1]}) and inference ({X_event.shape[1]}) column counts match")
check(preprocessor.feature_names == loaded.feature_names,
      "Feature names identical after pkl round-trip")

# ============================================================
print(f"\n{SEP}")
print("TEST 6 — UNSEEN PROTOCOL HANDLING")
print(SEP)

event_quic = dict(infer_enriched)
event_quic["protocol"] = "QUIC"
X_quic = loaded.transform_single(event_quic)
protocol_start = len(SecurityEventPreprocessor._NUMERIC_FEATURES)
ohe_sum = X_quic[0, protocol_start:].sum()
print(f"\n  Unseen protocol 'QUIC': X shape={X_quic.shape}, OHE cols sum={ohe_sum}")
check(X_quic.shape[1] == 16, f"Column count unchanged for unseen protocol (got {X_quic.shape[1]})")
check(ohe_sum == 0.0, f"OHE cols are all-zero for unseen protocol (sum={ohe_sum})")

# ============================================================
print(f"\n{SEP}")
print("FINAL SUMMARY")
print(SEP)

if errors:
    print(f"\n  {len(errors)} CHECK(S) FAILED:")
    for e in errors:
        print(f"    [FAIL] {e}")
    sys.exit(1)
else:
    print(f"\n  ALL CHECKS PASSED — Phase 2 Correction is valid.")
    print(f"  preprocessor.pkl rebuilt at: {artifact_path}")
print(SEP)
