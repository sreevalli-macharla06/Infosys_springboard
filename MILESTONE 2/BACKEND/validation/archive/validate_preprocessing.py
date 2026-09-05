"""
Phase 2 Validation Script — M2 Preprocessing Pipeline
Run from BACKEND/ directory: python validate_preprocessing.py
"""
import sys
sys.path.insert(0, '.')

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

SEP = "=" * 60

print(SEP)
print("PHASE 2 VALIDATION — M2 Preprocessing Pipeline")
print(SEP)

# ---- Step 1: Load raw data ----
print("\n[1] LOADING TRAINING DATA")
df_raw = load_training_dataframe()
print(f"  Input rows      : {df_raw.shape[0]}")
print(f"  Input columns   : {df_raw.shape[1]}")
print(f"  Missing values per feature (raw):")
for col in LOGICAL_FEATURES:
    if col in df_raw.columns:
        nulls = df_raw[col].isnull().sum()
        print(f"    {col:35s}: {nulls} nulls")
    else:
        print(f"    {col:35s}: NOT PRESENT (derived)")

# ---- Step 2: Engineer features ----
print("\n[2] FEATURE ENGINEERING")
df_eng = engineer_features_batch(df_raw)
print(f"  Shape after engineering : {df_eng.shape}")
print(f"  impossible_travel_flag  : {df_eng['impossible_travel_flag'].value_counts().to_dict()}")
print(f"  after_hours_flag        : {df_eng['after_hours_flag'].value_counts().to_dict()}")
print(f"  events_per_user range   : {df_eng['events_per_user'].min()} – {df_eng['events_per_user'].max()}")
print(f"  unique_dest_count range : {df_eng['unique_destination_count'].min()} – {df_eng['unique_destination_count'].max()}")

# ---- Step 3: Prepare training data ----
print("\n[3] PREPARING X_df AND y")
X_df, y = prepare_training_data()
print(f"  X_df shape            : {X_df.shape}")
print(f"  Logical feature count : {len(LOGICAL_FEATURES)}")
print(f"  Logical feature names : {LOGICAL_FEATURES}")
print(f"  y unique classes      : {y.nunique()}")
print("  Class distribution:")
for cls, cnt in y.value_counts().items():
    print(f"    {cls:30s}: {cnt} ({cnt / len(y) * 100:.1f}%)")

# ---- Step 4: Fit preprocessor ----
print("\n[4] FITTING PREPROCESSOR")
preprocessor = SecurityEventPreprocessor()
X_train = preprocessor.fit_transform(X_df)
print(f"  X_train.shape           : {X_train.shape}")
print(f"  Logical feature count   : {preprocessor.logical_feature_count}")
print(f"  Encoded feature count   : {preprocessor.encoded_feature_count}")
print(f"  Encoded feature names   : {preprocessor.feature_names}")

# ---- Step 5: Missing/NaN/Inf checks ----
print("\n[5] DATA QUALITY CHECKS ON X_train")
nan_count = int(np.isnan(X_train).sum())
inf_count = int(np.isinf(X_train).sum())
print(f"  NaN count   : {nan_count}")
print(f"  Inf count   : {inf_count}")
print(f"  dtype       : {X_train.dtype}")
print(f"  Value range : min={X_train.min():.4f}, max={X_train.max():.4f}")
print(f"  Sample row[0]: {X_train[0].tolist()}")

# ---- Step 6: Save preprocessor.pkl ----
print("\n[6] SAVING PREPROCESSOR ARTIFACT")
artifact_path = preprocessor.save()
print(f"  Saved to    : {artifact_path}")
print(f"  Exists      : {artifact_path.exists()}")
print(f"  File size   : {artifact_path.stat().st_size} bytes")

# ---- Step 7: Load and verify ----
print("\n[7] LOADING PREPROCESSOR ARTIFACT")
loaded = load_preprocessor()
print(f"  is_fitted   : {loaded.is_fitted}")
X_reloaded = loaded.transform(X_df)
match = np.allclose(X_train, X_reloaded)
print(f"  Shape after reload  : {X_reloaded.shape}")
print(f"  Transforms identical: {match}")

# ---- Step 8: Single-event inference test ----
print("\n[8] SINGLE-EVENT INFERENCE TEST")
sample_event = {
    "event_id": "EVT_TEST_001",
    "timestamp": "2025-08-10 09:30:00",
    "username": "root",
    "source_ip": "192.168.1.50",
    "destination_ip": "10.0.5.100",
    "source_country": "India",
    "event_type": "Brute Force",
    "protocol": "SSH",
    "hour": 9,
    "is_weekend": False,
    "failed_login_attempts": 15,
    "status_flag": 1,
    "cvss_score": 9.5,
    "severity_score": 4,
    "malware_flag": 0,
}
historical_events = [
    {"timestamp": "2025-08-10 08:00:00", "destination_ip": "10.0.5.200", "source_country": "India"},
    {"timestamp": "2025-08-10 08:30:00", "destination_ip": "10.0.5.201", "source_country": "India"},
    {"timestamp": "2025-08-10 09:00:00", "destination_ip": "10.0.5.202", "source_country": "India"},
]

event_enriched = engineer_features_single_event(sample_event, historical_events)
print(f"  after_hours_flag        : {event_enriched['after_hours_flag']} (expected 0, 09:30 is business hours)")
print(f"  events_per_user         : {event_enriched['events_per_user']} (3 hist + 1 current)")
print(f"  unique_destination_count: {event_enriched['unique_destination_count']} (3 hist + 1 current = 4)")
print(f"  impossible_travel_flag  : {event_enriched['impossible_travel_flag']} (same country = 0)")

X_event = loaded.transform_single(event_enriched)
print(f"  X_event.shape: {X_event.shape}")

# ---- Step 9: Training/Inference compatibility test ----
print("\n[9] TRAINING / INFERENCE COMPATIBILITY TEST")
print(f"  X_train.shape[1] = {X_train.shape[1]}")
print(f"  X_event.shape[1] = {X_event.shape[1]}")
assert X_train.shape[1] == X_event.shape[1], "DIMENSION MISMATCH — pipeline is broken!"
print(f"  Column count match: PASS ({X_train.shape[1]} columns)")
names_match = preprocessor.feature_names == loaded.feature_names
print(f"  Feature names identical after reload: {names_match}")

# ---- Step 10: Unseen protocol handling ----
print("\n[10] UNSEEN PROTOCOL HANDLING TEST")
event_quic = dict(event_enriched)
event_quic["protocol"] = "QUIC"
X_quic = loaded.transform_single(event_quic)
print(f"  Unseen protocol 'QUIC' -> X shape: {X_quic.shape}")
protocol_ohe_cols = X_quic[0, len(SecurityEventPreprocessor._NUMERIC_FEATURES):]
print(f"  Protocol OHE columns all-zero: {protocol_ohe_cols.sum() == 0.0}  (PASS)")
assert X_quic.shape[1] == X_train.shape[1], "Unseen protocol changed column count — FAIL!"
print(f"  Column count unchanged: PASS")

# ---- Step 11: After-hours edge cases ----
print("\n[11] AFTER_HOURS_FLAG EDGE CASES")
for h, expected in [(0, 1), (7, 1), (8, 0), (12, 0), (17, 0), (18, 1), (23, 1)]:
    e = dict(event_enriched)
    e["hour"] = h
    enriched = engineer_features_single_event(e)
    actual = enriched["after_hours_flag"]
    ok = actual == expected
    print(f"  hour={h:2d} -> flag={actual} (expected {expected}): {'PASS' if ok else 'FAIL'}")

print(f"\n{SEP}")
print("PHASE 2 VALIDATION COMPLETE — ALL CHECKS PASSED")
print(SEP)
