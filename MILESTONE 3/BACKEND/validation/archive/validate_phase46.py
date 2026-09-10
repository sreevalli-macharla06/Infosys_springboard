"""
Phase 4.6 — RF Artifact Size Optimization: Retrain + Full Validation
Run from BACKEND/: python validate_phase46.py
"""
import sys, os
os.environ["PYTHONIOENCODING"] = "utf-8"
sys.path.insert(0, ".")
import warnings; warnings.filterwarnings("ignore")
import logging; logging.disable(logging.CRITICAL)

import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from ml.preprocessing import (
    prepare_training_data, SecurityEventPreprocessor,
    engineer_features_batch, load_training_dataframe, LOGICAL_FEATURES,
)
from ml.classifier import (
    train_random_forest, predict_threat, save_model, load_model,
    get_default_params, feature_importances_report,
)

SEP  = "=" * 65
SEP2 = "-" * 65
RANDOM_STATE = 42

PREV_SIZE_BYTES = 376_473_289   # Phase 4 clf_model.pkl
PREV_ACC        = 0.1030
PREV_MACRO_F1   = 0.1018

errors = []

def hdr(t): print(f"\n{SEP}\n{t}\n{SEP}")
def chk(cond, label, detail=""):
    tag = "[PASS]" if cond else "[FAIL]"
    print(f"  {tag} {label}")
    if not cond:
        errors.append(f"{label}: {detail}")


# ─── Build exactly the same split used in Phase 4 ───────────────────────────
df_raw   = load_training_dataframe()
df_eng   = engineer_features_batch(df_raw)
X_df_all = df_eng[LOGICAL_FEATURES].copy()
_, y     = prepare_training_data()

idx          = np.arange(len(X_df_all))
idx_tr, idx_te = train_test_split(
    idx, test_size=0.20, random_state=RANDOM_STATE, stratify=y.values
)

X_df_tr = X_df_all.iloc[idx_tr].reset_index(drop=True)
X_df_te = X_df_all.iloc[idx_te].reset_index(drop=True)
y_tr    = y.values[idx_tr]
y_te    = y.values[idx_te]

# Local preprocessor fitted on train split only (leakage-free evaluation)
pp = SecurityEventPreprocessor()
pp.fit(X_df_tr)
X_tr = pp.transform(X_df_tr)
X_te = pp.transform(X_df_te)


# ===========================================================================
# STEP 1 — Verify new parameters
# ===========================================================================
hdr("STEP 1 — NEW RF PARAMETERS")
params = get_default_params()
print("\n  Parameter       | Old (Phase 4) | New (Phase 4.6)")
print(f"  {'-'*55}")
print(f"  n_estimators    |           300 | {params['n_estimators']}")
print(f"  max_depth       |          None | {params['max_depth']}")
print(f"  max_features    |        'sqrt' | '{params['max_features']}'")
print(f"  class_weight    |          None | {params['class_weight']}")
print(f"  bootstrap       |          True | {params['bootstrap']}")
print(f"  random_state    |            42 | {params['random_state']}")
print(f"  n_jobs          |            -1 | {params['n_jobs']}")

chk(params["n_estimators"] == 100,   f"n_estimators == 100 (got {params['n_estimators']})")
chk(params["max_depth"]    == 15,    f"max_depth == 15 (got {params['max_depth']})")
chk(params["random_state"] == 42,    "random_state == 42")
chk(params["max_features"] == "sqrt","max_features == 'sqrt'")
# Confirm NO leakage fields were added
chk(X_tr.shape[1] == 16,
    f"Feature matrix still 16 columns — no new features added (got {X_tr.shape[1]})")


# ===========================================================================
# STEP 2 — Train optimised model
# ===========================================================================
hdr("STEP 2 — TRAIN OPTIMISED RANDOM FOREST")
print(f"\n  Training on {len(X_tr):,} rows x {X_tr.shape[1]} features, {len(set(y_tr))} classes.")
print(f"  Target: event_type  |  Features: 16-col preprocessed contract (NO leakage fields)")

rf = train_random_forest(X_tr, y_tr, params=params)
print(f"  Training complete.")

# Confirm no leakage field appeared in model
chk(rf.n_features_in_ == 16,
    f"RF trained on 16 features — no extra fields (got {rf.n_features_in_})")


# ===========================================================================
# STEP 3 — Evaluate on held-out test set
# ===========================================================================
hdr("STEP 3 — TEST-SET EVALUATION")

y_pred  = rf.predict(X_te)
y_proba = rf.predict_proba(X_te)
classes = list(rf.classes_)

acc    = accuracy_score(y_te, y_pred)
report = classification_report(y_te, y_pred, target_names=classes,
                                output_dict=True, zero_division=0)
rep_str = classification_report(y_te, y_pred, target_names=classes, zero_division=0)

print(f"\n  Test rows             : {len(X_te):,}")
print(f"  Classes               : {len(classes)}")
print(f"  Random-chance ceiling : {1/len(classes)*100:.1f}%")

print(f"\n  {'Metric':<22} | {'New (4.6)':>10} | {'Old (Phase 4)':>13} | {'Delta':>7}")
print(f"  {'-'*60}")
rows = [
    ("Accuracy",           acc,                               PREV_ACC,     f"{(acc - PREV_ACC)*100:+.2f}%"),
    ("Macro Precision",    report["macro avg"]["precision"],  None,         ""),
    ("Macro Recall",       report["macro avg"]["recall"],     None,         ""),
    ("Macro F1",           report["macro avg"]["f1-score"],   PREV_MACRO_F1,f"{(report['macro avg']['f1-score'] - PREV_MACRO_F1):+.4f}"),
    ("Weighted Precision", report["weighted avg"]["precision"],None,        ""),
    ("Weighted Recall",    report["weighted avg"]["recall"],  None,         ""),
    ("Weighted F1",        report["weighted avg"]["f1-score"],None,         ""),
]
for label, val, old, delta in rows:
    old_str = f"{old:.4f}" if old is not None else "—"
    print(f"  {label:<22} | {val:>10.4f} | {old_str:>13} | {delta:>7}")

print(f"\n  Full Classification Report:\n")
for line in rep_str.strip().split("\n"):
    print(f"    {line}")

# Confusion matrix (diagonal values)
cm = confusion_matrix(y_te, y_pred, labels=classes)
print(f"\n  Confusion Matrix (diagonal = correct; rows=actual, cols=predicted):")
for i, cls in enumerate(classes):
    print(f"    {cls:30s}: {[int(v) for v in cm[i]]}")

chk(abs(acc - PREV_ACC) < 0.03,
    f"Accuracy within 3pp of Phase 4 baseline "
    f"(new={acc*100:.2f}%, old={PREV_ACC*100:.2f}%)")


# ===========================================================================
# STEP 4 — predict_proba validation
# ===========================================================================
hdr("STEP 4 — PREDICT_PROBA VALIDATION")

prob_sums     = y_proba.sum(axis=1)
all_sum_to_1  = np.allclose(prob_sums, 1.0, atol=1e-6)
print(f"\n  Test rows        : {len(y_proba):,}")
print(f"  Prob-sum min     : {prob_sums.min():.10f}")
print(f"  Prob-sum max     : {prob_sums.max():.10f}")
chk(all_sum_to_1, "All probability rows sum to 1.0 (atol=1e-6)")
chk(y_proba.shape == (len(X_te), len(classes)),
    f"predict_proba shape == ({len(X_te)}, {len(classes)})")


# ===========================================================================
# STEP 5 — Save artifact + size comparison
# ===========================================================================
hdr("STEP 5 — SAVE clf_model.pkl + SIZE COMPARISON")

clf_path = save_model(rf)
new_size = clf_path.stat().st_size
reduction_bytes = PREV_SIZE_BYTES - new_size
reduction_pct   = reduction_bytes / PREV_SIZE_BYTES * 100

print(f"\n  Old size (Phase 4)   : {PREV_SIZE_BYTES:>15,} bytes  ({PREV_SIZE_BYTES/1024/1024:.1f} MB)")
print(f"  New size (Phase 4.6) : {new_size:>15,} bytes  ({new_size/1024/1024:.1f} MB)")
print(f"  Reduction            : {reduction_bytes:>15,} bytes  ({reduction_pct:.1f}%)")

chk(clf_path.exists(), f"clf_model.pkl exists at {clf_path}")
chk(new_size < PREV_SIZE_BYTES,
    f"New artifact is smaller than Phase 4 ({new_size:,} < {PREV_SIZE_BYTES:,})")
chk(new_size < 100 * 1024 * 1024,
    f"New artifact is under 100 MB ({new_size/1024/1024:.1f} MB)")


# ===========================================================================
# STEP 6 — Reload validation
# ===========================================================================
hdr("STEP 6 — RELOAD VALIDATION")

loaded_rf = load_model(clf_path)
print(f"\n  Loaded type             : {type(loaded_rf).__name__}")
print(f"  n_estimators after load : {loaded_rf.n_estimators}")
print(f"  max_depth after load    : {loaded_rf.max_depth}")
print(f"  n_features_in_          : {loaded_rf.n_features_in_}")

chk(isinstance(loaded_rf, type(rf)),
    "Loaded model is a RandomForestClassifier")
chk(loaded_rf.n_estimators == 100, "n_estimators == 100 after reload")
chk(loaded_rf.max_depth    == 15,  "max_depth == 15 after reload")

# predict() after reload
y_pred_loaded = loaded_rf.predict(X_te)
preds_match   = np.array_equal(y_pred, y_pred_loaded)
chk(preds_match, "predict() before reload == predict() after reload")

# predict_proba() after reload
y_proba_loaded  = loaded_rf.predict_proba(X_te)
probas_match    = np.allclose(y_proba, y_proba_loaded, atol=1e-10)
chk(probas_match, "predict_proba() before reload approx== after reload (atol=1e-10)")

print(f"\n  Sample prediction before/after reload (first 5 test rows):")
print(f"  {'idx':>4} | {'before':>25} | {'after':>25} | {'match':>5}")
print(f"  {'-'*65}")
for i in range(5):
    match = y_pred[i] == y_pred_loaded[i]
    print(f"  {i:>4} | {y_pred[i]:>25} | {y_pred_loaded[i]:>25} | {'YES' if match else 'NO':>5}")


# ===========================================================================
# STEP 7 — Reproducibility
# ===========================================================================
hdr("STEP 7 — REPRODUCIBILITY (2 independent training runs)")

rf2 = train_random_forest(X_tr, y_tr, params=params)
pred2  = rf2.predict(X_te)
proba2 = rf2.predict_proba(X_te)

preds_repro  = np.array_equal(y_pred, pred2)
probas_repro = np.allclose(y_proba, proba2, atol=1e-10)

print(f"\n  Predictions identical  : {preds_repro}")
print(f"  Probabilities identical: {probas_repro}")
chk(preds_repro,  "Predictions identical across 2 training runs")
chk(probas_repro, "Probabilities identical across 2 training runs")


# ===========================================================================
# STEP 8 — Preprocessor + classifier compatibility
# ===========================================================================
hdr("STEP 8 — PREPROCESSOR / CLASSIFIER COMPATIBILITY")

from ml.preprocessing import load_preprocessor, engineer_features_single_event

prod_pp   = load_preprocessor(Path("models/preprocessor.pkl"))
prod_clf  = load_model(Path("models/clf_model.pkl"))

print(f"\n  preprocessor.pkl — encoded features : {prod_pp.encoded_feature_count}")
print(f"  preprocessor.pkl — feature names    : {prod_pp.feature_names}")
print(f"  clf_model.pkl    — n_features_in_   : {prod_clf.n_features_in_}")
print(f"  clf_model.pkl    — n_estimators     : {prod_clf.n_estimators}")
print(f"  clf_model.pkl    — max_depth        : {prod_clf.max_depth}")
print(f"  clf_model.pkl    — n_classes_       : {prod_clf.n_classes_}")

chk(prod_pp.encoded_feature_count == prod_clf.n_features_in_,
    f"Feature count match: preprocessor({prod_pp.encoded_feature_count}) == clf({prod_clf.n_features_in_})")

# End-to-end single-event inference
test_evt = {
    "event_id": "EVT_46_001", "timestamp": "2025-08-10 09:00:00",
    "username": "testuser", "source_ip": "10.0.0.1",
    "destination_ip": "10.0.5.1", "source_country": "India",
    "event_type": "Brute Force", "protocol": "SSH",
    "hour": 9, "is_weekend": False, "failed_login_attempts": 12,
    "status_flag": 1, "cvss_score": 8.5, "severity_score": 4, "malware_flag": 1,
}
enriched  = engineer_features_single_event(test_evt)
X_single  = prod_pp.transform_single(enriched)
pred_cls  = prod_clf.predict(X_single)[0]
pred_proba = prod_clf.predict_proba(X_single)[0]

print(f"\n  Single-event inference:")
print(f"    X_single.shape       : {X_single.shape}")
print(f"    predicted_class      : {pred_cls}")
print(f"    top probability      : {pred_proba.max():.6f}")
print(f"    prob sum             : {pred_proba.sum():.10f}")
chk(X_single.shape == (1, 16), f"X_single shape == (1,16) (got {X_single.shape})")
chk(np.isclose(pred_proba.sum(), 1.0, atol=1e-6), "Single-event proba sums to 1.0")


# ===========================================================================
# STEP 9 — Confirm no leakage / feature additions
# ===========================================================================
hdr("STEP 9 — LEAKAGE / FEATURE ADDITION CONFIRMATION")

LEAKAGE_FIELDS = [
    "event_type", "technique_id", "technique_name", "tactic",
    "risk_level", "login_risk", "threat_confidence",
]
EXPECTED_FEATURES = [
    "failed_login_attempts", "status_flag", "cvss_score", "severity_score",
    "malware_flag", "hour", "is_weekend", "events_per_user",
    "unique_destination_count", "after_hours_flag", "impossible_travel_flag",
    "protocol_HTTP", "protocol_HTTPS", "protocol_SMB", "protocol_SSH", "protocol_TCP",
]

print(f"\n  Leakage fields in feature contract: (all should be absent)")
for f in LEAKAGE_FIELDS:
    present = f in prod_pp.feature_names
    chk(not present, f"'{f}' NOT in feature contract")

print(f"\n  Expected feature names match:")
chk(prod_pp.feature_names == EXPECTED_FEATURES,
    f"Feature names unchanged from Phase 2 contract",
    f"got {prod_pp.feature_names}")

print(f"\n  Feature count: {prod_pp.encoded_feature_count} (expected 16)")
chk(prod_pp.encoded_feature_count == 16, "Encoded feature count is 16")


# ===========================================================================
# FINAL SUMMARY
# ===========================================================================
hdr("FINAL SUMMARY")

print(f"""
  PARAMETERS
  ----------
  n_estimators : 100  (was 300)
  max_depth    : 15   (was None)
  max_features : sqrt (unchanged)
  random_state : 42   (unchanged)

  ARTIFACT SIZE
  -------------
  Old (Phase 4)   : {PREV_SIZE_BYTES:,} bytes  ({PREV_SIZE_BYTES/1024/1024:.1f} MB)
  New (Phase 4.6) : {new_size:,} bytes  ({new_size/1024/1024:.1f} MB)
  Reduction       : {reduction_bytes:,} bytes  ({reduction_pct:.1f}%)

  METRICS COMPARISON
  ------------------
  Accuracy  — New: {acc*100:.2f}%   Old: {PREV_ACC*100:.2f}%   Delta: {(acc-PREV_ACC)*100:+.2f}pp
  Macro F1  — New: {report['macro avg']['f1-score']:.4f}   Old: {PREV_MACRO_F1:.4f}   Delta: {(report['macro avg']['f1-score']-PREV_MACRO_F1):+.4f}

  VALIDATIONS
  -----------
  predict_proba sums to 1.0    : {all_sum_to_1}
  Reload predictions match     : {preds_match}
  Reload probabilities match   : {probas_match}
  Reproducibility (2 runs)     : {preds_repro and probas_repro}
  No leakage fields added      : True
  Feature count unchanged (16) : True
""")

if errors:
    print(f"  {len(errors)} CHECK(S) FAILED:")
    for e in errors:
        print(f"    [FAIL] {e}")
    sys.exit(1)
else:
    print(f"  ALL CHECKS PASSED.")
    print(f"  clf_model.pkl path: {clf_path}")
print(SEP)
