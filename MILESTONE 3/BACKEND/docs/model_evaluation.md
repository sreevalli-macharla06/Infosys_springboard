# Milestone 2 — Model Evaluation & Performance Document

## Executive Summary

This document provides a comprehensive evaluation of the machine learning models implemented for **SentinelAI Milestone 2 (AI-Assisted Threat Detection Dashboard)**.

The system uses a multi-layered hybrid threat detection engine:
- **Layer 1: Isolation Forest** (Unsupervised Anomaly Detection — 50% weight)
- **Layer 2: Random Forest Classifier** (Supervised Multi-Class Classification — 10% weight)
- **Layer 3: Heuristic Security Rule Engine** (Domain Rule Scoring — 40% weight)

---

## 1. Dataset & Telemetry Specifications

| Parameter | Value |
|---|---|
| Total Security Events ($N$) | 10,000 documents |
| Dataset Timeline | 2025-08-01 to 2025-08-07 |
| Primary Database | MongoDB (`security_events` & `threat_predictions`) |
| Label Availability | Unsupervised M1 telemetry data with synthetic labels |

---

## 2. Feature Selection & Matrix Encoding

The pipeline transforms 12 logical features into 16 encoded ML matrix columns ($X$) using `OneHotEncoder(handle_unknown='ignore')` on categorical `protocol`:

### Selected Features (12 Logical Inputs)
1. `failed_login_attempts` (Numeric)
2. `status_flag` (Numeric)
3. `cvss_score` (Numeric)
4. `severity_score` (Numeric)
5. `malware_flag` (Numeric)
6. `hour` (Numeric)
7. `is_weekend` (Boolean / Numeric)
8. `protocol` (Categorical: HTTP, HTTPS, SMB, SSH, TCP $\rightarrow$ OneHot Encoded)
9. `events_per_user` (Numeric, Causal Historical Feature)
10. `unique_destination_count` (Numeric, Causal Historical Feature)
11. `after_hours_flag` (Numeric)
12. `impossible_travel_flag` (Numeric, Causal Historical Feature)

### Excluded Features (Data Leakage & Non-Predictive Direct Identifiers)
- `event_id` (Unique identifier)
- `timestamp` (Target for temporal ordering, not feature value)
- `source_ip`, `destination_ip` (High cardinality network IPs)
- `username` (User entity identifier)
- `source_country`, `destination_country`, `year`, `month` (Zero-variance constant fields)
- `event_type` (Supervised target label)

---

## 3. Model Architecture & Hyperparameters

### Layer 1: Isolation Forest (`if_model.pkl`)
- **Algorithm**: `sklearn.ensemble.IsolationForest`
- **n_estimators**: 200
- **contamination**: 0.10 (10% anomaly prior assumption)
- **random_state**: 42
- **Purpose**: Detect anomalous behavioral spikes without relying on target labels.

### Layer 2: Random Forest Classifier (`clf_model.pkl`)
- **Algorithm**: `sklearn.ensemble.RandomForestClassifier`
- **n_estimators**: 100
- **max_depth**: 15
- **random_state**: 42
- **Target Classes**: 10 Threat Categories (`Brute Force`, `Failed Login`, `File Access`, `Login Success`, `Malware Detection`, `Phishing Email`, `Port Scan`, `Privilege Escalation`, `SQL Injection Attempt`, `USB Device Connected`).

---

## 4. Offline Model Evaluation Results

### Model Comparison (80/20 Train-Test Split)

The system's primary supervised classifier is a Random Forest. A Logistic Regression model was trained on the identical 80/20 train/test split for baseline comparison.

```text
Test Set Evaluation Metrics (2,000 Test Events):
------------------------------------------------
Random Forest Classifier:
  - Test Accuracy   : 9.85%
  - Macro Precision : 9.70%
  - Macro Recall    : 9.68%
  - Macro F1-Score  : 9.61%

Logistic Regression:
  - Test Accuracy   : 11.60%
  - Macro Precision : 10.09%
  - Macro Recall    : 10.83%
  - Macro F1-Score  : 8.74%
```

### Confusion Matrices

**Random Forest Confusion Matrix:**
```text
                         Brute Fo Failed L File Acc Login Su Malware  Phishing Port Sca Privileg SQL Inje USB Devi
  Brute Force                 20       22       31        8       20       11       28       27       20       25
  Failed Login                24       26       22       11       15        9       21       31       22       12
  File Access                 27       18       26       19       15       10       21       40       32       13
  Login Success               21       13       26       11       17       11       15       30       31       17
  Malware Detection           21       14       23       14       19       11       15       20       25       18
  Phishing Email              20       12       27       15       18        8       14       21       23       16
  Port Scan                   17       14       16       20       14       13       18       33       31       18
  Privilege Escalation        23       20       27       19       13       15       19       26       29       29
  SQL Injection Attempt       20       19       36       19       17       16       18       23       32       23
  USB Device Connected        18       14       36        9       14       13       24       31       21       11
```

**Logistic Regression Confusion Matrix:**
```text
                         Brute Fo Failed L File Acc Login Su Malware  Phishing Port Sca Privileg SQL Inje USB Devi
  Brute Force                 26        2       58        7        8        0       25       46       38        2
  Failed Login                22        3       57        3       10        0        8       40       41        9
  File Access                 27        2       55        2       12        1       19       55       45        3
  Login Success               15        2       56        4       10        0       17       47       38        3
  Malware Detection           16        1       50        7        9        0       21       33       38        5
  Phishing Email              16        0       62        7        5        0       15       34       31        4
  Port Scan                   22        1       53        4        7        0       21       41       43        2
  Privilege Escalation        24        2       54        6        6        0       22       60       44        2
  SQL Injection Attempt       13        4       70        8       15        0       19       42       51        1
  USB Device Connected        13        4       51        4       10        1       21       47       37        3
```

### Technical Explanation of Baseline Classifier Accuracy
The Measured Test Accuracy of **9.85%** is near the theoretical random-guess baseline ($\frac{1}{10} = 10.0\%$).

**Root Cause (Data Characteristic):**
In the synthetic M1 baseline dataset, generic telemetry features (such as `cvss_score`, `failed_login_attempts`, `protocol`) exhibit low linear correlation with specific categorical attack class targets (`event_type`).

**Architectural Safeguard & Soft Weighting:**
Rather than fabricating artificial accuracy or modifying the M1 dataset:
1. Random Forest is constrained to a **10% soft weight** in the hybrid scoring engine ($50\%\text{ IF} + 40\%\text{ Rules} + 10\%\text{ RF}$).
2. Primary threat detection is driven by **Isolation Forest anomaly scores** and **Evidentiary Rule Triggers**, ensuring high operational reliability for SOC analysts.

---

## 5. Global Milestone 2 Anomaly & Verdict Distribution

Evaluated across all 10,000 security events:

| Category | Population Count | Percentage |
|---|---|---|
| **Total Predictions** | 10,000 | 100.0% |
| **Normal Verdicts** | 5,165 | 51.65% |
| **Suspicious Verdicts** | 3,518 | 35.18% |
| **Critical Verdicts** | 1,317 | 13.17% |
| **Isolation Forest Flagged Anomalies** | 1,000 | 10.0% |
| **Average Hybrid Confidence Score** | 37.18% | N/A |

### Terminology Clarity
- **`anomaly_label`**: The raw, unsupervised anomaly signal generated purely by the Isolation Forest (Phase 3).
- **`verdict`**: The final, authoritative threat classification computed by the Hybrid Scoring Engine (Phase 5), combining IF, RF, and rule-based scores. The system classifies verdicts into `Normal`, `Suspicious`, and `Critical`.

> **Note on `/anomalies` Endpoint:** The API endpoint `GET /anomalies` and the "High-Risk Events" frontend KPI strictly use **verdict-based** semantics (i.e., `verdict IN ["Suspicious", "Critical"]`), intentionally returning the final evaluated high-risk events rather than just raw Isolation Forest signals.

---

## 6. Summary of Evidentiary Rules & Explainability

The rule engine triggers XAI evidence factors when specific threshold conditions are met:
- `RULE_MALWARE`: `malware_flag == 1` (+50 pts)
- `RULE_IMPOSSIBLE_TRAVEL`: `impossible_travel_flag == 1` (+45 pts)
- `RULE_FAILED_LOGINS_HIGH`: `failed_login_attempts >= 15` (+40 pts)
- `RULE_CRITICAL_SEVERITY`: `severity_score >= 4` (+35 pts)
- `RULE_HIGH_CVSS`: `cvss_score >= 9.0` (+30 pts)
- `RULE_FAILED_LOGINS_MED`: `8 <= failed_login_attempts < 15` (+20 pts)
- `RULE_HIGH_SEVERITY`: `severity_score == 3` (+20 pts)
- `RULE_MEDIUM_CVSS`: `7.0 <= cvss_score < 9.0` (+15 pts)
- `RULE_AFTER_HOURS`: `after_hours_flag == 1` (+10 pts)
- `IF_ANOMALY_SIGNAL`: Isolation Forest anomaly signal (+0 pts explanation trigger)
