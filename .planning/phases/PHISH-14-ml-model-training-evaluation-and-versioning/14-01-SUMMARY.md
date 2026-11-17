# Phase 14: ML Model Training Evaluation and Versioning Summary

**Phase**: 14  
**Plan**: 01  
**Wave**: 4  
**Status**: COMPLETE  
**Execution Date**: 2026-11-14  

---

### Executive Summary
Phase 14 trains, benchmarks, versions, and serves machine learning models for PhishGuard. It completes **Wave 4: Machine Learning Pipeline**, bringing overall project completion to **70% (14 of 20 milestones)**. Three candidate models (Logistic Regression, Random Forest, GBDT) were trained and benchmarked on holdout test data using leakage-free domain grouping. The champion Random Forest model was serialized with Joblib and seamlessly integrated into the FastAPI backend Layer 6 detection engine.

---

### Key Deliverables Implemented

1. **Model Evaluation & Security Metrics Engine** (`ml/src/evaluate.py`):
   - Computes Accuracy, Precision, Recall, F1-Score, Confusion Matrix ($TN, FP, FN, TP$), False Positive Rate (FPR), False Negative Rate (FNR), and per-sample inference latency.

2. **Automated Training & Benchmark Pipeline** (`ml/src/train.py`):
   - Trains three candidate classifiers on domain-grouped split data:
     - Logistic Regression (Baseline with StandardScaler)
     - Random Forest (100 estimators, max_depth=12)
     - Gradient Boosted Decision Trees (GBDT, learning_rate=0.1)
   - Evaluates each model on holdout test set with zero domain leakage.
   - Generates benchmark reports: `ml/models/benchmark_report.json` and `ml/models/benchmark_report.md`.
   - Serializes champion model artifact with Joblib to `ml/models/phishguard_rf_v1.joblib` with feature metadata and 0.65 decision threshold.

3. **Backend Layer 6 ML Classifier Adapter** (`backend/app/detection/ml_classifier.py`):
   - `MLClassifier`: Discovers, loads, and caches the Joblib artifact with graceful fallback.
   - Converts URLs into 34-dimensional feature vectors with 100% parity with training data.
   - Computes phishing probability: `predict_proba(url)`.
   - Generates structured `MLEvaluationResult` with score impact and confidence.

4. **Risk Engine Layer 6 Integration** (`backend/app/detection/scoring.py`):
   - `RiskEngine.evaluate` calls `MLClassifier.evaluate()`.
   - When phishing probability $\ge 0.65$, contributes up to 35 points towards composite risk score and emits `EvidenceItem` with `rule_code="ML_PREDICTED_PHISHING"` and `layer_name="ml_classifier"`.
   - Leaves clean URLs unaffected (score 0 contribution).

5. **Automated Verification**:
   - `ml/tests/test_model.py`: 2 tests verifying end-to-end training, benchmark report creation, Joblib serialization/deserialization, and clean vs. phishing inference separation.
   - `backend/tests/test_ml_classifier.py`: 5 tests verifying artifact discovery, 34-feature vector extraction, probability predictions, and RiskEngine Layer 6 aggregation.
   - **Monorepo Suite: 115 passed tests (100%)**:
     - Extension Vitest: 48 passed
     - Dashboard Vitest: 2 passed
     - Backend Pytest: 52 passed
     - ML Pytest: 13 passed
