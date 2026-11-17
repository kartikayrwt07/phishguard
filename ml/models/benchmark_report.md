# PhishGuard ML Benchmark Report

**Generated:** 2026-11-14T08:20:31.771307+00:00  
**Champion Model:** `Random Forest`  
**Dataset Partition:** Train=409 | Val=89 | Test=102  

## Model Comparison Matrix

| Model | Accuracy | Precision | Recall | F1-Score | FPR | FNR | Avg Latency |
|---|---|---|---|---|---|---|---|
| Logistic Regression (Baseline) | 100.0% | 100.0% | 100.0% | 100.0% | 0.00% | 0.00% | 0.00ms |
| Random Forest | 100.0% | 100.0% | 100.0% | 100.0% | 0.00% | 0.00% | 0.31ms |
| Gradient Boosted Trees (GBDT) | 100.0% | 100.0% | 100.0% | 100.0% | 0.00% | 0.00% | 0.00ms |

## Champion Model Artifact

- **Path:** `phishguard_rf_v1.joblib`
- **Feature Dimension:** 34 features
- **Phishing Decision Threshold:** 0.65
- **Serialization Format:** Joblib compressed object