# Phase 13: ML Dataset and Feature Engineering Summary

**Phase**: 13  
**Plan**: 01  
**Wave**: 4  
**Status**: COMPLETE  
**Execution Date**: 2026-11-14  

---

### Executive Summary
Phase 13 establishes the data curation, leakage-free domain splitting, and feature transformation foundation for PhishGuard's machine learning detection pipeline. It guarantees mathematical zero domain leakage between training, validation, and holdout test sets using eTLD+1 grouping, and delivers a scikit-learn compatible `URLFeatureTransformer` extracting 34 lexical, structural, and entropy features with exact mathematical parity with the backend inference engine.

---

### Key Deliverables Implemented

1. **Curated & Balanced URL Dataset Engine** (`ml/src/dataset.py`):
   - Comprehensive seed corpus spanning legitimate websites (search, technology, finance, news, education, government) and phishing threat archetypes (homoglyphs, typosquats, compound lookalikes, subdomain spoofing, raw IP hosts, non-standard ports, credential harvesting keywords).
   - Dynamic procedural variant generator expanding diverse query parameters, auth tokens, and subpaths while tracking authentic `registered_domain` (eTLD+1) keys.
   - Verified 50/50 balanced label distribution with automatic URL deduplication.
   - Persistence utilities saving raw and processed CSV datasets to `ml/data/raw/` and `ml/data/processed/`.

2. **Leakage-Free Domain Grouped Splitter** (`ml/src/splitters.py`):
   - Implemented `DomainGroupedSplitter` partitioning data into Train (70%), Validation (15%), and Test (15%) subsets.
   - Strict grouping by `registered_domain`: guarantees that all URLs sharing an eTLD+1 domain are placed exclusively into the same partition, preventing model memorization.
   - Included `verify_no_leakage()` runtime validator that asserts zero domain set intersection between train, val, and test partitions:
     $$\text{Train}_{\text{domains}} \cap \text{Val}_{\text{domains}} = \emptyset, \quad \text{Train}_{\text{domains}} \cap \text{Test}_{\text{domains}} = \emptyset, \quad \text{Val}_{\text{domains}} \cap \text{Test}_{\text{domains}} = \emptyset$$

3. **34-Dimensional URL Feature Extraction Pipeline** (`ml/src/features.py`):
   - Implemented `URLFeatureTransformer` implementing Scikit-learn's `BaseEstimator` and `TransformerMixin`.
   - Extracts all 34 numeric features matching `backend/app/detection/features.py`:
     - 4 Structural lengths (`url_length`, `hostname_length`, `path_length`, `query_length`)
     - 11 Delimiter counts (`num_dots`, `num_hyphens`, `num_underscores`, `num_slashes`, etc.)
     - 2 Subdomain metrics (`subdomain_count`, `subdomain_depth`)
     - 6 Host & protocol properties (`is_ip_host`, `ip_version`, `has_port`, `is_standard_port`, `has_https`, `has_punycode`)
     - 3 Shannon entropy calculations (`entropy_url`, `entropy_host`, `entropy_path`)
     - 5 Character ratios & statistical indicators (`digits_ratio_host`, `digits_ratio_url`, `vowel_ratio_host`, `consonant_ratio_host`, `max_consecutive_consonants`)
     - 3 Reputation & TLD indicators (`num_suspicious_keywords`, `high_risk_tld`, `tld_length`)
   - Guaranteed float64 output matrix without NaN or infinite values.
   - Compatible with `sklearn.pipeline.Pipeline`.

4. **Automated Verification**:
   - `ml/tests/test_dataset.py`: 5 tests verifying sample generation, label balance, deduplication, CSV persistence, and mathematical verification of zero domain leakage.
   - `ml/tests/test_features.py`: 6 tests verifying 34-feature dimensions, data types, clean vs. phishing signal extraction, edge-case URL resilience, and scikit-learn Pipeline interoperability.
   - **Monorepo Suite: 108 passed tests (100%)**:
     - Extension: 48 passed
     - Dashboard: 2 passed
     - Backend: 47 passed
     - ML: 11 passed
