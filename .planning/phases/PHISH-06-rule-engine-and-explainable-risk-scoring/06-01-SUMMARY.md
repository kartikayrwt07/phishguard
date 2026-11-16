---
phase: PHISH-06-rule-engine-and-explainable-risk-scoring
plan: "01"
subsystem: detection
tags: [brand-matcher, homoglyphs, levenshtein, dom-signals, risk-scoring, explainability, overrides]

requires:
  - phase: PHISH-05-local-url-analysis-engine
    provides: ParsedURL and URLFeatures extraction engine
provides:
  - Layer 2 Brand Impersonation matcher (homoglyphs, edit-distance, tokenized hyphen inspection, legitimate domain exemptions)
  - Layer 4 DOM structural indicator evaluator (credential targets, IP form actions, hidden iframes) with zero secret inspection
  - High-priority override policies (Threat feed -> PHISHING/100; Allowlist -> SAFE/0)
  - Layer 7 Explainable Risk Scoring Engine producing normalized 0-100 scores, categorical verdicts, and itemized evidence records
affects: [backend, detection, extension, dashboard]

tech-stack:
  added: []
  patterns: [Levenshtein edit-distance, Cyrillic/digit homoglyph substitution, privacy-preserving DOM structural evaluation, explainable weighted scoring]

key-files:
  created:
    - backend/app/detection/brand_matcher.py
    - backend/app/detection/dom_evaluator.py
    - backend/app/detection/scoring.py
    - backend/tests/test_scoring.py
  modified:
    - backend/app/detection/__init__.py

key-decisions:
  - "Maintain a catalog of top 16 targeted brands with legitimate domains to prevent self-flagging"
  - "Tokenize hyphen-separated domain labels to catch compound lookalikes (e.g., paypa1-account-verify.xyz)"
  - "Enforce strict privacy: evaluate structural DOM signals only without collecting or inspecting form values, passwords, or cookies"
  - "High-priority override policies for deterministic allowlists (Score 0, SAFE) and verified threat feed hits (Score 100, PHISHING)"
  - "Produce itemized ScanEvidenceItem for every score-increasing signal for full auditability and explainability"

patterns-established:
  - "BrandMatchResult dataclass with brand, rule, distance, and similarity score"
  - "DOMEvaluationResult dataclass with risk contribution and itemized evidence strings"
  - "RiskReport dataclass containing score, verdict, confidence, and itemized ScanEvidenceItem list"

requirements-completed:
  - DET-02
  - DET-04
  - DET-07
  - DET-08

duration: 25min
completed: 2026-11-14
---

# Phase 06: Rule Engine and Explainable Risk Scoring Summary

**Implemented Layer 2 Brand Impersonation matcher, Layer 4 privacy-preserving DOM structural evaluator, high-priority override policies, and Layer 7 explainable risk scoring engine with itemized evidence.**

## Accomplishments
- **Layer 2 Brand Impersonation & Homoglyphs**:
  - Implemented `BrandMatcher` covering homoglyphs (Cyrillic `а`, `е`, `о`, `р`, digits `0`->`o`, `1`->`l`), Levenshtein distance, tokenized hyphenated domain analysis, and subdomain impersonation.
  - Curated catalog of 16 high-value financial, tech, and enterprise brands.
  - Guaranteed zero false positives on legitimate brand root and subdomains.
- **Layer 4 DOM Structural Indicator Evaluation**:
  - Implemented `DOMSignalEvaluator` analyzing password field presence, cross-origin credential posting, IP destination form actions, hidden iframes, and external resource ratios.
  - Strictly adheres to privacy guarantees: zero collection of password values, inputs, or cookies.
- **Layer 7 Explainable Risk Scoring & Override Policies**:
  - Created `RiskEngine` aggregating Layer 1 URL features, Layer 2 Brand matches, and Layer 4 DOM structural signals into a 0-100 normalized score and categorical verdict (`SAFE`, `SUSPICIOUS`, `PHISHING`, `UNKNOWN`).
  - Implemented deterministic override policies: explicit allowlist overrides to score 0.0 (`SAFE`); verified threat feeds override to score 100.0 (`PHISHING`).
  - Produces an itemized list of `ScanEvidenceItem` records with rule names, layer tags, score impacts, and human-readable descriptions.
- **Automated Verification**:
  - Authored `backend/tests/test_scoring.py` with 10 comprehensive test functions.
  - 10/10 scoring tests pass; 31/31 backend tests pass; all 35 monorepo tests pass.

