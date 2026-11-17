"""
Automated Training, Benchmark Evaluation, and Versioning Pipeline for PhishGuard ML.
Trains Logistic Regression, Random Forest, and GBDT classifiers on domain-grouped datasets.
Exports champion model artifact to ml/models/phishguard_rf_v1.joblib.
"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.src.dataset import DEFAULT_PROCESSED_PATH, generate_dataset, load_dataset
from ml.src.evaluate import ModelMetrics, evaluate_model
from ml.src.features import FEATURE_NAMES, URLFeatureTransformer
from ml.src.splitters import DomainGroupedSplitter

MODELS_DIR = PROJECT_ROOT / "ml" / "models"
CHAMPION_ARTIFACT_PATH = MODELS_DIR / "phishguard_rf_v1.joblib"
BENCHMARK_JSON_PATH = MODELS_DIR / "benchmark_report.json"
BENCHMARK_MD_PATH = MODELS_DIR / "benchmark_report.md"


def get_candidate_models() -> List[Tuple[str, Any]]:
    """Define candidate ML models for benchmark comparison."""
    return [
        (
            "Logistic Regression (Baseline)",
            Pipeline([
                ("scaler", StandardScaler()),
                ("classifier", LogisticRegression(max_iter=1000, C=1.0, random_state=42)),
            ]),
        ),
        (
            "Random Forest",
            RandomForestClassifier(
                n_estimators=100,
                max_depth=12,
                min_samples_split=2,
                random_state=42,
                n_jobs=-1,
            ),
        ),
        (
            "Gradient Boosted Trees (GBDT)",
            GradientBoostingClassifier(
                n_estimators=100,
                max_depth=5,
                learning_rate=0.1,
                random_state=42,
            ),
        ),
    ]


def run_training_pipeline(
    dataset_path: Path = DEFAULT_PROCESSED_PATH,
    models_dir: Path = MODELS_DIR,
    target_size: int = 600,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Execute full training, benchmark evaluation, and artifact serialization.
    """
    models_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load or Generate Dataset
    if dataset_path.exists():
        df = load_dataset(dataset_path)
    else:
        df = generate_dataset(target_size=target_size, random_state=random_state)

    # 2. Domain-level Leakage-Free Splitting
    train_df, val_df, test_df = DomainGroupedSplitter.split(
        df,
        train_ratio=0.70,
        val_ratio=0.15,
        test_ratio=0.15,
        random_state=random_state,
    )

    # 3. Feature Extraction
    transformer = URLFeatureTransformer()
    X_train = transformer.transform(train_df["url"])
    y_train = train_df["label"].values.astype(int)

    X_val = transformer.transform(val_df["url"])
    y_val = val_df["label"].values.astype(int)

    X_test = transformer.transform(test_df["url"])
    y_test = test_df["label"].values.astype(int)

    # 4. Train and Benchmark Candidates
    candidates = get_candidate_models()
    benchmark_results: List[ModelMetrics] = []
    trained_models: Dict[str, Any] = {}

    for name, model in candidates:
        model.fit(X_train, y_train)
        trained_models[name] = model

        # Evaluate on holdout test set
        metrics = evaluate_model(model, X_test, y_test, model_name=name)
        benchmark_results.append(metrics)

    # 5. Select Champion Model (prefer Random Forest / GBDT on ties)
    model_priority = {
        "Random Forest": 3,
        "Gradient Boosted Trees (GBDT)": 2,
        "Logistic Regression (Baseline)": 1,
    }
    ranked = sorted(
        benchmark_results,
        key=lambda m: (m.f1, -m.false_positive_rate, m.accuracy, model_priority.get(m.model_name, 0)),
        reverse=True,
    )
    champion_metrics = ranked[0]
    champion_name = champion_metrics.model_name
    champion_model = trained_models[champion_name]

    # 6. Serialize Champion Model Artifact
    artifact = {
        "model": champion_model,
        "model_name": champion_name,
        "feature_names": FEATURE_NAMES,
        "feature_count": len(FEATURE_NAMES),
        "threshold": 0.65,
        "metrics": champion_metrics.to_dict(),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
        "dataset_split": {
            "train_samples": len(train_df),
            "val_samples": len(val_df),
            "test_samples": len(test_df),
            "total_samples": len(df),
        },
    }

    joblib.dump(artifact, CHAMPION_ARTIFACT_PATH)

    # 7. Write Benchmark Reports
    report_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "champion_model": champion_name,
        "splits": {
            "train": len(train_df),
            "val": len(val_df),
            "test": len(test_df),
        },
        "models": [m.to_dict() for m in benchmark_results],
    }

    with open(BENCHMARK_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # Write Markdown Benchmark Report
    md_lines = [
        "# PhishGuard ML Benchmark Report",
        "",
        f"**Generated:** {report_data['generated_at']}  ",
        f"**Champion Model:** `{champion_name}`  ",
        f"**Dataset Partition:** Train={len(train_df)} | Val={len(val_df)} | Test={len(test_df)}  ",
        "",
        "## Model Comparison Matrix",
        "",
        "| Model | Accuracy | Precision | Recall | F1-Score | FPR | FNR | Avg Latency |",
        "|---|---|---|---|---|---|---|---|",
    ]

    for m in benchmark_results:
        md_lines.append(
            f"| {m.model_name} | {m.accuracy*100:.1f}% | {m.precision*100:.1f}% | {m.recall*100:.1f}% | {m.f1*100:.1f}% | {m.false_positive_rate*100:.2f}% | {m.false_negative_rate*100:.2f}% | {m.avg_latency_ms:.2f}ms |"
        )

    md_lines.extend([
        "",
        "## Champion Model Artifact",
        "",
        f"- **Path:** `{CHAMPION_ARTIFACT_PATH.name}`",
        f"- **Feature Dimension:** {len(FEATURE_NAMES)} features",
        f"- **Phishing Decision Threshold:** 0.65",
        f"- **Serialization Format:** Joblib compressed object",
    ])

    with open(BENCHMARK_MD_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    return {
        "champion_name": champion_name,
        "champion_metrics": champion_metrics.to_dict(),
        "artifact_path": str(CHAMPION_ARTIFACT_PATH),
        "benchmark_report_path": str(BENCHMARK_JSON_PATH),
    }


if __name__ == "__main__":
    result = run_training_pipeline()
    print(f"Training Complete. Champion: {result['champion_name']}")
    print(f"Artifact saved to: {result['artifact_path']}")
