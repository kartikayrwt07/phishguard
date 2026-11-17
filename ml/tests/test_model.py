"""
Automated tests for ML model training, benchmarking, and artifact versioning.
"""
from pathlib import Path
import joblib
import numpy as np
import pytest

from ml.src.train import CHAMPION_ARTIFACT_PATH, run_training_pipeline
from ml.src.features import URLFeatureTransformer


def test_training_pipeline_execution(tmp_path: Path):
    """Verify training pipeline trains models, outputs benchmark report, and serializes artifact."""
    output_dir = tmp_path / "models"
    result = run_training_pipeline(
        models_dir=output_dir,
        target_size=200,
        random_state=42,
    )

    assert "champion_name" in result
    assert "champion_metrics" in result
    metrics = result["champion_metrics"]

    # Verify high security quality thresholds
    assert metrics["accuracy"] >= 0.85
    assert metrics["f1"] >= 0.85
    assert metrics["false_positive_rate"] <= 0.15

    # Verify artifact was created and is loadable
    artifact_path = Path(result["artifact_path"])
    assert artifact_path.exists()

    artifact = joblib.load(artifact_path)
    assert "model" in artifact
    assert "threshold" in artifact
    assert "feature_names" in artifact
    assert len(artifact["feature_names"]) == 34
    assert artifact["threshold"] == 0.65


def test_champion_model_inference():
    """Verify champion model predicts probability for clean vs phishing URLs."""
    assert CHAMPION_ARTIFACT_PATH.exists()
    artifact = joblib.load(CHAMPION_ARTIFACT_PATH)
    model = artifact["model"]

    transformer = URLFeatureTransformer()
    clean_vec = transformer.transform(["https://www.google.com"])
    phish_vec = transformer.transform(["http://paypa1-account-security.xyz:8080/login.php"])

    clean_prob = model.predict_proba(clean_vec)[0][1]
    phish_prob = model.predict_proba(phish_vec)[0][1]

    assert 0.0 <= clean_prob <= 1.0
    assert 0.0 <= phish_prob <= 1.0
    # Phishing URL must have significantly higher phishing probability than clean URL
    assert phish_prob > clean_prob
    assert clean_prob < 0.35
    assert phish_prob > 0.65
