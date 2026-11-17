"""
Automated tests for Backend Layer 6 ML Classifier and RiskEngine Integration.
"""
import pytest
from app.detection.ml_classifier import MLClassifier
from app.detection.scoring import RiskEngine
from app.models.scan import ScanVerdict


def test_ml_classifier_model_loading():
    """Verify backend MLClassifier successfully discovers and loads Joblib model artifact."""
    is_loaded = MLClassifier.load_model()
    assert is_loaded is True
    assert MLClassifier._is_loaded is True
    assert MLClassifier._cached_model is not None


def test_ml_classifier_feature_vector_dimensions():
    """Verify 34-feature vector extraction conforms to expected dimensions."""
    vec = MLClassifier.extract_vector("https://www.google.com")
    assert vec.shape == (1, 34)
    assert not (vec == 0).all()


def test_ml_classifier_clean_vs_phishing_predictions():
    """Verify inference probabilities for clean vs deceptive phishing URLs."""
    clean_prob = MLClassifier.predict_proba("https://www.google.com/search?q=security")
    phish_prob = MLClassifier.predict_proba("http://paypa1-account-security.xyz:8080/login.php")

    assert 0.0 <= clean_prob <= 1.0
    assert 0.0 <= phish_prob <= 1.0
    assert clean_prob < 0.40
    assert phish_prob >= 0.65


def test_ml_classifier_evaluation_structure():
    """Verify MLEvaluationResult data contract for clean vs threat URLs."""
    clean_eval = MLClassifier.evaluate("https://www.wikipedia.org/wiki/Phishing")
    assert clean_eval is not None
    assert clean_eval.is_phishing is False
    assert clean_eval.score_contribution == 0.0

    phish_eval = MLClassifier.evaluate("http://paypa1-account-security.xyz:8080/login.php")
    assert phish_eval is not None
    assert phish_eval.is_phishing is True
    assert phish_eval.score_contribution > 0.0
    assert phish_eval.score_contribution <= 35.0


def test_risk_engine_layer_6_ml_integration():
    """Verify RiskEngine aggregates Layer 6 ML evidence into composite report."""
    phish_url = "http://paypa1-account-security.xyz:8080/login.php"
    report = RiskEngine.evaluate(phish_url)

    assert report.verdict == ScanVerdict.PHISHING
    assert report.risk_score >= 70.0

    rule_codes = [e.rule_code for e in report.evidence]
    assert "ML_PREDICTED_PHISHING" in rule_codes

    ml_ev = next(e for e in report.evidence if e.rule_code == "ML_PREDICTED_PHISHING")
    assert ml_ev.layer_name == "ml_classifier"
    assert ml_ev.score_contribution > 0.0
    assert "probability" in ml_ev.details
