"""
Layer 6: Machine Learning Classifier Serving and Inference Adapter.
Loads serialized Scikit-learn champion model and evaluates URL phishing probability.
"""
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
import numpy as np

from app.detection.features import FeatureExtractor, URLFeatures
from app.detection.url_parser import ParsedURL, URLNormalizer

logger = logging.getLogger("phishguard.ml_classifier")

# Determine model artifact location
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_MODEL_PATH = WORKSPACE_ROOT / "ml" / "models" / "phishguard_rf_v1.joblib"


@dataclass
class MLEvaluationResult:
    """Evaluation result from Layer 6 ML model."""
    probability: float
    is_phishing: bool
    score_contribution: float
    confidence: float
    model_name: str
    version: str


class MLClassifier:
    """
    Inference adapter for Layer 6 Scikit-learn Classifier.
    Extracts 34 features and computes phishing probability.
    """
    _cached_model: Optional[Any] = None
    _cached_metadata: Dict[str, Any] = {}
    _is_loaded: bool = False

    @classmethod
    def load_model(cls, model_path: Optional[Path] = None) -> bool:
        """Load and cache the serialized Joblib model artifact."""
        path = model_path or DEFAULT_MODEL_PATH
        if not path.exists():
            logger.warning(f"ML model artifact not found at {path}. Operating without Layer 6 ML.")
            cls._is_loaded = False
            return False

        try:
            import joblib
            artifact = joblib.load(path)
            if isinstance(artifact, dict) and "model" in artifact:
                cls._cached_model = artifact["model"]
                cls._cached_metadata = {
                    "model_name": artifact.get("model_name", "RandomForest"),
                    "version": artifact.get("version", "1.0.0"),
                    "threshold": artifact.get("threshold", 0.65),
                }
            else:
                cls._cached_model = artifact
                cls._cached_metadata = {
                    "model_name": "RandomForest",
                    "version": "1.0.0",
                    "threshold": 0.65,
                }
            cls._is_loaded = True
            logger.info(f"Loaded ML model '{cls._cached_metadata['model_name']}' v{cls._cached_metadata['version']}.")
            return True
        except Exception as e:
            logger.error(f"Failed to load ML model from {path}: {e}")
            cls._is_loaded = False
            return False

    @classmethod
    def extract_vector(cls, url: str) -> np.ndarray:
        """Extract ordered 34-dimensional feature vector matching training schema."""
        if not url:
            return np.zeros((1, 34), dtype=np.float64)

        parsed: ParsedURL = URLNormalizer.parse(url)
        features: URLFeatures = FeatureExtractor.extract_from_parsed(parsed)

        vector = [
            float(features.url_length),
            float(features.hostname_length),
            float(features.path_length),
            float(features.query_length),
            float(features.num_dots),
            float(features.num_hyphens),
            float(features.num_underscores),
            float(features.num_slashes),
            float(features.num_question_marks),
            float(features.num_equal_signs),
            float(features.num_at_symbols),
            float(features.num_ampersands),
            float(features.num_exclamations),
            float(features.num_tildes),
            float(features.num_percent_signs),
            float(features.subdomain_count),
            float(features.subdomain_depth),
            1.0 if features.is_ip_host else 0.0,
            float(features.ip_version),
            1.0 if features.has_port else 0.0,
            1.0 if features.is_standard_port else 0.0,
            1.0 if features.has_https else 0.0,
            1.0 if features.has_punycode else 0.0,
            float(features.entropy_url),
            float(features.entropy_host),
            float(features.entropy_path),
            float(features.digits_ratio_host),
            float(features.digits_ratio_url),
            float(features.vowel_ratio_host),
            float(features.consonant_ratio_host),
            float(features.max_consecutive_consonants),
            float(features.num_suspicious_keywords),
            1.0 if features.high_risk_tld else 0.0,
            float(len(parsed.tld)),
        ]
        arr = np.array([vector], dtype=np.float64)
        np.nan_to_num(arr, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
        return arr

    @classmethod
    def predict_proba(cls, url: str) -> float:
        """Predict probability of phishing for a target URL (0.0 to 1.0)."""
        if not cls._is_loaded:
            if not cls.load_model():
                return 0.0

        if not cls._cached_model:
            return 0.0

        try:
            X = cls.extract_vector(url)
            proba = cls._cached_model.predict_proba(X)
            # Binary classification: return probability of class 1 (phishing)
            return float(proba[0][1])
        except Exception as e:
            logger.error(f"Inference error on URL '{url}': {e}")
            return 0.0

    @classmethod
    def evaluate(cls, url: str) -> Optional[MLEvaluationResult]:
        """
        Evaluate URL with ML classifier and return structured risk contribution.
        """
        if not cls._is_loaded:
            if not cls.load_model():
                return None

        prob = cls.predict_proba(url)
        threshold = cls._cached_metadata.get("threshold", 0.65)
        is_phish = prob >= threshold

        # Score impact: up to 35 points if predicted phishing
        score_impact = round(prob * 35.0, 1) if is_phish else 0.0
        confidence = round(max(0.70, prob), 2) if is_phish else round(1.0 - prob, 2)

        return MLEvaluationResult(
            probability=round(prob, 4),
            is_phishing=is_phish,
            score_contribution=score_impact,
            confidence=confidence,
            model_name=cls._cached_metadata.get("model_name", "RandomForest"),
            version=cls._cached_metadata.get("version", "1.0.0"),
        )
