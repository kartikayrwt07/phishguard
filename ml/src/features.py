"""
34-Dimensional URL Feature Extraction Pipeline for PhishGuard ML Pipeline.
Guarantees 100% parity between training feature vectors and backend serving inference.
"""
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

# Ensure backend detection packages can be imported
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.detection.features import FeatureExtractor, URLFeatures
from app.detection.url_parser import ParsedURL, URLNormalizer


FEATURE_NAMES: List[str] = [
    # 1-4: Structural lengths
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",

    # 5-15: Delimiter counts
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_question_marks",
    "num_equal_signs",
    "num_at_symbols",
    "num_ampersands",
    "num_exclamations",
    "num_tildes",
    "num_percent_signs",

    # 16-17: Subdomain analysis
    "subdomain_count",
    "subdomain_depth",

    # 18-23: Host & Protocol properties
    "is_ip_host",
    "ip_version",
    "has_port",
    "is_standard_port",
    "has_https",
    "has_punycode",

    # 24-26: Shannon Entropies
    "entropy_url",
    "entropy_host",
    "entropy_path",

    # 27-31: Character distributions & ratios
    "digits_ratio_host",
    "digits_ratio_url",
    "vowel_ratio_host",
    "consonant_ratio_host",
    "max_consecutive_consonants",

    # 32-34: Reputation & TLD indicators
    "num_suspicious_keywords",
    "high_risk_tld",
    "tld_length",
]


class URLFeatureTransformer(BaseEstimator, TransformerMixin):
    """
    Scikit-learn compatible transformer converting raw URL strings
    into a standardized 34-dimensional numeric feature matrix.
    """

    def __init__(self):
        self.feature_names = list(FEATURE_NAMES)

    def fit(self, X: Any, y: Any = None) -> "URLFeatureTransformer":
        """No fitting required; feature extraction is deterministic."""
        return self

    @classmethod
    def extract_vector(cls, url: str) -> List[float]:
        """Extract ordered 34-element float vector for a single URL string."""
        if not isinstance(url, str) or not url.strip():
            # Return zero vector if empty or invalid
            return [0.0] * len(FEATURE_NAMES)

        parsed: ParsedURL = URLNormalizer.parse(url)
        features: URLFeatures = FeatureExtractor.extract_from_parsed(parsed)

        return [
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

    def transform(self, X: Union[Sequence[str], pd.Series, pd.DataFrame, np.ndarray]) -> np.ndarray:
        """
        Transform a collection of URLs into a 2D float64 NumPy array of shape (N, 34).
        """
        urls: List[str] = []
        if isinstance(X, pd.DataFrame):
            if "url" in X.columns:
                urls = X["url"].astype(str).tolist()
            else:
                urls = X.iloc[:, 0].astype(str).tolist()
        elif isinstance(X, (pd.Series, np.ndarray)):
            urls = [str(u) for u in X]
        elif isinstance(X, (list, tuple)):
            urls = [str(u) for u in X]
        else:
            raise TypeError(f"Unsupported input type for URLFeatureTransformer: {type(X)}")

        matrix = [self.extract_vector(url) for url in urls]
        arr = np.array(matrix, dtype=np.float64)

        # Replace any unexpected NaN or infinite values with 0.0
        np.nan_to_num(arr, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
        return arr

    def transform_df(self, X: Union[Sequence[str], pd.Series, pd.DataFrame, np.ndarray]) -> pd.DataFrame:
        """Transform URLs directly into a labeled pandas DataFrame."""
        matrix = self.transform(X)
        return pd.DataFrame(matrix, columns=self.feature_names)

    def get_feature_names_out(self, input_features: Optional[Sequence[str]] = None) -> np.ndarray:
        """Scikit-learn compliant feature names output."""
        return np.array(self.feature_names)
