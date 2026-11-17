"""
Unit and integration tests for 34-feature extraction pipeline and Scikit-learn transformer compatibility.
"""
import numpy as np
import pandas as pd
import pytest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ml.src.features import FEATURE_NAMES, URLFeatureTransformer


def test_feature_count_and_names():
    """Verify exactly 34 features are configured and all names are unique strings."""
    assert len(FEATURE_NAMES) == 34
    assert len(set(FEATURE_NAMES)) == 34
    for name in FEATURE_NAMES:
        assert isinstance(name, str)
        assert len(name) > 0


def test_transformer_shape_and_types():
    """Verify URLFeatureTransformer output matrix dimensions, float64 dtype, and no NaNs."""
    urls = [
        "https://www.google.com/search?q=test",
        "http://paypa1-security.xyz/login.php",
        "http://192.168.1.1:8080/admin",
        "https://github.com/torvalds/linux",
    ]

    transformer = URLFeatureTransformer()
    matrix = transformer.transform(urls)

    assert isinstance(matrix, np.ndarray)
    assert matrix.shape == (4, 34)
    assert matrix.dtype == np.float64
    assert not np.isnan(matrix).any()
    assert not np.isinf(matrix).any()


def test_transformer_df_output():
    """Verify transform_df produces a DataFrame with exact column names."""
    urls = ["https://www.apple.com", "http://login.appleid.top"]
    transformer = URLFeatureTransformer()
    df = transformer.transform_df(urls)

    assert isinstance(df, pd.DataFrame)
    assert df.shape == (2, 34)
    assert list(df.columns) == FEATURE_NAMES
    assert df["has_https"].iloc[0] == 1.0
    assert df["has_https"].iloc[1] == 0.0


def test_feature_values_clean_vs_phishing():
    """Verify specific security features capture expected signals."""
    clean_url = "https://www.microsoft.com/en-us"
    phish_url = "http://micros0ft-login.xyz:8080/auth/login.php"
    ip_url = "http://198.51.100.25/signin"

    transformer = URLFeatureTransformer()
    df = transformer.transform_df([clean_url, phish_url, ip_url])

    # Clean URL expectations
    assert df.loc[0, "has_https"] == 1.0
    assert df.loc[0, "is_ip_host"] == 0.0
    assert df.loc[0, "has_port"] == 0.0
    assert df.loc[0, "high_risk_tld"] == 0.0
    assert df.loc[0, "num_suspicious_keywords"] == 0.0

    # Phishing URL expectations
    assert df.loc[1, "has_https"] == 0.0
    assert df.loc[1, "high_risk_tld"] == 1.0  # .xyz
    assert df.loc[1, "has_port"] == 1.0  # :8080
    assert df.loc[1, "is_standard_port"] == 0.0
    assert df.loc[1, "num_suspicious_keywords"] >= 1.0  # login

    # IP URL expectations
    assert df.loc[2, "is_ip_host"] == 1.0
    assert df.loc[2, "ip_version"] == 4.0


def test_empty_and_edge_case_urls():
    """Verify graceful zero-vector handling for empty or malformed inputs without crashing."""
    transformer = URLFeatureTransformer()
    matrix = transformer.transform(["", "   ", "http://"])

    assert matrix.shape == (3, 34)
    assert not np.isnan(matrix).any()
    # Empty string should yield all zeros
    assert np.all(matrix[0] == 0.0)


def test_scikit_learn_pipeline_integration():
    """Verify URLFeatureTransformer integrates smoothly into a scikit-learn Pipeline."""
    urls = [
        "https://www.wikipedia.org/wiki/Phishing",
        "https://www.chase.com/personal",
        "http://paypa1-account.xyz/verify",
        "http://secure-login.top/account",
    ]

    pipe = Pipeline([
        ("features", URLFeatureTransformer()),
        ("scaler", StandardScaler()),
    ])

    # Fit and transform pipeline
    scaled_matrix = pipe.fit_transform(urls)
    assert scaled_matrix.shape == (4, 34)
    assert not np.isnan(scaled_matrix).any()
