"""
Unit and integration tests for ML dataset generation, serialization, and leakage-free grouped splitting.
"""
from pathlib import Path
import pytest
import pandas as pd

from ml.src.dataset import (
    generate_curated_samples,
    generate_dataset,
    save_dataset,
    load_dataset,
)
from ml.src.splitters import DomainGroupedSplitter


def test_curated_samples_structure():
    """Verify curated seed samples have expected fields and label balance."""
    samples = generate_curated_samples()
    assert len(samples) >= 40

    legit = [s for s in samples if s["label"] == 0]
    phish = [s for s in samples if s["label"] == 1]
    assert len(legit) > 0
    assert len(phish) > 0

    for s in samples:
        assert s["url"].startswith("http")
        assert s["label"] in (0, 1)
        assert s["category"] != ""
        assert s["domain"] != ""


def test_generate_dataset_balanced_and_deduplicated():
    """Verify generated dataset meets size, balance, and deduplication criteria."""
    size = 200
    df = generate_dataset(target_size=size, random_state=123)

    assert isinstance(df, pd.DataFrame)
    assert len(df) == size
    # Check exact balance
    label_counts = df["label"].value_counts().to_dict()
    assert label_counts[0] == size // 2
    assert label_counts[1] == size // 2

    # Check deduplication
    assert df["url"].nunique() == size

    # Check required columns
    for col in ["url", "label", "category", "domain"]:
        assert col in df.columns
        assert not df[col].isnull().any()


def test_dataset_save_and_load(tmp_path: Path):
    """Verify saving dataset to disk and reloading retains data integrity."""
    test_csv = tmp_path / "test_dataset.csv"
    original_df = generate_dataset(target_size=50, random_state=42)

    saved_path = save_dataset(original_df, test_csv)
    assert saved_path.exists()

    loaded_df = load_dataset(test_csv)
    assert len(loaded_df) == len(original_df)
    assert list(loaded_df["url"]) == list(original_df["url"])
    assert list(loaded_df["label"]) == list(original_df["label"])


def test_domain_grouped_splitter_zero_leakage():
    """Verify that domain grouped splitting strictly guarantees zero overlapping domains."""
    df = generate_dataset(target_size=300, random_state=42)
    train_df, val_df, test_df = DomainGroupedSplitter.split(
        df,
        train_ratio=0.70,
        val_ratio=0.15,
        test_ratio=0.15,
        random_state=42,
    )

    # Assert partitions are non-empty
    assert len(train_df) > 0
    assert len(val_df) > 0
    assert len(test_df) > 0
    assert len(train_df) + len(val_df) + len(test_df) == len(df)

    # Assert zero domain leakage
    train_domains = set(train_df["domain"])
    val_domains = set(val_df["domain"])
    test_domains = set(test_df["domain"])

    assert len(train_domains & val_domains) == 0
    assert len(train_domains & test_domains) == 0
    assert len(val_domains & test_domains) == 0

    # Ensure helper validation returns True
    assert DomainGroupedSplitter.verify_no_leakage(train_df, val_df, test_df) is True


def test_domain_grouped_splitter_detects_leakage():
    """Verify that verify_no_leakage raises ValueError if cross-split leakage is introduced."""
    df = generate_dataset(target_size=100, random_state=42)
    train_df, val_df, test_df = DomainGroupedSplitter.split(df, random_state=42)

    # Intentionally corrupt splits by injecting a train domain row into test
    corrupted_test = pd.concat([test_df, train_df.iloc[[0]]], ignore_index=True)

    with pytest.raises(ValueError, match="Data Leakage Detected"):
        DomainGroupedSplitter.verify_no_leakage(train_df, val_df, corrupted_test)
