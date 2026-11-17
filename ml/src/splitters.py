"""
Domain-Level (eTLD+1) Leakage-Free Grouped Splitter for PhishGuard ML Pipeline.
Guarantees zero cross-split domain overlap between Train, Validation, and Test sets.
"""
import random
from typing import Dict, List, Set, Tuple
import pandas as pd


class DomainGroupedSplitter:
    """
    Partitions datasets into Train, Validation, and Holdout Test splits
    grouped strictly by eTLD+1 domain to prevent model memorization and data leakage.
    """

    @classmethod
    def split(
        cls,
        df: pd.DataFrame,
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
        random_state: int = 42,
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Split DataFrame into train, validation, and test subsets with 0 overlapping domains.
        Maintains class balance by stratifying unique domains by their majority label.
        """
        if not abs((train_ratio + val_ratio + test_ratio) - 1.0) < 1e-6:
            raise ValueError("Ratios must sum to 1.0 (train + val + test)")

        if "domain" not in df.columns or "label" not in df.columns:
            raise ValueError("DataFrame must contain 'domain' and 'label' columns")

        rng = random.Random(random_state)

        # 1. Determine dominant label for each unique domain
        domain_labels: Dict[str, int] = {}
        for domain, group in df.groupby("domain"):
            # Assign majority label for stratification
            majority_label = int(group["label"].mode()[0])
            domain_labels[domain] = majority_label

        legit_domains = [d for d, l in domain_labels.items() if l == 0]
        phish_domains = [d for d, l in domain_labels.items() if l == 1]

        rng.shuffle(legit_domains)
        rng.shuffle(phish_domains)

        def partition_domains(domains: List[str]) -> Tuple[Set[str], Set[str], Set[str]]:
            n = len(domains)
            n_train = max(1, int(n * train_ratio))
            n_val = max(1, int(n * val_ratio))
            
            # Ensure at least 1 in test if possible
            if n_train + n_val >= n and n >= 3:
                n_train = n - 2
                n_val = 1

            train_set = set(domains[:n_train])
            val_set = set(domains[n_train:n_train + n_val])
            test_set = set(domains[n_train + n_val:])
            return train_set, val_set, test_set

        legit_train, legit_val, legit_test = partition_domains(legit_domains)
        phish_train, phish_val, phish_test = partition_domains(phish_domains)

        train_domains = legit_train | phish_train
        val_domains = legit_val | phish_val
        test_domains = legit_test | phish_test

        train_df = df[df["domain"].isin(train_domains)].copy().reset_index(drop=True)
        val_df = df[df["domain"].isin(val_domains)].copy().reset_index(drop=True)
        test_df = df[df["domain"].isin(test_domains)].copy().reset_index(drop=True)

        # Verification assertion
        cls.verify_no_leakage(train_df, val_df, test_df)

        return train_df, val_df, test_df

    @classmethod
    def verify_no_leakage(
        cls,
        train_df: pd.DataFrame,
        val_df: pd.DataFrame,
        test_df: pd.DataFrame,
    ) -> bool:
        """
        Mathematically verify that domain sets across all splits are mutually disjoint.
        Raises ValueError if any leakage is detected.
        """
        train_domains = set(train_df["domain"].unique())
        val_domains = set(val_df["domain"].unique())
        test_domains = set(test_df["domain"].unique())

        train_val_overlap = train_domains & val_domains
        train_test_overlap = train_domains & test_domains
        val_test_overlap = val_domains & test_domains

        if train_val_overlap:
            raise ValueError(
                f"Data Leakage Detected: {len(train_val_overlap)} domains overlap between Train and Val: {train_val_overlap}"
            )

        if train_test_overlap:
            raise ValueError(
                f"Data Leakage Detected: {len(train_test_overlap)} domains overlap between Train and Test: {train_test_overlap}"
            )

        if val_test_overlap:
            raise ValueError(
                f"Data Leakage Detected: {len(val_test_overlap)} domains overlap between Val and Test: {val_test_overlap}"
            )

        return True
