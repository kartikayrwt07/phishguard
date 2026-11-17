"""
Model Evaluation and Benchmark Metrics Engine for PhishGuard ML.
Computes Accuracy, Precision, Recall, F1, FPR, FNR, Confusion Matrix, and Inference Latency.
"""
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Tuple
import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score


@dataclass
class ModelMetrics:
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    false_negative_rate: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    avg_latency_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def evaluate_model(
    model: Any,
    X_test: np.ndarray,
    y_test: np.ndarray,
    model_name: str,
) -> ModelMetrics:
    """
    Evaluate a fitted model on holdout test set and compute complete security metrics.
    """
    # 1. Measure inference latency
    start_time = time.monotonic()
    y_pred = model.predict(X_test)
    elapsed = time.monotonic() - start_time
    avg_latency_ms = (elapsed / max(1, len(X_test))) * 1000.0

    # 2. Confusion matrix components
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    # 3. Security error rates
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    # 4. Standard classification metrics
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))

    return ModelMetrics(
        model_name=model_name,
        accuracy=round(acc, 4),
        precision=round(prec, 4),
        recall=round(rec, 4),
        f1=round(f1, 4),
        false_positive_rate=round(fpr, 4),
        false_negative_rate=round(fnr, 4),
        true_positives=int(tp),
        false_positives=int(fp),
        true_negatives=int(tn),
        false_negatives=int(fn),
        avg_latency_ms=round(avg_latency_ms, 3),
    )
