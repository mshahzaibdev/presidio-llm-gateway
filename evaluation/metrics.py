"""
Metrics calculation for gateway evaluation.
Computes precision, recall, F1, accuracy, TPR, FPR.
"""

from typing import List, Dict, Tuple
import statistics


def compute_classification_metrics(
    true_labels: List[bool],
    predicted_labels: List[bool],
) -> Dict[str, float]:
    """
    Compute binary classification metrics.

    Parameters
    ----------
    true_labels : list[bool]
        Ground truth – True means the input is an attack.
    predicted_labels : list[bool]
        Predicted – True means the system flagged it as an attack
        (decision = BLOCK or MASK).

    Returns
    -------
    dict with TP, FP, TN, FN, precision, recall, f1, accuracy, tpr, fpr.
    """
    tp = sum(1 for t, p in zip(true_labels, predicted_labels) if t and p)
    fp = sum(1 for t, p in zip(true_labels, predicted_labels) if not t and p)
    tn = sum(1 for t, p in zip(true_labels, predicted_labels) if not t and not p)
    fn = sum(1 for t, p in zip(true_labels, predicted_labels) if t and not p)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy  = (tp + tn) / len(true_labels) if len(true_labels) > 0 else 0.0
    tpr       = recall
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
        "accuracy":  round(accuracy, 4),
        "tpr":       round(tpr, 4),
        "fpr":       round(fpr, 4),
    }


def latency_stats(latencies: List[float]) -> Dict[str, float]:
    """Return min/max/mean/median/stdev for a list of latency values (ms)."""
    if not latencies:
        return {}
    return {
        "min_ms":    round(min(latencies), 3),
        "max_ms":    round(max(latencies), 3),
        "mean_ms":   round(statistics.mean(latencies), 3),
        "median_ms": round(statistics.median(latencies), 3),
        "stdev_ms":  round(statistics.stdev(latencies) if len(latencies) > 1 else 0.0, 3),
    }


def threshold_sweep(
    scores: List[int],
    true_labels: List[bool],
    thresholds: List[int],
) -> List[Dict]:
    """
    Evaluate detection performance at different injection score thresholds.

    Returns list of dicts, one per threshold, with metrics.
    """
    rows = []
    for t in thresholds:
        predicted = [s >= t for s in scores]
        m = compute_classification_metrics(true_labels, predicted)
        m["threshold"] = t
        rows.append(m)
    return rows
