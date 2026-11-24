"""Calibration and seeded-finding metrics for deterministic scoring."""
from __future__ import annotations


def reliability_table(labels: list[dict]) -> dict:
    tp = sum(bool(x.get("actual") and x.get("predicted")) for x in labels)
    fp = sum(bool(not x.get("actual") and x.get("predicted")) for x in labels)
    fn = sum(bool(x.get("actual") and not x.get("predicted")) for x in labels)
    tn = sum(bool(not x.get("actual") and not x.get("predicted")) for x in labels)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    accuracy = (tp + tn) / len(labels) if labels else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4),
            "accuracy": round(accuracy, 4), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "false_positive_rate": round(fp / (fp + tn) if fp + tn else 0.0, 4)}
