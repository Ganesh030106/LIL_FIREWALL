"""Model evaluation harness for Volcano AI Firewall phishing classifier.
Evaluates model performance on labeled CSV data, computes precision, recall, F1,
ROC-AUC, FPR, performs probability calibration, generates ROC curves, checks for
FPR drift against historical baselines, and enforces CI/CD quality gates.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedKFold, train_test_split

# Ensure parent package imports work
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from model_generator import extract_features

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("volcano.evaluator")


def load_labeled_csv(filepath: str | Path) -> Tuple[List[str], np.ndarray, np.ndarray]:
    """Load URLs and binary labels from CSV (header: url, label)."""
    p = Path(filepath)
    if not p.exists():
        raise FileNotFoundError(f"Dataset file not found: {filepath}")

    urls: List[str] = []
    features_list: List[List[float]] = []
    labels: List[int] = []

    with open(p, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header:
            raise ValueError("CSV file is empty")

        # Detect column indices
        url_idx = 0
        label_idx = 1
        for idx, col in enumerate(header):
            col_clean = col.strip().lower()
            if col_clean in ("url", "urls", "domain", "uri"):
                url_idx = idx
            elif col_clean in ("label", "labels", "is_phishing", "target", "class"):
                label_idx = idx

        for line_num, row in enumerate(reader, start=2):
            if not row or len(row) <= max(url_idx, label_idx):
                continue
            url_str = row[url_idx].strip()
            raw_label = row[label_idx].strip().lower()

            # Normalize label: 1 / phishing / malicious -> 1; 0 / safe / benign -> 0
            if raw_label in ("1", "1.0", "phishing", "malicious", "true", "yes"):
                label = 1
            elif raw_label in ("0", "0.0", "safe", "benign", "false", "no"):
                label = 0
            else:
                try:
                    label = int(float(raw_label))
                except ValueError:
                    continue

            urls.append(url_str)
            labels.append(label)
            features_list.append(extract_features(url_str))

    if not labels or len(set(labels)) < 2:
        raise ValueError("Dataset must contain at least 2 classes (safe and phishing).")

    return urls, np.asarray(features_list, dtype=np.float32), np.asarray(labels, dtype=np.int32)


def evaluate_classifier(
    X: np.ndarray,
    y: np.ndarray,
    model: Optional[Any] = None,
    calibration_method: str = "sigmoid",
    test_size: float = 0.2,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Perform stratified split, 5-fold cross-validation, and probability calibration."""
    # 1. Stratified Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=random_state
    )

    if model is None:
        model = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=random_state)
        model.fit(X_train, y_train)

    # 2. 5-Fold Cross Validation on full dataset
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=random_state)
    cv_roc_scores: List[float] = []
    cv_f1_scores: List[float] = []

    for train_idx, val_idx in skf.split(X, y):
        fold_model = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=random_state)
        fold_model.fit(X[train_idx], y[train_idx])
        fold_probs = fold_model.predict_proba(X[val_idx])[:, 1]
        fold_preds = (fold_probs >= 0.5).astype(int)

        cv_roc_scores.append(float(roc_auc_score(y[val_idx], fold_probs)))
        cv_f1_scores.append(float(f1_score(y[val_idx], fold_preds, zero_division=0)))

    # 3. Test Set Evaluation
    uncalibrated_probs = model.predict_proba(X_test)[:, 1]
    default_preds = (uncalibrated_probs >= 0.5).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_test, default_preds, labels=[0, 1]).ravel()
    fpr = float(fp / max(1, (fp + tn)))
    tpr = float(tp / max(1, (tp + fn)))
    precision = float(precision_score(y_test, default_preds, zero_division=0))
    recall = float(recall_score(y_test, default_preds, zero_division=0))
    f1 = float(f1_score(y_test, default_preds, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, uncalibrated_probs))

    # 4. Probability Calibration & Brier Score
    brier_before = float(brier_score_loss(y_test, uncalibrated_probs))
    try:
        from sklearn.frozen import FrozenEstimator
        calibrator = CalibratedClassifierCV(estimator=FrozenEstimator(model), method=calibration_method)
    except ImportError:
        calibrator = CalibratedClassifierCV(estimator=model, method=calibration_method, cv="prefit")
    calibrator.fit(X_train, y_train)
    calibrated_probs = calibrator.predict_proba(X_test)[:, 1]
    brier_after = float(brier_score_loss(y_test, calibrated_probs))

    # 5. ROC Curve points
    fpr_curve, tpr_curve, thresholds = roc_curve(y_test, uncalibrated_probs)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sample_count": int(len(y)),
        "train_samples": int(len(y_train)),
        "test_samples": int(len(y_test)),
        "metrics": {
            "threshold": 0.5,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "false_positive_rate": round(fpr, 4),
            "true_positive_rate": round(tpr, 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        },
        "cross_validation": {
            "folds": 5,
            "cv_roc_auc_mean": round(float(np.mean(cv_roc_scores)), 4),
            "cv_roc_auc_std": round(float(np.std(cv_roc_scores)), 4),
            "cv_f1_mean": round(float(np.mean(cv_f1_scores)), 4),
            "cv_f1_std": round(float(np.std(cv_f1_scores)), 4),
        },
        "calibration": {
            "method": calibration_method,
            "brier_score_before": round(brier_before, 4),
            "brier_score_after": round(brier_after, 4),
            "brier_score_improvement": round(brier_before - brier_after, 4),
        },
        "_roc_data": {
            "fpr": fpr_curve.tolist(),
            "tpr": tpr_curve.tolist(),
            "roc_auc": roc_auc,
        },
    }


def render_roc_curve(roc_data: Dict[str, Any], output_path: str | Path) -> None:
    """Generate and save publication-quality ROC curve PNG."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fpr = roc_data["fpr"]
        tpr = roc_data["tpr"]
        auc = roc_data["roc_auc"]

        plt.figure(figsize=(8, 6), dpi=150)
        plt.plot(fpr, tpr, color="#ff4500", lw=2.5, label=f"Volcano Phishing Model (AUC = {auc:.3f})")
        plt.plot([0, 1], [0, 1], color="#708090", lw=1.5, linestyle="--", label="Random Classifier (AUC = 0.500)")
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel("False Positive Rate (FPR)", fontsize=11, fontweight="bold")
        plt.ylabel("True Positive Rate (Recall / TPR)", fontsize=11, fontweight="bold")
        plt.title("Receiver Operating Characteristic (ROC) Curve", fontsize=13, fontweight="bold")
        plt.legend(loc="lower right", frameon=True)
        plt.grid(True, linestyle=":", alpha=0.6)

        out_path = Path(output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        plt.tight_layout()
        plt.savefig(out_path, dpi=150)
        plt.close()
        logger.info(f"Saved ROC curve visualization to: {out_path}")
    except Exception as exc:
        logger.warning(f"Could not render ROC curve image: {exc}")


def check_drift(current_fpr: float, baseline_report_path: str | Path, max_drift: float = 0.05) -> Dict[str, Any]:
    """Compare current FPR against baseline report and detect drift."""
    p = Path(baseline_report_path)
    if not p.exists():
        logger.warning(f"Baseline report not found at: {baseline_report_path}")
        return {"baseline_found": False, "drift_detected": False}

    with open(p, "r", encoding="utf-8") as f:
        baseline_data = json.load(f)

    baseline_fpr = float(baseline_data.get("metrics", {}).get("false_positive_rate", 0.0))
    fpr_increase = current_fpr - baseline_fpr
    drift_detected = fpr_increase > max_drift

    drift_info = {
        "baseline_found": True,
        "baseline_fpr": round(baseline_fpr, 4),
        "current_fpr": round(current_fpr, 4),
        "fpr_drift": round(fpr_increase, 4),
        "drift_threshold": round(max_drift, 4),
        "drift_detected": drift_detected,
    }

    if drift_detected:
        logger.warning(
            f"[DRIFT DETECTED] False positive rate increased by {fpr_increase:.4f} "
            f"(baseline: {baseline_fpr:.4f}, current: {current_fpr:.4f}, threshold: {max_drift:.4f})"
        )
    else:
        logger.info(f"Drift check passed: FPR change {fpr_increase:+.4f} is within tolerance ({max_drift:.4f})")

    return drift_info


def run_evaluation_harness(
    data_path: str | Path,
    model_path: Optional[str | Path] = None,
    output_json: Optional[str | Path] = None,
    output_roc: Optional[str | Path] = None,
    calibration_method: str = "sigmoid",
    min_auc: Optional[float] = None,
    max_fpr: Optional[float] = None,
    baseline_report: Optional[str | Path] = None,
    drift_threshold: float = 0.05,
) -> Tuple[Dict[str, Any], bool]:
    """Execute evaluation pipeline and check threshold gates."""
    urls, X, y = load_labeled_csv(data_path)
    logger.info(f"Loaded {len(y)} labeled URLs ({sum(y)} phishing, {len(y) - sum(y)} safe).")

    model = None
    if model_path and Path(model_path).exists():
        try:
            artifact = joblib.load(model_path)
            model = artifact.get("model") if isinstance(artifact, dict) else artifact
            logger.info(f"Loaded existing model artifact from {model_path}")
        except Exception as exc:
            logger.warning(f"Failed to load model from {model_path}: {exc}. Training temporary evaluation model.")

    results = evaluate_classifier(X, y, model=model, calibration_method=calibration_method)

    # Drift check
    if baseline_report:
        drift_info = check_drift(
            current_fpr=results["metrics"]["false_positive_rate"],
            baseline_report_path=baseline_report,
            max_drift=drift_threshold,
        )
        results["drift_check"] = drift_info

    # Gate verification
    current_auc = results["metrics"]["roc_auc"]
    current_fpr = results["metrics"]["false_positive_rate"]
    gate_passed = True
    gate_failures: List[str] = []

    if min_auc is not None:
        if current_auc < min_auc:
            gate_passed = False
            gate_failures.append(f"ROC-AUC {current_auc:.4f} < min threshold {min_auc:.4f}")

    if max_fpr is not None:
        if current_fpr > max_fpr:
            gate_passed = False
            gate_failures.append(f"FPR {current_fpr:.4f} > max threshold {max_fpr:.4f}")

    results["gate_results"] = {
        "passed": gate_passed,
        "min_auc_required": min_auc,
        "max_fpr_allowed": max_fpr,
        "failures": gate_failures,
    }

    # Render ROC curve image
    if output_roc:
        render_roc_curve(results["_roc_data"], output_roc)

    # Clean internal data before JSON dump
    roc_internal = results.pop("_roc_data", None)

    # Save JSON report
    if output_json:
        out_json_path = Path(output_json)
        out_json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        logger.info(f"Evaluation report written to: {out_json_path}")

    # Restore internal data for python callers
    if roc_internal is not None:
        results["_roc_data"] = roc_internal

    return results, gate_passed


def main() -> None:
    parser = argparse.ArgumentParser(description="Volcano AI Firewall Phishing Classifier Evaluation Harness")
    parser.add_argument("--data-path", "-d", required=True, help="Path to labeled CSV file (url,label)")
    parser.add_argument("--model-path", "-m", default="backend/phishing_model.joblib", help="Path to model file")
    parser.add_argument("--output-json", "-o", default="backend/reports/phishing_eval_report.json", help="Path to write JSON report")
    parser.add_argument("--output-roc", "-r", default="backend/reports/roc_curve.png", help="Path to write ROC curve PNG")
    parser.add_argument("--calibration", "-c", choices=["sigmoid", "isotonic"], default="sigmoid", help="Calibration method")
    parser.add_argument("--min-auc", type=float, default=None, help="Minimum ROC-AUC threshold gate")
    parser.add_argument("--max-fpr", type=float, default=None, help="Maximum False Positive Rate threshold gate")
    parser.add_argument("--baseline-report", default=None, help="Path to previous JSON report to check for drift")
    parser.add_argument("--drift-threshold", type=float, default=0.05, help="FPR drift threshold for warning")

    args = parser.parse_args()

    try:
        report, gate_passed = run_evaluation_harness(
            data_path=args.data_path,
            model_path=args.model_path,
            output_json=args.output_json,
            output_roc=args.output_roc,
            calibration_method=args.calibration,
            min_auc=args.min_auc,
            max_fpr=args.max_fpr,
            baseline_report=args.baseline_report,
            drift_threshold=args.drift_threshold,
        )

        print("\n" + "=" * 60)
        print("Volcano AI Firewall - Model Evaluation Summary")
        print("=" * 60)
        print(f"Sample Count : {report['sample_count']} (Train: {report['train_samples']}, Test: {report['test_samples']})")
        print(f"Precision    : {report['metrics']['precision']:.4f}")
        print(f"Recall       : {report['metrics']['recall']:.4f}")
        print(f"F1 Score     : {report['metrics']['f1']:.4f}")
        print(f"ROC-AUC      : {report['metrics']['roc_auc']:.4f}")
        print(f"False Pos.   : {report['metrics']['false_positive_rate']:.4f} (FPR)")
        print(f"5-Fold CV AUC: {report['cross_validation']['cv_roc_auc_mean']:.4f} ± {report['cross_validation']['cv_roc_auc_std']:.4f}")
        print(f"Brier Score  : {report['calibration']['brier_score_before']:.4f} -> {report['calibration']['brier_score_after']:.4f} (Calibrated)")
        print(f"Quality Gate : {'PASSED' if gate_passed else 'FAILED'}")
        if not gate_passed:
            for fail in report["gate_results"]["failures"]:
                print(f"  [-] {fail}")
        print("=" * 60 + "\n")

        if not gate_passed:
            sys.exit(1)

    except Exception as exc:
        logger.error(f"Evaluation failed: {exc}")
        sys.exit(2)


if __name__ == "__main__":
    main()
