"""Unit tests for Phishing Model Evaluation Harness (Task 2)."""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest

from ai_engine.evaluate_model import (
    check_drift,
    load_labeled_csv,
    run_evaluation_harness,
)


@pytest.fixture
def synthetic_csv(tmp_path: Path) -> Path:
    """Generate a small synthetic CSV dataset for testing without real URLs."""
    csv_file = tmp_path / "synthetic_urls.csv"
    rows = [["url", "label"]]

    # 25 safe samples
    for i in range(25):
        rows.append([f"https://trusted-domain-{i}.com/docs/page{i}", "0"])
    
    # 25 phishing samples
    for i in range(25):
        rows.append([
            f"http://192.168.1.{i}/secure-bank-login-verify-account-update/token={i}",
            "1",
        ])

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

    return csv_file


def test_load_labeled_csv(synthetic_csv: Path) -> None:
    urls, X, y = load_labeled_csv(synthetic_csv)
    assert len(urls) == 50
    assert X.shape[0] == 50
    assert X.shape[1] == 10  # 10 features extracted
    assert len(y) == 50
    assert sum(y) == 25


def test_evaluation_harness_synthetic_dataset(synthetic_csv: Path, tmp_path: Path) -> None:
    json_out = tmp_path / "report.json"
    roc_out = tmp_path / "roc.png"

    results, gate_passed = run_evaluation_harness(
        data_path=synthetic_csv,
        output_json=json_out,
        output_roc=roc_out,
        calibration_method="sigmoid",
        min_auc=0.5,
        max_fpr=0.5,
    )

    assert gate_passed is True
    assert results["sample_count"] == 50
    assert results["train_samples"] == 40
    assert results["test_samples"] == 10

    metrics = results["metrics"]
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1" in metrics
    assert "roc_auc" in metrics
    assert "false_positive_rate" in metrics
    assert "confusion_matrix" in metrics

    # Cross validation results
    cv = results["cross_validation"]
    assert cv["folds"] == 5
    assert "cv_roc_auc_mean" in cv

    # Calibration & Brier score
    calib = results["calibration"]
    assert calib["method"] == "sigmoid"
    assert "brier_score_before" in calib
    assert "brier_score_after" in calib

    # Verify JSON file written
    assert json_out.exists()
    with open(json_out, "r", encoding="utf-8") as f:
        saved_report = json.load(f)
    assert saved_report["sample_count"] == 50

    # Verify ROC curve PNG written
    assert roc_out.exists()
    assert roc_out.stat().st_size > 0


def test_evaluation_gate_threshold_failures(synthetic_csv: Path) -> None:
    # Impossible min-auc (> 1.0)
    results, gate_passed = run_evaluation_harness(
        data_path=synthetic_csv,
        min_auc=1.05,
        max_fpr=0.5,
    )
    assert gate_passed is False
    assert len(results["gate_results"]["failures"]) > 0
    assert any("ROC-AUC" in f for f in results["gate_results"]["failures"])

    # Impossible max-fpr (< 0.0)
    results2, gate_passed2 = run_evaluation_harness(
        data_path=synthetic_csv,
        min_auc=0.5,
        max_fpr=-0.01,
    )
    assert gate_passed2 is False
    assert any("FPR" in f for f in results2["gate_results"]["failures"])


def test_drift_check(tmp_path: Path) -> None:
    baseline_file = tmp_path / "baseline_report.json"
    baseline_content = {
        "metrics": {
            "false_positive_rate": 0.02,
        }
    }
    with open(baseline_file, "w", encoding="utf-8") as f:
        json.dump(baseline_content, f)

    # 1. No drift: current FPR is 0.03 (+0.01 <= 0.05)
    drift_ok = check_drift(current_fpr=0.03, baseline_report_path=baseline_file, max_drift=0.05)
    assert drift_ok["baseline_found"] is True
    assert drift_ok["drift_detected"] is False
    assert drift_ok["fpr_drift"] == 0.01

    # 2. Drift detected: current FPR is 0.12 (+0.10 > 0.05)
    drift_bad = check_drift(current_fpr=0.12, baseline_report_path=baseline_file, max_drift=0.05)
    assert drift_bad["baseline_found"] is True
    assert drift_bad["drift_detected"] is True
    assert drift_bad["fpr_drift"] == 0.10


def test_cli_execution_and_exit_codes(synthetic_csv: Path, tmp_path: Path) -> None:
    script_path = Path(__file__).resolve().parent.parent / "ai_engine" / "evaluate_model.py"
    json_path = tmp_path / "cli_report.json"
    roc_path = tmp_path / "cli_roc.png"

    # 1. Passing execution -> exit code 0
    cmd_pass = [
        sys.executable,
        str(script_path),
        "--data-path",
        str(synthetic_csv),
        "--output-json",
        str(json_path),
        "--output-roc",
        str(roc_path),
        "--min-auc",
        "0.1",
        "--max-fpr",
        "0.9",
    ]
    res_pass = subprocess.run(cmd_pass, capture_output=True, text=True)
    assert res_pass.returncode == 0
    assert "Model Evaluation Summary" in res_pass.stdout
    assert "PASSED" in res_pass.stdout
    assert json_path.exists()

    # 2. Failing gate -> exit code 1
    cmd_fail = [
        sys.executable,
        str(script_path),
        "--data-path",
        str(synthetic_csv),
        "--min-auc",
        "1.05",  # Impossible to meet, will fail gate
    ]
    res_fail = subprocess.run(cmd_fail, capture_output=True, text=True)
    assert res_fail.returncode == 1
    assert "FAILED" in res_fail.stdout
