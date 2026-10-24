from __future__ import annotations

import argparse
import csv
import math
import re
from collections import Counter
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier


HEAVY_KEYWORDS = (
    "login", "verify", "banking", "secure", "update", "password",
    "signin", "confirm", "account", "oauth", "wallet", "support",
    "alert", "credential", "auth", "billing", "recover"
)

URL_IP_PATTERN = re.compile(
    r"(?:(?:https?://)?)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
)

URL_SHORTENERS = (
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy"
)

SUSPICIOUS_TLDS = (
    ".xyz", ".top", ".buzz", ".club", ".work", ".loan", ".pw",
    ".tk", ".cc", ".ga", ".cf", ".ml", ".gq", ".click", ".link"
)

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "subdomain_count",
    "domain_entropy",
    "digit_ratio",
    "has_raw_ip",
    "is_shortener",
    "is_punycode",
    "suspicious_tld",
    "keyword_hits",
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for text."""
    if not text:
        return 0.0
    length = len(text)
    freq = Counter(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _extract_domain(url: str) -> str:
    """Extract domain or host from URL safely."""
    lowered = url.lower().strip()
    if not lowered.startswith(("http://", "https://", "ftp://")):
        lowered = "http://" + lowered
    try:
        parsed = urlparse(lowered)
        return parsed.hostname or parsed.netloc or ""
    except Exception:
        return ""


def extract_features(url: str) -> list[float]:
    """Extract 10 numerical features for phishing classification."""
    lowered = url.lower().strip()
    domain = _extract_domain(lowered)

    # 1. Total URL length
    url_length = float(len(lowered))

    # 2. Domain length
    domain_length = float(len(domain))

    # 3. Subdomain count (dots minus 1)
    subdomain_count = float(max(0, domain.count(".") - 1)) if domain else 0.0

    # 4. Domain Shannon entropy
    domain_entropy = float(calculate_entropy(domain))

    # 5. Digit ratio in domain
    digit_ratio = (
        float(sum(c.isdigit() for c in domain) / max(1, len(domain)))
        if domain
        else 0.0
    )

    # 6. Has raw IPv4 / IPv6 address
    has_raw_ip = 1.0 if URL_IP_PATTERN.search(lowered) else 0.0

    # 7. Uses URL shortener
    is_shortener = 1.0 if any(short in domain for short in URL_SHORTENERS) else 0.0

    # 8. Punycode presence
    is_punycode = 1.0 if "xn--" in domain else 0.0

    # 9. Suspicious TLD
    suspicious_tld = 1.0 if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0.0

    # 10. Keyword hits
    keyword_hits = float(sum(keyword in lowered for keyword in HEAVY_KEYWORDS))

    return [
        url_length,
        domain_length,
        subdomain_count,
        domain_entropy,
        digit_ratio,
        has_raw_ip,
        is_shortener,
        is_punycode,
        suspicious_tld,
        keyword_hits,
    ]


def build_training_data(sample_count: int = 2500) -> tuple[np.ndarray, np.ndarray]:
    """Generate synthetic training dataset covering all 10 features."""
    rng = np.random.default_rng(42)
    feature_rows: list[list[float]] = []
    labels: list[int] = []

    safe_hosts = (
        "google.com", "github.com", "microsoft.com", "fastapi.tiangolo.com",
        "docs.python.org", "wikipedia.org", "cloudflare.com", "amazon.com",
        "stackoverflow.com", "apple.com", "mozilla.org", "nytimes.com",
    )
    safe_paths = ("docs", "blog", "learn", "guide", "article", "search", "explore", "project")

    phishing_brands = ("paypal", "chase-bank", "apple-id", "microsoft-online", "netflix-verify", "google-security", "wellsfargo")
    phishing_tlds = (".xyz", ".top", ".buzz", ".club", ".click", ".work", ".link", ".cf", ".tk")

    for _ in range(sample_count):
        is_phishing = int(rng.random() > 0.5)
        if is_phishing:
            dice = rng.random()
            if dice < 0.25:
                # Raw IP URL
                ip = f"{rng.integers(10, 223)}.{rng.integers(0, 255)}.{rng.integers(0, 255)}.{rng.integers(1, 254)}"
                kw = str(rng.choice(HEAVY_KEYWORDS))
                url = f"http://{ip}/{kw}/session_{rng.integers(1000, 9999)}"
            elif dice < 0.45:
                # URL Shortener redirection
                shortener = str(rng.choice(URL_SHORTENERS))
                slug = "".join(rng.choice(list("abcdefghijklmnopqrstuvwxyz0123456789")) for _ in range(7))
                url = f"https://{shortener}/{slug}"
            elif dice < 0.65:
                # Punycode or heavy subdomain nesting
                brand = str(rng.choice(phishing_brands))
                tld = str(rng.choice(phishing_tlds))
                kw = str(rng.choice(HEAVY_KEYWORDS))
                url = f"https://xn--{brand}-{rng.integers(100, 999)}{tld}/{kw}?token={rng.integers(100000, 999999)}"
            else:
                # High-entropy random domain with suspicious TLD and keywords
                brand = str(rng.choice(phishing_brands))
                tld = str(rng.choice(phishing_tlds))
                kw = str(rng.choice(HEAVY_KEYWORDS))
                sub = f"{kw}.verify-{rng.integers(10, 99)}"
                url = f"http://{sub}.{brand}{tld}/account/login?id={rng.integers(1000, 9999)}"
        else:
            host = str(rng.choice(safe_hosts))
            path = str(rng.choice(safe_paths))
            url = f"https://{host}/{path}/{rng.integers(1, 100)}"
            if rng.random() < 0.3:
                url += f"?query=security&page={rng.integers(1, 5)}"

        feature_rows.append(extract_features(url))
        labels.append(is_phishing)

    return np.asarray(feature_rows, dtype=np.float32), np.asarray(labels, dtype=np.int32)


def load_dataset_from_csv(csv_path: Path) -> Tuple[np.ndarray, np.ndarray]:
    """Load and parse URL dataset from an external CSV file."""
    features: List[List[float]] = []
    labels: List[int] = []

    with open(csv_path, mode="r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError(f"CSV file {csv_path} contains no headers.")

        # Identify url column
        url_col = None
        for col in ["url", "URL", "url_address", "domain", "link"]:
            if col in reader.fieldnames:
                url_col = col
                break
        if not url_col:
            url_col = reader.fieldnames[0]

        # Identify label column
        label_col = None
        for col in ["label", "Label", "target", "status", "phishing", "class", "result"]:
            if col in reader.fieldnames:
                label_col = col
                break
        if not label_col and len(reader.fieldnames) > 1:
            label_col = reader.fieldnames[1]

        if not label_col:
            raise ValueError(f"Could not identify label column in {csv_path}.")

        for row in reader:
            url_val = row.get(url_col, "").strip()
            raw_label = row.get(label_col, "").strip().lower()
            if not url_val:
                continue

            # Parse label
            if raw_label in ("1", "phishing", "bad", "malicious", "yes", "true"):
                lbl = 1
            else:
                lbl = 0

            features.append(extract_features(url_val))
            labels.append(lbl)

    if not features:
        raise ValueError(f"No valid rows found in {csv_path}.")

    return np.asarray(features, dtype=np.float32), np.asarray(labels, dtype=np.int32)


def train_model(
    output_path: str | Path = "phishing_model.joblib",
    dataset_path: Optional[str | Path] = None,
) -> Path:
    """Train RandomForest phishing classifier and persist joblib artifact."""
    output_path = Path(output_path)

    if dataset_path and Path(dataset_path).exists():
        print(f"Loading training data from dataset: {dataset_path}")
        features, labels = load_dataset_from_csv(Path(dataset_path))
    else:
        print("Generating synthetic 10-feature training data...")
        features, labels = build_training_data(sample_count=3000)

    model = RandomForestClassifier(
        n_estimators=256,
        max_depth=14,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(features, labels)

    artifact = {
        "model": model,
        "feature_order": FEATURE_NAMES,
        "feature_count": len(FEATURE_NAMES),
        "heavy_keywords": list(HEAVY_KEYWORDS),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, output_path)
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train Volcano's enhanced 10-feature Phishing Classifier."
    )
    parser.add_argument(
        "--output",
        default="phishing_model.joblib",
        help="Destination joblib artifact path (default: phishing_model.joblib).",
    )
    parser.add_argument(
        "--dataset",
        default=None,
        help="Optional path to external CSV dataset with URL and label columns.",
    )
    args = parser.parse_args()
    path = train_model(output_path=args.output, dataset_path=args.dataset)
    print(f"[+] Saved enhanced phishing model ({len(FEATURE_NAMES)} features) to {path.resolve()}")


if __name__ == "__main__":
    main()