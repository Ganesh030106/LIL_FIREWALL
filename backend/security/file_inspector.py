"""File Download & Ransomware Payload Inspector.

Provides static heuristics, Shannon byte entropy analysis, binary header inspection,
double-extension detection, and ransomware payload signature matching for downloaded files.
"""

from __future__ import annotations

import hashlib
import math
import re
import threading
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".pif", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".bat", ".cmd", ".hta", ".ps1", ".psm1", ".jar", ".dll", ".sys",
}

RANSOMWARE_HEURISTIC_STRINGS = [
    b"vssadmin delete shadows",
    b"bcdedit /set",
    b"recoveryenabled no",
    b"wbadmin delete",
    b"wevtutil cl",
    b"your personal files are encrypted",
    b"all your files have been encrypted",
    b"restore your files",
    b"bitcoin",
    b"decrypt your files",
    b"tor browser",
    b".onion",
]

DOUBLE_EXT_PATTERN = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv|zip|mp3|mp4)\.(?:exe|scr|vbs|bat|cmd|hta|js|ps1|pif)$",
    re.IGNORECASE,
)


def calculate_byte_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of binary data (0.0 to 8.0 bits/byte)."""
    if not data:
        return 0.0
    length = len(data)
    freq = Counter(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


class FileInspector:
    """Analyzes file payloads for ransomware markers, high entropy, and deceptive extensions."""

    @staticmethod
    def inspect(filename: str, content: bytes) -> Dict[str, Any]:
        file_size = len(content)
        signals: List[str] = []
        threat_types: List[str] = []
        risk_score = 0.0

        # 1. Double extension check (common phishing / ransomware dropper technique)
        has_double_ext = bool(DOUBLE_EXT_PATTERN.search(filename))
        if has_double_ext:
            signals.append("Dangerous deceptive double extension detected (e.g., .pdf.exe)")
            threat_types.append("Deceptive Extension")
            risk_score += 0.40

        # 2. Dangerous executable extension check
        ext = Path(filename).suffix.lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            signals.append(f"Executable/script extension ({ext})")
            risk_score += 0.25

        # 3. Shannon Byte Entropy (Packed / Encrypted payload detection)
        # Ransomware binaries or encrypted file drops typically exhibit entropy > 7.15
        entropy = round(calculate_byte_entropy(content), 4)
        if file_size > 512:
            if entropy >= 7.30:
                signals.append(f"Extremely high byte entropy ({entropy:.2f} / 8.00) indicates encrypted/packed ransomware payload")
                threat_types.append("High-Entropy Packed Payload")
                risk_score += 0.40
            elif entropy >= 6.80:
                signals.append(f"Elevated byte entropy ({entropy:.2f} / 8.00) indicates packed or obfuscated code")
                risk_score += 0.20

        # 4. Binary Header Inspection
        is_pe = content.startswith(b"MZ")
        is_elf = content.startswith(b"\x7fELF")
        is_archive = content.startswith((b"PK\x03\x04", b"Rar!", b"7z\xbc\xaf\x27\x1c"))

        if is_pe:
            signals.append("Windows Portable Executable (PE / MZ) binary signature detected")
            if ext in {".pdf", ".docx", ".xlsx", ".jpg", ".png", ".txt"}:
                signals.append("CRITICAL: Executable binary disguised under non-executable file extension!")
                threat_types.append("Masquerading Binary")
                risk_score += 0.60
            else:
                risk_score += 0.15

        if is_elf:
            signals.append("Linux ELF binary header detected")
            risk_score += 0.15

        # 5. Ransomware Heuristic Pattern Scanning in Binary Strings
        lowered_content = content.lower()
        matched_ransom_patterns = [
            pattern.decode("ascii", errors="ignore")
            for pattern in RANSOMWARE_HEURISTIC_STRINGS
            if pattern in lowered_content
        ]
        if matched_ransom_patterns:
            signals.append(f"Ransomware indicators matched: {', '.join(matched_ransom_patterns[:3])}")
            threat_types.append("Ransomware Heuristics")
            risk_score += 0.50

        # 6. Cryptographic Hashes
        sha256 = hashlib.sha256(content).hexdigest()
        md5 = hashlib.md5(content).hexdigest()

        # Clamp risk score
        final_risk = round(min(1.0, risk_score), 4)
        is_malicious = final_risk >= 0.50

        if not threat_types:
            threat_type_str = "Ransomware / Suspicious Executable" if is_malicious else "Benign File"
        else:
            threat_type_str = " + ".join(threat_types)

        recommendation = "QUARANTINE / BLOCK EXECUTION" if is_malicious else "ALLOW / SAFE"

        return {
            "filename": filename,
            "file_size": file_size,
            "extension": ext,
            "entropy": entropy,
            "sha256": sha256,
            "md5": md5,
            "is_pe": is_pe,
            "is_elf": is_elf,
            "is_malicious": is_malicious,
            "risk_score": final_risk,
            "threat_classification": threat_type_str,
            "signals": signals,
            "recommendation": recommendation,
        }

    def inspect_bytes(self, content: bytes, filename: str = "file") -> Dict[str, Any]:
        """Convenience method to inspect raw bytes."""
        return self.inspect(filename, content)

    def inspect_file(self, filepath: str | Path) -> Dict[str, Any]:
        """Inspect a file from the local filesystem."""
        p = Path(filepath)
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(f"File not found: {filepath}")
        content = p.read_bytes()
        return self.inspect(p.name, content)



_inspector_instance: Optional[FileInspector] = None
_inspector_lock = threading.Lock()


def get_file_inspector() -> FileInspector:
    """Retrieve or initialize the singleton FileInspector instance."""
    global _inspector_instance
    if _inspector_instance is None:
        with _inspector_lock:
            if _inspector_instance is None:
                _inspector_instance = FileInspector()
    return _inspector_instance

