"""FastAPI router for Port Scanning & Vulnerability Detection endpoints."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Depends

from scanner.port_scanner import get_port_scanner, TOP_20_PORTS, TOP_100_PORTS
from vulns.vuln_database import get_vuln_database
from vulns.vuln_scanner import get_vuln_scanner


router = APIRouter(prefix="/api/scanner", tags=["Scanner & Vulnerabilities"])

# In-memory scan history buffer (last 50 scans)
_scan_history: List[Dict[str, Any]] = []


class PortScanRequest(BaseModel):
    target: str = Field(..., description="Target hostname or IP address to scan")
    profile: str = Field(default="top20", description="'top20', 'top100', or 'custom'")
    custom_ports: Optional[str] = Field(default=None, description="Comma-separated ports or ranges, e.g. '80,443,8000-8080'")
    timeout: Optional[float] = Field(default=0.8, description="Socket connect timeout in seconds")
    grab_banner: bool = Field(default=True, description="Whether to grab service banner / HTTP header")


class VulnScanRequest(BaseModel):
    target: str = Field(..., description="Target hostname or IP address to scan and audit")
    profile: str = Field(default="top20", description="'top20', 'top100', or 'custom'")
    custom_ports: Optional[str] = Field(default=None, description="Comma-separated ports or ranges")
    timeout: Optional[float] = Field(default=0.8, description="Socket connect timeout in seconds")


class VulnAuditRequest(BaseModel):
    open_ports: List[Dict[str, Any]] = Field(..., description="List of open port objects with port, service, banner")
    target: Optional[str] = Field(default="Manual Audit Target", description="Identifier for audited system")


@router.post("/port-scan")
def run_port_scan(req: PortScanRequest) -> Dict[str, Any]:
    """Execute a multi-threaded TCP port scan and service banner grab on target."""
    scanner = get_port_scanner()
    try:
        result = scanner.scan(
            target=req.target,
            profile=req.profile,
            custom_ports=req.custom_ports,
            timeout=req.timeout,
            grab_banner=req.grab_banner,
        )
        # Record in history
        _scan_history.insert(0, {
            "type": "port_scan",
            "target": result["target"],
            "resolved_ip": result["resolved_ip"],
            "profile": result["profile"],
            "open_ports_count": result["open_ports_count"],
            "timestamp": result["timestamp"],
        })
        if len(_scan_history) > 50:
            _scan_history.pop()
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Port scan failed: {e}")


@router.post("/vuln-scan")
def run_vuln_scan(req: VulnScanRequest) -> Dict[str, Any]:
    """Execute an end-to-end port scan and evaluate discovered services against vulnerability database."""
    vuln_scanner = get_vuln_scanner()
    try:
        result = vuln_scanner.scan_target(
            target=req.target,
            profile=req.profile,
            custom_ports=req.custom_ports,
            timeout=req.timeout,
        )
        assessment = result.get("vulnerability_assessment", {})
        # Record in history
        _scan_history.insert(0, {
            "type": "vuln_scan",
            "target": result["target"],
            "resolved_ip": result["resolved_ip"],
            "profile": result["profile"],
            "open_ports_count": result["open_ports_count"],
            "overall_risk": assessment.get("overall_risk", "UNKNOWN"),
            "composite_risk_score": assessment.get("composite_risk_score", 0.0),
            "total_vulnerabilities": assessment.get("total_vulnerabilities", 0),
            "timestamp": result["timestamp"],
        })
        if len(_scan_history) > 50:
            _scan_history.pop()
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Vulnerability scan failed: {e}")


@router.post("/vuln-audit")
def audit_open_ports(req: VulnAuditRequest) -> Dict[str, Any]:
    """Audit pre-existing port scan results against the vulnerability signature database."""
    vuln_scanner = get_vuln_scanner()
    return vuln_scanner.evaluate_open_ports(open_ports=req.open_ports, target=req.target or "Target")


@router.get("/signatures")
def get_vulnerability_signatures() -> Dict[str, Any]:
    """List all vulnerability signatures, CVE mappings, and CVSS ratings in the database."""
    db = get_vuln_database()
    sigs = db.get_all_signatures()
    return {
        "total_signatures": len(sigs),
        "signatures": sigs,
    }


@router.get("/history")
def get_scanner_history() -> List[Dict[str, Any]]:
    """Retrieve the recent scan history."""
    return _scan_history
