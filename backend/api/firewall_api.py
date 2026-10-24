"""Comprehensive REST APIs for firewall management and monitoring."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel
from typing import Any, Dict, Optional


class RuleCreateRequest(BaseModel):
    name: str
    action: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    app_name: Optional[str] = None
    priority: int = 10
    description: str = ""


class RuleResponse(BaseModel):
    id: int
    name: str
    action: str
    enabled: bool
    priority: int
    app_name: Optional[str] = None


class ACLEntryRequest(BaseModel):
    name: str
    subject_type: str
    subject_value: str
    resource: str
    action: str


class SessionResponse(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    state: str
    packets_sent: int
    bytes_sent: int


class DeviceRiskResponse(BaseModel):
    mac_address: str
    risk_score: float
    threat_count: int


class AlertResponse(BaseModel):
    id: int
    timestamp: str
    source: str
    severity: str
    category: str
    message: str


class ThreatReportRequest(BaseModel):
    incident_type: str
    severity: str
    days: int = 1


def create_firewall_routes(
    rule_engine,
    state_engine,
    acl_engine,
    risk_engine,
    anomaly_detector,
    response_engine,
    alerts,
    threat_correlation,
    report_generator,
    db=None,
    grounded_copilot=None,
):
    router = APIRouter(prefix="/api", tags=["firewall"])
    from storage.auth import get_optional_current_user

    @router.post("/rules")
    def create_rule(req: RuleCreateRequest, user: Optional[Dict[str, Any]] = Depends(get_optional_current_user)):
        from core.rule_engine import RuleAction, RulePriority

        try:
            rule = rule_engine.add_rule(
                name=req.name,
                action=RuleAction(req.action),
                src_ip=req.src_ip,
                dst_ip=req.dst_ip,
                src_port=req.src_port,
                dst_port=req.dst_port,
                protocol=req.protocol,
                app_name=req.app_name,
                priority=RulePriority(req.priority),
                description=req.description,
            )
            if db:
                username = (user or {}).get("username", "system")
                db.log_audit(username, "create_rule", f"rule:{rule.name}", {"action": req.action, "id": rule.id, "app_name": req.app_name})
                try:
                    db.save_rule(rule)
                except Exception:
                    pass
            return {"id": rule.id, "name": rule.name, "app_name": rule.app_name, "status": "created"}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.get("/rules")
    def list_rules():
        rules = rule_engine.list_rules()
        return [
            {
                "id": r.id,
                "name": r.name,
                "action": getattr(r.action, "value", r.action),
                "priority": getattr(r.priority, "value", r.priority),
                "enabled": r.enabled,
                "app_name": getattr(r, "app_name", None),
                "src_ip": getattr(r, "src_ip", None),
                "dst_ip": getattr(r, "dst_ip", None),
                "dst_port": getattr(r, "dst_port", None),
                "protocol": getattr(r, "protocol", None),
                "description": getattr(r, "description", ""),
                "hits": getattr(r, "hits", 0),
            }
            for r in rules
        ]

    @router.delete("/rules/{rule_id}")
    def delete_rule(rule_id: int, user: Optional[Dict[str, Any]] = Depends(get_optional_current_user)):
        if rule_engine.delete_rule(rule_id):
            if db:
                username = (user or {}).get("username", "system")
                db.log_audit(username, "delete_rule", f"rule:{rule_id}")
            return {"status": "deleted"}
        raise HTTPException(status_code=404, detail="Rule not found")

    @router.get("/sessions")
    def get_sessions():
        sessions = state_engine.list_tcp_sessions()
        result = [
            {
                "src_ip": s.src_ip,
                "dst_ip": s.dst_ip,
                "src_port": s.src_port,
                "dst_port": s.dst_port,
                "state": s.state.value,
                "packets_sent": s.packets_sent,
                "bytes_sent": s.bytes_sent,
                "process": "Firewall Sniffer",
            }
            for s in sessions[:100]
        ]
        # Supplement with live OS sockets
        try:
            import psutil
            proc_cache = {}
            for c in psutil.net_connections(kind="tcp"):
                if c.status == "ESTABLISHED" and c.raddr and c.laddr:
                    pname = "System"
                    pid = c.pid or 0
                    if pid > 0:
                        if pid not in proc_cache:
                            try:
                                proc_cache[pid] = psutil.Process(pid).name()
                            except Exception:
                                proc_cache[pid] = "Process"
                        pname = proc_cache[pid]
                    result.append({
                        "src_ip": c.laddr.ip,
                        "dst_ip": c.raddr.ip,
                        "src_port": c.laddr.port,
                        "dst_port": c.raddr.port,
                        "state": "established",
                        "packets_sent": 1,
                        "bytes_sent": 64,
                        "process": f"{pname} (PID: {pid})" if pid else pname,
                    })
        except Exception:
            pass
        return result[:100]

    @router.get("/acl")
    def list_acl_entries():
        entries = acl_engine.list_entries()
        return [{"id": e.id, "name": e.name, "subject_type": e.subject_type, "action": e.action.value} for e in entries]

    @router.post("/acl")
    def create_acl_entry(req: ACLEntryRequest):
        from core.acl_engine import ACLAction

        entry = acl_engine.add_entry(
            name=req.name,
            subject_type=req.subject_type,
            subject_value=req.subject_value,
            resource=req.resource,
            action=ACLAction(req.action),
        )
        return {"id": entry.id, "status": "created"}

    @router.get("/risk/devices")
    def get_high_risk_devices(threshold: float = 0.0):
        devices = risk_engine.list_high_risk_devices(threshold=threshold)
        return [
            {
                "mac": d.mac_address,
                "risk": round(d.risk_score, 3),
                "threats": d.threat_count,
                "ip": (d.metadata or {}).get("ip", ""),
                "type": (d.metadata or {}).get("type", "Network Device"),
                "hostname": (d.metadata or {}).get("hostname", ""),
            }
            for d in devices
        ]

    @router.get("/risk/users")
    def get_high_risk_users(threshold: float = 0.0):
        users = risk_engine.list_high_risk_users(threshold=threshold)
        return [{"user": u.user_id, "risk": round(u.risk_score, 3), "threats": u.threat_count} for u in users]

    @router.get("/risk/stats")
    def get_risk_stats():
        return risk_engine.get_risk_stats()

    @router.get("/threats/recent")
    def get_recent_threats():
        return threat_correlation._incident_clusters[:10]

    @router.post("/copilot/ask")
    def copilot_query(query: Optional[str] = None, payload: Optional[Dict[str, Any]] = Body(default=None)):
        q = query or (payload.get("query") if payload else "") or "Show status"
        if grounded_copilot:
            return grounded_copilot.query(q)

        from copilot.security_copilot import SecurityCopilot
        copilot = SecurityCopilot()
        intent = copilot.parse_query(q)
        response_data = {"intent": intent.intent_type, "entity": intent.entity}
        return {"answer": copilot.generate_response(intent, response_data), "confidence": intent.confidence}

    @router.post("/reports/incident")
    def generate_incident_report(req: ThreatReportRequest):
        report = report_generator.generate_report(
            incident_id="incident_001",
            incident_type=req.incident_type,
            severity=req.severity,
            indicators=[],
            affected_resources=[],
            timestamp=0.0,
        )
        return report

    @router.post("/autonomous/block-ip")
    def autonomous_block_ip(ip: str, duration: int = 3600, user: Optional[Dict[str, Any]] = Depends(get_optional_current_user)):
        from ai.response_engine import ResponseAction

        response = response_engine.trigger_response(
            action=ResponseAction.BLOCK,
            target_ip=ip,
            duration=float(duration),
            reason="Autonomous threat response",
        )
        username = (user or {}).get("username", "system")
        if response.id == 0:
            if db:
                db.log_audit(username, "block_ip_rejected", f"ip:{ip}", {"reason": response.reason})
            raise HTTPException(status_code=400, detail=response.reason)

        if db:
            db.log_audit(username, "block_ip", f"ip:{ip}", {"duration": duration})
        return {"id": response.id, "status": "blocked", "duration": duration}

    @router.post("/autonomous/unblock-ip")
    def autonomous_unblock_ip(ip: str, user: Optional[Dict[str, Any]] = Depends(get_optional_current_user)):
        success = response_engine.unblock_ip(ip)
        if db:
            username = (user or {}).get("username", "system")
            db.log_audit(username, "manual_unblock_ip", f"ip:{ip}", {"success": success})
        return {"status": "unblocked" if success else "not_found", "ip": ip}

    @router.get("/state")
    def get_engine_state():
        return {
            "rules": len(rule_engine.list_rules()),
            "tcp_sessions": state_engine.get_stats(),
            "acl_entries": len(acl_engine.list_entries()),
            "response_actions": response_engine.get_response_stats(),
        }

    return router
