import { useState, useEffect } from "react";
import { createPortal } from "react-dom";
import { apiFetch } from "../services/api";

export default function IncidentDrawer({ alert, onClose, onAlertUpdated, currentUser }) {
    const [triageStatus, setTriageStatus] = useState("investigating");
    const [notes, setNotes] = useState("");
    const [saving, setSaving] = useState(false);
    const [actionMsg, setActionMsg] = useState("");
    const [containing, setContaining] = useState(false);
    const [xaiData, setXaiData] = useState(null);
    const [copied, setCopied] = useState(false);

    const isViewer = false;
    const isAdmin = true;

    // Close on Escape key press
    useEffect(() => {
        const handleKeyDown = (e) => {
            if (e.key === "Escape") onClose();
        };
        window.addEventListener("keydown", handleKeyDown);
        return () => window.removeEventListener("keydown", handleKeyDown);
    }, [onClose]);

    useEffect(() => {
        if (!alert) return;
        setTriageStatus(alert.status || "new");
        setNotes(alert.notes || "");
        setActionMsg("");

        // Fetch or compute XAI feature contribution explanation
        const meta = alert.meta || {};
        const cat = alert.category || "";

        apiFetch("/api/ai/explain", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                type: cat === "phishing" ? "url" : "flow",
                target: alert.message || "Security telemetry event",
                pps: meta.pps || 75.0,
                byte_size: meta.byte_size || 1200,
                score: alert.severity === "critical" ? 0.92 : 0.75,
            }),
        })
            .then(res => res.ok ? res.json() : null)
            .then(data => { if (data) setXaiData(data); })
            .catch(() => {});
    }, [alert]);

    if (!alert) return null;

    const handleSaveTriage = async () => {
        if (isViewer) return;
        setSaving(true);
        setActionMsg("");
        try {
            const res = await apiFetch(`/api/alerts/${alert.id}/triage`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    status: triageStatus,
                    notes,
                    assignee: currentUser?.username || "analyst",
                }),
            });
            if (res.ok) {
                setActionMsg("✓ Incident triage updated successfully.");
                if (onAlertUpdated) onAlertUpdated({ ...alert, status: triageStatus, notes });
            } else {
                setActionMsg("✗ Failed to save triage status.");
            }
        } catch (e) {
            setActionMsg(`✗ Error: ${e.message}`);
        }
        setSaving(false);
    };

    const handleContainIp = async () => {
        const targetIp = (alert.meta || {}).source_ip;
        if (!targetIp || targetIp === "N/A" || !isAdmin) return;
        if (!window.confirm(`Autonomous Containment: Deploy kernel firewall DROP rule for hostile IP ${targetIp}?`)) return;

        setContaining(true);
        setActionMsg("");
        try {
            const res = await apiFetch("/api/autonomous/block-ip", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ip: targetIp, duration: 3600 }),
            });
            if (res.ok) {
                setActionMsg(`✓ Host ${targetIp} contained in kernel firewall (3600s TTL).`);
            } else {
                const err = await res.json().catch(() => ({}));
                setActionMsg(`✗ Containment failed: ${err.detail || "Error"}`);
            }
        } catch (e) {
            setActionMsg(`✗ Error: ${e.message}`);
        }
        setContaining(false);
    };

    const copyToClipboard = (text) => {
        if (!text) return;
        navigator.clipboard?.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const mitre = {
        technique_id: alert.mitre?.technique_id || "T1190",
        technique_name: alert.mitre?.technique_name || "Exploit Public-Facing Application",
        tactic_id: alert.mitre?.tactic_id || "TA0001",
        tactic_name: alert.mitre?.tactic_name || "Initial Access",
        tactic_icon: alert.mitre?.tactic_icon || "🚪",
        description: alert.mitre?.description || "Adversary exploiting application vulnerabilities or anomalous network behavior.",
    };

    const meta = alert.meta || {};
    const sourceIp = meta.source_ip || meta.src_ip || alert.source || "N/A";
    const destIp = meta.destination_ip || meta.dst_ip || "127.0.0.1";
    const destPort = meta.dest_port || meta.port || (Array.isArray(meta.unique_ports) ? meta.unique_ports.join(", ") : "N/A");
    const protocol = meta.protocol || "TCP/IP";
    const severity = String(alert.severity || "medium").toLowerCase();
    const isCritical = severity === "critical";
    const isHigh = severity === "high";

    const drawerContent = (
        <div className="incident-drawer-backdrop" onClick={onClose} style={{ zIndex: 10000 }}>
            <div className="incident-drawer" onClick={e => e.stopPropagation()} style={{ color: "var(--text)" }}>
                {/* Header */}
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", borderBottom: "1px solid var(--border)", paddingBottom: "14px" }}>
                    <div>
                        <div style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.08em", fontWeight: 700 }}>
                            Security Event Forensic Dossier • #{alert.id}
                        </div>
                        <h2 style={{ fontSize: "1.25rem", margin: "4px 0 0 0", color: "var(--text)", fontWeight: 700 }}>
                            {alert.category ? alert.category.toUpperCase().replace(/_/g, " ") : "SECURITY ALERT"}
                        </h2>
                    </div>
                    <button className="modal-close-btn" onClick={onClose} aria-label="Close Drawer" style={{ fontSize: "1.3rem", padding: "4px 8px" }}>
                        ✕
                    </button>
                </div>

                {/* Key Status Indicators */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                    <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", padding: "10px 14px" }}>
                        <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" }}>Severity Level</div>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "4px" }}>
                            <span className={`badge ${isCritical ? "badge-critical" : isHigh ? "badge-danger" : "badge-safe"}`} style={{ fontSize: "11px", padding: "3px 8px" }}>
                                {severity.toUpperCase()}
                            </span>
                        </div>
                    </div>
                    <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "8px", padding: "10px 14px" }}>
                        <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase" }}>Detection Timestamp</div>
                        <div style={{ fontSize: "0.85rem", fontWeight: 600, marginTop: "4px", fontFamily: "var(--font-mono)" }}>
                            {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : "Recent Telemetry"}
                        </div>
                    </div>
                </div>

                {/* Alert Message Summary */}
                <div style={{ background: "rgba(0,0,0,0.35)", border: "1px solid var(--border)", borderRadius: "8px", padding: "12px 14px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                        <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 600 }}>Incident Payload / Trigger</div>
                        <button
                            type="button"
                            onClick={() => copyToClipboard(alert.message)}
                            style={{ background: "none", border: "none", color: "var(--accent)", fontSize: "11px", cursor: "pointer", padding: "2px 6px" }}
                        >
                            {copied ? "✓ Copied" : "📋 Copy"}
                        </button>
                    </div>
                    <div style={{ fontSize: "0.88rem", color: "var(--text)", lineHeight: 1.5, wordBreak: "break-word" }}>
                        {alert.message || "No payload string recorded."}
                    </div>
                </div>

                {/* MITRE ATT&CK Mapping Card */}
                <div style={{ background: "rgba(139, 92, 246, 0.08)", border: "1px solid rgba(139, 92, 246, 0.3)", borderRadius: "8px", padding: "14px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                            <span style={{ fontSize: "1.1rem" }}>{mitre.tactic_icon || "🛡️"}</span>
                            <span style={{ fontWeight: 700, fontSize: "0.9rem", color: "#c4b5fd" }}>MITRE ATT&CK Mapping</span>
                        </div>
                        <span className="mitre-badge" style={{ fontFamily: "var(--font-mono)", fontSize: "11px", padding: "2px 8px" }}>
                            {mitre.technique_id}
                        </span>
                    </div>
                    <div style={{ fontSize: "0.88rem", fontWeight: 600, color: "var(--text)", marginBottom: "4px" }}>
                        {mitre.technique_name}
                    </div>
                    <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", lineHeight: 1.4 }}>
                        Tactic: <strong>{mitre.tactic_name}</strong> ({mitre.tactic_id}). {mitre.description}
                    </div>
                </div>

                {/* Explainable AI (XAI) Attribution */}
                {xaiData && (xaiData.feature_contributions || xaiData.factors || xaiData.contributions) && (
                    <div style={{ background: "rgba(0, 210, 255, 0.05)", border: "1px solid rgba(0, 210, 255, 0.25)", borderRadius: "8px", padding: "14px" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                            <span style={{ fontWeight: 700, fontSize: "0.9rem", color: "#00d2ff" }}>🧠 Explainable AI (XAI) Attribution</span>
                            <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>{xaiData.model_type || xaiData.engine || "IsoForest + Random Forest"}</span>
                        </div>
                        <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: "8px" }}>
                            Factors driving automated classification ({xaiData.decision || xaiData.classification || "Malicious Anomaly"}):
                        </div>
                        <div className="xai-bar-wrap">
                            {(xaiData.feature_contributions || xaiData.factors || xaiData.contributions || []).slice(0, 4).map((f, i) => (
                                <div key={i} className="xai-bar-item">
                                    <div className="xai-bar-header">
                                        <span style={{ fontWeight: 600 }}>{f.feature || f.dimension}</span>
                                        <span style={{ fontFamily: "var(--font-mono)", color: f.influence === "Malicious" || f.influence === "High" ? "var(--danger)" : "var(--primary)" }}>
                                            {f.percentage || f.importance || 25}%
                                        </span>
                                    </div>
                                    <div className="xai-bar-track">
                                        <div
                                            className="xai-bar-fill"
                                            style={{
                                                width: `${f.percentage || f.importance || 25}%`,
                                                background: f.influence === "Malicious" || f.influence === "High" ? "var(--danger)" : "var(--primary)",
                                            }}
                                        />
                                    </div>
                                    <div style={{ fontSize: "10px", color: "var(--text-muted)", marginTop: "3px" }}>
                                        {f.evidence || f.detail}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Network & Host Intelligence */}
                <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "8px", padding: "14px" }}>
                    <div style={{ fontWeight: 600, fontSize: "0.85rem", marginBottom: "8px", color: "var(--text-secondary)" }}>
                        🌐 Network Context & Attribution
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", fontSize: "0.8rem" }}>
                        <div>Hostile Source: <strong style={{ color: "var(--danger)", fontFamily: "var(--font-mono)" }}>{sourceIp}</strong></div>
                        <div>Target Host: <strong style={{ fontFamily: "var(--font-mono)" }}>{destIp}</strong></div>
                        <div>Target Port: <strong style={{ fontFamily: "var(--font-mono)" }}>{destPort}</strong></div>
                        <div>Protocol: <strong>{protocol}</strong></div>
                        <div style={{ gridColumn: "span 2" }}>Geo/Origin: <strong>{meta.country || "External / RFC-1918"}</strong></div>
                    </div>
                </div>

                {/* Forensic PCAP Slice Download & Containment */}
                <div style={{ display: "flex", gap: "8px" }}>
                    <a
                        href={`/api/alerts/${alert.id}/pcap`}
                        target="_blank"
                        rel="noreferrer"
                        className="btn btn-secondary"
                        style={{ flex: 1, textAlign: "center", fontSize: "0.82rem", padding: "8px" }}
                    >
                        📥 Download Incident PCAP
                    </a>
                    {sourceIp !== "N/A" && isAdmin && (
                        <button
                            type="button"
                            className="btn btn-primary"
                            style={{ flex: 1, background: "var(--danger)", borderColor: "var(--danger)", fontSize: "0.82rem", padding: "8px" }}
                            onClick={handleContainIp}
                            disabled={containing}
                        >
                            {containing ? "Containing..." : `🚫 Contain ${sourceIp}`}
                        </button>
                    )}
                </div>

                {/* Analyst Triage & Investigation Notes */}
                <div style={{ borderTop: "1px solid var(--border)", paddingTop: "14px", display: "flex", flexDirection: "column", gap: "10px" }}>
                    <div style={{ fontWeight: 600, fontSize: "0.85rem", color: "var(--text-secondary)" }}>
                        ✍️ Analyst Triage & Investigation Notes
                    </div>

                    <div style={{ display: "flex", gap: "8px" }}>
                        <select
                            className="form-select"
                            value={triageStatus}
                            onChange={e => setTriageStatus(e.target.value)}
                            disabled={isViewer}
                            style={{ flex: 1, fontSize: "0.82rem" }}
                        >
                            <option value="new">Status: New Alert</option>
                            <option value="investigating">Status: Under Investigation</option>
                            <option value="triaged">Status: Triaged / Confirmed</option>
                            <option value="resolved">Status: Resolved & Remediated</option>
                            <option value="false_positive">Status: False Positive</option>
                        </select>
                        <button
                            type="button"
                            className="btn btn-secondary"
                            onClick={handleSaveTriage}
                            disabled={saving || isViewer}
                            style={{ fontSize: "0.82rem", padding: "6px 14px" }}
                        >
                            {saving ? "Saving..." : "Update Triage"}
                        </button>
                    </div>

                    <textarea
                        className="form-input"
                        rows={3}
                        value={notes}
                        onChange={e => setNotes(e.target.value)}
                        placeholder="Add investigation findings, root cause analysis, or operator notes..."
                        disabled={isViewer}
                        style={{ fontSize: "0.82rem" }}
                    />

                    {actionMsg && (
                        <div style={{
                            fontSize: "0.78rem",
                            color: actionMsg.startsWith("✓") ? "var(--safe)" : "var(--danger)",
                            fontFamily: "var(--font-mono)"
                        }}>
                            {actionMsg}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );

    return createPortal(drawerContent, document.body);
}
