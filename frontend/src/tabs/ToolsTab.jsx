import { useState } from "react";
import { apiFetch } from "../services/api";

export default function ToolsTab({ currentUser }) {
    // ── URL Phishing Analyzer ──
    const [urlValue, setUrlValue] = useState("");
    const [analysis, setAnalysis] = useState(null);
    const [analysisLoading, setAnalysisLoading] = useState(false);

    // ── Ransomware & File Payload Inspector ──
    const [fileObj, setFileObj] = useState(null);
    const [fileAnalysis, setFileAnalysis] = useState(null);
    const [fileLoading, setFileLoading] = useState(false);

    // ── Isolation Forest & LSTM Flow Anomaly Scorer ──
    const [flowForm, setFlowForm] = useState({ packet_size: "1420", src_port: "54321", dst_port: "80", protocol: "TCP", flow_rate: "15", model_type: "isolation_forest" });
    const [flowAnalysis, setFlowAnalysis] = useState(null);
    const [flowLoading, setFlowLoading] = useState(false);

    // ── Security Copilot ──
    const [copilotQuery, setCopilotQuery] = useState("");
    const [copilotHistory, setCopilotHistory] = useState([]);
    const [copilotLoading, setCopilotLoading] = useState(false);

    // ── Incident Report ──
    const [reportForm, setReportForm] = useState({ incident_type: "malware", severity: "high", days: 1 });
    const [report, setReport] = useState(null);
    const [reportLoading, setReportLoading] = useState(false);

    // ── Kill Switch ──
    const [panicState, setPanicState] = useState({ loading: false, message: "" });
    const [dryRun, setDryRun] = useState(true);

    // ── Port Scanner & Vulnerability Assessment ──
    const [scanTarget, setScanTarget] = useState("127.0.0.1");
    const [scanProfile, setScanProfile] = useState("top20");
    const [customPorts, setCustomPorts] = useState("80,443,8000-8080");
    const [scanMode, setScanMode] = useState("vuln"); // "vuln" | "ports"
    const [scanLoading, setScanLoading] = useState(false);
    const [scanResult, setScanResult] = useState(null);
    const [remediatingPort, setRemediatingPort] = useState(null);
    const [remediationMsg, setRemediationMsg] = useState("");

    const isViewer = currentUser?.role === "viewer";

    // ─── Handlers ───
    const handlePortScan = async (e) => {
        e.preventDefault();
        if (!scanTarget.trim()) return;
        setScanLoading(true);
        setScanResult(null);
        setRemediationMsg("");
        try {
            const endpoint = scanMode === "vuln" ? "/api/scanner/vuln-scan" : "/api/scanner/port-scan";
            const payload = {
                target: scanTarget.trim(),
                profile: scanProfile,
                custom_ports: scanProfile === "custom" ? customPorts : undefined,
                timeout: 0.8,
                grab_banner: true,
            };
            const res = await apiFetch(endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || "Scan execution failed.");
            }
            setScanResult(await res.json());
        } catch (err) {
            setScanResult({ error: err.message });
        } finally {
            setScanLoading(false);
        }
    };

    const handleApplyRemediationRule = async (rule) => {
        if (isViewer) {
            alert("Viewer role is read-only. Login as Admin or Analyst to deploy firewall rules.");
            return;
        }
        setRemediatingPort(rule.dst_port);
        setRemediationMsg("");
        try {
            const res = await apiFetch("/api/rules", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(rule),
            });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || "Failed to deploy remediation rule.");
            }
            setRemediationMsg(`✓ Firewall rule successfully created: ${rule.name}`);
        } catch (err) {
            setRemediationMsg(`✗ Failed to create rule: ${err.message}`);
        } finally {
            setRemediatingPort(null);
        }
    };

    const handleFileInspect = async (e) => {
        e.preventDefault();
        if (!fileObj) return;
        setFileLoading(true);
        setFileAnalysis(null);
        try {
            const formData = new FormData();
            formData.append("file", fileObj);
            const token = localStorage.getItem("token");
            const res = await fetch("/api/check-file", {
                method: "POST",
                headers: token ? { "Authorization": `Bearer ${token}` } : {},
                body: formData,
            });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || "File inspection failed.");
            }
            setFileAnalysis(await res.json());
        } catch (err) {
            setFileAnalysis({ error: err.message });
        } finally {
            setFileLoading(false);
        }
    };

    const handleFlowScore = async (e) => {
        e.preventDefault();
        setFlowLoading(true);
        setFlowAnalysis(null);
        try {
            const isLstm = flowForm.model_type === "lstm";
            const endpoint = isLstm ? "/api/lstm-flow-score" : "/api/anomaly-score";
            const rate = parseFloat(flowForm.flow_rate) || 5;
            const payload = isLstm ? {
                delta_time: 1.0 / Math.max(0.1, rate),
                packet_size: parseFloat(flowForm.packet_size) || 64,
                direction: 1,
                protocol: flowForm.protocol || "TCP",
            } : {
                packet_size: parseFloat(flowForm.packet_size) || 64,
                src_port: parseInt(flowForm.src_port) || 50000,
                dst_port: parseInt(flowForm.dst_port) || 80,
                protocol: flowForm.protocol || "TCP",
                flow_rate: rate,
            };

            const res = await apiFetch(endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || "Traffic anomaly scoring failed.");
            }
            setFlowAnalysis(await res.json());
        } catch (err) {
            setFlowAnalysis({ error: err.message });
        } finally {
            setFlowLoading(false);
        }
    };

    const handleAnalyze = async (e) => {
        e.preventDefault();
        if (!urlValue.trim()) return;
        setAnalysisLoading(true);
        setAnalysis(null);
        try {
            const res = await apiFetch("/api/check-url", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: urlValue.trim() }),
            });
            if (!res.ok) {
                const fallback = await res.text();
                throw new Error(fallback || "Phishing check failed.");
            }
            setAnalysis(await res.json());
        } catch (err) {
            setAnalysis({ error: err?.message ?? "Phishing check failed." });
        } finally {
            setAnalysisLoading(false);
        }
    };

    const handleCopilot = async (e) => {
        e.preventDefault();
        if (!copilotQuery.trim()) return;
        const userMsg = copilotQuery.trim();
        setCopilotHistory(h => [...h, { role: "user", text: userMsg }]);
        setCopilotQuery("");
        setCopilotLoading(true);
        try {
            const res = await apiFetch(`/api/copilot/ask?query=${encodeURIComponent(userMsg)}`, {
                method: "POST",
            });
            if (!res.ok) throw new Error("Copilot request failed");
            const data = await res.json();
            setCopilotHistory(h => [...h, { role: "bot", text: data.answer, confidence: data.confidence }]);
        } catch (err) {
            setCopilotHistory(h => [...h, { role: "bot", text: `Error: ${err.message}` }]);
        } finally {
            setCopilotLoading(false);
        }
    };

    const handleReport = async (e) => {
        e.preventDefault();
        setReportLoading(true);
        setReport(null);
        try {
            const res = await apiFetch("/api/reports/incident", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(reportForm),
            });
            if (!res.ok) throw new Error("Report generation failed");
            setReport(await res.json());
        } catch (err) {
            setReport({ error: err.message });
        } finally {
            setReportLoading(false);
        }
    };

    const exportReportMarkdown = () => {
        if (!report) return;
        const mdContent = `# AI-Powered Contextual Firewall for Traffic Anomaly Detection — Security Incident Report\n\n` +
            `**Generated:** ${new Date().toISOString()}\n` +
            `**Incident Type:** ${reportForm.incident_type}\n` +
            `**Severity:** ${reportForm.severity.toUpperCase()}\n\n` +
            `## Summary\n\`\`\`json\n${JSON.stringify(report, null, 2)}\n\`\`\`\n`;
        const blob = new Blob([mdContent], { type: "text/markdown;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `incident_report_${Date.now()}.md`;
        a.click();
    };

    const handlePanic = async () => {
        if (isViewer) {
            alert("Viewer role is read-only. Login as Admin for emergency controls.");
            return;
        }
        const confirmMsg = dryRun
            ? "Simulate emergency network isolation in DRY-RUN mode? (No hardware will be disabled)"
            : "⚠️ WARNING: This will DISABLE the host network interface. Are you sure you want to isolate the system?";
        if (!window.confirm(confirmMsg)) return;

        setPanicState({ loading: true, message: "" });
        try {
            const res = await apiFetch("/api/killswitch", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ confirm: true, dry_run: dryRun }),
            });
            const payload = await res.json();
            if (!res.ok) throw new Error(payload?.detail?.message || payload?.detail || "Killswitch failed.");
            setPanicState({
                loading: false,
                message: payload?.status === "dry_run" ? "✓ Dry-Run Simulated: Network isolation command verified." : "🔴 Killswitch Engaged: Interface disabled.",
            });
        } catch (err) {
            setPanicState({ loading: false, message: `✗ ${err?.message ?? "Killswitch failed."}` });
        }
    };

    const handleRestore = async () => {
        if (isViewer) {
            alert("Viewer role is read-only. Login as Admin for emergency controls.");
            return;
        }
        setPanicState({ loading: true, message: "" });
        try {
            const res = await apiFetch("/api/killswitch/restore", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ confirm: true, dry_run: dryRun }),
            });
            const payload = await res.json();
            if (!res.ok) throw new Error(payload?.detail?.message || payload?.detail || "Restore failed.");
            setPanicState({
                loading: false,
                message: payload?.status === "dry_run" ? "✓ Dry-Run Simulated: Interface restore verified." : "🟢 Network Interface Restored.",
            });
        } catch (err) {
            setPanicState({ loading: false, message: `✗ ${err?.message ?? "Restore failed."}` });
        }
    };

    return (
        <div className="tab-content" key="tools">
            <div className="tab-header">
                <div className="tab-header-info">
                    <div className="tab-eyebrow">🔧 Security Tools</div>
                    <h1>Analysis & Response Toolkit</h1>
                    <p className="tab-subtitle">
                        Interactive tools for URL phishing analysis, AI security copilot, incident reporting, and emergency network isolation.
                    </p>
                </div>
            </div>

            <div className="grid-2">
                {/* ─── URL Phishing Analyzer ─── */}
                <div className="panel animate-fade-up stagger-1">
                    <div className="panel-header">
                        <div>
                            <h2>URL Phishing Analyzer</h2>
                            <p className="panel-header-sub">AI-powered contextual safety check</p>
                        </div>
                    </div>
                    <form onSubmit={handleAnalyze} style={{ display: "grid", gap: 10 }}>
                        <div className="form-group">
                            <label className="form-label">Target URL</label>
                            <input
                                className="form-input"
                                type="text"
                                value={urlValue}
                                onChange={e => setUrlValue(e.target.value)}
                                placeholder="https://example.com/login"
                                required
                            />
                        </div>
                        <button className="btn btn-primary" type="submit" disabled={analysisLoading}>
                            {analysisLoading ? "Scanning…" : "🔍 Scan URL"}
                        </button>
                    </form>

                    {analysis && (
                        analysis.error ? (
                            <div className="detail-box" style={{ marginTop: 12, borderColor: "rgba(239,68,68,0.3)" }}>
                                <p className="text-danger">{analysis.error}</p>
                            </div>
                        ) : (
                            <div className="detail-box" style={{ marginTop: 12 }}>
                                <div className="detail-row">
                                    <span className="detail-key">Verdict</span>
                                    <span className={analysis.is_phishing ? "text-danger" : "text-safe"} style={{ fontWeight: 700 }}>
                                        {analysis.verdict || (analysis.is_phishing ? "Phishing Threat" : "Legitimate")}
                                    </span>
                                </div>
                                <div className="detail-row">
                                    <span className="detail-key">Probability</span>
                                    <span>{analysis.final_risk_score ? `${(analysis.final_risk_score * 100).toFixed(1)}%` : (analysis.probability ? `${(analysis.probability * 100).toFixed(1)}%` : "—")}</span>
                                </div>
                                {analysis.ssl_info && (
                                    <>
                                        <div className="detail-row">
                                            <span className="detail-key">SSL / TLS Validation</span>
                                            <span className={analysis.ssl_info.is_valid ? "text-safe" : "text-danger"} style={{ fontWeight: 600 }}>
                                                {analysis.ssl_info.has_ssl
                                                    ? (analysis.ssl_info.is_valid ? `✓ Valid TLS (${analysis.ssl_info.issuer || "Trusted CA"})` : "✗ Invalid / Expired SSL")
                                                    : "⚠️ Plaintext HTTP (No TLS)"}
                                            </span>
                                        </div>
                                        <div className="detail-row">
                                            <span className="detail-key">Domain Age Profile</span>
                                            <span style={{ fontSize: "0.82rem" }}>{analysis.ssl_info.domain_age_heuristic || "Normal"}</span>
                                        </div>
                                    </>
                                )}
                                {analysis.signals && (
                                    <div className="detail-row" style={{ alignItems: "flex-start" }}>
                                        <span className="detail-key">Detected Signals</span>
                                        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                                            {analysis.signals.map((sig, idx) => (
                                                <span key={idx} className="badge badge-warning" style={{ fontSize: "0.72rem" }}>⚠️ {sig}</span>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )
                    )}
                </div>

                {/* ─── Security Copilot ─── */}
                <div className="panel animate-fade-up stagger-2" style={{ display: "flex", flexDirection: "column" }}>
                    <div className="panel-header">
                        <div>
                            <h2>AI Security Copilot</h2>
                            <p className="panel-header-sub">Ask questions about telemetry, decisions, and threats</p>
                        </div>
                    </div>
                    <div style={{ flex: 1, minHeight: 180, maxHeight: 260, overflowY: "auto", border: "1px solid var(--border-color)", borderRadius: "var(--radius-sm)", padding: 12, marginBottom: 12, background: "var(--bg-surface)" }}>
                        {copilotHistory.length === 0 ? (
                            <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", textAlign: "center", marginTop: 40 }}>
                                Ask questions like: "Why was 192.168.1.105 blocked?" or "List critical alerts"
                            </p>
                        ) : (
                            copilotHistory.map((msg, i) => (
                                <div key={i} style={{ marginBottom: 10, textAlign: msg.role === "user" ? "right" : "left" }}>
                                    <span style={{
                                        display: "inline-block",
                                        padding: "6px 12px",
                                        borderRadius: 8,
                                        fontSize: "0.82rem",
                                        background: msg.role === "user" ? "rgba(239,68,68,0.2)" : "var(--bg-card)",
                                        border: "1px solid var(--border-color)",
                                        maxWidth: "85%",
                                        whiteSpace: "pre-wrap",
                                    }}>
                                        {msg.text}
                                    </span>
                                </div>
                            ))
                        )}
                    </div>
                    <form onSubmit={handleCopilot} style={{ display: "flex", gap: 8 }}>
                        <input
                            className="form-input"
                            type="text"
                            value={copilotQuery}
                            onChange={e => setCopilotQuery(e.target.value)}
                            placeholder="Query the copilot…"
                            style={{ flex: 1 }}
                        />
                        <button className="btn btn-primary" type="submit" disabled={copilotLoading}>
                            {copilotLoading ? "…" : "Ask"}
                        </button>
                    </form>
                </div>
            </div>

            {/* ─── Second Row: File Payload Inspector & Isolation Forest Flow Anomaly Scorer ─── */}
            <div className="grid-2" style={{ marginTop: 24 }}>
                {/* ─── Ransomware & Download Payload Inspector ─── */}
                <div className="panel animate-fade-up stagger-2">
                    <div className="panel-header">
                        <div>
                            <h2>Ransomware & File Payload Inspector</h2>
                            <p className="panel-header-sub">Static heuristics, Shannon byte entropy, PE headers & double extensions</p>
                        </div>
                    </div>
                    <form onSubmit={handleFileInspect} style={{ display: "grid", gap: 12 }}>
                        <div className="form-group">
                            <label className="form-label">Select File to Inspect (EXE, DLL, PDF, ZIP, Script)</label>
                            <input
                                className="form-input"
                                type="file"
                                onChange={e => setFileObj(e.target.files[0] || null)}
                                required
                            />
                        </div>
                        <button className="btn btn-primary" type="submit" disabled={fileLoading || !fileObj}>
                            {fileLoading ? "Analyzing File…" : "🛡️ Inspect File Payload"}
                        </button>
                    </form>

                    {fileAnalysis && (
                        fileAnalysis.error ? (
                            <div className="detail-box" style={{ marginTop: 12, borderColor: "rgba(239,68,68,0.3)" }}>
                                <p className="text-danger">{fileAnalysis.error}</p>
                            </div>
                        ) : (
                            <div className="detail-box" style={{ marginTop: 12 }}>
                                <div className="detail-row">
                                    <span className="detail-key">Target File</span>
                                    <span style={{ fontWeight: 600 }}>{fileAnalysis.filename} ({fileAnalysis.file_size} bytes)</span>
                                </div>
                                <div className="detail-row">
                                    <span className="detail-key">Verdict</span>
                                    <span className={fileAnalysis.is_malicious ? "badge badge-critical" : "badge badge-safe"} style={{ fontSize: "0.85rem" }}>
                                        {fileAnalysis.threat_classification}
                                    </span>
                                </div>
                                <div className="detail-row">
                                    <span className="detail-key">Action Recommendation</span>
                                    <span style={{ fontWeight: 700, color: fileAnalysis.is_malicious ? "var(--danger)" : "var(--safe)" }}>
                                        {fileAnalysis.recommendation}
                                    </span>
                                </div>
                                <div className="detail-row">
                                    <span className="detail-key">Shannon Byte Entropy</span>
                                    <div>
                                        <span style={{ fontWeight: 600 }}>{fileAnalysis.entropy} / 8.0</span>
                                        <div style={{ width: 140, height: 6, background: "rgba(255,255,255,0.1)", borderRadius: 3, marginTop: 4, overflow: "hidden" }}>
                                            <div style={{
                                                width: `${(fileAnalysis.entropy / 8.0) * 100}%`,
                                                height: "100%",
                                                background: fileAnalysis.entropy > 7.0 ? "#ef4444" : fileAnalysis.entropy > 5.5 ? "#f59e0b" : "#22c55e"
                                            }} />
                                        </div>
                                    </div>
                                </div>
                                <div className="detail-row">
                                    <span className="detail-key">Risk Score</span>
                                    <span className="table-mono">{(fileAnalysis.risk_score * 100).toFixed(1)}%</span>
                                </div>
                                {fileAnalysis.signals && fileAnalysis.signals.length > 0 && (
                                    <div className="detail-row" style={{ alignItems: "flex-start" }}>
                                        <span className="detail-key">Heuristic Signals</span>
                                        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                                            {fileAnalysis.signals.map((sig, idx) => (
                                                <span key={idx} className="badge badge-warning" style={{ fontSize: "0.75rem" }}>⚠️ {sig}</span>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                {fileAnalysis.quarantine_enforced && (
                                    <div className="detail-row" style={{ background: "rgba(239,68,68,0.15)", borderRadius: 6, padding: "6px 8px", border: "1px solid rgba(239,68,68,0.3)" }}>
                                        <span className="detail-key" style={{ color: "var(--danger)", fontWeight: 700 }}>Automated Quarantine</span>
                                        <span className="badge badge-critical">🚨 ENFORCED: {fileAnalysis.quarantine_rule_name}</span>
                                    </div>
                                )}
                                <div className="detail-row">
                                    <span className="detail-key">SHA-256</span>
                                    <span className="table-mono" style={{ fontSize: "0.72rem", wordBreak: "break-all" }}>{fileAnalysis.sha256}</span>
                                </div>
                            </div>
                        )
                    )}
                </div>

                {/* ─── Traffic Flow Anomaly Scorer (Isolation Forest & PyTorch LSTM) ─── */}
                <div className="panel animate-fade-up stagger-3">
                    <div className="panel-header">
                        <div>
                            <h2>{flowForm.model_type === "lstm" ? "PyTorch LSTM Flow Sequence Scorer" : "Isolation Forest Flow Anomaly Scorer"}</h2>
                            <p className="panel-header-sub">
                                {flowForm.model_type === "lstm"
                                    ? "Deep recurrent neural network evaluating temporal packet sequences"
                                    : "Multi-variate flow outlier detection & continuous scoring"}
                            </p>
                        </div>
                    </div>
                    <form onSubmit={handleFlowScore} style={{ display: "grid", gap: 10 }}>
                        <div className="form-group">
                            <label className="form-label">AI Anomaly Architecture</label>
                            <select
                                className="form-select"
                                value={flowForm.model_type}
                                onChange={e => setFlowForm({ ...flowForm, model_type: e.target.value })}
                            >
                                <option value="isolation_forest">Isolation Forest (Unsupervised Multi-variate Outlier)</option>
                                <option value="lstm">Deep PyTorch LSTM (Recurrent Temporal Sequence Network)</option>
                            </select>
                        </div>
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                            <div className="form-group">
                                <label className="form-label">Packet Size (Bytes)</label>
                                <input
                                    className="form-input"
                                    type="number"
                                    value={flowForm.packet_size}
                                    onChange={e => setFlowForm({ ...flowForm, packet_size: e.target.value })}
                                    placeholder="1420"
                                />
                            </div>
                            <div className="form-group">
                                <label className="form-label">{flowForm.model_type === "lstm" ? "Flow Rate (pps)" : "Dst Port"}</label>
                                <input
                                    className="form-input"
                                    type="number"
                                    value={flowForm.model_type === "lstm" ? flowForm.flow_rate : flowForm.dst_port}
                                    onChange={e => flowForm.model_type === "lstm" ? setFlowForm({ ...flowForm, flow_rate: e.target.value }) : setFlowForm({ ...flowForm, dst_port: e.target.value })}
                                    placeholder={flowForm.model_type === "lstm" ? "15" : "80"}
                                />
                            </div>
                        </div>
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
                            <div className="form-group">
                                <label className="form-label">Src Port</label>
                                <input
                                    className="form-input"
                                    type="number"
                                    value={flowForm.src_port}
                                    onChange={e => setFlowForm({ ...flowForm, src_port: e.target.value })}
                                    placeholder="54321"
                                />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Protocol</label>
                                <select
                                    className="form-select"
                                    value={flowForm.protocol}
                                    onChange={e => setFlowForm({ ...flowForm, protocol: e.target.value })}
                                >
                                    <option value="TCP">TCP</option>
                                    <option value="UDP">UDP</option>
                                    <option value="ICMP">ICMP</option>
                                </select>
                            </div>
                            <div className="form-group">
                                <label className="form-label">Burst Rate (pps)</label>
                                <input
                                    className="form-input"
                                    type="number"
                                    value={flowForm.flow_rate}
                                    onChange={e => setFlowForm({ ...flowForm, flow_rate: e.target.value })}
                                    placeholder="15"
                                />
                            </div>
                        </div>
                        <button className="btn btn-primary" type="submit" disabled={flowLoading}>
                            {flowLoading
                                ? "Evaluating Flow…"
                                : (flowForm.model_type === "lstm"
                                    ? "🧠 Score Sequence with PyTorch LSTM"
                                    : "⚡ Score Flow with Isolation Forest")}
                        </button>
                    </form>

                    {flowAnalysis && (
                        flowAnalysis.error ? (
                            <div className="detail-box" style={{ marginTop: 12, borderColor: "rgba(239,68,68,0.3)" }}>
                                <p className="text-danger">{flowAnalysis.error}</p>
                            </div>
                        ) : (
                            <div className="detail-box" style={{ marginTop: 12 }}>
                                <div className="detail-row">
                                    <span className="detail-key">Engine Model</span>
                                    <span style={{ fontWeight: 600 }}>{flowAnalysis.model}</span>
                                </div>
                                <div className="detail-row">
                                    <span className="detail-key">Classification</span>
                                    <span className={flowAnalysis.is_anomaly ? "badge badge-critical" : "badge badge-safe"} style={{ fontSize: "0.85rem" }}>
                                        {flowAnalysis.classification}
                                    </span>
                                </div>
                                <div className="detail-row">
                                    <span className="detail-key">Anomaly Probability</span>
                                    <div>
                                        {(() => {
                                            const scoreVal = flowAnalysis.anomaly_score ?? flowAnalysis.anomaly_probability ?? 0.0;
                                            return (
                                                <>
                                                    <span className="table-mono" style={{ fontWeight: 700 }}>
                                                        {(scoreVal * 100).toFixed(1)}% ({scoreVal})
                                                    </span>
                                                    <div style={{ width: 140, height: 6, background: "rgba(255,255,255,0.1)", borderRadius: 3, marginTop: 4, overflow: "hidden" }}>
                                                        <div style={{
                                                            width: `${scoreVal * 100}%`,
                                                            height: "100%",
                                                            background: scoreVal >= 0.65 ? "#ef4444" : scoreVal >= 0.4 ? "#f59e0b" : "#22c55e"
                                                        }} />
                                                    </div>
                                                </>
                                            );
                                        })()}
                                    </div>
                                </div>
                                {flowAnalysis.raw_decision_score !== undefined && (
                                    <div className="detail-row">
                                        <span className="detail-key">Raw Decision Score</span>
                                        <span className="table-mono">{flowAnalysis.raw_decision_score}</span>
                                    </div>
                                )}
                                {flowAnalysis.signals && flowAnalysis.signals.length > 0 && (
                                    <div className="detail-row" style={{ alignItems: "flex-start" }}>
                                        <span className="detail-key">Diagnostic Signals</span>
                                        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                                            {flowAnalysis.signals.map((sig, idx) => (
                                                <span key={idx} className="badge badge-warning" style={{ fontSize: "0.75rem" }}>⚡ {sig}</span>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )
                    )}
                </div>
            </div>

            {/* ─── Incident Report Generator & Compliance Audit ─── */}
            <div className="panel animate-fade-up stagger-3" style={{ marginTop: 24 }}>
                <div className="panel-header">
                    <div>
                        <h2>Automated Incident Reporting & Compliance Audit</h2>
                        <p className="panel-header-sub">Forensic audit summaries with ISO 27001, NIST CSF 2.0 & UN SDG-9 mapping</p>
                    </div>
                    {report && !report.error && (
                        <div style={{ display: "flex", gap: 8 }}>
                            <button className="btn" onClick={exportReportMarkdown}>📥 Export Markdown</button>
                            <button className="btn" onClick={() => window.print()}>🖨️ Print / PDF</button>
                        </div>
                    )}
                </div>
                <form onSubmit={handleReport} className="form-inline" style={{ marginBottom: 16 }}>
                    <div className="form-group">
                        <label className="form-label">Incident Type</label>
                        <select className="form-select" value={reportForm.incident_type} onChange={e => setReportForm({ ...reportForm, incident_type: e.target.value })}>
                            <option value="malware">Malware</option>
                            <option value="ddos">DDoS</option>
                            <option value="phishing">Phishing</option>
                            <option value="data_breach">Data Breach</option>
                            <option value="ransomware">Ransomware</option>
                            <option value="port_scan">Port Scan</option>
                        </select>
                    </div>
                    <div className="form-group">
                        <label className="form-label">Severity</label>
                        <select className="form-select" value={reportForm.severity} onChange={e => setReportForm({ ...reportForm, severity: e.target.value })}>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                        </select>
                    </div>
                    <div className="form-group" style={{ maxWidth: 120 }}>
                        <label className="form-label">Days</label>
                        <input className="form-input" type="number" min="1" max="30" value={reportForm.days} onChange={e => setReportForm({ ...reportForm, days: parseInt(e.target.value) || 1 })} />
                    </div>
                    <button className="btn btn-primary" type="submit" disabled={reportLoading} style={{ marginTop: "auto" }}>
                        {reportLoading ? "Generating…" : "📄 Generate Report"}
                    </button>
                </form>

                {report && (
                    report.error ? (
                        <div className="detail-box" style={{ borderColor: "rgba(239,68,68,0.3)" }}>
                            <p className="text-danger">{report.error}</p>
                        </div>
                    ) : (
                        <>
                            {report.compliance_audit && (
                                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 14 }}>
                                    <div className="detail-box">
                                        <div style={{ fontWeight: 700, color: "var(--accent-primary)", marginBottom: 6, fontSize: "0.85rem" }}>
                                            🏛️ ISO 27001:2022 & NIST CSF Controls
                                        </div>
                                        {Object.entries(report.compliance_audit.iso_27001_mapping || {}).map(([ctrl, desc]) => (
                                            <div key={ctrl} className="detail-row" style={{ fontSize: "0.78rem" }}>
                                                <span className="detail-key">{ctrl}</span>
                                                <span className="text-safe" style={{ fontWeight: 600 }}>{desc}</span>
                                            </div>
                                        ))}
                                    </div>
                                    <div className="detail-box">
                                        <div style={{ fontWeight: 700, color: "var(--accent-safe)", marginBottom: 6, fontSize: "0.85rem" }}>
                                            🌱 UN SDG-9 Infrastructure Resilience
                                        </div>
                                        <div className="detail-row">
                                            <span className="detail-key">Target 9.1</span>
                                            <span>Reliable & Resilient Infrastructure</span>
                                        </div>
                                        <div className="detail-row">
                                            <span className="detail-key">Resilience Score</span>
                                            <span className="badge badge-safe">{report.compliance_audit.sdg_9_alignment?.infrastructure_resilience_rating}</span>
                                        </div>
                                        <div className="detail-row">
                                            <span className="detail-key">Audit Verdict</span>
                                            <span className="text-safe" style={{ fontWeight: 700 }}>{report.compliance_audit.sdg_9_alignment?.audit_verdict}</span>
                                        </div>
                                    </div>
                                </div>
                            )}
                            <pre className="code-block">{JSON.stringify(report, null, 2)}</pre>
                        </>
                    )
                )}
            </div>

            {/* ─── Port Scanner & Vulnerability Assessment ─── */}
            <div className="panel animate-fade-up stagger-3" style={{ gridColumn: "1 / -1", marginTop: 8 }}>
                <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
                    <div>
                        <h2>📡 Defensive Port Scanner & Vulnerability Assessment</h2>
                        <p className="panel-header-sub">
                            Active TCP service discovery, banner interrogation, and automated CVE vulnerability correlation
                        </p>
                    </div>
                    <span className="badge badge-info" style={{ alignSelf: "center" }}>Enterprise Auditor</span>
                </div>

                <form onSubmit={handlePortScan} style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12, marginTop: 12 }}>
                    <div className="form-group">
                        <label className="form-label">Target Host or IP</label>
                        <input
                            className="form-input"
                            type="text"
                            value={scanTarget}
                            onChange={(e) => setScanTarget(e.target.value)}
                            placeholder="127.0.0.1 or hostname"
                            required
                        />
                    </div>

                    <div className="form-group">
                        <label className="form-label">Port Profile</label>
                        <select
                            className="form-select"
                            value={scanProfile}
                            onChange={(e) => setScanProfile(e.target.value)}
                        >
                            <option value="top20">Top 20 Critical Ports</option>
                            <option value="top100">Top 100 Extended Ports</option>
                            <option value="custom">Custom Ports / Range</option>
                        </select>
                    </div>

                    {scanProfile === "custom" && (
                        <div className="form-group">
                            <label className="form-label">Port Range / List</label>
                            <input
                                className="form-input"
                                type="text"
                                value={customPorts}
                                onChange={(e) => setCustomPorts(e.target.value)}
                                placeholder="80,443,8000-8080"
                                required
                            />
                        </div>
                    )}

                    <div className="form-group">
                        <label className="form-label">Audit Engine</label>
                        <select
                            className="form-select"
                            value={scanMode}
                            onChange={(e) => setScanMode(e.target.value)}
                        >
                            <option value="vuln">🔍 Port Discovery + CVE Vulnerability Audit</option>
                            <option value="ports">⚡ Rapid Port Discovery Only</option>
                        </select>
                    </div>

                    <div className="form-group" style={{ display: "flex", alignItems: "flex-end" }}>
                        <button
                            className="btn btn-primary"
                            type="submit"
                            disabled={scanLoading}
                            style={{ width: "100%", height: 38 }}
                        >
                            {scanLoading ? "Scanning Target…" : "🚀 Launch Scan"}
                        </button>
                    </div>
                </form>

                {remediationMsg && (
                    <div className="detail-box" style={{ marginTop: 12, borderColor: remediationMsg.startsWith("✓") ? "rgba(34,197,94,0.4)" : "rgba(239,68,68,0.4)" }}>
                        <span style={{ color: remediationMsg.startsWith("✓") ? "#22c55e" : "#ef4444", fontWeight: 600 }}>
                            {remediationMsg}
                        </span>
                    </div>
                )}

                {scanResult && (
                    scanResult.error ? (
                        <div className="detail-box" style={{ marginTop: 14, borderColor: "rgba(239,68,68,0.3)" }}>
                            <p className="text-danger">❌ {scanResult.error}</p>
                        </div>
                    ) : (
                        <div style={{ marginTop: 20 }}>
                            {/* Summary Metrics Bar */}
                            <div className="metrics-strip" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 10, marginBottom: 16 }}>
                                <div className="metric-card" style={{ padding: 12, background: "rgba(255,255,255,0.03)", borderRadius: 8, border: "1px solid var(--border)" }}>
                                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Target Resolved</div>
                                    <div style={{ fontSize: "1.05rem", fontWeight: 700, color: "var(--text-primary)" }}>{scanResult.resolved_ip || scanResult.target}</div>
                                </div>
                                <div className="metric-card" style={{ padding: 12, background: "rgba(255,255,255,0.03)", borderRadius: 8, border: "1px solid var(--border)" }}>
                                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Ports Scanned</div>
                                    <div style={{ fontSize: "1.05rem", fontWeight: 700, color: "var(--text-primary)" }}>{scanResult.ports_scanned_count}</div>
                                </div>
                                <div className="metric-card" style={{ padding: 12, background: "rgba(255,255,255,0.03)", borderRadius: 8, border: "1px solid var(--border)" }}>
                                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Open Ports</div>
                                    <div style={{ fontSize: "1.05rem", fontWeight: 700, color: scanResult.open_ports_count > 0 ? "var(--accent)" : "var(--safe)" }}>{scanResult.open_ports_count}</div>
                                </div>
                                <div className="metric-card" style={{ padding: 12, background: "rgba(255,255,255,0.03)", borderRadius: 8, border: "1px solid var(--border)" }}>
                                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Duration</div>
                                    <div style={{ fontSize: "1.05rem", fontWeight: 700, color: "var(--text-primary)" }}>{scanResult.scan_duration_seconds}s</div>
                                </div>
                                {scanResult.vulnerability_assessment && (
                                    <>
                                        <div className="metric-card" style={{ padding: 12, background: "rgba(255,255,255,0.03)", borderRadius: 8, border: "1px solid var(--border)" }}>
                                            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Risk Rating</div>
                                            <div style={{
                                                fontSize: "1.05rem",
                                                fontWeight: 800,
                                                color: scanResult.vulnerability_assessment.overall_risk === "CRITICAL" ? "#ef4444" :
                                                    scanResult.vulnerability_assessment.overall_risk === "HIGH" ? "#f97316" :
                                                    scanResult.vulnerability_assessment.overall_risk === "MEDIUM" ? "#eab308" : "#22c55e"
                                            }}>
                                                {scanResult.vulnerability_assessment.overall_risk}
                                            </div>
                                        </div>
                                        <div className="metric-card" style={{ padding: 12, background: "rgba(255,255,255,0.03)", borderRadius: 8, border: "1px solid var(--border)" }}>
                                            <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>CVSS Risk Score</div>
                                            <div style={{ fontSize: "1.05rem", fontWeight: 800, color: "var(--accent)" }}>
                                                {scanResult.vulnerability_assessment.composite_risk_score} / 10.0
                                            </div>
                                        </div>
                                    </>
                                )}
                            </div>

                            {/* Discovered Open Ports Table */}
                            <div style={{ marginTop: 16 }}>
                                <h3 style={{ fontSize: "0.95rem", marginBottom: 8, color: "var(--text-primary)" }}>
                                    Discovered Services ({scanResult.open_ports?.length || 0})
                                </h3>
                                {scanResult.open_ports?.length === 0 ? (
                                    <div className="detail-box" style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
                                        No open ports discovered in target scan profile.
                                    </div>
                                ) : (
                                    <div style={{ overflowX: "auto" }}>
                                        <table className="data-table" style={{ width: "100%", fontSize: "0.82rem" }}>
                                            <thead>
                                                <tr>
                                                    <th>Port</th>
                                                    <th>Identified Service</th>
                                                    <th>Status</th>
                                                    <th>Latency</th>
                                                    <th>Captured Banner</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {scanResult.open_ports.map((p, idx) => (
                                                    <tr key={idx}>
                                                        <td style={{ fontWeight: 700, color: "var(--accent)" }}>{p.port} / TCP</td>
                                                        <td>{p.service}</td>
                                                        <td><span className="badge badge-safe">OPEN</span></td>
                                                        <td>{p.latency_ms} ms</td>
                                                        <td style={{ fontFamily: "monospace", maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                                            {p.banner || "—"}
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                )}
                            </div>

                            {/* Vulnerability Findings Section */}
                            {scanResult.vulnerability_assessment && (
                                <div style={{ marginTop: 24 }}>
                                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                                        <h3 style={{ fontSize: "0.95rem", color: "var(--text-primary)" }}>
                                            Vulnerability Findings ({scanResult.vulnerability_assessment.vulnerabilities?.length || 0})
                                        </h3>
                                        <div style={{ display: "flex", gap: 6 }}>
                                            {Object.entries(scanResult.vulnerability_assessment.severity_breakdown || {}).map(([sev, count]) => count > 0 && (
                                                <span key={sev} className={`badge ${sev === 'critical' ? 'badge-danger' : sev === 'high' ? 'badge-warning' : 'badge-info'}`} style={{ textTransform: "uppercase" }}>
                                                    {sev}: {count}
                                                </span>
                                            ))}
                                        </div>
                                    </div>

                                    {scanResult.vulnerability_assessment.vulnerabilities?.length === 0 ? (
                                        <div className="detail-box" style={{ borderColor: "rgba(34,197,94,0.3)", color: "var(--safe)" }}>
                                            ✓ No known security vulnerabilities or risky exposures detected on scanned ports.
                                        </div>
                                    ) : (
                                        <div style={{ display: "grid", gap: 12 }}>
                                            {scanResult.vulnerability_assessment.vulnerabilities.map((vuln, vIdx) => (
                                                <div key={vIdx} className="detail-box" style={{
                                                    borderColor: vuln.severity === "critical" ? "rgba(239,68,68,0.5)" :
                                                        vuln.severity === "high" ? "rgba(249,115,22,0.4)" : "rgba(234,179,8,0.3)",
                                                    padding: 14,
                                                }}>
                                                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 8 }}>
                                                        <div>
                                                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                                                <span className={`badge ${vuln.severity === 'critical' ? 'badge-danger' : vuln.severity === 'high' ? 'badge-warning' : 'badge-info'}`} style={{ textTransform: "uppercase" }}>
                                                                    {vuln.severity}
                                                                </span>
                                                                <strong style={{ fontSize: "0.92rem", color: "var(--text-primary)" }}>{vuln.title}</strong>
                                                            </div>
                                                            <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginTop: 4 }}>
                                                                Port: <span style={{ color: "var(--accent)" }}>{vuln.port}</span> | {vuln.service} {vuln.cve_id ? `| CVE: ${vuln.cve_id}` : ""} {vuln.cwe_id ? `| CWE: ${vuln.cwe_id}` : ""} | CVSS: <strong>{vuln.cvss_score}</strong>
                                                            </div>
                                                        </div>

                                                        {/* 1-Click Remediation Button */}
                                                        <button
                                                            className="btn btn-sm"
                                                            type="button"
                                                            onClick={() => handleApplyRemediationRule({
                                                                name: `Block Port ${vuln.port} (${vuln.vulnerability_id})`,
                                                                action: "drop",
                                                                dst_port: vuln.port,
                                                                protocol: "TCP",
                                                                priority: vuln.severity === "critical" ? 10 : 20,
                                                                description: `Auto-mitigation for ${vuln.title}`,
                                                            })}
                                                            disabled={remediatingPort === vuln.port || isViewer}
                                                            style={{
                                                                borderColor: "rgba(239,68,68,0.4)",
                                                                color: "#ef4444",
                                                                fontSize: "0.78rem",
                                                                padding: "4px 10px",
                                                            }}
                                                        >
                                                            {remediatingPort === vuln.port ? "Applying…" : `🛡️ Deploy Firewall Block (Port ${vuln.port})`}
                                                        </button>
                                                    </div>

                                                    <p style={{ fontSize: "0.82rem", color: "var(--text-secondary)", marginTop: 8, lineHeight: 1.45 }}>
                                                        {vuln.description}
                                                    </p>

                                                    <div style={{ marginTop: 8, background: "rgba(0,0,0,0.2)", padding: "6px 10px", borderRadius: 4, fontSize: "0.78rem", color: "var(--text-muted)" }}>
                                                        <strong style={{ color: "var(--text-primary)" }}>Remediation:</strong> {vuln.remediation}
                                                    </div>

                                                    {vuln.compliance_tags?.length > 0 && (
                                                        <div style={{ marginTop: 8, display: "flex", gap: 6, flexWrap: "wrap" }}>
                                                            {vuln.compliance_tags.map((tag, tIdx) => (
                                                                <span key={tIdx} style={{ fontSize: "0.7rem", padding: "2px 6px", background: "rgba(255,255,255,0.06)", borderRadius: 4, color: "var(--text-muted)" }}>
                                                                    {tag}
                                                                </span>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    )}

                                    {/* Compliance Tags Impacted */}
                                    {scanResult.vulnerability_assessment.compliance_frameworks_impacted?.length > 0 && (
                                        <div style={{ marginTop: 14, fontSize: "0.78rem", color: "var(--text-muted)" }}>
                                            <strong>Impacted Compliance Benchmarks:</strong> {scanResult.vulnerability_assessment.compliance_frameworks_impacted.join(", ")}
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    )
                )}
            </div>

            {/* ─── Emergency Kill Switch ─── */}
            <div className="panic-panel animate-fade-up stagger-4" style={{ marginTop: 24 }}>
                <div className="panic-info">
                    <div className="card-label" style={{ color: "var(--accent)" }}>⚠️ Emergency Control & Containment</div>
                    <h2>Host Isolation Killswitch</h2>
                    <p>Enforce network adapter deactivation on the host machine to contain critical lateral spread.</p>
                    <label style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: "0.82rem", marginTop: 8, cursor: "pointer", color: "var(--text-primary)" }}>
                        <input
                            type="checkbox"
                            checked={dryRun}
                            onChange={(e) => setDryRun(e.target.checked)}
                        />
                        <span>Dry-Run Simulation Mode (Safely test containment without cutting host connectivity)</span>
                    </label>
                </div>
                <div className="panic-actions" style={{ display: "flex", gap: 10, alignItems: "center" }}>
                    <button className="btn-panic" type="button" onClick={handlePanic} disabled={panicState.loading || isViewer}>
                        {panicState.loading ? "Executing…" : (dryRun ? "🧪 Test Killswitch" : "🔴 Disconnect Host")}
                    </button>
                    <button
                        className="btn"
                        type="button"
                        onClick={handleRestore}
                        disabled={panicState.loading || isViewer}
                        style={{ height: "48px", borderColor: "rgba(34,197,94,0.4)", color: "#22c55e" }}
                    >
                        🟢 Restore Network
                    </button>
                    {panicState.message && <span className="panic-message" style={{ display: "block", marginTop: 8 }}>{panicState.message}</span>}
                </div>
            </div>
        </div>
    );
}
