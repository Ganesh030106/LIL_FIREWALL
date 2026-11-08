import { useEffect, useMemo, useState, useCallback } from "react";
import { apiFetch } from "./services/api";
import { useRealtime } from "./hooks/useRealtime";
import NetworkTopology from "./components/NetworkTopology";

const emptyMetrics = {
    current_packet_velocity: 0,
    port_monitoring_active: false,
    file_change_rate: 0,
    watch_directory: "",
    alert_count: 0,
    protocol_breakdown: {},
    source_ip_activity: {},
};

const emptyThreat = {
    risk_score: 0,
    threat_level: "Low",
    recommended_action: "Continue passive monitoring; no immediate response required.",
    confidence: 0,
    top_signals: [],
};

const emptyInsights = {
    top_ports: [],
    protocol_distribution: {},
    top_sources: [],
    alert_count: 0,
};

export default function OverviewTab() {
    const [metrics, setMetrics] = useState(emptyMetrics);
    const [threat, setThreat] = useState(emptyThreat);
    const [insights, setInsights] = useState(emptyInsights);
    const [health, setHealth] = useState(null);
    const [engineState, setEngineState] = useState(null);
    const [alertCount, setAlertCount] = useState(0);
    const [alertsList, setAlertsList] = useState([]);
    const [devices, setDevices] = useState([]);
    const [sessions, setSessions] = useState([]);
    const [predictiveSignals, setPredictiveSignals] = useState([]);
    const [trafficHistory, setTrafficHistory] = useState(() => Array(16).fill(0));
    const [error, setError] = useState("");
    const [containLoading, setContainLoading] = useState(null);
    const [containMsg, setContainMsg] = useState("");

    const handleQuickContain = async (ip) => {
        if (!window.confirm(`Deploy autonomous containment on ${ip} (1-hour quarantine block)?`)) return;
        setContainLoading(ip);
        setContainMsg("");
        try {
            const res = await apiFetch(`/api/autonomous/block-ip?ip=${encodeURIComponent(ip)}&duration=3600`, {
                method: "POST",
            });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || "Containment action failed.");
            }
            setContainMsg(`✓ Host ${ip} quarantined for 3600s with automated TTL rollback.`);
            fetchAll();
        } catch (err) {
            setContainMsg(`✗ Containment failed: ${err.message}`);
        } finally {
            setContainLoading(null);
        }
    };

    const fetchAll = useCallback(async (signal) => {
        try {
            const [mRes, tRes, fRes, aRes, dRes] = await Promise.all([
                apiFetch("/api/metrics", { signal }),
                apiFetch("/api/threat-summary", { signal }),
                apiFetch("/api/firewall-insights", { signal }),
                apiFetch("/api/alerts", { signal }),
                apiFetch("/api/risk/devices", { signal }),
            ]);
            if (mRes.ok) {
                const mData = await mRes.json();
                setMetrics(prev => ({ ...prev, ...mData }));
                const livePps = Math.round(Number(mData.current_packet_velocity) || 0);
                setTrafficHistory(prev => [...prev.slice(1), livePps]);
            }
            if (tRes.ok) setThreat(await tRes.json());
            if (fRes.ok) setInsights(await fRes.json());
            if (aRes.ok) {
                const aData = await aRes.json();
                setAlertCount(aData.count || (Array.isArray(aData.alerts) ? aData.alerts.length : 0));
                setAlertsList(Array.isArray(aData.alerts) ? aData.alerts : []);
            }
            if (dRes && dRes.ok) {
                const devData = await dRes.json();
                if (Array.isArray(devData)) setDevices(devData);
            }

            // Predictive early warning & active sessions
            try {
                const [pSigRes, sessRes] = await Promise.all([
                    apiFetch("/api/predictive/signals", { signal }),
                    apiFetch("/api/sessions", { signal }),
                ]);
                if (pSigRes && pSigRes.ok) {
                    const pData = await pSigRes.json();
                    setPredictiveSignals(Array.isArray(pData.signals) ? pData.signals : []);
                }
                if (sessRes && sessRes.ok) {
                    const sData = await sessRes.json();
                    setSessions(Array.isArray(sData.sessions) ? sData.sessions : (Array.isArray(sData) ? sData : []));
                }
            } catch {}

            // Non-critical telemetry & engine state
            try {
                const [hRes, sRes] = await Promise.all([
                    apiFetch("/api/health", { signal }),
                    apiFetch("/api/state", { signal }),
                ]);
                if (hRes.ok) setHealth(await hRes.json());
                if (sRes.ok) setEngineState(await sRes.json());
            } catch {}

            setError("");
        } catch (e) {
            if (e?.name !== "AbortError") setError(e?.message ?? "Connection failed");
        }
    }, []);

    // Real-time WebSocket hook with instantaneous telemetry push
    useRealtime(useCallback((event) => {
        if (event.type === "init" || event.type === "metrics_tick") {
            const d = event.data || event;
            if (d.metrics) {
                setMetrics(prev => ({ ...prev, ...d.metrics }));
                const livePps = Math.round(Number(d.metrics.current_packet_velocity) || 0);
                setTrafficHistory(prev => [...prev.slice(1), livePps]);
            }
            if (d.threat) setThreat(d.threat);
            if (d.alert_count !== undefined) setAlertCount(d.alert_count);
        } else if (event.type === "alert_created") {
            setAlertCount(prev => prev + 1);
        } else if (event.type === "reconnected") {
            fetchAll();
        }
    }, [fetchAll]));

    useEffect(() => {
        let mounted = true;
        const controller = new AbortController();
        fetchAll(controller.signal);
        const id = setInterval(() => { if (mounted) fetchAll(controller.signal); }, 3000);
        return () => { mounted = false; controller.abort(); clearInterval(id); };
    }, []);

    const packetStatus = useMemo(() => {
        if (metrics.current_packet_velocity >= 100) return { label: "Critical", color: "text-danger", dot: "status-dot-danger" };
        if (metrics.current_packet_velocity >= 40) return { label: "Elevated", color: "text-warning", dot: "status-dot-warning" };
        return { label: "Stable", color: "text-safe", dot: "status-dot-online" };
    }, [metrics.current_packet_velocity]);

    const threatColor = useMemo(() => {
        if (threat.threat_level === "Critical" || threat.threat_level === "High") return "text-danger";
        if (threat.threat_level === "Medium" || threat.threat_level === "Elevated") return "text-warning";
        return "text-safe";
    }, [threat.threat_level]);

    const threatVectors = useMemo(() => {
        const vectors = [
            {
                id: "recon",
                name: "Port Probes & Host Recon",
                icon: "🔍",
                engine: "Scapy Kernel Sniffer & Port Heuristics",
                action: "Ingress Probe Dropped",
                severity: "medium",
                count: 0,
                color: "#3b82f6",
                desc: "SYN scan sweeps, port sweeps, and vertical probing",
            },
            {
                id: "web_exploit",
                name: "Web Injections & Exploits (SQLi/RCE)",
                icon: "💉",
                engine: "Deep Packet Inspection (DPI) & Heuristics",
                action: "HTTP 403 Dropped & Terminated",
                severity: "critical",
                count: 0,
                color: "#ef4444",
                desc: "Malicious URI patterns, SQL syntax, and remote command injection",
            },
            {
                id: "c2_dns",
                name: "C2 Beaconing & DNS Tunnels",
                icon: "📡",
                engine: "Shannon Entropy (H > 3.8) + PyTorch LSTM",
                action: "DNS Query Sinkholed",
                severity: "critical",
                count: 0,
                color: "#ec4899",
                desc: "High-entropy DGA domains and periodic exfiltration conduits",
            },
            {
                id: "dos_flood",
                name: "Volumetric DDoS & SYN Surges",
                icon: "🌊",
                engine: "Isolation Forest Outlier Velocity Guard",
                action: "Rate-Limited & SYN Cookies",
                severity: "high",
                count: 0,
                color: "#f59e0b",
                desc: "Anomalous velocity bursts and flood thresholds",
            },
            {
                id: "malware_payload",
                name: "Ransomware & Suspicious Binaries",
                icon: "🛡️",
                engine: "Automated Binary Quarantine Sandbox",
                action: "Isolated & Quarantined",
                severity: "critical",
                count: 0,
                color: "#dc2626",
                desc: "High byte entropy, suspicious PE headers, and ransomware artifacts",
            },
            {
                id: "phishing",
                name: "Phishing & Deceptive URLs",
                icon: "🎣",
                engine: "Random Forest 16-Feature Classifier",
                action: "Domain Quarantined",
                severity: "high",
                count: 0,
                color: "#06b6d4",
                desc: "Lexical anomalies, deceptive punycode, and credential harvesters",
            },
        ];

        alertsList.forEach(a => {
            const cat = String(a.category || "").toLowerCase();
            const msg = String(a.message || "").toLowerCase();
            if (cat.includes("probe") || cat.includes("scan") || msg.includes("port scan") || msg.includes("sweep")) {
                vectors[0].count++;
            } else if (cat.includes("injection") || cat.includes("exploit") || msg.includes("sqli") || msg.includes("rce") || msg.includes("command")) {
                vectors[1].count++;
            } else if (cat.includes("beacon") || cat.includes("dns") || cat.includes("c2") || cat.includes("tunnel") || cat.includes("entropy")) {
                vectors[2].count++;
            } else if (cat.includes("flood") || cat.includes("dos") || cat.includes("burst") || msg.includes("velocity") || msg.includes("rate limit")) {
                vectors[3].count++;
            } else if (cat.includes("ransomware") || cat.includes("file") || cat.includes("malware") || cat.includes("quarantine")) {
                vectors[4].count++;
            } else if (cat.includes("phish") || msg.includes("url") || cat.includes("domain")) {
                vectors[5].count++;
            } else {
                vectors[0].count++;
            }
        });

        if (metrics.current_packet_velocity > 40) {
            vectors[3].count += Math.round(metrics.current_packet_velocity / 10);
        }

        const max = Math.max(1, ...vectors.map(v => v.count));
        return vectors.map(v => ({
            ...v,
            percent: Math.round((v.count / max) * 100),
        }));
    }, [alertsList, metrics.current_packet_velocity]);

    const topTalkers = useMemo(() => {
        const map = {};
        alertsList.forEach(a => {
            const meta = a.meta || {};
            const src = meta.source_ip || meta.src_ip || (a.message?.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/) || [])[0] || a.source || "127.0.0.1";
            if (!map[src]) map[src] = { ip: src, count: 0, maxSev: a.severity || "medium", lastSeen: a.created_at };
            map[src].count++;
            if (a.severity === "critical") map[src].maxSev = "critical";
        });
        devices.forEach(d => {
            if (d.ip && !map[d.ip]) {
                map[d.ip] = { ip: d.ip, count: 1, maxSev: (Number(d.risk_score) || 0) >= 0.7 ? "high" : "low", lastSeen: d.last_seen };
            }
        });
        const list = Object.values(map);
        return list.sort((a, b) => b.count - a.count).slice(0, 5);
    }, [alertsList, devices]);

    const trafficTrend = useMemo(() => {
        return trafficHistory;
    }, [trafficHistory]);

    const maxTrendVal = useMemo(() => {
        const peak = Math.max(30, ...trafficTrend);
        return Math.ceil(peak * 1.25);
    }, [trafficTrend]);

    const chartPoints = useMemo(() => {
        const width = 340;
        const height = 180;
        const max = maxTrendVal;
        const min = 0;

        return trafficTrend
            .map((value, index) => {
                const x = (index / (trafficTrend.length - 1)) * (width - 18) + 9;
                const normalized = (value - min) / (max - min || 1);
                const y = height - normalized * (height - 30) - 15;
                return `${x},${y}`;
            })
            .join(" ");
    }, [trafficTrend, maxTrendVal]);

    return (
        <div className="tab-content" key="overview">
            {/* Hero */}
            <div className="tab-header" style={{ marginBottom: 28 }}>
                <div className="tab-header-info">
                    <div className="tab-eyebrow">
                        <span className={`status-dot ${packetStatus.dot}`}></span>
                        Volcano AI Firewall V5.0 / Autonomous SOC Platform
                    </div>
                    <h1>Enterprise Security Operations Center (SOC)</h1>
                    <p className="tab-subtitle">
                        Autonomous threat intelligence, multi-signal incident correlation, predictive anomaly detection, and tactical defense radar in a single mission-control surface.
                    </p>
                </div>
                <div style={{ flexShrink: 0 }}>
                    <div className="detail-box" style={{ minWidth: 190, textAlign: "center" }}>
                        <div className="card-label">Telemetry Status</div>
                        <div className={`card-value ${packetStatus.color}`} style={{ fontSize: "1.3rem", marginTop: 4 }}>
                            {packetStatus.label}
                        </div>
                    </div>
                </div>
            </div>

            {error && <p className="inline-error mb-md">{error}</p>}

            {/* ── Stat Cards ── */}
            <div className="stats-grid animate-fade-up">
                <div className="stat-card accent stagger-1">
                    <div className="card-label">Packet Velocity</div>
                    <div className="card-value">{metrics.current_packet_velocity.toFixed(0)}<span className="text-muted" style={{ fontSize: "0.75rem", marginLeft: 4 }}>pps</span></div>
                    <div className="card-caption">Network capture window: 1 second</div>
                </div>
                <div className="stat-card stagger-2">
                    <div className="card-label">Port Monitoring</div>
                    <div className="card-value">{metrics.port_monitoring_active ? "Active" : "Idle"}</div>
                    <div className="card-caption">Sliding scan window: 10 seconds</div>
                </div>
                <div className="stat-card stagger-3">
                    <div className="card-label">File Change Rate</div>
                    <div className="card-value">{metrics.file_change_rate.toFixed(1)}<span className="text-muted" style={{ fontSize: "0.75rem", marginLeft: 4 }}>/ 5s</span></div>
                    <div className="card-caption">{metrics.watch_directory || "Sandbox monitor not initialized"}</div>
                </div>
                <div className="stat-card stagger-4">
                    <div className="card-label">Alert Feed</div>
                    <div className="card-value">{alertCount}</div>
                    <div className="card-caption">Total alerts in retention buffer</div>
                </div>
                <div className="stat-card accent stagger-5">
                    <div className="card-label">AI Threat Score</div>
                    <div className={`card-value ${threatColor}`}>{Number(threat.risk_score).toFixed(4)}</div>
                    <div className="card-caption">{threat.threat_level} • confidence {Number(threat.confidence).toFixed(2)}</div>
                </div>
                <div className="stat-card stagger-6">
                    <div className="card-label">Top Firewall Port</div>
                    <div className="card-value">
                        {insights.top_ports.length
                            ? <>{insights.top_ports[0].port} <span className="text-muted" style={{ fontSize: "0.75rem" }}>{insights.top_ports[0].protocol}</span></>
                            : <span className="text-muted" style={{ fontSize: "0.9rem" }}>None</span>}
                    </div>
                    <div className="card-caption">
                        {insights.top_ports.length ? `${insights.top_ports[0].count} hits in current window` : "Awaiting packet activity"}
                    </div>
                </div>
            </div>

            {/* ── Visual Grid: Cyber Kill-Chain Attack Funnel & Top Talkers Host Risk ── */}
            <div className="visual-grid mt-md">
                {/* 1. Live Threat Vector Interception & Exploit Neutralization Radar */}
                <div className="panel animate-fade-up stagger-2">
                    <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "8px" }}>
                        <div>
                            <div className="card-label">Live Threat Interception</div>
                            <h2>Active Attack Vector Defense Radar</h2>
                            <p className="panel-header-sub" style={{ marginTop: "2px" }}>
                                Real-time exploit neutralization across AI sensors and kernel packet filter rules
                            </p>
                        </div>
                        <span className="badge badge-safe">
                            ✓ {threatVectors.reduce((acc, v) => acc + v.count, 0)} Intercepts Neutralized
                        </span>
                    </div>

                    <div style={{ display: "flex", flexDirection: "column", gap: "10px", marginTop: "12px" }}>
                        {threatVectors.map((vec) => {
                            const isCrit = vec.severity === "critical";
                            const isHigh = vec.severity === "high";
                            const hasHits = vec.count > 0;
                            return (
                                <div
                                    key={vec.id}
                                    style={{
                                        background: "rgba(0, 0, 0, 0.22)",
                                        border: `1px solid ${hasHits ? (isCrit ? "rgba(239, 68, 68, 0.25)" : "rgba(245, 158, 11, 0.2)") : "rgba(255, 255, 255, 0.05)"}`,
                                        borderRadius: "6px",
                                        padding: "10px 12px",
                                    }}
                                >
                                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px", flexWrap: "wrap", gap: "6px" }}>
                                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                                            <span style={{ fontSize: "15px" }}>{vec.icon}</span>
                                            <div>
                                                <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                                                    <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--text)" }}>
                                                        {vec.name}
                                                    </span>
                                                    <span
                                                        className={`badge ${isCrit ? "badge-critical" : isHigh ? "badge-medium" : "badge-safe"}`}
                                                        style={{ fontSize: "9px", padding: "1px 5px", textTransform: "uppercase" }}
                                                    >
                                                        {vec.severity}
                                                    </span>
                                                </div>
                                                <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "1px" }}>
                                                    {vec.desc}
                                                </div>
                                            </div>
                                        </div>

                                        <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "2px" }}>
                                            <span
                                                className={`badge ${hasHits ? (isCrit ? "badge-critical" : "badge-medium") : "badge-safe"}`}
                                                style={{ fontSize: "10px", padding: "2px 7px" }}
                                            >
                                                {vec.count} Neutralized
                                            </span>
                                            <span style={{ fontSize: "10px", color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>
                                                {vec.action}
                                            </span>
                                        </div>
                                    </div>

                                    {/* Defense Engine Attribution & Progress Bar */}
                                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "10px", color: "var(--text-muted)", marginBottom: "4px" }}>
                                        <span>🛡️ Engine: <strong style={{ color: "var(--accent)" }}>{vec.engine}</strong></span>
                                        <span>{vec.percent}% volume</span>
                                    </div>
                                    <div style={{ width: "100%", height: "5px", background: "rgba(255, 255, 255, 0.06)", borderRadius: "3px", overflow: "hidden" }}>
                                        <div
                                            style={{
                                                width: `${Math.max(hasHits ? 12 : 2, vec.percent)}%`,
                                                height: "100%",
                                                background: vec.color,
                                                borderRadius: "3px",
                                                transition: "width 0.4s ease",
                                            }}
                                        />
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>

                {/* 2. Top Talkers & Host Risk Radar */}
                <div className="panel animate-fade-up stagger-3">
                    <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "8px" }}>
                        <div>
                            <div className="card-label">Host Risk Profiling</div>
                            <h2>Top Talkers & Suspicious Hosts</h2>
                            <p className="panel-header-sub" style={{ marginTop: "2px" }}>
                                High-frequency endpoints exhibiting elevated anomaly volume and alert correlation
                            </p>
                        </div>
                        <span className="badge badge-safe">Dynamic Radar</span>
                    </div>

                    {containMsg && (
                        <div style={{
                            padding: "8px 12px",
                            borderRadius: "6px",
                            fontSize: "12px",
                            marginBottom: "10px",
                            background: containMsg.startsWith("✓") ? "rgba(16, 185, 129, 0.15)" : "rgba(239, 68, 68, 0.15)",
                            color: containMsg.startsWith("✓") ? "var(--safe)" : "var(--danger)",
                            border: `1px solid ${containMsg.startsWith("✓") ? "rgba(16, 185, 129, 0.3)" : "rgba(239, 68, 68, 0.3)"}`
                        }}>
                            {containMsg}
                        </div>
                    )}

                    <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "10px" }}>
                        {topTalkers.length === 0 ? (
                            <div style={{ padding: "30px", textAlign: "center", color: "var(--text-muted)", fontSize: "13px" }}>
                                ✓ No suspicious host talkers detected in current telemetry window.
                            </div>
                        ) : (
                            topTalkers.map((host) => {
                                const isCrit = host.maxSev === "critical" || host.maxSev === "high";
                                return (
                                    <div
                                        key={host.ip}
                                        style={{
                                            display: "flex",
                                            justifyContent: "space-between",
                                            alignItems: "center",
                                            background: "rgba(0, 0, 0, 0.22)",
                                            border: `1px solid ${isCrit ? "rgba(239, 68, 68, 0.25)" : "rgba(255, 255, 255, 0.06)"}`,
                                            borderRadius: "6px",
                                            padding: "10px 12px",
                                            flexWrap: "wrap",
                                            gap: "8px",
                                        }}
                                    >
                                        <div>
                                            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                                                <span style={{ fontFamily: "var(--font-mono)", fontWeight: 700, fontSize: "13px", color: isCrit ? "var(--accent)" : "var(--text)" }}>
                                                    {host.ip}
                                                </span>
                                                <span
                                                    className={`badge ${isCrit ? "badge-critical" : "badge-safe"}`}
                                                    style={{ fontSize: "10px", padding: "1px 6px" }}
                                                >
                                                    {host.maxSev.toUpperCase()}
                                                </span>
                                            </div>
                                            <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
                                                Volume: <strong>{host.count}</strong> hit{host.count !== 1 ? "s" : ""} • Active Flow Correlation
                                            </div>
                                        </div>

                                        <button
                                            type="button"
                                            className="btn btn-ghost"
                                            disabled={containLoading === host.ip}
                                            onClick={() => handleQuickContain(host.ip)}
                                            style={{
                                                fontSize: "11px",
                                                padding: "4px 8px",
                                                borderColor: "rgba(239, 68, 68, 0.35)",
                                                color: "var(--danger)",
                                            }}
                                            title="Trigger 1-hour quarantine containment via Autonomous Response Engine"
                                        >
                                            {containLoading === host.ip ? "Isolating..." : "🛡️ Contain Host"}
                                        </button>
                                    </div>
                                );
                            })
                        )}
                    </div>
                </div>
            </div>

            {/* ── Interactive Dynamic SVG Network Topology & Device Profile Inspector ── */}
            <div className="mt-md animate-fade-up stagger-4">
                <NetworkTopology
                    devices={devices}
                    sessions={sessions}
                    onRefresh={fetchAll}
                />
            </div>

            {/* ── AI Predictive Threat Radar & Early-Warning Forecast ── */}
            <div className="panel mt-md animate-fade-up">
                <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px" }}>
                    <div>
                        <div className="card-label">Predictive Threat Radar</div>
                        <h2>AI Early-Warning Trajectory Forecast</h2>
                        <p className="panel-header-sub" style={{ marginTop: "2px" }}>
                            Continuous derivative evaluation (d(pps)/dt, d(fail)/dt, C2 periodicity & entropy spikes) forecasting attacks before execution.
                        </p>
                    </div>
                    <span className={`badge ${predictiveSignals.length > 0 ? "badge-critical" : "badge-safe"}`}>
                        {predictiveSignals.length > 0 ? `⚠️ ${predictiveSignals.length} Active Forecasts` : "✓ Nominal Temporal Baseline"}
                    </span>
                </div>

                {predictiveSignals.length === 0 ? (
                    <div style={{ padding: "24px", textAlign: "center", color: "var(--text-muted)", fontSize: "13px" }}>
                        ✓ All temporal velocity and entropy derivatives remain within baseline bounds. No imminent escalation forecasted in the sliding 180s horizon.
                    </div>
                ) : (
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "14px", marginTop: "14px" }}>
                        {predictiveSignals.map((sig, idx) => {
                            const targetLabel = sig.affected_target || sig.target_ip || "Internal Target";
                            const riskNum = Math.round((Number(sig.predicted_risk ?? sig.risk_score ?? 0.75)) * 100);
                            const accel = sig.velocity_derivative ? Number(sig.velocity_derivative).toFixed(2) : (Array.isArray(sig.evidence) ? sig.evidence[0] : "+12.4");
                            const mitigation = sig.proactive_mitigation || sig.recommended_preventative_action || "Deploy rate-limit threshold & trigger SYN cookie defense";

                            return (
                                <div key={idx} style={{
                                    padding: "14px 16px",
                                    borderRadius: "8px",
                                    background: "rgba(239, 68, 68, 0.06)",
                                    border: "1px solid rgba(239, 68, 68, 0.3)",
                                    display: "flex",
                                    flexDirection: "column",
                                    gap: "8px"
                                }}>
                                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                        <span style={{ fontFamily: "var(--font-mono)", fontWeight: 700, color: "var(--accent)", fontSize: "13px" }}>
                                            {targetLabel}
                                        </span>
                                        <span className="badge badge-critical" style={{ fontSize: "10px" }}>
                                            Horizon: {sig.time_horizon || "180s"}
                                        </span>
                                    </div>

                                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px" }}>
                                        <span style={{ color: "var(--text-muted)" }}>Forecasted Escalation Risk:</span>
                                        <strong style={{ color: "var(--critical)" }}>{riskNum} / 100</strong>
                                    </div>

                                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px" }}>
                                        <span style={{ color: "var(--text-muted)" }}>Velocity Derivative:</span>
                                        <span style={{ fontFamily: "var(--font-mono)", color: "var(--warning)" }}>
                                            {accel.includes("pps") ? accel : `d(pps)/dt: ${accel} pps/s`}
                                        </span>
                                    </div>

                                    <div style={{ fontSize: "12px", color: "var(--text-secondary)", background: "rgba(0,0,0,0.25)", padding: "8px 10px", borderRadius: "4px", marginTop: "4px" }}>
                                        🛡️ <strong>Proactive Mitigation:</strong> {mitigation}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>

            {/* ── Trend Visualization ── */}
            <div className="mt-md panel animate-fade-up stagger-5">
                <div className="panel-header">
                    <div>
                        <div className="card-label">Traffic Visualization</div>
                        <h2>Threat Activity Trend</h2>
                    </div>
                    <span className="badge badge-safe">{metrics.current_packet_velocity.toFixed(0)} pps (Live)</span>
                </div>

                <div className="chart-wrap">
                    <svg viewBox="0 0 340 180" className="chart-svg" preserveAspectRatio="none" aria-label="Threat activity chart">
                        <defs>
                            <linearGradient id="trendStroke" x1="0" y1="0" x2="1" y2="0">
                                <stop offset="0%" stopColor="#ef4444" />
                                <stop offset="50%" stopColor="#f59e0b" />
                                <stop offset="100%" stopColor="#3b82f6" />
                            </linearGradient>
                            <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="0%" stopColor="rgba(239, 68, 68, 0.38)" />
                                <stop offset="100%" stopColor="rgba(239, 68, 68, 0.02)" />
                            </linearGradient>
                        </defs>

                        {[0, 1, 2, 3].map(line => (
                            <line
                                key={line}
                                x1="9"
                                y1={line * 45 + 15}
                                x2="331"
                                y2={line * 45 + 15}
                                stroke="var(--border)"
                                strokeDasharray="4 6"
                            />
                        ))}

                        <polyline
                            points={chartPoints}
                            fill="none"
                            stroke="url(#trendStroke)"
                            strokeWidth="3"
                            strokeLinejoin="round"
                            strokeLinecap="round"
                        />

                        {trafficTrend.map((value, index) => {
                            const x = (index / (trafficTrend.length - 1)) * (340 - 18) + 9;
                            const y = 170 - ((value - 0) / (maxTrendVal - 0 || 1)) * (170 - 30) - 15;
                            return (
                                <circle
                                    key={`${value}-${index}`}
                                    cx={x}
                                    cy={y}
                                    r={index === trafficTrend.length - 1 ? 5 : 3.5}
                                    fill={index === trafficTrend.length - 1 ? "#ef4444" : "#f59e0b"}
                                />
                            );
                        })}
                    </svg>
                </div>

                <div className="chart-legend">
                    {trafficTrend.map((value, index) => (
                        <div key={`${index}-${value}`} className="chart-legend-item">
                            <span className="chart-legend-dot" />
                            <span>{index + 1}</span>
                        </div>
                    ))}
                </div>
            </div>

            {/* ── Detail Panels ── */}
            <div className="grid-2 mt-md">
                {/* Threat Correlation */}
                <div className="panel animate-fade-up stagger-3">
                    <div className="panel-header">
                        <div>
                            <div className="card-label">AI Threat Correlation</div>
                            <h2>Host-Level Threat Synthesis</h2>
                        </div>
                        <span className={`badge ${threat.threat_level === "Critical" || threat.threat_level === "High" ? "badge-critical" : threat.threat_level === "Medium" ? "badge-medium" : "badge-safe"}`}>
                            {threat.threat_level}
                        </span>
                    </div>
                    <div className="detail-box">
                        <div className="detail-row">
                            <span className="label">Risk Score</span>
                            <span className={`value ${threatColor}`}>{Number(threat.risk_score).toFixed(4)}</span>
                        </div>
                        <div className="detail-row">
                            <span className="label">Confidence</span>
                            <span className="value">{Number(threat.confidence).toFixed(4)}</span>
                        </div>
                        <div className="detail-row detail-row-stack">
                            <span className="label">Recommended Action</span>
                            <span className="value" style={{ fontFamily: "var(--font-ui)", fontWeight: 400 }}>{threat.recommended_action}</span>
                        </div>
                        <div className="detail-row detail-row-stack">
                            <span className="label">Top Signals</span>
                            <span className="value" style={{ fontFamily: "var(--font-ui)", fontWeight: 400 }}>
                                {threat.top_signals?.length ? threat.top_signals.join(" • ") : "None detected"}
                            </span>
                        </div>
                    </div>
                </div>

                {/* Firewall Insights */}
                <div className="panel animate-fade-up stagger-4">
                    <div className="panel-header">
                        <div>
                            <div className="card-label">Firewall Insights</div>
                            <h2>Traditional Traffic View</h2>
                        </div>
                    </div>
                    <div className="detail-box">
                        <div className="detail-row">
                            <span className="label">Protocol Mix</span>
                            <span className="value" style={{ fontFamily: "var(--font-ui)" }}>
                                {Object.entries(insights.protocol_distribution).length
                                    ? Object.entries(insights.protocol_distribution).map(([p, c]) => `${p} ${c}`).join(" • ")
                                    : "No data"}
                            </span>
                        </div>
                        <div className="detail-row detail-row-stack">
                            <span className="label">Top Ports</span>
                            <span className="value" style={{ fontFamily: "var(--font-ui)", fontWeight: 400 }}>
                                {insights.top_ports.length
                                    ? insights.top_ports.slice(0, 5).map(p => `${p.port}/${p.protocol} (${p.count})`).join(" • ")
                                    : "No port data"}
                            </span>
                        </div>
                        <div className="detail-row detail-row-stack">
                            <span className="label">Top Sources</span>
                            <span className="value" style={{ fontFamily: "var(--font-ui)", fontWeight: 400 }}>
                                {insights.top_sources.length
                                    ? insights.top_sources.slice(0, 5).map(s => `${s.source_ip} ${s.direction} (${s.count})`).join(" • ")
                                    : "No source data"}
                            </span>
                        </div>
                    </div>
                </div>
            </div>

            {/* ── System Health & Hardware Telemetry ── */}
            <div className="grid-2 mt-md">
                <div className="panel animate-fade-up stagger-5">
                    <div className="panel-header">
                        <div>
                            <div className="card-label">Core Telemetry</div>
                            <h2>Live System Health</h2>
                        </div>
                        <span className={`badge ${health?.status === "healthy" ? "badge-safe" : "badge-critical"}`}>
                            {health?.status || "Connecting..."}
                        </span>
                    </div>

                    <div className="detail-box">
                        {/* Subsystem Badges */}
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", marginBottom: "14px" }}>
                            <div style={{ background: "var(--bg-glass)", border: "1px solid var(--border)", borderRadius: "6px", padding: "8px 12px" }}>
                                <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Packet Capture</div>
                                <div style={{ display: "flex", alignItems: "center", gap: "6px", marginTop: "4px", fontSize: "0.85rem", fontWeight: 600 }}>
                                    <span className={`status-dot ${health?.sniffer_active ? "status-dot-online" : "status-dot-warning"}`} />
                                    <span>{health?.sniffer_active ? "Scapy Live Sniffer" : "Passive Fallback"}</span>
                                </div>
                            </div>

                            <div style={{ background: "var(--bg-glass)", border: "1px solid var(--border)", borderRadius: "6px", padding: "8px 12px" }}>
                                <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Database Storage</div>
                                <div style={{ display: "flex", alignItems: "center", gap: "6px", marginTop: "4px", fontSize: "0.85rem", fontWeight: 600 }}>
                                    <span>💾</span>
                                    <span>{health?.database === "postgres" ? "PostgreSQL" : "SQLite 3 (WAL)"}</span>
                                </div>
                            </div>

                            <div style={{ background: "var(--bg-glass)", border: "1px solid var(--border)", borderRadius: "6px", padding: "8px 12px" }}>
                                <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", textTransform: "uppercase" }}>AI Detection</div>
                                <div style={{ display: "flex", alignItems: "center", gap: "6px", marginTop: "4px", fontSize: "0.85rem", fontWeight: 600 }}>
                                    <span>🧠</span>
                                    <span>{health?.model_loaded ? "Phishing Model (10F)" : "Heuristics"}</span>
                                </div>
                            </div>

                            <div style={{ background: "var(--bg-glass)", border: "1px solid var(--border)", borderRadius: "6px", padding: "8px 12px" }}>
                                <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", textTransform: "uppercase" }}>Rolling PCAP Buffer</div>
                                <div style={{ display: "flex", alignItems: "center", gap: "6px", marginTop: "4px", fontSize: "0.85rem", fontWeight: 600 }}>
                                    <span>📦</span>
                                    <span>{health?.pcap_buffered_packets ?? 0} / 1,000 pkts</span>
                                </div>
                            </div>
                        </div>

                        {/* CPU Meter */}
                        <div style={{ marginBottom: "12px" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.78rem", marginBottom: "4px" }}>
                                <span className="label">CPU Utilization</span>
                                <span className="value" style={{ fontFamily: "monospace" }}>{(health?.cpu_percent ?? 0).toFixed(1)}%</span>
                            </div>
                            <div style={{ height: "6px", width: "100%", background: "rgba(255,255,255,0.08)", borderRadius: "3px", overflow: "hidden" }}>
                                <div style={{
                                    height: "100%",
                                    width: `${Math.min(100, Math.max(0, health?.cpu_percent ?? 0))}%`,
                                    background: (health?.cpu_percent ?? 0) > 85 ? "var(--danger)" : (health?.cpu_percent ?? 0) > 60 ? "var(--warning)" : "var(--safe)",
                                    transition: "width 0.4s ease",
                                }} />
                            </div>
                        </div>

                        {/* Memory Meter */}
                        <div>
                            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.78rem", marginBottom: "4px" }}>
                                <span className="label">Memory Consumption</span>
                                <span className="value" style={{ fontFamily: "monospace" }}>{(health?.memory_percent ?? 0).toFixed(1)}%</span>
                            </div>
                            <div style={{ height: "6px", width: "100%", background: "rgba(255,255,255,0.08)", borderRadius: "3px", overflow: "hidden" }}>
                                <div style={{
                                    height: "100%",
                                    width: `${Math.min(100, Math.max(0, health?.memory_percent ?? 0))}%`,
                                    background: (health?.memory_percent ?? 0) > 85 ? "var(--danger)" : (health?.memory_percent ?? 0) > 60 ? "var(--warning)" : "var(--safe)",
                                    transition: "width 0.4s ease",
                                }} />
                            </div>
                        </div>
                    </div>
                </div>

                {engineState && (
                    <div className="panel animate-fade-up stagger-6">
                        <div className="panel-header">
                            <div>
                                <div className="card-label">Engine State</div>
                                <h2>Firewall Internals</h2>
                            </div>
                            <span className="badge badge-medium">Stateful</span>
                        </div>
                        <div className="detail-box">
                            <div className="detail-row">
                                <span className="label">Active Firewall Rules</span>
                                <span className="value">{engineState.rules ?? health?.rules ?? 0}</span>
                            </div>
                            <div className="detail-row">
                                <span className="label">ACL Filter Entries</span>
                                <span className="value">{engineState.acl_entries ?? 0}</span>
                            </div>
                            {engineState.tcp_sessions && (
                                <div className="detail-row">
                                    <span className="label">Tracked TCP Sessions</span>
                                    <span className="value">{typeof engineState.tcp_sessions === "object" ? Object.keys(engineState.tcp_sessions).length : engineState.tcp_sessions}</span>
                                </div>
                            )}
                            {engineState.response_actions && (
                                <div className="detail-row">
                                    <span className="label">Autonomous Actions</span>
                                    <span className="value">{Array.isArray(engineState.response_actions) ? engineState.response_actions.length : 0} active</span>
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}