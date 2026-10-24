import { useEffect, useMemo, useState, useCallback } from "react";
import { apiFetch } from "./services/api";
import { useRealtime } from "./hooks/useRealtime";

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
    const [error, setError] = useState("");

    // Real-time WebSocket hook with instantaneous telemetry push
    useRealtime(useCallback((event) => {
        if (event.type === "init" || event.type === "metrics_tick") {
            const d = event.data || event;
            if (d.metrics) setMetrics(prev => ({ ...prev, ...d.metrics }));
            if (d.threat) setThreat(d.threat);
            if (d.alert_count !== undefined) setAlertCount(d.alert_count);
        } else if (event.type === "alert_created") {
            setAlertCount(prev => prev + 1);
        }
    }, []));

    const fetchAll = async (signal) => {
        try {
            const [mRes, tRes, fRes, aRes] = await Promise.all([
                apiFetch("/api/metrics", { signal }),
                apiFetch("/api/threat-summary", { signal }),
                apiFetch("/api/firewall-insights", { signal }),
                apiFetch("/api/alerts", { signal }),
            ]);
            if (mRes.ok) { const mData = await mRes.json(); setMetrics(prev => ({ ...prev, ...mData })); }
            if (tRes.ok) setThreat(await tRes.json());
            if (fRes.ok) setInsights(await fRes.json());
            if (aRes.ok) {
                const aData = await aRes.json();
                setAlertCount(aData.count || 0);
            }

            // Non-critical
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
    };

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

    const geoRegions = useMemo(() => [
        { name: "North America", x: 128, y: 118, risk: 82, rate: 920 },
        { name: "Europe", x: 245, y: 102, risk: 68, rate: 760 },
        { name: "Middle East", x: 300, y: 150, risk: 74, rate: 800 },
        { name: "Asia Pacific", x: 360, y: 130, risk: 88, rate: 980 },
        { name: "South America", x: 180, y: 198, risk: 58, rate: 620 },
        { name: "Africa", x: 268, y: 182, risk: 63, rate: 680 },
    ], [alertCount, metrics.current_packet_velocity]);

    const heatmapCells = useMemo(() => {
        const labels = ["TCP", "UDP", "ICMP", "HTTP", "DNS", "SSH"];
        const values = labels.map((label, index) => {
            const base = (metrics.current_packet_velocity || 0) / 2;
            const signal = (insights.protocol_distribution?.[label] ?? 0) || (index + 1) * 14;
            return Math.max(18, Math.min(100, base + signal + index * 10));
        });

        return labels.map((label, rowIndex) => ({
            label,
            value: values[rowIndex],
            tone: rowIndex % 2 === 0 ? "warm" : "cool",
        }));
    }, [insights.protocol_distribution, metrics.current_packet_velocity]);

    const topologyNodes = useMemo(() => [
        { id: "FW", x: 76, y: 126, label: "Firewall" },
        { id: "AI", x: 220, y: 72, label: "AI Sensor" },
        { id: "N1", x: 204, y: 174, label: "Core Net" },
        { id: "N2", x: 350, y: 126, label: "Edge Host" },
        { id: "D1", x: 390, y: 224, label: "DB" },
    ], [metrics.current_packet_velocity]);

    const trafficTrend = useMemo(() => {
        const base = Number(metrics.current_packet_velocity) || 0;
        const alertPulse = Number(alertCount) || 0;

        return Array.from({ length: 8 }, (_, index) => {
            const wave = Math.sin((index + 1) * 1.1) * 18;
            const drift = index * 4;
            const alertBoost = (alertPulse / 6) * (index % 3 === 0 ? 1.2 : 0.8);
            const value = Math.max(6, Math.min(98, base * 0.5 + wave + drift + alertBoost));
            return Number(value.toFixed(1));
        });
    }, [metrics.current_packet_velocity, alertCount]);

    const chartPoints = useMemo(() => {
        const width = 340;
        const height = 180;
        const max = 100;
        const min = 0;

        return trafficTrend
            .map((value, index) => {
                const x = (index / (trafficTrend.length - 1)) * (width - 18) + 9;
                const normalized = (value - min) / (max - min || 1);
                const y = height - normalized * (height - 20) - 10;
                return `${x},${y}`;
            })
            .join(" ");
    }, [trafficTrend]);

    return (
        <div className="tab-content" key="overview">
            {/* Hero */}
            <div className="tab-header" style={{ marginBottom: 28 }}>
                <div className="tab-header-info">
                    <div className="tab-eyebrow">
                        <span className={`status-dot ${packetStatus.dot}`}></span>
                        Volcano / AI Firewall
                    </div>
                    <h1>Context-Aware Network Defense Console</h1>
                    <p className="tab-subtitle">
                        Real-time anomaly detection, filesystem sentinel monitoring, contextual phishing scoring, and AI-powered threat correlation in a single operational surface.
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

            <div className="visual-grid mt-md">
                <div className="panel animate-fade-up stagger-2">
                    <div className="panel-header">
                        <div>
                            <div className="card-label">Geographic Visualization</div>
                            <h2>Threat Regions</h2>
                        </div>
                        <span className="badge badge-medium">Global</span>
                    </div>

                    <div className="map-panel-body">
                        <svg viewBox="0 0 420 240" className="geo-map" role="img" aria-label="Threat activity map">
                            <path d="M55 90 L95 65 L155 70 L180 55 L235 60 L270 45 L320 55 L355 82 L365 120 L335 150 L300 175 L260 171 L220 190 L175 180 L120 190 L88 160 L70 128 Z" fill="rgba(59,130,246,0.08)" stroke="var(--border)" strokeWidth="1" />
                            <path d="M160 90 L208 85 L210 120 L160 128 Z" fill="rgba(16,185,129,0.06)" stroke="var(--border)" strokeWidth="1" />
                            <path d="M250 120 L300 108 L318 130 L290 160 L250 155 Z" fill="rgba(239,68,68,0.06)" stroke="var(--border)" strokeWidth="1" />

                            {geoRegions.map(region => (
                                <g key={region.name}>
                                    <circle
                                        cx={region.x}
                                        cy={region.y}
                                        r={Math.max(8, region.risk / 8)}
                                        fill={region.risk > 75 ? "rgba(239,68,68,0.55)" : "rgba(245,158,11,0.45)"}
                                        stroke="rgba(255,255,255,0.4)"
                                        strokeWidth="1.5"
                                    />
                                    <circle cx={region.x} cy={region.y} r={Math.max(12, region.risk / 5)} fill="rgba(255,255,255,0.04)" />
                                    <text x={region.x + 12} y={region.y - 10} className="geo-label">{region.name}</text>
                                </g>
                            ))}
                        </svg>
                    </div>
                </div>

                <div className="panel animate-fade-up stagger-3">
                    <div className="panel-header">
                        <div>
                            <div className="card-label">Bar / Heatmap</div>
                            <h2>Protocol Risk Heat</h2>
                        </div>
                        <span className="badge badge-safe">Avg risk</span>
                    </div>

                    <div className="heatmap-grid" aria-label="Protocol risk heatmap">
                        {heatmapCells.map(cell => (
                            <div key={cell.label} className="heatmap-cell-wrap">
                                <div
                                    className="heatmap-cell"
                                    style={{
                                        background: cell.tone === "warm"
                                            ? `rgba(239, 68, 68, ${Math.min(0.9, cell.value / 100)})`
                                            : `rgba(59, 130, 246, ${Math.min(0.9, cell.value / 100)})`,
                                    }}
                                    title={`${cell.label}: ${cell.value.toFixed(0)} risk`}
                                >
                                    <span>{cell.label}</span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            <div className="panel mt-md animate-fade-up stagger-4">
                <div className="panel-header">
                    <div>
                        <div className="card-label">Topology Graph</div>
                        <h2>Network Trust Map</h2>
                    </div>
                    <span className="badge badge-critical">Active</span>
                </div>

                <div className="topology-wrap">
                    <svg viewBox="0 0 460 290" className="topology-svg" role="img" aria-label="Network topology graph">
                        <line x1="76" y1="126" x2="220" y2="72" stroke="rgba(59,130,246,0.72)" strokeWidth="3" />
                        <line x1="220" y1="72" x2="204" y2="174" stroke="rgba(245,158,11,0.72)" strokeWidth="3" />
                        <line x1="204" y1="174" x2="350" y2="126" stroke="rgba(16,185,129,0.72)" strokeWidth="3" />
                        <line x1="350" y1="126" x2="390" y2="224" stroke="rgba(239,68,68,0.72)" strokeWidth="3" />
                        <line x1="76" y1="126" x2="204" y2="174" stroke="rgba(100,116,139,0.62)" strokeWidth="3" />

                        {topologyNodes.map(node => (
                            <g key={node.id}>
                                <circle cx={node.x} cy={node.y} r="30" fill="var(--diagram-node-bg)" stroke="var(--border-strong)" strokeWidth="2" />
                                <circle cx={node.x} cy={node.y} r="12" fill={node.id === "FW" ? "#ef4444" : node.id === "AI" ? "#3b82f6" : node.id === "D1" ? "#f59e0b" : "#10b981"} />
                                <text x={node.x} y={node.y + 48} textAnchor="middle" className="topology-label">{node.label}</text>
                            </g>
                        ))}
                    </svg>
                </div>
            </div>

            {/* ── Trend Visualization ── */}
            <div className="mt-md panel animate-fade-up stagger-5">
                <div className="panel-header">
                    <div>
                        <div className="card-label">Traffic Visualization</div>
                        <h2>Threat Activity Trend</h2>
                    </div>
                    <span className="badge badge-safe">Live</span>
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
                            const y = 170 - ((value - 0) / (100 - 0 || 1)) * (170 - 20) - 10;
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