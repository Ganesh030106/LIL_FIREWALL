import { useEffect, useState, useCallback, useMemo } from "react";
import { apiFetch } from "../services/api";

export default function NetworkTab() {
    const [sessions, setSessions] = useState([]);
    const [connections, setConnections] = useState([]);
    const [ports, setPorts] = useState([]);
    const [ips, setIps] = useState([]);
    const [devices, setDevices] = useState([]);
    const [activeSection, setActiveSection] = useState("sessions");
    const [searchQuery, setSearchQuery] = useState("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    const fetchAll = useCallback(async () => {
        setLoading(true);
        try {
            const [sRes, cRes, pRes, iRes, dRes] = await Promise.all([
                apiFetch("/api/sessions").catch(() => null),
                apiFetch("/api/current/connections").catch(() => null),
                apiFetch("/api/history/ports").catch(() => null),
                apiFetch("/api/history/ips").catch(() => null),
                apiFetch("/api/risk/devices").catch(() => null),
            ]);

            // TCP Sessions
            if (sRes && sRes.ok) {
                const sData = await sRes.json().catch(() => []);
                if (Array.isArray(sData)) {
                    setSessions(sData);
                } else if (sData && Array.isArray(sData.sessions)) {
                    setSessions(sData.sessions);
                } else {
                    setSessions([]);
                }
            }

            // Live Sockets & Connections
            if (cRes && cRes.ok) {
                const cData = await cRes.json().catch(() => ({}));
                setConnections(Array.isArray(cData.connections) ? cData.connections : (Array.isArray(cData) ? cData : []));
            }

            // Port Activity
            if (pRes && pRes.ok) {
                const pData = await pRes.json().catch(() => ({}));
                setPorts(Array.isArray(pData.ports) ? pData.ports : (Array.isArray(pData) ? pData : []));
            }

            // IP Address History
            if (iRes && iRes.ok) {
                const iData = await iRes.json().catch(() => ({}));
                let ipList = [];
                if (Array.isArray(iData.ips)) {
                    ipList = iData.ips;
                } else if (iData.ips && typeof iData.ips === "object") {
                    ipList = Object.entries(iData.ips).map(([ip, events]) => {
                        const arr = Array.isArray(events) ? events : [];
                        return {
                            ip,
                            first_seen: arr[0]?.timestamp || "—",
                            last_seen: arr[arr.length - 1]?.timestamp || "—",
                            count: arr.length || 1,
                        };
                    });
                } else if (Array.isArray(iData)) {
                    ipList = iData;
                }
                setIps(ipList);
            }

            // Discovered Devices
            if (dRes && dRes.ok) {
                const dData = await dRes.json().catch(() => []);
                if (Array.isArray(dData)) {
                    setDevices(dData);
                } else if (dData && Array.isArray(dData.devices)) {
                    setDevices(dData.devices);
                }
            }

            setError("");
        } catch (e) {
            setError(e?.message || "Failed to load network telemetry");
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchAll();
        const id = setInterval(fetchAll, 3000);
        return () => clearInterval(id);
    }, [fetchAll]);

    // Guaranteed safe array references
    const safeSessions = useMemo(() => Array.isArray(sessions) ? sessions : [], [sessions]);
    const safeConnections = useMemo(() => Array.isArray(connections) ? connections : [], [connections]);
    const safeDevices = useMemo(() => Array.isArray(devices) ? devices : [], [devices]);
    const safePorts = useMemo(() => Array.isArray(ports) ? ports : [], [ports]);
    const safeIps = useMemo(() => Array.isArray(ips) ? ips : [], [ips]);

    const sections = useMemo(() => [
        { id: "sessions", label: "TCP Sessions", count: safeSessions.length },
        { id: "connections", label: "Live Sockets", count: safeConnections.length },
        { id: "devices", label: "Device Profiles", count: safeDevices.length },
        { id: "ports", label: "Port Activity", count: safePorts.length },
        { id: "ips", label: "IP History", count: safeIps.length },
    ], [safeSessions.length, safeConnections.length, safeDevices.length, safePorts.length, safeIps.length]);

    const stateColor = (state) => {
        const s = String(state || "").toLowerCase();
        if (s === "established") return "badge-safe";
        if (s === "syn_sent" || s === "syn_recv") return "badge-info";
        if (s === "closed" || s === "close_wait") return "badge-neutral";
        return "badge-medium";
    };

    const q = searchQuery.toLowerCase().trim();

    const filteredSessions = useMemo(() => {
        return safeSessions.filter(s =>
            !q ||
            (s.src_ip && String(s.src_ip).toLowerCase().includes(q)) ||
            (s.dst_ip && String(s.dst_ip).toLowerCase().includes(q)) ||
            (s.process && String(s.process).toLowerCase().includes(q)) ||
            String(s.dst_port || "").includes(q)
        );
    }, [safeSessions, q]);

    const filteredConnections = useMemo(() => {
        return safeConnections.filter(c => {
            const src = String(c.src || c.Src || "");
            const dst = String(c.dst || c.Dst || "");
            const proc = String(c.process || "");
            return !q || src.toLowerCase().includes(q) || dst.toLowerCase().includes(q) || proc.toLowerCase().includes(q);
        });
    }, [safeConnections, q]);

    const filteredDevices = useMemo(() => {
        return safeDevices.filter(d => {
            const ip = String(d.ip || "");
            const mac = String(d.mac || "");
            return !q || ip.toLowerCase().includes(q) || mac.toLowerCase().includes(q);
        });
    }, [safeDevices, q]);

    const filteredPorts = useMemo(() => {
        return safePorts.filter(p => {
            const src = String(p.src || p.Src || "");
            const dst = String(p.dst || p.Dst || "");
            const port = String(p.port || p.Port || "");
            return !q || src.toLowerCase().includes(q) || dst.toLowerCase().includes(q) || port.includes(q);
        });
    }, [safePorts, q]);

    const filteredIps = useMemo(() => {
        return safeIps.filter(ip => {
            if (typeof ip === "string") return !q || ip.toLowerCase().includes(q);
            const addr = String(ip.ip || ip.IP || "");
            return !q || addr.toLowerCase().includes(q);
        });
    }, [safeIps, q]);

    return (
        <div className="tab-content" key="network">
            <div className="tab-header">
                <div className="tab-header-info">
                    <div className="tab-eyebrow">🌐 Network Operations</div>
                    <h1>Network Traffic & Sessions</h1>
                    <p className="tab-subtitle">
                        Inspect active TCP sessions, current connections, port activity logs, and IP address history tracked by the stateful inspection engine.
                    </p>
                </div>
                <div className="tab-header-actions">
                    <button type="button" className="btn btn-ghost" onClick={fetchAll} disabled={loading}>
                        {loading ? "Refreshing..." : "↻ Refresh"}
                    </button>
                </div>
            </div>

            {error && (
                <div className="banner banner-error animate-fade-up" style={{ margin: "12px 0", display: "flex", justifyContent: "space-between" }}>
                    <span>⚠️ {error}</span>
                    <button type="button" className="btn-icon" onClick={() => setError("")}>×</button>
                </div>
            )}

            {/* Section switcher & Search Bar */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px", margin: "16px 0" }}>
                <div className="filter-bar" style={{ margin: 0 }}>
                    {sections.map(s => (
                        <button
                            key={s.id}
                            type="button"
                            className={`filter-pill${activeSection === s.id ? " active" : ""}`}
                            onClick={() => setActiveSection(s.id)}
                        >
                            {s.label} ({s.count})
                        </button>
                    ))}
                </div>

                <div style={{ position: "relative", minWidth: "240px" }}>
                    <input
                        type="text"
                        className="form-input"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder="Filter by IP, port, process..."
                        style={{ padding: "6px 28px 6px 12px", fontSize: "0.82rem", width: "100%" }}
                    />
                    {searchQuery && (
                        <button
                            type="button"
                            onClick={() => setSearchQuery("")}
                            style={{ position: "absolute", right: "8px", top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", fontSize: "0.8rem" }}
                        >
                            ✕
                        </button>
                    )}
                </div>
            </div>

            {/* ─── TCP Sessions ─── */}
            {activeSection === "sessions" && (
                <div className="panel animate-fade-up">
                    <div className="panel-header">
                        <div>
                            <h2>Active TCP Sessions</h2>
                            <p className="panel-header-sub">Tracked by stateful packet inspection & live socket engine</p>
                        </div>
                        <span className="chip">{filteredSessions.length} session{filteredSessions.length !== 1 ? "s" : ""}</span>
                    </div>
                    <div className="table-wrap">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>Source IP</th>
                                    <th>Source Port</th>
                                    <th>Dest IP</th>
                                    <th>Dest Port</th>
                                    <th>State</th>
                                    <th>Process</th>
                                    <th>Packets</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredSessions.length === 0 ? (
                                    <tr><td colSpan={7} className="table-empty">No active TCP sessions match query</td></tr>
                                ) : (
                                    filteredSessions.map((s, i) => (
                                        <tr key={i}>
                                            <td className="table-mono">{s.src_ip || "—"}</td>
                                            <td className="table-mono">{s.src_port || "—"}</td>
                                            <td className="table-mono">{s.dst_ip || "—"}</td>
                                            <td className="table-mono">{s.dst_port || "—"}</td>
                                            <td><span className={`badge ${stateColor(s.state)}`}>{s.state || "active"}</span></td>
                                            <td className="table-mono" style={{ color: "var(--accent)" }}>{s.process || "Firewall Sniffer"}</td>
                                            <td className="table-mono">{s.packets_sent ?? 0}</td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* ─── Current Connections ─── */}
            {activeSection === "connections" && (
                <div className="panel animate-fade-up">
                    <div className="panel-header">
                        <div>
                            <h2>Live System Sockets & Connections</h2>
                            <p className="panel-header-sub">Real-time operating system network sockets and active processes</p>
                        </div>
                        <span className="chip">{filteredConnections.length} socket{filteredConnections.length !== 1 ? "s" : ""}</span>
                    </div>
                    <div className="table-wrap">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>Local Address</th>
                                    <th>Remote Address</th>
                                    <th>Protocol</th>
                                    <th>Status</th>
                                    <th>Process / PID</th>
                                    <th>Last Seen</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredConnections.length === 0 ? (
                                    <tr><td colSpan={6} className="table-empty">No active system sockets match query</td></tr>
                                ) : (
                                    filteredConnections.map((c, i) => (
                                        <tr key={i}>
                                            <td className="table-mono">{c.src || c.Src || "—"}</td>
                                            <td className="table-mono">{c.dst || c.Dst || "—"}</td>
                                            <td><span className="chip" style={{ padding: "2px 8px" }}>{c.protocol || c.Protocol || "TCP"}</span></td>
                                            <td><span className={`badge ${stateColor(c.status || "ESTABLISHED")}`}>{c.status || "ESTABLISHED"}</span></td>
                                            <td className="table-mono" style={{ color: "var(--accent)" }}>{c.process || "System"}</td>
                                            <td className="table-mono">{c.last_seen || c.Last_seen || "Live"}</td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* ─── Device Profiles ─── */}
            {activeSection === "devices" && (
                <div className="panel animate-fade-up">
                    <div className="panel-header">
                        <div>
                            <h2>Network Device Profiles & Behavior Baselines</h2>
                            <p className="panel-header-sub">Automated host discovery, MAC address fingerprinting & heuristic risk assessment</p>
                        </div>
                        <span className="chip">{filteredDevices.length} device{filteredDevices.length !== 1 ? "s" : ""}</span>
                    </div>
                    <div className="table-wrap">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>MAC Address</th>
                                    <th>Host Role</th>
                                    <th>Risk Score</th>
                                    <th>Behavior Status</th>
                                    <th>Last Active</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredDevices.length === 0 ? (
                                    <tr><td colSpan={6} className="table-empty">No device profiles discovered yet</td></tr>
                                ) : (
                                    filteredDevices.map((d, i) => {
                                        const score = Math.round((Number(d.risk_score || d.risk || 0)) * 100);
                                        const badgeClass = score >= 70 ? "badge-critical" : score >= 40 ? "badge-high" : "badge-safe";
                                        return (
                                            <tr key={i}>
                                                <td className="table-mono">{d.ip || "—"}</td>
                                                <td className="table-mono">{d.mac || "—"}</td>
                                                <td>{d.role || (d.ip === "127.0.0.1" ? "Local Host" : "Discovered Endpoint")}</td>
                                                <td><span className={`badge ${badgeClass}`}>{score} / 100</span></td>
                                                <td>
                                                    <span className="chip" style={{ background: score >= 50 ? "rgba(239, 68, 68, 0.12)" : "rgba(34, 197, 94, 0.12)", color: score >= 50 ? "#ef4444" : "#22c55e" }}>
                                                        {score >= 50 ? "Suspicious Activity" : "Normal Baseline"}
                                                    </span>
                                                </td>
                                                <td className="table-mono">{d.last_seen ? new Date(d.last_seen).toLocaleTimeString() : "Live"}</td>
                                            </tr>
                                        );
                                    })
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* ─── Port Activity ─── */}
            {activeSection === "ports" && (
                <div className="panel animate-fade-up">
                    <div className="panel-header">
                        <div>
                            <h2>Port Activity History</h2>
                            <p className="panel-header-sub">Historical port access records from network monitoring</p>
                        </div>
                        <span className="chip">{filteredPorts.length} record{filteredPorts.length !== 1 ? "s" : ""}</span>
                    </div>
                    <div className="table-wrap">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Source</th>
                                    <th>Destination</th>
                                    <th>Port</th>
                                    <th>Protocol</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredPorts.length === 0 ? (
                                    <tr><td colSpan={5} className="table-empty">No port activity recorded</td></tr>
                                ) : (
                                    filteredPorts.map((p, i) => (
                                        <tr key={i}>
                                            <td className="table-mono">{p.timestamp || p.Timestamp || "—"}</td>
                                            <td className="table-mono">{p.src || p.Src || "—"}</td>
                                            <td className="table-mono">{p.dst || p.Dst || "—"}</td>
                                            <td className="table-mono">{p.port || p.Port || "—"}</td>
                                            <td>{p.protocol || p.Protocol || "—"}</td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* ─── IP History ─── */}
            {activeSection === "ips" && (
                <div className="panel animate-fade-up">
                    <div className="panel-header">
                        <div>
                            <h2>IP Address History</h2>
                            <p className="panel-header-sub">All tracked IP addresses and their access patterns</p>
                        </div>
                        <span className="chip">{filteredIps.length} record{filteredIps.length !== 1 ? "s" : ""}</span>
                    </div>
                    <div className="table-wrap">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>First Seen</th>
                                    <th>Last Seen</th>
                                    <th>Access Count</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredIps.length === 0 ? (
                                    <tr><td colSpan={4} className="table-empty">No IP history recorded</td></tr>
                                ) : (
                                    filteredIps.map((ip, i) => {
                                        const ipStr = typeof ip === "string" ? ip : (ip.ip || ip.IP || "—");
                                        const firstSeen = typeof ip === "object" ? (ip.first_seen || ip.First_seen || "—") : "—";
                                        const lastSeen = typeof ip === "object" ? (ip.last_seen || ip.Last_seen || "—") : "—";
                                        const count = typeof ip === "object" ? (ip.count ?? ip.Count ?? 1) : 1;
                                        return (
                                            <tr key={i}>
                                                <td className="table-mono">{ipStr}</td>
                                                <td className="table-mono">{firstSeen}</td>
                                                <td className="table-mono">{lastSeen}</td>
                                                <td className="table-mono">{count}</td>
                                            </tr>
                                        );
                                    })
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    );
}
