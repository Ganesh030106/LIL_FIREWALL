import { useEffect, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";

export default function NetworkTab() {
    const [sessions, setSessions] = useState([]);
    const [connections, setConnections] = useState([]);
    const [ports, setPorts] = useState([]);
    const [ips, setIps] = useState([]);
    const [activeSection, setActiveSection] = useState("sessions");
    const [loading, setLoading] = useState(false);

    const fetchAll = async () => {
        setLoading(true);
        try {
            const [sRes, cRes, pRes, iRes] = await Promise.all([
                fetch(`${API_BASE}/api/sessions`),
                fetch(`${API_BASE}/api/current/connections`),
                fetch(`${API_BASE}/api/history/ports`),
                fetch(`${API_BASE}/api/history/ips`),
            ]);
            if (sRes.ok) setSessions(await sRes.json());
            if (cRes.ok) {
                const cData = await cRes.json();
                setConnections(cData.connections || []);
            }
            if (pRes.ok) {
                const pData = await pRes.json();
                setPorts(pData.ports || []);
            }
            if (iRes.ok) {
                const iData = await iRes.json();
                setIps(iData.ips || []);
            }
        } catch {}
        setLoading(false);
    };

    useEffect(() => { fetchAll(); }, []);

    const sections = [
        { id: "sessions", label: "TCP Sessions", count: sessions.length },
        { id: "connections", label: "Connections", count: connections.length },
        { id: "ports", label: "Port Activity", count: ports.length },
        { id: "ips", label: "IP History", count: ips.length },
    ];

    const stateColor = (state) => {
        if (state === "established" || state === "ESTABLISHED") return "badge-safe";
        if (state === "syn_sent" || state === "SYN_SENT") return "badge-info";
        if (state === "closed" || state === "CLOSED") return "badge-neutral";
        return "badge-medium";
    };

    return (
        <div className="tab-content" key="network">
            <div className="tab-header">
                <div className="tab-header-info">
                    <div className="tab-eyebrow">🌐 Network</div>
                    <h1>Network Traffic & Sessions</h1>
                    <p className="tab-subtitle">
                        Inspect active TCP sessions, current connections, port activity logs, and IP address history tracked by the stateful inspection engine.
                    </p>
                </div>
                <div className="tab-header-actions">
                    <button className="btn" onClick={fetchAll} disabled={loading}>
                        {loading ? "Loading…" : "↻ Refresh"}
                    </button>
                </div>
            </div>

            {/* Section switcher */}
            <div className="filter-bar">
                {sections.map(s => (
                    <button
                        key={s.id}
                        className={`filter-pill${activeSection === s.id ? " active" : ""}`}
                        onClick={() => setActiveSection(s.id)}
                    >
                        {s.label} ({s.count})
                    </button>
                ))}
            </div>

            {/* ─── TCP Sessions ─── */}
            {activeSection === "sessions" && (
                <div className="panel animate-fade-up">
                    <div className="panel-header">
                        <div>
                            <h2>Active TCP Sessions</h2>
                            <p className="panel-header-sub">Tracked by stateful packet inspection & live socket engine</p>
                        </div>
                        <span className="chip">{sessions.length} session{sessions.length !== 1 ? "s" : ""}</span>
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
                                {sessions.length === 0 ? (
                                    <tr><td colSpan={7} className="table-empty">No active TCP sessions</td></tr>
                                ) : (
                                    sessions.map((s, i) => (
                                        <tr key={i}>
                                            <td className="table-mono">{s.src_ip}</td>
                                            <td className="table-mono">{s.src_port}</td>
                                            <td className="table-mono">{s.dst_ip}</td>
                                            <td className="table-mono">{s.dst_port}</td>
                                            <td><span className={`badge ${stateColor(s.state)}`}>{s.state}</span></td>
                                            <td className="table-mono" style={{ color: "var(--accent)" }}>{s.process || "Firewall Sniffer"}</td>
                                            <td className="table-mono">{s.packets_sent}</td>
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
                        <span className="chip">{connections.length} socket{connections.length !== 1 ? "s" : ""}</span>
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
                                {connections.length === 0 ? (
                                    <tr><td colSpan={6} className="table-empty">No active system sockets</td></tr>
                                ) : (
                                    connections.map((c, i) => (
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

            {/* ─── Port Activity ─── */}
            {activeSection === "ports" && (
                <div className="panel animate-fade-up">
                    <div className="panel-header">
                        <div>
                            <h2>Port Activity History</h2>
                            <p className="panel-header-sub">Historical port access records from network monitoring</p>
                        </div>
                        <span className="chip">{ports.length} record{ports.length !== 1 ? "s" : ""}</span>
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
                                {ports.length === 0 ? (
                                    <tr><td colSpan={5} className="table-empty">No port activity recorded</td></tr>
                                ) : (
                                    ports.map((p, i) => (
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
                        <span className="chip">{ips.length} record{ips.length !== 1 ? "s" : ""}</span>
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
                                {ips.length === 0 ? (
                                    <tr><td colSpan={4} className="table-empty">No IP history recorded</td></tr>
                                ) : (
                                    ips.map((ip, i) => (
                                        <tr key={i}>
                                            <td className="table-mono">{ip.ip || ip.IP || JSON.stringify(ip)}</td>
                                            <td className="table-mono">{ip.first_seen || ip.First_seen || "—"}</td>
                                            <td className="table-mono">{ip.last_seen || ip.Last_seen || "—"}</td>
                                            <td className="table-mono">{ip.count || ip.Count || "—"}</td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    );
}
