import { useEffect, useState } from "react";
import { apiFetch } from "../services/api";

export default function ThreatIntelTab() {
    const [threatSummary, setThreatSummary] = useState(null);
    const [insights, setInsights] = useState(null);
    const [riskDevices, setRiskDevices] = useState([]);
    const [riskUsers, setRiskUsers] = useState([]);
    const [riskStats, setRiskStats] = useState(null);
    const [recentThreats, setRecentThreats] = useState([]);
    const [feedsData, setFeedsData] = useState(null);
    const [syncingFeeds, setSyncingFeeds] = useState(false);
    const [feedSyncMsg, setFeedSyncMsg] = useState("");

    // Quick IoC Lookup
    const [lookupTarget, setLookupTarget] = useState("");
    const [lookupResult, setLookupResult] = useState(null);
    const [lookupLoading, setLookupLoading] = useState(false);

    // Autonomous Block
    const [blockIp, setBlockIp] = useState("");
    const [blockDuration, setBlockDuration] = useState("3600");
    const [blockStatus, setBlockStatus] = useState("");
    const [loading, setLoading] = useState(false);

    const fetchAll = async () => {
        setLoading(true);
        try {
            const [tRes, iRes, dRes, uRes, sRes, rRes, fRes] = await Promise.all([
                apiFetch("/api/threat-summary"),
                apiFetch("/api/firewall-insights"),
                apiFetch("/api/risk/devices"),
                apiFetch("/api/risk/users"),
                apiFetch("/api/risk/stats"),
                apiFetch("/api/threats/recent"),
                apiFetch("/api/threats/feeds"),
            ]);
            if (tRes.ok) setThreatSummary(await tRes.json());
            if (iRes.ok) setInsights(await iRes.json());
            if (dRes.ok) setRiskDevices(await dRes.json());
            if (uRes.ok) setRiskUsers(await uRes.json());
            if (sRes.ok) setRiskStats(await sRes.json());
            if (rRes.ok) setRecentThreats(await rRes.json());
            if (fRes.ok) setFeedsData(await fRes.json());
        } catch (err) {
            console.error("ThreatIntel fetch error:", err);
        }
        setLoading(false);
    };

    useEffect(() => {
        fetchAll();
        const id = setInterval(fetchAll, 6000);
        return () => clearInterval(id);
    }, []);

    const handleSyncFeeds = async () => {
        setSyncingFeeds(true);
        setFeedSyncMsg("");
        try {
            const res = await apiFetch("/api/threats/feeds/refresh", { method: "POST" });
            if (res.ok) {
                const data = await res.json();
                setFeedSyncMsg(`✓ Feeds synchronized! Loaded ${data.local_indicators} local IoCs.`);
                await fetchAll();
            } else {
                setFeedSyncMsg("✗ Feed synchronization failed.");
            }
        } catch (err) {
            setFeedSyncMsg(`✗ Error: ${err.message}`);
        }
        setSyncingFeeds(false);
    };

    const handleLookup = async (e) => {
        e.preventDefault();
        if (!lookupTarget.trim()) return;
        setLookupLoading(true);
        setLookupResult(null);
        try {
            const res = await apiFetch(`/api/threats/lookup?target=${encodeURIComponent(lookupTarget.trim())}`);
            if (res.ok) {
                setLookupResult(await res.json());
            } else {
                setLookupResult({ error: "Lookup request failed" });
            }
        } catch (err) {
            setLookupResult({ error: err.message });
        }
        setLookupLoading(false);
    };

    const handleBlockIp = async (e) => {
        e.preventDefault();
        if (!blockIp.trim()) return;
        setBlockStatus("");
        try {
            const res = await apiFetch(`/api/autonomous/block-ip?ip=${encodeURIComponent(blockIp)}&duration=${blockDuration}`, {
                method: "POST",
            });
            if (!res.ok) throw new Error("Failed to block IP");
            const data = await res.json();
            setBlockStatus(`✓ IP ${blockIp} blocked for ${blockDuration}s (Action ID: ${data.id})`);
            setBlockIp("");
        } catch (err) {
            setBlockStatus(`✗ ${err.message}`);
        }
    };

    const threatLevelColor = (level) => {
        if (level === "Critical") return "text-danger";
        if (level === "High") return "text-danger";
        if (level === "Medium" || level === "Elevated") return "text-warning";
        return "text-safe";
    };

    const riskColor = (score) => {
        if (score >= 0.8) return "badge-critical";
        if (score >= 0.5) return "badge-high";
        if (score >= 0.3) return "badge-medium";
        return "badge-safe";
    };

    const formatTimestamp = (ts) => {
        if (!ts) return "—";
        try {
            const d = typeof ts === "number" ? new Date(ts * 1000) : new Date(ts);
            return d.toLocaleTimeString();
        } catch {
            return String(ts);
        }
    };

    return (
        <div className="tab-content" key="threat-intel">
            <div className="tab-header">
                <div className="tab-header-info">
                    <div className="tab-eyebrow">🧠 AI Threat Intelligence</div>
                    <h1>Threat Analysis & Feeds</h1>
                    <p className="tab-subtitle">
                        Multi-source threat intelligence feeds, DNS tunneling & DGA detection, brute force defenses, and device risk profiling.
                    </p>
                </div>
                <div className="tab-header-actions">
                    <span className="chip chip-live">Live feeds active</span>
                    <button className="btn" onClick={fetchAll} disabled={loading}>
                        {loading ? "Loading…" : "↻ Refresh"}
                    </button>
                </div>
            </div>

            {/* ─── Top Stats ─── */}
            {threatSummary && (
                <div className="stats-grid" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
                    <div className="stat-card accent animate-fade-up stagger-1">
                        <div className="card-label">Risk Score</div>
                        <div className={`card-value ${threatLevelColor(threatSummary.threat_level)}`}>
                            {Number(threatSummary.risk_score).toFixed(4)}
                        </div>
                        <div className="card-caption">{threatSummary.threat_level} threat level</div>
                    </div>
                    <div className="stat-card animate-fade-up stagger-2">
                        <div className="card-label">Model Confidence</div>
                        <div className="card-value">{(Number(threatSummary.confidence) * 100).toFixed(1)}%</div>
                        <div className="card-caption">Certainty in assessment</div>
                    </div>
                    <div className="stat-card animate-fade-up stagger-3">
                        <div className="card-label">High-Risk Devices</div>
                        <div className="card-value">{riskDevices.length}</div>
                        <div className="card-caption">Above 0.5 risk threshold</div>
                    </div>
                    <div className="stat-card animate-fade-up stagger-4">
                        <div className="card-label">Threat Feeds</div>
                        <div className="card-value">{feedsData?.total_feeds || 0}</div>
                        <div className="card-caption">Active IoC repositories</div>
                    </div>
                </div>
            )}

            {/* ─── Threat Intelligence Feeds Panel ─── */}
            <div className="panel animate-fade-up stagger-2">
                <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div>
                        <h2>📡 Threat Intelligence Feeds</h2>
                        <p className="panel-header-sub">
                            Ingested feeds tracking active botnet C2 nodes, phishing infrastructure, and malicious indicators.
                        </p>
                    </div>
                    <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                        {feedSyncMsg && <span className="chip" style={{ fontSize: "11px" }}>{feedSyncMsg}</span>}
                        <button className="btn btn-secondary" onClick={handleSyncFeeds} disabled={syncingFeeds}>
                            {syncingFeeds ? "Syncing..." : "⚡ Sync Feeds Now"}
                        </button>
                    </div>
                </div>
                <div className="table-wrap">
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th>Feed Name</th>
                                <th>Source Type</th>
                                <th>Status</th>
                                <th>IoCs Ingested</th>
                                <th>Last Synchronized</th>
                            </tr>
                        </thead>
                        <tbody>
                            {!feedsData || !feedsData.feeds || feedsData.feeds.length === 0 ? (
                                <tr>
                                    <td colSpan={5} className="table-empty">No threat feeds loaded</td>
                                </tr>
                            ) : (
                                feedsData.feeds.map((feed, idx) => {
                                    const isSynced = feed.status === "synced";
                                    const isOffline = feed.status === "degraded_offline";
                                    const badgeClass = isSynced ? "badge-safe" : (isOffline ? "badge-warning" : "badge-critical");
                                    return (
                                        <tr key={idx}>
                                            <td style={{ fontWeight: 600 }}>{feed.name}</td>
                                            <td>
                                                <span className="chip" style={{ padding: "2px 8px" }}>
                                                    {feed.source_type === "file" ? "📁 Local File" : "🌐 Remote Feed"}
                                                </span>
                                            </td>
                                            <td>
                                                <span className={`badge ${badgeClass}`}>
                                                    {feed.status.toUpperCase()}
                                                </span>
                                            </td>
                                            <td className="table-mono">{feed.item_count?.toLocaleString() || 0}</td>
                                            <td className="table-mono">{formatTimestamp(feed.last_updated)}</td>
                                        </tr>
                                    );
                                })
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* ─── IoC Quick Lookup & Autonomous Block Grid ─── */}
            <div className="grid-2">
                {/* ─── IoC Lookup ─── */}
                <div className="panel animate-fade-up stagger-3">
                    <div className="panel-header">
                        <div>
                            <h2>🔍 IoC Intelligence Lookup</h2>
                            <p className="panel-header-sub">Check any IP, domain, or hash against active feeds & GeoIP</p>
                        </div>
                    </div>
                    <form className="form-inline" onSubmit={handleLookup} style={{ marginBottom: "16px" }}>
                        <div className="form-group" style={{ flex: 1 }}>
                            <input
                                className="form-input"
                                value={lookupTarget}
                                onChange={e => setLookupTarget(e.target.value)}
                                placeholder="e.g. 185.220.101.5, update-system-secure.xyz"
                                required
                            />
                        </div>
                        <button className="btn btn-primary" type="submit" disabled={lookupLoading}>
                            {lookupLoading ? "Searching..." : "Lookup"}
                        </button>
                    </form>

                    {lookupResult && (
                        <div style={{ background: "rgba(255, 255, 255, 0.03)", padding: "14px", borderRadius: "8px", border: "1px solid rgba(255, 255, 255, 0.08)" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                                <span style={{ fontWeight: 600 }}>Target: {lookupResult.target}</span>
                                <span className={`badge ${lookupResult.is_threat ? "badge-critical" : "badge-safe"}`}>
                                    {lookupResult.is_threat ? "⚠️ KNOWN THREAT" : "✓ NOT IN FEEDS"}
                                </span>
                            </div>
                            <div style={{ fontSize: "12px", color: "var(--color-text-muted)", display: "flex", flexDirection: "column", gap: "4px" }}>
                                <div><strong>Indicator Type:</strong> {lookupResult.type?.toUpperCase()}</div>
                                {lookupResult.reputation && (
                                    <div><strong>Reason:</strong> {lookupResult.reputation.reputation?.reason || "Listed in Blocklist"}</div>
                                )}
                                {lookupResult.geoip && (
                                    <div><strong>Location:</strong> {lookupResult.geoip.city}, {lookupResult.geoip.country} ({lookupResult.geoip.country_code})</div>
                                )}
                            </div>
                        </div>
                    )}
                </div>

                {/* ─── Autonomous Block ─── */}
                <div className="panel animate-fade-up stagger-3">
                    <div className="panel-header">
                        <div>
                            <h2>⛔ Autonomous IP Containment</h2>
                            <p className="panel-header-sub">Trigger immediate automated firewall drop rule for an IP</p>
                        </div>
                    </div>
                    <form className="form-inline" onSubmit={handleBlockIp} style={{ marginBottom: "12px" }}>
                        <div className="form-group" style={{ flex: 1 }}>
                            <label className="form-label">IP Address</label>
                            <input className="form-input" value={blockIp} onChange={e => setBlockIp(e.target.value)} placeholder="192.168.1.100" required />
                        </div>
                        <div className="form-group" style={{ maxWidth: 120 }}>
                            <label className="form-label">Duration (s)</label>
                            <input className="form-input" type="number" value={blockDuration} onChange={e => setBlockDuration(e.target.value)} min="60" />
                        </div>
                        <button className="btn btn-danger" type="submit" style={{ marginTop: "auto" }}>Block IP</button>
                    </form>
                    {blockStatus && <p className={`mt-sm ${blockStatus.startsWith("✓") ? "text-safe" : "text-danger"}`} style={{ fontSize: "12px" }}>{blockStatus}</p>}
                </div>
            </div>

            {/* ─── Device Risk & User Risk Grid ─── */}
            <div className="grid-2">
                {/* ─── High Risk Devices ─── */}
                <div className="panel animate-fade-up stagger-4">
                    <div className="panel-header">
                        <div>
                            <h2>High-Risk Devices</h2>
                            <p className="panel-header-sub">Discovered network hosts with elevated risk scores</p>
                        </div>
                        <span className="chip">{riskDevices.length} host{riskDevices.length !== 1 ? "s" : ""}</span>
                    </div>
                    <div className="table-wrap">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>MAC / IP</th>
                                    <th>Type</th>
                                    <th>Risk Score</th>
                                    <th>Threats</th>
                                </tr>
                            </thead>
                            <tbody>
                                {riskDevices.length === 0 ? (
                                    <tr><td colSpan={4} className="table-empty">No high-risk devices detected</td></tr>
                                ) : (
                                    riskDevices.map((d, i) => (
                                        <tr key={i}>
                                            <td className="table-mono">
                                                <div>{d.mac}</div>
                                                {d.ip && <div style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>{d.ip}</div>}
                                            </td>
                                            <td><span className="chip" style={{ padding: "2px 8px" }}>{d.type || "Network Device"}</span></td>
                                            <td><span className={`badge ${riskColor(d.risk)}`}>{d.risk}</span></td>
                                            <td className="table-mono">{d.threats}</td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* ─── High Risk Users ─── */}
                <div className="panel animate-fade-up stagger-4">
                    <div className="panel-header">
                        <div>
                            <h2>High-Risk Accounts</h2>
                            <p className="panel-header-sub">User entities monitored for suspicious auth or volume</p>
                        </div>
                        <span className="chip">{riskUsers.length} user{riskUsers.length !== 1 ? "s" : ""}</span>
                    </div>
                    <div className="table-wrap">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>User</th>
                                    <th>Risk Score</th>
                                    <th>Threats</th>
                                </tr>
                            </thead>
                            <tbody>
                                {riskUsers.length === 0 ? (
                                    <tr><td colSpan={3} className="table-empty">No high-risk users detected</td></tr>
                                ) : (
                                    riskUsers.map((u, i) => (
                                        <tr key={i}>
                                            <td style={{ fontWeight: 600 }}>{u.user}</td>
                                            <td><span className={`badge ${riskColor(u.risk)}`}>{u.risk}</span></td>
                                            <td className="table-mono">{u.threats}</td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            {/* ─── Recent Correlated Threats ─── */}
            <div className="panel animate-fade-up stagger-5">
                <div className="panel-header">
                    <div>
                        <h2>Recent Correlated Threat Clusters</h2>
                        <p className="panel-header-sub">Correlated attack pattern indicators from the detection pipeline</p>
                    </div>
                </div>
                {recentThreats.length === 0 ? (
                    <div className="detail-box"><p className="text-muted" style={{ textAlign: "center", padding: 16 }}>No recent threat clusters detected</p></div>
                ) : (
                    <div className="table-wrap">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>Title</th>
                                    <th>Category</th>
                                    <th>Severity</th>
                                    <th>Source IP</th>
                                    <th>Time</th>
                                </tr>
                            </thead>
                            <tbody>
                                {recentThreats.map((t, idx) => (
                                    <tr key={idx}>
                                        <td style={{ fontWeight: 500 }}>{t.title || t.message || "Threat Pattern"}</td>
                                        <td><span className="chip">{t.category || "General"}</span></td>
                                        <td><span className={`badge badge-${t.severity || "medium"}`}>{(t.severity || "MED").toUpperCase()}</span></td>
                                        <td className="table-mono">{t.source_ip || "—"}</td>
                                        <td className="table-mono">{t.timestamp ? new Date(t.timestamp).toLocaleTimeString() : "—"}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
}
