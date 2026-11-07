import { useEffect, useState } from "react";
import { apiFetch } from "../services/api";

export default function ThreatIntelTab() {
    const [threatSummary, setThreatSummary] = useState(null);
    const [riskDevices, setRiskDevices] = useState([]);
    const [riskUsers, setRiskUsers] = useState([]);
    const [recentThreats, setRecentThreats] = useState([]);
    const [feedsData, setFeedsData] = useState(null);
    const [syncingFeeds, setSyncingFeeds] = useState(false);
    const [feedSyncMsg, setFeedSyncMsg] = useState("");

    // Quick IoC Lookup
    const [lookupTarget, setLookupTarget] = useState("");
    const [lookupResult, setLookupResult] = useState(null);
    const [lookupLoading, setLookupLoading] = useState(false);

    // DNS Threat & Shannon Entropy Inspector
    const [dnsDomain, setDnsDomain] = useState("");
    const [dnsResult, setDnsResult] = useState(null);
    const [dnsLoading, setDnsLoading] = useState(false);

    // Brute Force Defense Stats
    const [bfStats, setBfStats] = useState(null);

    // Autonomous Block
    const [blockIp, setBlockIp] = useState("");
    const [blockDuration, setBlockDuration] = useState("3600");
    const [blockStatus, setBlockStatus] = useState("");
    const [loading, setLoading] = useState(false);

    const fetchAll = async () => {
        setLoading(true);
        try {
            const [tRes, dRes, uRes, rRes, fRes, bRes] = await Promise.all([
                apiFetch("/api/threat-summary"),
                apiFetch("/api/risk/devices"),
                apiFetch("/api/risk/users"),
                apiFetch("/api/threats/recent"),
                apiFetch("/api/threats/feeds"),
                apiFetch("/api/security/brute-force/stats"),
            ]);
            if (tRes.ok) setThreatSummary(await tRes.json());
            if (dRes.ok) {
                const dData = await dRes.json().catch(() => []);
                setRiskDevices(Array.isArray(dData) ? dData : (Array.isArray(dData?.devices) ? dData.devices : []));
            }
            if (uRes.ok) {
                const uData = await uRes.json().catch(() => []);
                setRiskUsers(Array.isArray(uData) ? uData : (Array.isArray(uData?.users) ? uData.users : []));
            }
            if (rRes.ok) {
                const rData = await rRes.json().catch(() => []);
                setRecentThreats(Array.isArray(rData) ? rData : (Array.isArray(rData?.threats) ? rData.threats : []));
            }
            if (fRes.ok) setFeedsData(await fRes.json());
            if (bRes.ok) setBfStats(await bRes.json());
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

    const handleDnsInspect = async (e, customDomain = null) => {
        if (e && e.preventDefault) e.preventDefault();
        const target = (customDomain !== null ? customDomain : dnsDomain).trim();
        if (!target) return;
        setDnsDomain(target);
        setDnsLoading(true);
        setDnsResult(null);
        try {
            const res = await apiFetch("/api/security/dns/inspect", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain: target, src_ip: "127.0.0.1" }),
            });
            if (res.ok) {
                setDnsResult(await res.json());
            } else {
                setDnsResult({ error: "DNS inspection request failed." });
            }
        } catch (err) {
            setDnsResult({ error: err.message });
        }
        setDnsLoading(false);
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

            {/* ─── Shannon Entropy & Brute Force Defense Grid ─── */}
            <div className="grid-2">
                {/* ─── Shannon Entropy & DNS Tunneling Inspector ─── */}
                <div className="panel animate-fade-up stagger-3">
                    <div className="panel-header">
                        <div>
                            <h2>🧪 Shannon Entropy & DNS Tunneling Hunter</h2>
                            <p className="panel-header-sub">Calculates Shannon entropy H(X) and detects DGA botnet domains</p>
                        </div>
                    </div>
                    <form className="form-inline" onSubmit={handleDnsInspect} style={{ marginBottom: "10px" }}>
                        <div className="form-group" style={{ flex: 1 }}>
                            <input
                                className="form-input"
                                value={dnsDomain}
                                onChange={e => setDnsDomain(e.target.value)}
                                placeholder="e.g. c2VjcmV0ZGF0YQ.tunnel.evilcorp.com"
                                required
                            />
                        </div>
                        <button className="btn btn-primary" type="submit" disabled={dnsLoading}>
                            {dnsLoading ? "Calculating..." : "Inspect Domain"}
                        </button>
                    </form>

                    {/* Quick evaluation presets */}
                    <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginBottom: "12px", alignItems: "center" }}>
                        <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Quick Test:</span>
                        <button
                            type="button"
                            className="chip"
                            style={{ cursor: "pointer", fontSize: "0.72rem" }}
                            onClick={() => handleDnsInspect(null, "google.com")}
                        >
                            ✓ Clean: google.com
                        </button>
                        <button
                            type="button"
                            className="chip"
                            style={{ cursor: "pointer", fontSize: "0.72rem", color: "#f59e0b" }}
                            onClick={() => handleDnsInspect(null, "v8q9z3p2k1m5x7r.c2-pool.ru")}
                        >
                            ⚠️ DGA Pattern
                        </button>
                        <button
                            type="button"
                            className="chip"
                            style={{ cursor: "pointer", fontSize: "0.72rem", color: "#ef4444" }}
                            onClick={() => handleDnsInspect(null, "c2VjcmV0ZGF0YXRvYmVleGZpbHRyYXRlZDFmMjM0.tunnel.evilcorp.com")}
                        >
                            🔴 Exfiltration Tunnel
                        </button>
                    </div>

                    {dnsResult && (
                        <div style={{ background: "rgba(255, 255, 255, 0.03)", padding: "14px", borderRadius: "8px", border: "1px solid rgba(255, 255, 255, 0.08)" }}>
                            {dnsResult.error ? (
                                <p className="text-danger" style={{ margin: 0, fontSize: "0.85rem" }}>{dnsResult.error}</p>
                            ) : (
                                <>
                                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
                                        <span style={{ fontWeight: 600, fontSize: "0.9rem" }}>{dnsResult.analysis?.domain}</span>
                                        <span className={`badge ${dnsResult.is_threat ? "badge-critical" : "badge-safe"}`}>
                                            {dnsResult.is_threat ? `⚠️ THREAT: ${dnsResult.alert?.category || "MALICIOUS DNS"}` : "✓ BENIGN QUERY"}
                                        </span>
                                    </div>

                                    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "8px", marginBottom: "10px", textAlign: "center" }}>
                                        <div style={{ background: "rgba(0,0,0,0.25)", padding: "8px", borderRadius: "6px" }}>
                                            <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>Subdomain Entropy</div>
                                            <div style={{ fontSize: "1.1rem", fontWeight: 700, color: (dnsResult.analysis?.subdomain_entropy > 3.8 ? "#ef4444" : "#22c55e") }}>
                                                {dnsResult.analysis?.subdomain_entropy ?? 0}
                                            </div>
                                            <div style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>Threshold: 3.80</div>
                                        </div>
                                        <div style={{ background: "rgba(0,0,0,0.25)", padding: "8px", borderRadius: "6px" }}>
                                            <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>Base Domain Entropy</div>
                                            <div style={{ fontSize: "1.1rem", fontWeight: 700, color: (dnsResult.analysis?.base_entropy > 3.5 ? "#f59e0b" : "#22c55e") }}>
                                                {dnsResult.analysis?.base_entropy ?? 0}
                                            </div>
                                            <div style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>Threshold: 3.50</div>
                                        </div>
                                        <div style={{ background: "rgba(0,0,0,0.25)", padding: "8px", borderRadius: "6px" }}>
                                            <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>Vowel Ratio</div>
                                            <div style={{ fontSize: "1.1rem", fontWeight: 700 }}>
                                                {((dnsResult.analysis?.vowel_ratio ?? 0) * 100).toFixed(1)}%
                                            </div>
                                            <div style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>Consonants: {dnsResult.analysis?.consecutive_consonants ?? 0} max</div>
                                        </div>
                                    </div>

                                    {dnsResult.alert && (
                                        <div style={{ fontSize: "0.78rem", background: "rgba(239, 68, 68, 0.12)", border: "1px solid rgba(239, 68, 68, 0.3)", padding: "8px 10px", borderRadius: "6px", color: "#fca5a5" }}>
                                            <strong>Detection Signal:</strong> {dnsResult.alert.message}
                                        </div>
                                    )}
                                </>
                            )}
                        </div>
                    )}
                </div>

                {/* ─── Brute-Force & Credential Stuffing Defenses ─── */}
                <div className="panel animate-fade-up stagger-3">
                    <div className="panel-header">
                        <div>
                            <h2>🛡️ Credential Stuffing & Auth Defenses</h2>
                            <p className="panel-header-sub">Monitors repeated connection bursts across SSH, RDP, and FTP</p>
                        </div>
                        <span className="chip chip-live">Active Sensor</span>
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "8px", marginBottom: "14px", textAlign: "center" }}>
                        <div style={{ background: "rgba(0,0,0,0.25)", padding: "10px", borderRadius: "6px" }}>
                            <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Monitored Ports</div>
                            <div style={{ fontSize: "1rem", fontWeight: 700, color: "var(--accent)" }}>
                                {bfStats?.monitored_ports?.join(", ") || "22, 3389, 21"}
                            </div>
                            <div style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>SSH, RDP, FTP</div>
                        </div>
                        <div style={{ background: "rgba(0,0,0,0.25)", padding: "10px", borderRadius: "6px" }}>
                            <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Max Threshold</div>
                            <div style={{ fontSize: "1rem", fontWeight: 700 }}>
                                {bfStats?.threshold_attempts || 15} fails
                            </div>
                            <div style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>in {bfStats?.window_seconds || 60}s window</div>
                        </div>
                        <div style={{ background: "rgba(0,0,0,0.25)", padding: "10px", borderRadius: "6px" }}>
                            <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Active Suspects</div>
                            <div style={{ fontSize: "1rem", fontWeight: 700, color: (bfStats?.total_suspects > 0 ? "#ef4444" : "#22c55e") }}>
                                {bfStats?.total_suspects || 0}
                            </div>
                            <div style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>Under quarantine</div>
                        </div>
                    </div>

                    <div style={{ fontSize: "0.8rem", color: "var(--text-secondary)", background: "rgba(255,255,255,0.02)", padding: "10px 12px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.06)" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
                            <span style={{ fontWeight: 600 }}>Autonomous Containment:</span>
                            <span className="badge badge-safe">ENFORCED</span>
                        </div>
                        <p style={{ margin: 0, fontSize: "0.75rem", lineHeight: 1.4 }}>
                            Any host exceeding {bfStats?.threshold_attempts || 15} failed handshakes within {bfStats?.window_seconds || 60} seconds is automatically pushed to the autonomous quarantine queue with a 1-hour containment TTL and logged under MITRE technique <code>T1110 (Brute Force)</code>.
                        </p>
                    </div>
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
