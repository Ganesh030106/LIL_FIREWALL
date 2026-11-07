import { useEffect, useState } from "react";
import { apiFetch } from "../services/api";

function DataTable({ title, subtitle, columns, rows, keyMap }) {
    return (
        <div className="panel animate-fade-up">
            <div className="panel-header">
                <div>
                    <h2>{title}</h2>
                    {subtitle && <p className="panel-header-sub">{subtitle}</p>}
                </div>
                <span className="chip">{rows.length} record{rows.length !== 1 ? "s" : ""}</span>
            </div>
            <div className="table-wrap">
                <table className="data-table">
                    <thead>
                        <tr>{columns.map(c => <th key={c}>{c}</th>)}</tr>
                    </thead>
                    <tbody>
                        {rows.length === 0 ? (
                            <tr><td colSpan={columns.length} className="table-empty">No records found</td></tr>
                        ) : (
                            rows.map((r, i) => (
                                <tr key={i}>
                                    {columns.map(c => {
                                        const key = keyMap?.[c] || c.toLowerCase();
                                        const val = r[key] ?? r[c] ?? r[c.toLowerCase()] ?? "—";
                                        return <td key={c} className="table-mono">{String(val)}</td>;
                                    })}
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

export default function HistoryTab() {
    const [searches, setSearches] = useState([]);
    const [fileShares, setFileShares] = useState([]);
    const [ports, setPorts] = useState([]);
    const [connections, setConnections] = useState([]);
    const [pcapStats, setPcapStats] = useState(null);
    const [searchFilter, setSearchFilter] = useState("");
    const [loading, setLoading] = useState(false);
    const [downloadingPcap, setDownloadingPcap] = useState(false);

    const fetchAll = async () => {
        setLoading(true);
        try {
            const [sRes, fRes, pRes, cRes, pcRes] = await Promise.all([
                apiFetch("/api/history/searches"),
                apiFetch("/api/history/file-shares"),
                apiFetch("/api/history/ports"),
                apiFetch("/api/current/connections"),
                apiFetch("/api/pcap/stats"),
            ]);
            if (sRes.ok) { const d = await sRes.json(); setSearches(d.searches || []); }
            if (fRes.ok) { const d = await fRes.json(); setFileShares(d.file_shares || []); }
            if (pRes.ok) { const d = await pRes.json(); setPorts(d.ports || []); }
            if (cRes.ok) { const d = await cRes.json(); setConnections(d.connections || []); }
            if (pcRes.ok) { setPcapStats(await pcRes.json()); }
        } catch {}
        setLoading(false);
    };

    useEffect(() => {
        fetchAll();
        const id = setInterval(fetchAll, 4000);
        return () => clearInterval(id);
    }, []);

    const handleDownloadPcap = async () => {
        setDownloadingPcap(true);
        try {
            const res = await apiFetch("/api/pcap/export");
            if (!res.ok) throw new Error("PCAP export failed");
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `firewall_capture_${Date.now()}.pcap`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        } catch (err) {
            alert(`Failed to download PCAP capture: ${err.message}`);
        }
        setDownloadingPcap(false);
    };

    const q = searchFilter.toLowerCase().trim();
    const filterRows = (rows, keys) => {
        if (!q) return rows;
        return rows.filter(r =>
            keys.some(k => {
                const val = r[k] ?? "";
                return String(val).toLowerCase().includes(q);
            })
        );
    };

    const filteredSearches = filterRows(searches, ["who", "query", "url"]);
    const filteredFileShares = filterRows(fileShares, ["who", "filename", "dest_ip"]);
    const filteredPorts = filterRows(ports, ["src", "dst", "port", "protocol"]);
    const filteredConnections = filterRows(connections, ["src", "dst", "port", "protocol"]);

    return (
        <div className="tab-content" key="history">
            <div className="tab-header">
                <div className="tab-header-info">
                    <div className="tab-eyebrow">📜 Digital Forensics & History</div>
                    <h1>Activity Logs & Forensic Capture</h1>
                    <p className="tab-subtitle">
                        Historical audit logs of DNS queries, file system events, port activity, and rolling circular PCAP buffer for Wireshark inspection.
                    </p>
                </div>
                <div className="tab-header-actions" style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                    <button
                        className="btn btn-primary"
                        onClick={handleDownloadPcap}
                        disabled={downloadingPcap}
                        title="Download rolling circular PCAP capture"
                    >
                        {downloadingPcap ? "Generating PCAP…" : "📥 Download PCAP Capture"}
                    </button>
                    <button className="btn" onClick={fetchAll} disabled={loading}>
                        {loading ? "Loading…" : "↻ Refresh"}
                    </button>
                </div>
            </div>

            {/* PCAP Buffer Bar & Search Filter */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "12px", margin: "14px 0" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                    {pcapStats && (
                        <div className="chip chip-live" style={{ fontSize: "0.78rem" }}>
                            PCAP Ring Buffer: {pcapStats.packet_count ?? 0} / {pcapStats.maxlen ?? 1000} frames (
                            {pcapStats.maxlen ? Math.round(((pcapStats.packet_count ?? 0) / pcapStats.maxlen) * 100) : 0}% capacity)
                        </div>
                    )}
                </div>

                <div style={{ position: "relative", minWidth: "260px" }}>
                    <input
                        type="text"
                        className="form-input"
                        value={searchFilter}
                        onChange={(e) => setSearchFilter(e.target.value)}
                        placeholder="Search forensic history across all tables..."
                        style={{ padding: "6px 26px 6px 10px", fontSize: "0.82rem", width: "100%" }}
                    />
                    {searchFilter && (
                        <button
                            onClick={() => setSearchFilter("")}
                            style={{ position: "absolute", right: "8px", top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", fontSize: "0.8rem" }}
                        >
                            ✕
                        </button>
                    )}
                </div>
            </div>

            <div className="grid-2">
                <DataTable
                    title="DNS & Web Activity (Live Capture)"
                    subtitle="Real-time DNS query and domain resolution activity"
                    columns={["Timestamp", "Source Host", "Query", "URL"]}
                    rows={filteredSearches}
                    keyMap={{ Timestamp: "timestamp", "Source Host": "who", Query: "query", URL: "url" }}
                />
                <DataTable
                    title="File System & Transfer Activity (Live Watchdog)"
                    subtitle="Live filesystem modifications and transfer events"
                    columns={["Timestamp", "Source", "File / Stream", "Dest IP"]}
                    rows={filteredFileShares}
                    keyMap={{ Timestamp: "timestamp", Source: "who", "File / Stream": "filename", "Dest IP": "dest_ip" }}
                />
            </div>

            <div className="grid-2 mt-md">
                <DataTable
                    title="Port Activity"
                    subtitle="Historical port access records"
                    columns={["Timestamp", "Src", "Dst", "Port", "Protocol"]}
                    rows={filteredPorts}
                    keyMap={{ Timestamp: "timestamp", Src: "src", Dst: "dst", Port: "port", Protocol: "protocol" }}
                />
                <DataTable
                    title="Current Connections"
                    subtitle="Active network connections"
                    columns={["Src", "Dst", "Port", "Protocol", "Last Seen"]}
                    rows={filteredConnections}
                    keyMap={{ Src: "src", Dst: "dst", Port: "port", Protocol: "protocol", "Last Seen": "last_seen" }}
                />
            </div>
        </div>
    );
}
