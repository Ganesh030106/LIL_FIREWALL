import { useEffect, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";

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
                            <tr><td colSpan={columns.length} className="table-empty">No records</td></tr>
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
    const [loading, setLoading] = useState(false);

    const fetchAll = async () => {
        setLoading(true);
        try {
            const [sRes, fRes, pRes, cRes] = await Promise.all([
                fetch(`${API_BASE}/api/history/searches`),
                fetch(`${API_BASE}/api/history/file-shares`),
                fetch(`${API_BASE}/api/history/ports`),
                fetch(`${API_BASE}/api/current/connections`),
            ]);
            if (sRes.ok) { const d = await sRes.json(); setSearches(d.searches || []); }
            if (fRes.ok) { const d = await fRes.json(); setFileShares(d.file_shares || []); }
            if (pRes.ok) { const d = await pRes.json(); setPorts(d.ports || []); }
            if (cRes.ok) { const d = await cRes.json(); setConnections(d.connections || []); }
        } catch {}
        setLoading(false);
    };

    useEffect(() => { fetchAll(); }, []);

    return (
        <div className="tab-content" key="history">
            <div className="tab-header">
                <div className="tab-header-info">
                    <div className="tab-eyebrow">📜 History</div>
                    <h1>Activity Logs & History</h1>
                    <p className="tab-subtitle">
                        Browse historical records of web searches, file shares, port activity, and active connections tracked by the monitoring system.
                    </p>
                </div>
                <div className="tab-header-actions">
                    <button className="btn" onClick={fetchAll} disabled={loading}>
                        {loading ? "Loading…" : "↻ Refresh"}
                    </button>
                </div>
            </div>

            <div className="grid-2">
                <DataTable
                    title="DNS & Web Activity (Live Capture)"
                    subtitle="Real-time DNS query and domain resolution activity"
                    columns={["Timestamp", "Source Host", "Query", "URL"]}
                    rows={searches}
                    keyMap={{ Timestamp: "timestamp", "Source Host": "who", Query: "query", URL: "url" }}
                />
                <DataTable
                    title="File System & Transfer Activity (Live Watchdog)"
                    subtitle="Live filesystem modifications and transfer events"
                    columns={["Timestamp", "Source", "File / Stream", "Dest IP"]}
                    rows={fileShares}
                    keyMap={{ Timestamp: "timestamp", Source: "who", "File / Stream": "filename", "Dest IP": "dest_ip" }}
                />
            </div>

            <div className="grid-2 mt-md">
                <DataTable
                    title="Port Activity"
                    subtitle="Historical port access records"
                    columns={["Timestamp", "Src", "Dst", "Port", "Protocol"]}
                    rows={ports}
                    keyMap={{ Timestamp: "timestamp", Src: "src", Dst: "dst", Port: "port", Protocol: "protocol" }}
                />
                <DataTable
                    title="Current Connections"
                    subtitle="Active network connections"
                    columns={["Src", "Dst", "Port", "Protocol", "Last Seen"]}
                    rows={connections}
                    keyMap={{ Src: "src", Dst: "dst", Port: "port", Protocol: "protocol", "Last Seen": "last_seen" }}
                />
            </div>
        </div>
    );
}
