import { useEffect, useRef, useState, useCallback } from "react";
import { apiFetch } from "../services/api";
import { useRealtime } from "../hooks/useRealtime";

const SEVERITY_LEVELS = ["all", "critical", "high", "medium", "low"];
const STATUS_OPTIONS = ["new", "acknowledged", "investigating", "resolved", "false_positive"];

export default function AlertsTab({ currentUser }) {
    const [alerts, setAlerts] = useState([]);
    const [filter, setFilter] = useState("all");
    const [statusFilter, setStatusFilter] = useState("all");
    const [refreshing, setRefreshing] = useState(false);
    const [error, setError] = useState("");
    const [selectedIds, setSelectedIds] = useState(new Set());
    const logRef = useRef(null);

    const isViewer = currentUser?.role === "viewer";

    const fetchAlerts = async (signal) => {
        const res = await apiFetch("/api/alerts", { signal });
        if (!res.ok) throw new Error("Failed to fetch alerts");
        const data = await res.json();
        setAlerts(Array.isArray(data.alerts) ? data.alerts : []);
        setError("");
    };

    // Real-time WebSocket hook: instant prepend for newly arriving alerts
    useRealtime(useCallback((event) => {
        if (event.type === "alert_created") {
            const newAlert = event.data;
            if (newAlert && newAlert.id) {
                setAlerts(prev => {
                    if (prev.some(a => a.id === newAlert.id)) return prev;
                    return [newAlert, ...prev];
                });
            }
        } else if (event.type === "alert_triaged") {
            const { id, status, assignee, notes } = event.data;
            setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: status ?? a.status, assignee: assignee ?? a.assignee, notes: notes ?? a.notes } : a));
        } else if (event.type === "alerts_bulk_updated") {
            const { alert_ids, action, status_value } = event.data;
            const idSet = new Set(alert_ids);
            if (action === "delete") {
                setAlerts(prev => prev.filter(a => !idSet.has(a.id)));
                setSelectedIds(new Set());
            } else if (action === "status" && status_value) {
                setAlerts(prev => prev.map(a => idSet.has(a.id) ? { ...a, status: status_value } : a));
            }
        }
    }, []));

    useEffect(() => {
        let mounted = true;
        const controller = new AbortController();
        const refresh = async () => {
            try {
                await fetchAlerts(controller.signal);
            } catch (e) {
                if (!mounted || e?.name === "AbortError") return;
                setError(e?.message ?? "Connection failed");
            }
        };
        refresh();
        const id = setInterval(refresh, 3000);
        return () => { mounted = false; controller.abort(); clearInterval(id); };
    }, []);

    const handleRefresh = async () => {
        setRefreshing(true);
        try { await fetchAlerts(); } catch (e) { setError(e?.message ?? "Refresh failed"); }
        finally { setRefreshing(false); }
    };

    const handleTriageChange = async (alertId, newStatus) => {
        if (isViewer) {
            alert("Viewer role is read-only. Login as Analyst or Admin to triage alerts.");
            return;
        }
        try {
            const res = await apiFetch(`/api/alerts/${alertId}/triage`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ status: newStatus }),
            });
            if (!res.ok) throw new Error("Triage update failed");
            setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: newStatus } : a));
        } catch (err) {
            alert(err.message || "Triage failed");
        }
    };

    const toggleSelectAll = () => {
        if (selectedIds.size === filtered.length && filtered.length > 0) {
            setSelectedIds(new Set());
        } else {
            setSelectedIds(new Set(filtered.map(a => a.id)));
        }
    };

    const toggleSelect = (id) => {
        setSelectedIds(prev => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    };

    const handleBulkAction = async (action, statusValue = null) => {
        if (selectedIds.size === 0) return;
        if (isViewer) {
            alert("Viewer role is read-only. Login as Analyst or Admin for bulk actions.");
            return;
        }
        try {
            const res = await apiFetch("/api/alerts/bulk", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    alert_ids: Array.from(selectedIds),
                    action,
                    status_value: statusValue,
                }),
            });
            if (!res.ok) throw new Error("Bulk action failed");
            await fetchAlerts();
            setSelectedIds(new Set());
        } catch (err) {
            alert(err.message || "Bulk action failed");
        }
    };

    // Export helpers
    const exportCSV = () => {
        const headers = ["ID", "Timestamp", "Source", "Category", "Severity", "Status", "Message"];
        const rows = filtered.map(a => [
            a.id,
            a.timestamp,
            `"${a.source}"`,
            `"${a.category}"`,
            a.severity,
            a.status || "new",
            `"${(a.message || '').replace(/"/g, '""')}"`,
        ]);
        const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", `volcano_alerts_${Date.now()}.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    const exportJSON = () => {
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filtered, null, 2));
        const link = document.createElement("a");
        link.setAttribute("href", dataStr);
        link.setAttribute("download", `volcano_alerts_${Date.now()}.json`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    const filtered = alerts.filter(a => {
        const matchesSev = filter === "all" || String(a.severity).toLowerCase() === filter;
        const matchesStatus = statusFilter === "all" || (a.status || "new") === statusFilter;
        return matchesSev && matchesStatus;
    });

    const severityCounts = alerts.reduce((acc, a) => {
        const s = String(a.severity).toLowerCase();
        acc[s] = (acc[s] || 0) + 1;
        return acc;
    }, {});

    const renderPorts = (meta) => {
        const ports = meta?.unique_ports ?? meta?.port_samples?.map(i => i.port) ?? meta?.destination_port;
        if (Array.isArray(ports)) return ports.length ? ports.slice(0, 6).join(", ") : "—";
        return ports ?? "—";
    };

    return (
        <div className="tab-content" key="alerts">
            <div className="tab-header">
                <div className="tab-header-info">
                    <div className="tab-eyebrow">🔔 Live Alerts & Triage</div>
                    <h1>Security Event Stream</h1>
                    <p className="tab-subtitle">
                        Real-time feed of detected anomalies, blocked connections, and threat events with active triage and RBAC controls.
                    </p>
                </div>
                <div className="tab-header-actions" style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                    <button className="btn" onClick={exportCSV} title="Export as CSV">📥 CSV</button>
                    <button className="btn" onClick={exportJSON} title="Export as JSON">📥 JSON</button>
                    <button className="btn" onClick={handleRefresh} disabled={refreshing}>
                        {refreshing ? "Refreshing…" : "↻ Refresh"}
                    </button>
                </div>
            </div>

            {/* Stats row */}
            <div className="stats-grid" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
                <div className="stat-card animate-fade-up stagger-1">
                    <div className="card-label">Total Alerts</div>
                    <div className="card-value">{alerts.length}</div>
                </div>
                <div className="stat-card accent animate-fade-up stagger-2">
                    <div className="card-label">Critical</div>
                    <div className="card-value text-danger">{severityCounts.critical || 0}</div>
                </div>
                <div className="stat-card animate-fade-up stagger-3">
                    <div className="card-label">High</div>
                    <div className="card-value">{severityCounts.high || 0}</div>
                </div>
                <div className="stat-card animate-fade-up stagger-4">
                    <div className="card-label">Medium / Low</div>
                    <div className="card-value">{(severityCounts.medium || 0) + (severityCounts.low || 0)}</div>
                </div>
            </div>

            {/* Filters & Bulk Controls Bar */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px", margin: "16px 0" }}>
                <div className="filter-bar" style={{ margin: 0 }}>
                    {SEVERITY_LEVELS.map(s => (
                        <button
                            key={s}
                            className={`filter-pill${filter === s ? " active" : ""}`}
                            onClick={() => setFilter(s)}
                        >
                            {s === "all" ? `All (${alerts.length})` : `${s.charAt(0).toUpperCase() + s.slice(1)} (${severityCounts[s] || 0})`}
                        </button>
                    ))}
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <select
                        className="form-select"
                        value={statusFilter}
                        onChange={(e) => setStatusFilter(e.target.value)}
                        style={{ padding: "6px 28px 6px 10px", fontSize: "0.82rem" }}
                    >
                        <option value="all">Status: All</option>
                        {STATUS_OPTIONS.map(st => (
                            <option key={st} value={st}>{st.replace("_", " ").toUpperCase()}</option>
                        ))}
                    </select>

                    {selectedIds.size > 0 && !isViewer && (
                        <div style={{ display: "flex", gap: "6px" }}>
                            <button
                                className="btn"
                                style={{ padding: "6px 12px", fontSize: "0.8rem", background: "rgba(34, 197, 94, 0.15)", borderColor: "rgba(34, 197, 94, 0.4)" }}
                                onClick={() => handleBulkAction("status", "resolved")}
                            >
                                ✓ Resolve ({selectedIds.size})
                            </button>
                            <button
                                className="btn"
                                style={{ padding: "6px 12px", fontSize: "0.8rem", background: "rgba(239, 68, 68, 0.15)", borderColor: "rgba(239, 68, 68, 0.4)", color: "#f87171" }}
                                onClick={() => handleBulkAction("delete")}
                            >
                                ✕ Delete ({selectedIds.size})
                            </button>
                        </div>
                    )}
                </div>
            </div>

            {/* Alert Table */}
            <div className="panel animate-fade-up stagger-3">
                <div className="table-wrap" ref={logRef} style={{ maxHeight: "540px" }}>
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th style={{ width: "36px" }}>
                                    <input
                                        type="checkbox"
                                        checked={selectedIds.size === filtered.length && filtered.length > 0}
                                        onChange={toggleSelectAll}
                                        disabled={isViewer}
                                    />
                                </th>
                                <th>Time</th>
                                <th>Source</th>
                                <th>Category</th>
                                <th>Severity</th>
                                <th>Status / Triage</th>
                                <th>Port(s)</th>
                                <th>Protocol</th>
                                <th>Message</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.length === 0 ? (
                                <tr>
                                    <td colSpan={9} className="table-empty">
                                        {alerts.length === 0 ? "No alerts recorded yet. The system is monitoring for anomalies." : "No alerts match the selected filter."}
                                    </td>
                                </tr>
                            ) : (
                                filtered.map(alert => (
                                    <tr key={alert.id}>
                                        <td>
                                            <input
                                                type="checkbox"
                                                checked={selectedIds.has(alert.id)}
                                                onChange={() => toggleSelect(alert.id)}
                                                disabled={isViewer}
                                            />
                                        </td>
                                        <td className="table-mono" style={{ whiteSpace: "nowrap" }}>
                                            {new Date(alert.timestamp).toLocaleTimeString()}
                                        </td>
                                        <td>{alert.source}</td>
                                        <td>{alert.category}</td>
                                        <td>
                                            <span className={`badge badge-${String(alert.severity).toLowerCase()}`}>
                                                {alert.severity}
                                            </span>
                                        </td>
                                        <td>
                                            <select
                                                className="form-select"
                                                value={alert.status || "new"}
                                                onChange={(e) => handleTriageChange(alert.id, e.target.value)}
                                                disabled={isViewer}
                                                style={{
                                                    padding: "4px 24px 4px 8px",
                                                    fontSize: "0.76rem",
                                                    fontWeight: 600,
                                                    borderRadius: "4px",
                                                    color: (alert.status === "resolved" ? "#22c55e" : (alert.status === "investigating" ? "#eab308" : "inherit")),
                                                }}
                                            >
                                                {STATUS_OPTIONS.map(st => (
                                                    <option key={st} value={st}>{st.replace("_", " ")}</option>
                                                ))}
                                            </select>
                                        </td>
                                        <td className="table-mono">{renderPorts(alert.meta)}</td>
                                        <td>{alert.meta?.protocol ?? "—"}</td>
                                        <td style={{ maxWidth: "300px" }}>{alert.message}</td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
                {error && <p className="inline-error">{error}</p>}
            </div>
        </div>
    );
}
