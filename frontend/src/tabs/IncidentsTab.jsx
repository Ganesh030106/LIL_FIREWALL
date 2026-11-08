import { useEffect, useState, useCallback, useMemo } from "react";
import { apiFetch } from "../services/api";
import { useRealtime } from "../hooks/useRealtime";

const KILL_CHAIN_STAGES = [
    { key: "reconnaissance", label: "Reconnaissance", icon: "🔍", desc: "Network scanning & probe activity" },
    { key: "initial_access", label: "Initial Access", icon: "🚪", desc: "Entry attempts & exploit payloads" },
    { key: "execution", label: "Execution", icon: "⚡", desc: "Unauthorized commands & code execution" },
    { key: "persistence", label: "Persistence", icon: "⚓", desc: "Backdoors & scheduled implants" },
    { key: "lateral_movement", label: "Lateral Movement", icon: "🔄", desc: "Internal pivot & credential hopping" },
    { key: "command_and_control", label: "C2 Beaconing", icon: "📡", desc: "External beaconing & rhythmic telemetry" },
    { key: "exfiltration", label: "Exfiltration", icon: "📤", desc: "Data siphon & encrypted transfer" },
];

const AVAILABLE_PLAYBOOKS = [
    { id: "ssh-brute-force-response", name: "SSH Brute-Force Autonomous Mitigation", target: "source_ip", desc: "Blocks offending source IP, revokes active socket sessions, notifies SOC channel." },
    { id: "port-scan-response", name: "Port Scan Rapid Perimeter Quarantine", target: "source_ip", desc: "Quarantines reconnaissance scanners, lowers SYN rate-limits, dumps PCAP capture." },
    { id: "syn-flood-response", name: "SYN Flood Autonomous Rate Limiter", target: "source_ip", desc: "Applies kernel drop rule, enables TCP SYN cookies, verifies pipeline stability." },
    { id: "dns-tunneling-response", name: "DNS Tunneling Isolation & Blackhole", target: "source_ip", desc: "Blackholes rogue DNS queries, flushes local resolver cache, isolates host." },
    { id: "ransomware-containment-response", name: "Ransomware Endpoint Rapid Quarantine", target: "source_ip", desc: "Isolates compromised host network adapter, snapshots canary files, generates forensic report." },
];

export default function IncidentsTab({ currentUser }) {
    const [incidents, setIncidents] = useState([]);
    const [selectedIncident, setSelectedIncident] = useState(null);
    const [filterStatus, setFilterStatus] = useState("all");
    const [filterSeverity, setFilterSeverity] = useState("all");
    const [searchQuery, setSearchQuery] = useState("");
    const [loading, setLoading] = useState(true);
    const [correlating, setCorrelating] = useState(false);
    const [error, setError] = useState("");
    const [actionMsg, setActionMsg] = useState("");

    // PCAP evidence state
    const [pcapHash, setPcapHash] = useState("");
    const [downloadingPcap, setDownloadingPcap] = useState(false);

    // Playbook execution state
    const [selectedPlaybook, setSelectedPlaybook] = useState(AVAILABLE_PLAYBOOKS[0].id);
    const [isDryRun, setIsDryRun] = useState(true);
    const [executingPlaybook, setExecutingPlaybook] = useState(false);
    const [playbookResult, setPlaybookResult] = useState(null);

    // Analyst notes state
    const [newNote, setNewNote] = useState("");
    const [addingNote, setAddingNote] = useState(false);

    const isViewer = false;

    const fetchIncidents = useCallback(async (signal) => {
        try {
            const res = await apiFetch("/api/incidents", { signal });
            if (!res.ok) throw new Error("Failed to load incidents");
            const data = await res.json();
            const list = Array.isArray(data.incidents) ? data.incidents : [];
            setIncidents(list);
            setError("");
            return list;
        } catch (e) {
            if (e?.name !== "AbortError") {
                setError(e.message || "Failed to connect to incidents API");
            }
            return [];
        } finally {
            setLoading(false);
        }
    }, []);

    // WebSocket event hook for real-time incident notifications
    useRealtime(useCallback((event) => {
        if (event.type === "alert_created") {
            // New alert could correlate into incidents; refresh quietly
            fetchIncidents();
        } else if (event.type === "reconnected") {
            fetchIncidents();
        }
    }, [fetchIncidents]));

    useEffect(() => {
        let mounted = true;
        const controller = new AbortController();
        fetchIncidents(controller.signal).then(list => {
            if (mounted && list.length > 0 && !selectedIncident) {
                setSelectedIncident(list[0]);
            }
        });
        return () => {
            mounted = false;
            controller.abort();
        };
    }, [fetchIncidents]);

    // Handle manual trigger of threat correlation engine
    const handleTriggerCorrelation = async () => {
        setCorrelating(true);
        setActionMsg("");
        setError("");
        try {
            const res = await apiFetch("/api/incidents/correlate", { method: "POST" });
            if (!res.ok) throw new Error("Correlation engine evaluation failed");
            const data = await res.json();
            const count = data.incidents_count ?? (Array.isArray(data.incidents) ? data.incidents.length : 0);
            setActionMsg(`✓ Threat correlation complete. Evaluated active alert telemetry into ${count} correlated security incident${count === 1 ? "" : "s"}.`);
            const refreshed = await fetchIncidents();
            if (refreshed.length > 0) {
                // Keep selected or pick first
                setSelectedIncident(prev => prev ? refreshed.find(i => (i.incident_id && i.incident_id === prev.incident_id) || i.id === prev.id) || refreshed[0] : refreshed[0]);
            }
        } catch (e) {
            setError(e.message || "Error correlating alerts");
        } finally {
            setCorrelating(false);
        }
    };

    // Update incident status or triage
    const handleStatusChange = async (newStatus) => {
        if (!selectedIncident || isViewer) return;
        try {
            const res = await apiFetch(`/api/incidents/${selectedIncident.id}`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ status: newStatus }),
            });
            if (res.ok) {
                const updated = { ...selectedIncident, status: newStatus };
                setSelectedIncident(updated);
                setIncidents(prev => prev.map(i => i.id === updated.id ? updated : i));
                setActionMsg(`✓ Incident status updated to '${newStatus}'.`);
            }
        } catch {
            setError("Failed to update status");
        }
    };

    // Add analyst note
    const handleAddNote = async (e) => {
        e.preventDefault();
        if (!newNote.trim() || !selectedIncident || isViewer) return;
        setAddingNote(true);
        try {
            const res = await apiFetch(`/api/incidents/${selectedIncident.id}/notes`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ note: newNote.trim() }),
            });
            if (res.ok) {
                const author = currentUser?.username || "analyst";
                const now = new Date().toISOString();
                const noteObj = { note: newNote.trim(), author, created_at: now };
                const updatedNotes = Array.isArray(selectedIncident.analyst_notes)
                    ? [...selectedIncident.analyst_notes, noteObj]
                    : [noteObj];
                const updated = { ...selectedIncident, analyst_notes: updatedNotes };
                setSelectedIncident(updated);
                setIncidents(prev => prev.map(i => i.id === updated.id ? updated : i));
                setNewNote("");
                setActionMsg("✓ Analyst note recorded in investigation dossier.");
            }
        } catch {
            setError("Failed to save note");
        } finally {
            setAddingNote(false);
        }
    };

    // Download forensic PCAP with SHA-256 integrity hash verification
    const handleDownloadPcap = async () => {
        if (!selectedIncident) return;
        setDownloadingPcap(true);
        setPcapHash("");
        try {
            const res = await apiFetch(`/api/incidents/${selectedIncident.id}/pcap`);
            if (!res.ok) throw new Error("No PCAP frames available for this incident");
            const hashHeader = res.headers.get("X-Evidence-Hash-SHA256") || res.headers.get("x-evidence-hash-sha256");
            if (hashHeader) {
                setPcapHash(hashHeader);
            }
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `incident_${selectedIncident.id}_forensic.pcap`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
            setActionMsg(`✓ Forensic PCAP downloaded. Cryptographic SHA-256 Hash recorded.`);
        } catch (e) {
            setError(e.message || "Failed to download PCAP");
        } finally {
            setDownloadingPcap(false);
        }
    };

    // Execute response playbook
    const handleExecutePlaybook = async () => {
        if (!selectedIncident || isViewer) return;
        setExecutingPlaybook(true);
        setPlaybookResult(null);
        try {
            const targetIp = selectedIncident.source_ip || "192.168.1.100";
            const res = await apiFetch(`/api/playbooks/${selectedPlaybook}/execute`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    target_ip: targetIp,
                    dry_run: isDryRun,
                    incident_id: selectedIncident.id,
                }),
            });
            if (!res.ok) throw new Error("Playbook execution failed");
            const data = await res.json();
            setPlaybookResult(data);
            setActionMsg(`✓ Playbook '${selectedPlaybook}' finished in ${isDryRun ? "DRY-RUN (Simulated)" : "ACTIVE ENFORCEMENT"} mode.`);
        } catch (e) {
            setError(e.message || "Failed to execute playbook");
        } finally {
            setExecutingPlaybook(false);
        }
    };

    // Filtered incident list
    const filteredIncidents = useMemo(() => {
        return incidents.filter(inc => {
            if (filterStatus !== "all" && inc.status !== filterStatus) return false;
            if (filterSeverity !== "all" && inc.severity !== filterSeverity) return false;
            if (searchQuery.trim()) {
                const q = searchQuery.toLowerCase();
                const matchId = String(inc.id).toLowerCase().includes(q);
                const matchTitle = (inc.title || "").toLowerCase().includes(q);
                const matchSrc = (inc.source_ip || "").toLowerCase().includes(q);
                const matchDst = (inc.target_ip || "").toLowerCase().includes(q);
                const matchStage = (inc.kill_chain_stage || "").toLowerCase().includes(q);
                if (!matchId && !matchTitle && !matchSrc && !matchDst && !matchStage) return false;
            }
            return true;
        });
    }, [incidents, filterStatus, filterSeverity, searchQuery]);

    // Helper to format risk score normalized to 0-100 scale
    const formatRisk = (r) => {
        const n = Number(r) || 0;
        return n <= 1.0 ? Math.round(n * 100) : Math.round(n);
    };

    // Top metrics
    const stats = useMemo(() => {
        const total = incidents.length;
        const active = incidents.filter(i => i.status === "new" || i.status === "investigating").length;
        const critical = incidents.filter(i => String(i.severity).toLowerCase() === "critical").length;
        const avgRisk = total > 0
            ? Math.round(incidents.reduce((acc, i) => acc + formatRisk(i.risk_score), 0) / total)
            : 0;
        return { total, active, critical, avgRisk };
    }, [incidents]);

    // Helper to evaluate kill chain stage reached with flexible key/label matching
    const getStageIndex = (stageKey) => {
        if (!stageKey) return 0;
        const clean = String(stageKey).toLowerCase().replace(/[\s_-]+/g, "");
        const aliasMap = {
            reconnaissance: "reconnaissance",
            discovery: "reconnaissance",
            initialaccess: "initial_access",
            credentialaccess: "initial_access",
            defenseevasion: "initial_access",
            privilegeescalation: "execution",
            execution: "execution",
            persistence: "persistence",
            lateralmovement: "lateral_movement",
            commandandcontrol: "command_and_control",
            c2beaconing: "command_and_control",
            c2: "command_and_control",
            exfiltration: "exfiltration",
            impact: "exfiltration",
            actiononobjectives: "exfiltration",
        };
        const targetKey = aliasMap[clean] || clean;
        const idx = KILL_CHAIN_STAGES.findIndex(s => {
            const kClean = s.key.toLowerCase().replace(/[\s_-]+/g, "");
            const lClean = s.label.toLowerCase().replace(/[\s_-]+/g, "");
            return s.key === targetKey || kClean === clean || lClean === clean || clean.includes(kClean) || kClean.includes(clean);
        });
        return idx !== -1 ? idx : 0;
    };

    const currentStageIndex = selectedIncident?.kill_chain_stage
        ? getStageIndex(selectedIncident.kill_chain_stage)
        : 0;

    return (
        <div className="tab-pane animate-fade-in">
            {/* ── Header ── */}
            <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "16px" }}>
                <div>
                    <div className="card-label">Autonomous Security Operations Center</div>
                    <h1 style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <span>🚨</span> Incident Management & Response Workspace
                    </h1>
                    <p className="page-desc">
                        Correlated multi-alert incident timelines, MITRE ATTACK progression tracking, and verified automated containment playbooks.
                    </p>
                </div>
                <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                    <button
                        type="button"
                        className="btn btn-primary"
                        onClick={handleTriggerCorrelation}
                        disabled={correlating}
                        title="Run Threat Correlation Engine to synthesize raw alerts into security incidents"
                    >
                        {correlating ? "Correlating Signals..." : "⚡ Correlate Alerts Now"}
                    </button>
                    <button
                        type="button"
                        className="btn btn-ghost"
                        onClick={() => fetchIncidents()}
                        disabled={loading}
                        title="Refresh incident records"
                    >
                        🔄 Refresh
                    </button>
                </div>
            </div>

            {/* Notification Messages */}
            {actionMsg && (
                <div className="banner banner-success animate-fade-up" style={{ margin: "12px 0", display: "flex", justifyContent: "space-between" }}>
                    <span>{actionMsg}</span>
                    <button type="button" className="btn-icon" onClick={() => setActionMsg("")}>×</button>
                </div>
            )}
            {error && (
                <div className="banner banner-error animate-fade-up" style={{ margin: "12px 0", display: "flex", justifyContent: "space-between" }}>
                    <span>⚠️ {error}</span>
                    <button type="button" className="btn-icon" onClick={() => setError("")}>×</button>
                </div>
            )}

            {/* ── KPI Stat Cards ── */}
            <div className="stats-grid" style={{ marginBottom: "20px" }}>
                <div className="stat-card">
                    <div className="card-label">Total Correlated Incidents</div>
                    <div className="card-value">{stats.total}</div>
                    <div className="card-caption">Synthesized from raw alert stream</div>
                </div>
                <div className="stat-card accent">
                    <div className="card-label">Active Investigations</div>
                    <div className="card-value" style={{ color: stats.active > 0 ? "var(--warning)" : "var(--safe)" }}>
                        {stats.active}
                    </div>
                    <div className="card-caption">Status 'New' or 'Investigating'</div>
                </div>
                <div className="stat-card">
                    <div className="card-label">Critical Incidents</div>
                    <div className="card-value" style={{ color: stats.critical > 0 ? "var(--critical)" : "inherit" }}>
                        {stats.critical}
                    </div>
                    <div className="card-caption">Requiring immediate containment</div>
                </div>
                <div className="stat-card">
                    <div className="card-label">Average Risk Index</div>
                    <div className="card-value">{stats.avgRisk}<span style={{ fontSize: "1rem", color: "var(--text-muted)" }}>/100</span></div>
                    <div className="card-caption">Aggregated multi-signal risk rating</div>
                </div>
            </div>

            {/* ── Filter Bar ── */}
            <div className="filter-bar" style={{ display: "flex", gap: "12px", alignItems: "center", flexWrap: "wrap", marginBottom: "18px" }}>
                <div style={{ display: "flex", gap: "6px" }}>
                    {["all", "new", "investigating", "contained", "resolved", "false_positive"].map(st => (
                        <button
                            key={st}
                            type="button"
                            className={`btn ${filterStatus === st ? "btn-primary" : "btn-ghost"}`}
                            style={{ fontSize: "12px", padding: "6px 12px", textTransform: "capitalize" }}
                            onClick={() => setFilterStatus(st)}
                        >
                            {st === "false_positive" ? "False Pos" : st}
                        </button>
                    ))}
                </div>

                <div style={{ width: "1px", height: "20px", background: "var(--border)" }} />

                <select
                    className="select-input"
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    style={{ fontSize: "12px", padding: "6px 10px", width: "auto" }}
                >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>

                <div style={{ flex: 1, minWidth: "200px" }}>
                    <input
                        type="text"
                        className="text-input"
                        placeholder="Search by ID, IP, Title, or Kill-Chain..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        style={{ fontSize: "12px", padding: "6px 12px" }}
                    />
                </div>
            </div>

            {/* ── Main Dual-Pane Workspace ── */}
            <div style={{ display: "grid", gridTemplateColumns: "minmax(340px, 420px) 1fr", gap: "20px", alignItems: "start" }}>
                {/* ── Left Pane: Incident Feed ── */}
                <div className="panel" style={{ padding: "0", overflow: "hidden", display: "flex", flexDirection: "column", maxHeight: "800px" }}>
                    <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontWeight: 600, fontSize: "13px", letterSpacing: "0.5px", textTransform: "uppercase", color: "var(--text-muted)" }}>
                            Correlated Incidents ({filteredIncidents.length})
                        </span>
                        {loading && <span style={{ fontSize: "12px", color: "var(--accent)" }}>Syncing...</span>}
                    </div>

                    <div style={{ overflowY: "auto", flex: 1, padding: "8px" }}>
                        {filteredIncidents.length === 0 ? (
                            <div style={{ padding: "40px 20px", textAlign: "center", color: "var(--text-muted)" }}>
                                <div style={{ fontSize: "2rem", marginBottom: "8px" }}>🛡️</div>
                                <div style={{ fontWeight: 600 }}>No Incidents Found</div>
                                <div style={{ fontSize: "12px", marginTop: "4px" }}>
                                    Try adjusting your filters, or click "Correlate Alerts Now" to evaluate recent telemetry.
                                </div>
                            </div>
                        ) : (
                            filteredIncidents.map(inc => {
                                const isSelected = selectedIncident?.id === inc.id || (selectedIncident?.incident_id && selectedIncident.incident_id === inc.incident_id);
                                const isCritical = inc.severity === "critical";
                                const isHigh = inc.severity === "high";
                                const riskVal = formatRisk(inc.risk_score);

                                return (
                                    <div
                                        key={inc.id || inc.incident_id}
                                        onClick={() => { setSelectedIncident(inc); setPlaybookResult(null); setPcapHash(""); }}
                                        style={{
                                            padding: "12px 14px",
                                            marginBottom: "8px",
                                            borderRadius: "8px",
                                            cursor: "pointer",
                                            background: isSelected ? "var(--bg-card-hover)" : "var(--bg-card)",
                                            border: isSelected ? "1px solid var(--accent)" : "1px solid var(--border)",
                                            boxShadow: isSelected ? "0 0 12px rgba(0, 210, 255, 0.15)" : "none",
                                            transition: "all 0.15s ease",
                                        }}
                                    >
                                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                                            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                                                <span style={{
                                                    fontFamily: "var(--font-mono)",
                                                    fontSize: "11px",
                                                    fontWeight: 700,
                                                    color: "var(--accent)",
                                                    background: "rgba(0, 210, 255, 0.1)",
                                                    padding: "2px 6px",
                                                    borderRadius: "4px"
                                                }}>
                                                    {inc.incident_id || `INC-${inc.id}`}
                                                </span>
                                                <span className={`badge ${isCritical ? "badge-critical" : isHigh ? "badge-danger" : "badge-safe"}`} style={{ fontSize: "10px", padding: "1px 6px" }}>
                                                    {String(inc.severity).toUpperCase()}
                                                </span>
                                            </div>
                                            <span style={{
                                                fontSize: "11px",
                                                fontWeight: 700,
                                                color: riskVal >= 80 ? "var(--critical)" : riskVal >= 50 ? "var(--warning)" : "var(--safe)"
                                            }}>
                                                Risk {riskVal}/100
                                            </span>
                                        </div>

                                        <div style={{ fontWeight: 600, fontSize: "13px", color: "var(--text-primary)", marginBottom: "6px", lineHeight: "1.3" }}>
                                            {inc.title}
                                        </div>

                                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "11px", color: "var(--text-muted)" }}>
                                            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                                                <span style={{ fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
                                                    {inc.source_ip || "Internal"} ➔ {inc.target_ip || "Any"}
                                                </span>
                                            </div>
                                            <span style={{
                                                background: "rgba(255,255,255,0.05)",
                                                padding: "2px 6px",
                                                borderRadius: "4px",
                                                textTransform: "capitalize"
                                            }}>
                                                {inc.status}
                                            </span>
                                        </div>

                                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "6px", fontSize: "11px", color: "var(--text-muted)" }}>
                                            <span>⚡ {inc.alert_count || 1} correlated alerts</span>
                                            <span style={{ color: "var(--accent)", textTransform: "capitalize" }}>
                                                📍 {inc.kill_chain_stage ? String(inc.kill_chain_stage).replace(/_/g, " ") : "Initial Access"}
                                            </span>
                                        </div>
                                    </div>
                                );
                            })
                        )}
                    </div>
                </div>

                {/* ── Right Pane: Detailed Investigation Dossier ── */}
                {selectedIncident ? (
                    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                        {/* Dossier Header */}
                        <div className="panel animate-fade-in" style={{ padding: "20px" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "12px" }}>
                                <div>
                                    <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "6px" }}>
                                        <span style={{
                                            fontFamily: "var(--font-mono)",
                                            fontSize: "13px",
                                            fontWeight: 700,
                                            color: "var(--accent)",
                                            background: "rgba(0, 210, 255, 0.12)",
                                            padding: "3px 8px",
                                            borderRadius: "4px"
                                        }}>
                                            {selectedIncident.incident_id || `INC-${selectedIncident.id}`}
                                        </span>
                                        <span className={`badge ${selectedIncident.severity === "critical" ? "badge-critical" : "badge-danger"}`}>
                                            {String(selectedIncident.severity).toUpperCase()}
                                        </span>
                                        <span style={{
                                            fontSize: "12px",
                                            fontWeight: 700,
                                            color: formatRisk(selectedIncident.risk_score) >= 80 ? "var(--critical)" : formatRisk(selectedIncident.risk_score) >= 50 ? "var(--warning)" : "var(--safe)"
                                        }}>
                                            Risk {formatRisk(selectedIncident.risk_score)}/100
                                        </span>
                                        <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                                            Created: {selectedIncident.created_at ? new Date(selectedIncident.created_at).toLocaleString() : "Active"}
                                        </span>
                                    </div>
                                    <h2 style={{ fontSize: "1.3rem", fontWeight: 700, margin: "4px 0" }}>
                                        {selectedIncident.title}
                                    </h2>
                                    <p style={{ color: "var(--text-secondary)", fontSize: "13px", margin: "4px 0 0" }}>
                                        {selectedIncident.description}
                                    </p>
                                </div>

                                {/* Status Selector & Actions */}
                                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "8px" }}>
                                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                                        <label style={{ fontSize: "12px", color: "var(--text-muted)" }}>Triage Status:</label>
                                        <select
                                            className="select-input"
                                            value={selectedIncident.status}
                                            onChange={(e) => handleStatusChange(e.target.value)}
                                            disabled={isViewer}
                                            style={{
                                                fontSize: "12px",
                                                padding: "6px 12px",
                                                fontWeight: 600,
                                                background: "var(--bg-card)",
                                                border: "1px solid var(--border-strong)",
                                                color: "var(--accent)"
                                            }}
                                        >
                                            <option value="new">New</option>
                                            <option value="investigating">Investigating</option>
                                            <option value="contained">Contained</option>
                                            <option value="resolved">Resolved</option>
                                            <option value="false_positive">False Positive</option>
                                        </select>
                                    </div>
                                    <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                                        Assignee: <strong style={{ color: "var(--text-secondary)" }}>{selectedIncident.assignee || "SecOps Team"}</strong>
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* ── Cyber Kill-Chain Progression Visualizer ── */}
                        <div className="panel" style={{ padding: "18px 20px" }}>
                            <div className="card-label">Cyber Kill Chain® Attack Path Progression</div>
                            <h3 style={{ fontSize: "1.05rem", marginBottom: "16px", marginTop: "4px" }}>
                                Threat Actor Lifecycle & Execution Depth
                            </h3>

                            <div style={{
                                display: "grid",
                                gridTemplateColumns: `repeat(${KILL_CHAIN_STAGES.length}, 1fr)`,
                                gap: "8px",
                                position: "relative"
                            }}>
                                {KILL_CHAIN_STAGES.map((stage, index) => {
                                    const isReached = index <= currentStageIndex;
                                    const isCurrent = index === currentStageIndex;

                                    return (
                                        <div
                                            key={stage.key}
                                            style={{
                                                display: "flex",
                                                flexDirection: "column",
                                                alignItems: "center",
                                                padding: "12px 6px",
                                                borderRadius: "8px",
                                                background: isCurrent
                                                    ? "rgba(239, 68, 68, 0.15)"
                                                    : isReached
                                                    ? "rgba(0, 210, 255, 0.08)"
                                                    : "rgba(255, 255, 255, 0.02)",
                                                border: isCurrent
                                                    ? "1px solid #ef4444"
                                                    : isReached
                                                    ? "1px solid rgba(0, 210, 255, 0.3)"
                                                    : "1px dashed var(--border)",
                                                textAlign: "center",
                                                transition: "all 0.2s ease"
                                            }}
                                            title={stage.desc}
                                        >
                                            <div style={{ fontSize: "1.4rem", marginBottom: "6px" }}>{stage.icon}</div>
                                            <div style={{
                                                fontSize: "11px",
                                                fontWeight: isCurrent ? 700 : 600,
                                                color: isCurrent ? "#ef4444" : isReached ? "var(--accent)" : "var(--text-muted)",
                                                lineHeight: "1.2"
                                            }}>
                                                {stage.label}
                                            </div>
                                            {isCurrent && (
                                                <span style={{
                                                    marginTop: "6px",
                                                    fontSize: "9px",
                                                    fontWeight: 700,
                                                    background: "#ef4444",
                                                    color: "#fff",
                                                    padding: "2px 6px",
                                                    borderRadius: "10px",
                                                    letterSpacing: "0.5px"
                                                }}>
                                                    ACTIVE
                                                </span>
                                            )}
                                        </div>
                                    );
                                })}
                            </div>
                        </div>

                        {/* ── MITRE ATT&CK Matrix & Threat Details ── */}
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
                            {/* MITRE ATT&CK Mapping */}
                            <div className="panel" style={{ padding: "18px" }}>
                                <div className="card-label">MITRE ATT&CK Alignment</div>
                                <h3 style={{ fontSize: "1rem", margin: "4px 0 12px" }}>Techniques & Tactics</h3>

                                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                                    <div>
                                        <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "4px" }}>Tactics Identified:</div>
                                        <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                                            {(Array.isArray(selectedIncident.mitre_tactics) && selectedIncident.mitre_tactics.length > 0
                                                ? selectedIncident.mitre_tactics
                                                : typeof selectedIncident.mitre_tactics === "string" && selectedIncident.mitre_tactics
                                                ? [selectedIncident.mitre_tactics]
                                                : ["Initial Access"]
                                            ).map((t, i) => (
                                                <span key={i} className="badge badge-medium" style={{ fontSize: "11px" }}>
                                                    {t}
                                                </span>
                                            ))}
                                        </div>
                                    </div>

                                    <div>
                                        <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "4px" }}>Techniques Detected:</div>
                                        <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                                            {(Array.isArray(selectedIncident.mitre_techniques) && selectedIncident.mitre_techniques.length > 0
                                                ? selectedIncident.mitre_techniques
                                                : typeof selectedIncident.mitre_techniques === "string" && selectedIncident.mitre_techniques
                                                ? [selectedIncident.mitre_techniques]
                                                : ["T1110"]
                                            ).map((t, i) => (
                                                <span key={i} className="badge badge-critical" style={{ fontSize: "11px", fontFamily: "var(--font-mono)" }}>
                                                    {t}
                                                </span>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Threat Forensics & Evidence */}
                            <div className="panel" style={{ padding: "18px" }}>
                                <div className="card-label">Forensic Intelligence & PCAP</div>
                                <h3 style={{ fontSize: "1rem", margin: "4px 0 12px" }}>Evidence Package</h3>

                                <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginBottom: "12px" }}>
                                    <div><strong>Source IP:</strong> <span style={{ fontFamily: "var(--font-mono)", color: "var(--accent)" }}>{selectedIncident.source_ip || "Internal"}</span></div>
                                    <div style={{ marginTop: "4px" }}><strong>Target IP:</strong> <span style={{ fontFamily: "var(--font-mono)", color: "var(--text-primary)" }}>{selectedIncident.target_ip || "Perimeter"}</span></div>
                                    <div style={{ marginTop: "4px" }}><strong>Correlated Alerts:</strong> {selectedIncident.alert_count || 1} events</div>
                                </div>

                                <button
                                    type="button"
                                    className="btn btn-secondary"
                                    onClick={handleDownloadPcap}
                                    disabled={downloadingPcap}
                                    style={{ width: "100%", justifyContent: "center", display: "flex", alignItems: "center", gap: "8px" }}
                                >
                                    {downloadingPcap ? "Extracting Ring Buffer..." : "📥 Export Forensic PCAP & SHA-256"}
                                </button>

                                {pcapHash && (
                                    <div style={{
                                        marginTop: "10px",
                                        padding: "8px 10px",
                                        borderRadius: "6px",
                                        background: "rgba(0, 210, 255, 0.08)",
                                        border: "1px solid rgba(0, 210, 255, 0.25)",
                                        fontSize: "11px",
                                        fontFamily: "var(--font-mono)"
                                    }}>
                                        <div style={{ color: "var(--accent)", fontWeight: 700, marginBottom: "2px" }}>
                                            🔒 SHA-256 Forensic Evidence Hash:
                                        </div>
                                        <div style={{ wordBreak: "break-all", color: "var(--text-primary)" }}>
                                            {pcapHash}
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* ── Autonomous Response Playbook Execution Engine ── */}
                        <div className="panel" style={{ padding: "20px" }}>
                            <div className="card-label">Autonomous Response Engine</div>
                            <h3 style={{ fontSize: "1.1rem", margin: "4px 0 8px" }}>
                                Execute Incident Containment Playbook
                            </h3>
                            <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginBottom: "16px" }}>
                                Trigger deterministic multi-step mitigation workflows against the offending threat vector with safe allowlist immunity guards.
                            </p>

                            <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: "12px", alignItems: "center", marginBottom: "16px" }}>
                                <select
                                    className="select-input"
                                    value={selectedPlaybook}
                                    onChange={(e) => { setSelectedPlaybook(e.target.value); setPlaybookResult(null); }}
                                    disabled={isViewer}
                                    style={{ padding: "8px 12px", fontSize: "13px" }}
                                >
                                    {AVAILABLE_PLAYBOOKS.map(pb => (
                                        <option key={pb.id} value={pb.id}>
                                            {pb.name}
                                        </option>
                                    ))}
                                </select>

                                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                                    <label style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12px", cursor: "pointer" }}>
                                        <input
                                            type="checkbox"
                                            checked={isDryRun}
                                            onChange={(e) => setIsDryRun(e.target.checked)}
                                            disabled={isViewer}
                                        />
                                        <span>Dry-Run (Simulate Only)</span>
                                    </label>

                                    <button
                                        type="button"
                                        className={`btn ${isDryRun ? "btn-secondary" : "btn-critical"}`}
                                        onClick={handleExecutePlaybook}
                                        disabled={executingPlaybook || isViewer}
                                        style={{ minWidth: "180px" }}
                                    >
                                        {executingPlaybook ? "Executing Actions..." : (isDryRun ? "🧪 Test Playbook (Dry Run)" : "⚡ Enforce Containment")}
                                    </button>
                                </div>
                            </div>

                            {/* Playbook Description */}
                            <div style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "12px" }}>
                                ℹ️ {AVAILABLE_PLAYBOOKS.find(p => p.id === selectedPlaybook)?.desc}
                            </div>

                            {/* Playbook Execution Output Tray */}
                            {playbookResult && (
                                <div style={{
                                    marginTop: "14px",
                                    padding: "14px",
                                    borderRadius: "8px",
                                    background: "rgba(0, 0, 0, 0.4)",
                                    border: playbookResult.overall_success || playbookResult.success ? "1px solid var(--safe)" : "1px solid var(--critical)"
                                }}>
                                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                                        <span style={{ fontWeight: 700, fontSize: "12px", color: playbookResult.overall_success || playbookResult.success ? "var(--safe)" : "var(--critical)" }}>
                                            {playbookResult.overall_success || playbookResult.success ? "✓ Playbook Execution Succeeded" : "⚠️ Playbook Execution Encountered Errors"}
                                            {playbookResult.dry_run ? " (Simulated Mode)" : " (Active Enforcement)"}
                                        </span>
                                        <span style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                                            Target: {playbookResult.target_ip}
                                        </span>
                                    </div>

                                    <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                                        {(playbookResult.steps || []).map((step, idx) => (
                                            <div key={idx} style={{
                                                display: "flex",
                                                alignItems: "center",
                                                justifyContent: "space-between",
                                                fontSize: "12px",
                                                padding: "4px 8px",
                                                background: "rgba(255, 255, 255, 0.03)",
                                                borderRadius: "4px"
                                            }}>
                                                <span>Step {idx + 1}: <strong>{step.action || step.step}</strong></span>
                                                <span style={{ color: step.success ? "var(--safe)" : "var(--critical)", fontSize: "11px" }}>
                                                    {step.success ? "✓ Done" : "✕ Failed"}
                                                </span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* ── Analyst Investigation Notes & Audit Log ── */}
                        <div className="panel" style={{ padding: "20px" }}>
                            <div className="card-label">SOC Analyst Investigation Notes</div>
                            <h3 style={{ fontSize: "1.05rem", margin: "4px 0 12px" }}>Collaborative Case Timeline</h3>

                            {/* Timeline of notes */}
                            <div style={{ display: "flex", flexDirection: "column", gap: "10px", marginBottom: "16px", maxHeight: "240px", overflowY: "auto" }}>
                                {(!selectedIncident.analyst_notes || (Array.isArray(selectedIncident.analyst_notes) && selectedIncident.analyst_notes.length === 0)) ? (
                                    <div style={{ fontSize: "12px", color: "var(--text-muted)", fontStyle: "italic" }}>
                                        No analyst case notes recorded yet. Add initial assessment below.
                                    </div>
                                ) : (
                                    (Array.isArray(selectedIncident.analyst_notes)
                                        ? selectedIncident.analyst_notes
                                        : typeof selectedIncident.analyst_notes === "string"
                                        ? [{ note: selectedIncident.analyst_notes, author: "Analyst", created_at: selectedIncident.created_at }]
                                        : []
                                    ).map((n, i) => (
                                        <div key={i} style={{
                                            padding: "10px 12px",
                                            borderRadius: "6px",
                                            background: "var(--bg-card)",
                                            border: "1px solid var(--border)",
                                            fontSize: "12px"
                                        }}>
                                            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px", color: "var(--text-muted)", fontSize: "11px" }}>
                                                <strong>{n.author || "Analyst"}</strong>
                                                <span>{n.created_at ? new Date(n.created_at).toLocaleString() : "Just now"}</span>
                                            </div>
                                            <div style={{ color: "var(--text-primary)", whiteSpace: "pre-wrap" }}>
                                                {n.note || (typeof n === "string" ? n : JSON.stringify(n))}
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>

                            {/* Add Note Input Form */}
                            {!isViewer && (
                                <form onSubmit={handleAddNote} style={{ display: "flex", gap: "10px" }}>
                                    <input
                                        type="text"
                                        className="text-input"
                                        placeholder="Record forensic finding, hash analysis, or containment justification..."
                                        value={newNote}
                                        onChange={(e) => setNewNote(e.target.value)}
                                        style={{ flex: 1, fontSize: "12px" }}
                                    />
                                    <button
                                        type="submit"
                                        className="btn btn-primary"
                                        disabled={addingNote || !newNote.trim()}
                                        style={{ fontSize: "12px", whiteSpace: "nowrap" }}
                                    >
                                        {addingNote ? "Saving..." : "Add Case Note"}
                                    </button>
                                </form>
                            )}
                        </div>
                    </div>
                ) : (
                    <div className="panel" style={{ padding: "60px 20px", textAlign: "center", color: "var(--text-muted)" }}>
                        <div style={{ fontSize: "2.5rem", marginBottom: "12px" }}>🔍</div>
                        <h3 style={{ color: "var(--text-primary)", marginBottom: "6px" }}>No Incident Selected</h3>
                        <p style={{ fontSize: "13px" }}>
                            Select an incident from the left feed or click "Correlate Alerts Now" to triage new security threats.
                        </p>
                    </div>
                )}
            </div>
        </div>
    );
}
