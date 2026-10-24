import { useEffect, useState } from "react";
import { apiFetch } from "../services/api";

export default function SettingsTab({ currentUser }) {
    const [settings, setSettings] = useState(null);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [saveStatus, setSaveStatus] = useState("");

    // Notification testing
    const [testChannel, setTestChannel] = useState("all");
    const [testingNotification, setTestingNotification] = useState(false);
    const [testResult, setTestResult] = useState(null);

    // User management
    const [users, setUsers] = useState([]);
    const [newUsername, setNewUsername] = useState("");
    const [newPassword, setNewPassword] = useState("");
    const [newRole, setNewRole] = useState("analyst");
    const [userActionMsg, setUserActionMsg] = useState("");

    // Audit logs
    const [auditLogs, setAuditLogs] = useState([]);

    // PCAP stats
    const [pcapStats, setPcapStats] = useState(null);

    // Database maintenance
    const [dbStatus, setDbStatus] = useState(null);
    const [dbActionRunning, setDbActionRunning] = useState(false);
    const [dbActionMsg, setDbActionMsg] = useState("");

    // Active sub-section
    const [activeSection, setActiveSection] = useState("detection");

    const isAdmin = currentUser?.role === "admin";
    const isAnalystOrAdmin = currentUser?.role === "admin" || currentUser?.role === "analyst";

    const fetchAllData = async () => {
        setLoading(true);
        try {
            const [sRes, aRes, pRes, dRes] = await Promise.all([
                apiFetch("/api/settings"),
                apiFetch("/api/audit-logs?limit=25"),
                apiFetch("/api/pcap/stats"),
                apiFetch("/api/database/status"),
            ]);
            if (sRes.ok) setSettings(await sRes.json());
            if (aRes.ok) {
                const aData = await aRes.json();
                setAuditLogs(aData.audit_logs || []);
            }
            if (pRes.ok) setPcapStats(await pRes.json());
            if (dRes.ok) setDbStatus(await dRes.json());

            if (isAdmin) {
                const uRes = await apiFetch("/api/auth/users");
                if (uRes.ok) {
                    const uData = await uRes.json();
                    setUsers(uData.users || []);
                }
            }
        } catch (err) {
            console.error("Error loading settings:", err);
        }
        setLoading(false);
    };

    useEffect(() => {
        fetchAllData();
    }, [currentUser]);

    const handleSettingChange = (key, value) => {
        setSettings(prev => ({ ...prev, [key]: value }));
    };

    const handleSaveSettings = async (e) => {
        e.preventDefault();
        if (!isAdmin) {
            alert("Only operators with the 'admin' role can modify system settings.");
            return;
        }
        setSaving(true);
        setSaveStatus("");
        try {
            const res = await apiFetch("/api/settings", {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(settings),
            });
            if (res.ok) {
                const updated = await res.json();
                setSettings(updated);
                setSaveStatus("✓ Configuration updated successfully and applied in real-time.");
                fetchAllData();
            } else {
                const errData = await res.json().catch(() => ({}));
                setSaveStatus(`✗ Failed to save: ${errData.detail || "Server error"}`);
            }
        } catch (err) {
            setSaveStatus(`✗ Error: ${err.message}`);
        }
        setSaving(false);
    };

    const handleTestNotification = async (channel) => {
        setTestingNotification(true);
        setTestResult(null);
        try {
            const res = await apiFetch("/api/notifications/test", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ channel, message: "Diagnostic test from Volcano Settings UI." }),
            });
            if (res.ok) {
                setTestResult(await res.json());
            } else {
                setTestResult({ error: "Failed to dispatch test notification." });
            }
        } catch (err) {
            setTestResult({ error: err.message });
        }
        setTestingNotification(false);
    };

    const handleCreateUser = async (e) => {
        e.preventDefault();
        if (!isAdmin) return;
        setUserActionMsg("");
        try {
            const res = await apiFetch("/api/auth/users", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username: newUsername.trim(), password: newPassword, role: newRole }),
            });
            if (res.ok) {
                setUserActionMsg(`✓ Operator '${newUsername}' created successfully.`);
                setNewUsername("");
                setNewPassword("");
                fetchAllData();
            } else {
                const data = await res.json().catch(() => ({}));
                setUserActionMsg(`✗ ${data.detail || "Error creating user"}`);
            }
        } catch (err) {
            setUserActionMsg(`✗ ${err.message}`);
        }
    };

    const handleDbMaintenance = async (action, mode = "TRUNCATE") => {
        setDbActionRunning(true);
        setDbActionMsg("");
        try {
            const res = await apiFetch("/api/database/maintenance", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ action, mode }),
            });
            if (res.ok) {
                const data = await res.json();
                setDbStatus(data.status);
                setDbActionMsg(`✓ ${action.toUpperCase()} completed: ${JSON.stringify(data.result)}`);
            } else {
                const err = await res.json().catch(() => ({}));
                setDbActionMsg(`✗ Failed: ${err.detail || "Error"}`);
            }
        } catch (e) {
            setDbActionMsg(`✗ Error: ${e.message}`);
        }
        setDbActionRunning(false);
    };

    const handleRoleChange = async (username, newRoleVal) => {
        if (!isAdmin) return;
        try {
            const res = await apiFetch(`/api/auth/users/${encodeURIComponent(username)}/role`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ role: newRoleVal }),
            });
            if (res.ok) {
                fetchAllData();
            }
        } catch (err) {
            console.error("Error updating role:", err);
        }
    };

    const handleDownloadPcap = () => {
        window.open("/api/pcap/export", "_blank");
    };

    if (loading || !settings) {
        return (
            <div className="tab-content" key="settings-loading">
                <div className="tab-header">
                    <h1>System Configuration</h1>
                    <p className="tab-subtitle">Loading parameters...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="tab-content" key="settings">
            <div className="tab-header">
                <div className="tab-header-info">
                    <div className="tab-eyebrow">⚙️ Administration & Orchestration</div>
                    <h1>Firewall Settings & Controls</h1>
                    <p className="tab-subtitle">
                        Tune AI detection thresholds, safe allowlists, multi-channel webhook notifications, and RBAC operator accounts.
                    </p>
                </div>
                <div className="tab-header-actions">
                    {!isAdmin && (
                        <span className="chip chip-warning">Read-Only Mode ({currentUser?.role || "viewer"})</span>
                    )}
                    <button className="btn btn-secondary" onClick={fetchAllData}>
                        ↻ Refresh
                    </button>
                    {isAdmin && (
                        <button className="btn btn-primary" onClick={handleSaveSettings} disabled={saving}>
                            {saving ? "Saving..." : "💾 Save Changes"}
                        </button>
                    )}
                </div>
            </div>

            {saveStatus && (
                <div className={`notification-banner ${saveStatus.startsWith("✓") ? "banner-safe" : "banner-danger"}`} style={{ padding: "12px 16px", borderRadius: "8px", marginBottom: "16px", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)" }}>
                    {saveStatus}
                </div>
            )}

            {/* Navigation sub-tabs */}
            <div style={{ display: "flex", gap: "8px", borderBottom: "1px solid rgba(255,255,255,0.08)", paddingBottom: "12px", marginBottom: "20px" }}>
                {[
                    { id: "detection", label: "🎯 Detection Thresholds" },
                    { id: "allowlist", label: "🛡️ Allowlist & Response" },
                    { id: "notifications", label: "📢 Alerts & Webhooks" },
                    { id: "copilot", label: "🤖 AI Copilot & Feeds" },
                    { id: "database", label: "💾 SQLite Database" },
                    { id: "users", label: "👥 Operator Accounts" },
                    { id: "forensics", label: "🔬 PCAP & Audit Logs" },
                ].map(sec => (
                    <button
                        key={sec.id}
                        className={`btn ${activeSection === sec.id ? "btn-primary" : "btn-ghost"}`}
                        style={{ padding: "6px 14px", fontSize: "13px" }}
                        onClick={() => setActiveSection(sec.id)}
                    >
                        {sec.label}
                    </button>
                ))}
            </div>

            <form onSubmit={handleSaveSettings}>
                {/* ─── SECTION 1: Detection Thresholds ─── */}
                {activeSection === "detection" && (
                    <div className="grid-2 animate-fade-up">
                        <div className="panel">
                            <div className="panel-header">
                                <div>
                                    <h2>Network Volumetrics & Scans</h2>
                                    <p className="panel-header-sub">Thresholds for traffic bursts and reconnaissance</p>
                                </div>
                            </div>
                            <div className="form-grid" style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                                <div className="form-group">
                                    <label className="form-label">Port Scan Unique Ports Threshold</label>
                                    <input
                                        className="form-input"
                                        type="number"
                                        value={settings.port_scan_threshold}
                                        onChange={e => handleSettingChange("port_scan_threshold", parseInt(e.target.value) || 1)}
                                        disabled={!isAdmin}
                                    />
                                    <span style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>Unique ports touched to trigger a Port Scan alert</span>
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Port Scan Sliding Window (seconds)</label>
                                    <input
                                        className="form-input"
                                        type="number"
                                        step="0.5"
                                        value={settings.port_scan_window}
                                        onChange={e => handleSettingChange("port_scan_window", parseFloat(e.target.value) || 1.0)}
                                        disabled={!isAdmin}
                                    />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">DDoS Packet Velocity Threshold (pps)</label>
                                    <input
                                        className="form-input"
                                        type="number"
                                        value={settings.ddos_threshold}
                                        onChange={e => handleSettingChange("ddos_threshold", parseInt(e.target.value) || 10)}
                                        disabled={!isAdmin}
                                    />
                                    <span style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>Packets per 1-second burst to trigger a DDoS alert</span>
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Ransomware File Events Rate (events/window)</label>
                                    <input
                                        className="form-input"
                                        type="number"
                                        value={settings.ransomware_rate_threshold}
                                        onChange={e => handleSettingChange("ransomware_rate_threshold", parseInt(e.target.value) || 1)}
                                        disabled={!isAdmin}
                                    />
                                </div>
                            </div>
                        </div>

                        <div className="panel">
                            <div className="panel-header">
                                <div>
                                    <h2>Brute-Force & DNS Threat Detection</h2>
                                    <p className="panel-header-sub">Thresholds for authentication abuse and DNS tunneling</p>
                                </div>
                            </div>
                            <div className="form-grid" style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                                <div className="form-group">
                                    <label className="form-label">Brute-Force Connection Attempts Threshold</label>
                                    <input
                                        className="form-input"
                                        type="number"
                                        value={settings.brute_force_threshold}
                                        onChange={e => handleSettingChange("brute_force_threshold", parseInt(e.target.value) || 1)}
                                        disabled={!isAdmin}
                                    />
                                    <span style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>Failed/repeated SYNs to auth ports (22, 3389, 21, 445)</span>
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Brute-Force Tracking Window (seconds)</label>
                                    <input
                                        className="form-input"
                                        type="number"
                                        step="0.5"
                                        value={settings.brute_force_window}
                                        onChange={e => handleSettingChange("brute_force_window", parseFloat(e.target.value) || 1.0)}
                                        disabled={!isAdmin}
                                    />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">DNS Tunneling Subdomain Length Threshold</label>
                                    <input
                                        className="form-input"
                                        type="number"
                                        value={settings.dns_tunneling_subdomain_length}
                                        onChange={e => handleSettingChange("dns_tunneling_subdomain_length", parseInt(e.target.value) || 10)}
                                        disabled={!isAdmin}
                                    />
                                    <span style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>Subdomains longer than this are flagged for payload inspection</span>
                                </div>
                                <div className="form-group">
                                    <label className="form-label">DNS Shannon Entropy Threshold</label>
                                    <input
                                        className="form-input"
                                        type="number"
                                        step="0.1"
                                        value={settings.dns_tunneling_entropy}
                                        onChange={e => handleSettingChange("dns_tunneling_entropy", parseFloat(e.target.value) || 0.0)}
                                        disabled={!isAdmin}
                                    />
                                    <span style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>High entropy (&gt; 3.8) flags encoded exfiltration data</span>
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {/* ─── SECTION 2: Allowlist & Response ─── */}
                {activeSection === "allowlist" && (
                    <div className="grid-2 animate-fade-up">
                        <div className="panel">
                            <div className="panel-header">
                                <div>
                                    <h2>🛡️ System Allowlist (Immunity)</h2>
                                    <p className="panel-header-sub">Protected IP addresses and subnets that can NEVER be blocked</p>
                                </div>
                            </div>
                            <div className="form-group" style={{ marginBottom: "16px" }}>
                                <label className="form-label">Allowed IPs / CIDRs (comma or newline separated)</label>
                                <textarea
                                    className="form-input"
                                    rows={6}
                                    value={Array.isArray(settings.allowlist_ips) ? settings.allowlist_ips.join("\n") : settings.allowlist_ips}
                                    onChange={e => {
                                        const items = e.target.value.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
                                        handleSettingChange("allowlist_ips", items);
                                    }}
                                    disabled={!isAdmin}
                                    placeholder="127.0.0.1&#10;192.168.1.1&#10;10.0.0.0/24"
                                />
                                <span style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
                                    Default gateway, DNS servers, and loopback addresses are protected from accidental lockouts.
                                </span>
                            </div>
                            <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                                {(settings.allowlist_ips || []).map((ip, i) => (
                                    <span key={i} className="chip chip-safe" style={{ fontFamily: "monospace" }}>
                                        ✓ {ip}
                                    </span>
                                ))}
                            </div>
                        </div>

                        <div className="panel">
                            <div className="panel-header">
                                <div>
                                    <h2>Autonomous Containment Controls</h2>
                                    <p className="panel-header-sub">Emergency response parameters and safe operation modes</p>
                                </div>
                            </div>
                            <div className="form-group" style={{ marginBottom: "14px" }}>
                                <label className="form-label">Default Auto-Quarantine Duration (seconds)</label>
                                <input
                                    className="form-input"
                                    type="number"
                                    value={settings.quarantine_default_duration}
                                    onChange={e => handleSettingChange("quarantine_default_duration", parseFloat(e.target.value) || 300)}
                                    disabled={!isAdmin}
                                />
                                <span style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
                                    Automatic blocks will automatically revert when this duration expires.
                                </span>
                            </div>
                            <div className="form-group" style={{ marginBottom: "14px" }}>
                                <label className="form-label">Emergency Killswitch Interface</label>
                                <input
                                    className="form-input"
                                    value={settings.killswitch_interface || ""}
                                    onChange={e => handleSettingChange("killswitch_interface", e.target.value)}
                                    placeholder="e.g. Wi-Fi, Ethernet, eth0"
                                    disabled={!isAdmin}
                                />
                            </div>
                            <div style={{ background: "rgba(255,255,255,0.03)", padding: "14px", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.08)" }}>
                                <label style={{ display: "flex", alignItems: "center", gap: "10px", cursor: isAdmin ? "pointer" : "default" }}>
                                    <input
                                        type="checkbox"
                                        checked={Boolean(settings.killswitch_dry_run)}
                                        onChange={e => handleSettingChange("killswitch_dry_run", e.target.checked)}
                                        disabled={!isAdmin}
                                        style={{ width: "16px", height: "16px" }}
                                    />
                                    <div>
                                        <div style={{ fontWeight: 600 }}>Enable Killswitch Dry-Run Mode</div>
                                        <div style={{ fontSize: "12px", color: "var(--color-text-muted)" }}>
                                            Simulate hardware isolation actions safely without dropping actual physical network adapters.
                                        </div>
                                    </div>
                                </label>
                            </div>
                        </div>
                    </div>
                )}

                {/* ─── SECTION 3: Alerts & Webhooks ─── */}
                {activeSection === "notifications" && (
                    <div className="panel animate-fade-up">
                        <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <div>
                                <h2>📢 Multi-Channel Notification Dispatcher</h2>
                                <p className="panel-header-sub">Send automated alerts to Slack, Discord, Telegram, and Email</p>
                            </div>
                            <div style={{ display: "flex", gap: "8px" }}>
                                <select
                                    className="form-select"
                                    value={testChannel}
                                    onChange={e => setTestChannel(e.target.value)}
                                    style={{ maxWidth: "140px" }}
                                >
                                    <option value="all">All Channels</option>
                                    <option value="slack">Slack</option>
                                    <option value="discord">Discord</option>
                                    <option value="telegram">Telegram</option>
                                    <option value="email">Email (SMTP)</option>
                                </select>
                                <button
                                    type="button"
                                    className="btn btn-secondary"
                                    onClick={() => handleTestNotification(testChannel)}
                                    disabled={testingNotification || !isAnalystOrAdmin}
                                >
                                    {testingNotification ? "Testing..." : "⚡ Test Ping"}
                                </button>
                            </div>
                        </div>

                        {testResult && (
                            <div style={{ background: "rgba(255,255,255,0.04)", padding: "12px", borderRadius: "8px", marginBottom: "16px" }}>
                                <strong>Diagnostic Result:</strong>
                                <pre className="code-block" style={{ marginTop: "6px" }}>
                                    {JSON.stringify(testResult, null, 2)}
                                </pre>
                            </div>
                        )}

                        <div className="grid-2">
                            <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                                <div className="form-group">
                                    <label className="form-label">Slack Incoming Webhook URL</label>
                                    <input
                                        className="form-input"
                                        value={settings.slack_webhook_url || ""}
                                        onChange={e => handleSettingChange("slack_webhook_url", e.target.value)}
                                        placeholder="https://hooks.slack.com/services/..."
                                        disabled={!isAdmin}
                                    />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Discord Webhook URL</label>
                                    <input
                                        className="form-input"
                                        value={settings.discord_webhook_url || ""}
                                        onChange={e => handleSettingChange("discord_webhook_url", e.target.value)}
                                        placeholder="https://discord.com/api/webhooks/..."
                                        disabled={!isAdmin}
                                    />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Telegram Bot Token</label>
                                    <input
                                        className="form-input"
                                        value={settings.telegram_bot_token || ""}
                                        onChange={e => handleSettingChange("telegram_bot_token", e.target.value)}
                                        placeholder="123456789:ABCdefGhIJKlmNoP..."
                                        disabled={!isAdmin}
                                    />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Telegram Chat ID</label>
                                    <input
                                        className="form-input"
                                        value={settings.telegram_chat_id || ""}
                                        onChange={e => handleSettingChange("telegram_chat_id", e.target.value)}
                                        placeholder="e.g. -1001234567890"
                                        disabled={!isAdmin}
                                    />
                                </div>
                            </div>

                            <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                                <div className="form-group">
                                    <label className="form-label">SMTP Host & Port</label>
                                    <div style={{ display: "flex", gap: "8px" }}>
                                        <input
                                            className="form-input"
                                            value={settings.smtp_host || ""}
                                            onChange={e => handleSettingChange("smtp_host", e.target.value)}
                                            placeholder="smtp.example.com"
                                            disabled={!isAdmin}
                                            style={{ flex: 3 }}
                                        />
                                        <input
                                            className="form-input"
                                            type="number"
                                            value={settings.smtp_port || 587}
                                            onChange={e => handleSettingChange("smtp_port", parseInt(e.target.value) || 587)}
                                            disabled={!isAdmin}
                                            style={{ flex: 1 }}
                                        />
                                    </div>
                                </div>
                                <div className="form-group">
                                    <label className="form-label">SMTP Username & Password</label>
                                    <div style={{ display: "flex", gap: "8px" }}>
                                        <input
                                            className="form-input"
                                            value={settings.smtp_user || ""}
                                            onChange={e => handleSettingChange("smtp_user", e.target.value)}
                                            placeholder="alerts@company.com"
                                            disabled={!isAdmin}
                                            style={{ flex: 1 }}
                                        />
                                        <input
                                            className="form-input"
                                            type="password"
                                            value={settings.smtp_password || ""}
                                            onChange={e => handleSettingChange("smtp_password", e.target.value)}
                                            placeholder="••••••••"
                                            disabled={!isAdmin}
                                            style={{ flex: 1 }}
                                        />
                                    </div>
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Recipient Alert Email</label>
                                    <input
                                        className="form-input"
                                        type="email"
                                        value={settings.smtp_recipient || ""}
                                        onChange={e => handleSettingChange("smtp_recipient", e.target.value)}
                                        placeholder="soc-oncall@company.com"
                                        disabled={!isAdmin}
                                    />
                                </div>
                                <div style={{ display: "flex", gap: "12px" }}>
                                    <div className="form-group" style={{ flex: 1 }}>
                                        <label className="form-label">Min Notification Severity</label>
                                        <select
                                            className="form-select"
                                            value={settings.notification_min_severity || "high"}
                                            onChange={e => handleSettingChange("notification_min_severity", e.target.value)}
                                            disabled={!isAdmin}
                                        >
                                            <option value="critical">Critical Only</option>
                                            <option value="high">High & Critical</option>
                                            <option value="medium">Medium, High & Critical</option>
                                        </select>
                                    </div>
                                    <div className="form-group" style={{ flex: 1 }}>
                                        <label className="form-label">Channel Cooldown (sec)</label>
                                        <input
                                            className="form-input"
                                            type="number"
                                            value={settings.notification_cooldown || 60}
                                            onChange={e => handleSettingChange("notification_cooldown", parseFloat(e.target.value) || 10)}
                                            disabled={!isAdmin}
                                        />
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {/* ─── SECTION 4: AI Copilot & Feeds ─── */}
                {activeSection === "copilot" && (
                    <div className="grid-2 animate-fade-up">
                        <div className="panel">
                            <div className="panel-header">
                                <div>
                                    <h2>🤖 LLM Security Copilot Integration</h2>
                                    <p className="panel-header-sub">Configure external reasoning LLM for natural language telemetry questions</p>
                                </div>
                            </div>
                            <div className="form-group" style={{ marginBottom: "14px" }}>
                                <label className="form-label">LLM Provider</label>
                                <select
                                    className="form-select"
                                    value={settings.llm_provider || "mock"}
                                    onChange={e => handleSettingChange("llm_provider", e.target.value)}
                                    disabled={!isAdmin}
                                >
                                    <option value="mock">Local Heuristic Intent Engine (No API Key Required)</option>
                                    <option value="openai">OpenAI (GPT-4o-mini / GPT-4)</option>
                                    <option value="generic">Generic OpenAI-Compatible (Ollama, vLLM, Groq)</option>
                                    <option value="anthropic">Anthropic Claude</option>
                                </select>
                            </div>
                            <div className="form-group" style={{ marginBottom: "14px" }}>
                                <label className="form-label">Model Identifier</label>
                                <input
                                    className="form-input"
                                    value={settings.llm_model || "gpt-4o-mini"}
                                    onChange={e => handleSettingChange("llm_model", e.target.value)}
                                    placeholder="gpt-4o-mini, llama3, etc."
                                    disabled={!isAdmin}
                                />
                            </div>
                            <div className="form-group" style={{ marginBottom: "14px" }}>
                                <label className="form-label">API Base URL</label>
                                <input
                                    className="form-input"
                                    value={settings.llm_api_base || "https://api.openai.com/v1"}
                                    onChange={e => handleSettingChange("llm_api_base", e.target.value)}
                                    placeholder="https://api.openai.com/v1"
                                    disabled={!isAdmin}
                                />
                            </div>
                            <div className="form-group">
                                <label className="form-label">LLM API Key</label>
                                <input
                                    className="form-input"
                                    type="password"
                                    value={settings.llm_api_key || ""}
                                    onChange={e => handleSettingChange("llm_api_key", e.target.value)}
                                    placeholder="sk-••••••••"
                                    disabled={!isAdmin}
                                />
                                <span style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
                                    When blank, the copilot uses zero-external-dependency local rule matching.
                                </span>
                            </div>
                        </div>

                        <div className="panel">
                            <div className="panel-header">
                                <div>
                                    <h2>📡 Threat Intelligence Feeds</h2>
                                    <p className="panel-header-sub">Automated IoC feed synchronization</p>
                                </div>
                            </div>
                            <div className="form-group" style={{ marginBottom: "14px" }}>
                                <label className="form-label">Sync Refresh Interval (seconds)</label>
                                <input
                                    className="form-input"
                                    type="number"
                                    value={settings.feed_refresh_interval || 3600}
                                    onChange={e => handleSettingChange("feed_refresh_interval", parseInt(e.target.value) || 300)}
                                    disabled={!isAdmin}
                                />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Feed Ingestion URLs</label>
                                <textarea
                                    className="form-input"
                                    rows={5}
                                    value={Array.isArray(settings.feed_urls) ? settings.feed_urls.join("\n") : settings.feed_urls}
                                    onChange={e => {
                                        const urls = e.target.value.split(/[\n]+/).map(s => s.trim()).filter(Boolean);
                                        handleSettingChange("feed_urls", urls);
                                    }}
                                    disabled={!isAdmin}
                                />
                            </div>
                        </div>
                    </div>
                )}

                {/* ─── SECTION 5: SQLite Database Maintenance ─── */}
                {activeSection === "database" && (
                    <div className="grid-2 animate-fade-up">
                        <div className="panel">
                            <div className="panel-header">
                                <div>
                                    <h2>💾 SQLite Storage Health & Telemetry</h2>
                                    <p className="panel-header-sub">Local WAL database metrics, page allocation, and integrity</p>
                                </div>
                                <span className={`badge ${dbStatus?.integrity === "ok" || dbStatus?.integrity === "healthy" ? "badge-safe" : "badge-warning"}`}>
                                    {dbStatus?.integrity === "ok" || dbStatus?.integrity === "healthy" ? "Healthy (WAL)" : "Attention"}
                                </span>
                            </div>

                            {dbActionMsg && (
                                <div style={{
                                    padding: "10px 14px",
                                    borderRadius: "6px",
                                    marginBottom: "14px",
                                    fontSize: "12px",
                                    fontFamily: "monospace",
                                    background: dbActionMsg.startsWith("✓") ? "rgba(16,185,129,0.12)" : "rgba(239,68,68,0.12)",
                                    border: `1px solid ${dbActionMsg.startsWith("✓") ? "var(--safe)" : "var(--danger)"}`,
                                    color: dbActionMsg.startsWith("✓") ? "var(--safe)" : "var(--danger)",
                                }}>
                                    {dbActionMsg}
                                </div>
                            )}

                            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "16px" }}>
                                <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "6px", padding: "10px 14px" }}>
                                    <div style={{ fontSize: "11px", color: "var(--color-text-muted)", textTransform: "uppercase" }}>Database Size</div>
                                    <div style={{ fontSize: "1.2rem", fontWeight: 700, marginTop: "2px", color: "var(--color-text)" }}>
                                        {dbStatus?.file_size_mb ?? 0} <span style={{ fontSize: "12px", fontWeight: 400, color: "var(--color-text-muted)" }}>MB</span>
                                    </div>
                                    <div style={{ fontSize: "11px", color: "var(--color-text-muted)", marginTop: "2px" }}>
                                        {dbStatus?.page_count?.toLocaleString() ?? 0} pages @ {dbStatus?.page_size ?? 4096}B
                                    </div>
                                </div>

                                <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid var(--border)", borderRadius: "6px", padding: "10px 14px" }}>
                                    <div style={{ fontSize: "11px", color: "var(--color-text-muted)", textTransform: "uppercase" }}>WAL Journal Size</div>
                                    <div style={{ fontSize: "1.2rem", fontWeight: 700, marginTop: "2px", color: "var(--color-text)" }}>
                                        {dbStatus?.wal_size_mb ?? 0} <span style={{ fontSize: "12px", fontWeight: 400, color: "var(--color-text-muted)" }}>MB</span>
                                    </div>
                                    <div style={{ fontSize: "11px", color: "var(--color-text-muted)", marginTop: "2px" }}>
                                        Journal Mode: <strong style={{ color: "var(--safe)" }}>{dbStatus?.journal_mode?.toUpperCase() || "WAL"}</strong>
                                    </div>
                                </div>
                            </div>

                            <div style={{ marginBottom: "16px" }}>
                                <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--color-text)", marginBottom: "8px" }}>Table Record Counts</div>
                                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "8px" }}>
                                    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "6px", padding: "8px 12px" }}>
                                        <div style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>Alerts</div>
                                        <div style={{ fontSize: "1rem", fontWeight: 600 }}>{dbStatus?.table_counts?.alerts?.toLocaleString() ?? 0}</div>
                                    </div>
                                    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "6px", padding: "8px 12px" }}>
                                        <div style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>Rules</div>
                                        <div style={{ fontSize: "1rem", fontWeight: 600 }}>{dbStatus?.table_counts?.rules?.toLocaleString() ?? 0}</div>
                                    </div>
                                    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid var(--border)", borderRadius: "6px", padding: "8px 12px" }}>
                                        <div style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>Audit Logs</div>
                                        <div style={{ fontSize: "1rem", fontWeight: 600 }}>{dbStatus?.table_counts?.audit_logs?.toLocaleString() ?? 0}</div>
                                    </div>
                                </div>
                            </div>

                            <div style={{ borderTop: "1px solid var(--border)", paddingTop: "14px" }}>
                                <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--color-text)", marginBottom: "10px" }}>Storage Maintenance Operations</div>
                                <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                                    <button
                                        type="button"
                                        className="btn btn-outline"
                                        disabled={!isAdmin || dbActionRunning}
                                        onClick={() => handleDbMaintenance("vacuum")}
                                        title="Reclaims deleted disk space and rebuilds database B-trees"
                                    >
                                        🧹 Run VACUUM & Reclaim Space
                                    </button>

                                    <button
                                        type="button"
                                        className="btn btn-outline"
                                        disabled={!isAdmin || dbActionRunning}
                                        onClick={() => handleDbMaintenance("checkpoint", "TRUNCATE")}
                                        title="Flushes WAL journal pages into database and truncates WAL to 0 bytes"
                                    >
                                        💾 Checkpoint WAL Journal
                                    </button>

                                    <button
                                        type="button"
                                        className="btn btn-outline"
                                        disabled={!isAdmin || dbActionRunning}
                                        onClick={() => handleDbMaintenance("integrity")}
                                        title="Runs PRAGMA integrity_check and foreign key validation"
                                    >
                                        🔍 Check Integrity
                                    </button>

                                    <button
                                        type="button"
                                        className="btn btn-outline"
                                        disabled={!isAdmin || dbActionRunning}
                                        onClick={() => handleDbMaintenance("optimize")}
                                        title="Runs PRAGMA optimize for query planner tuning"
                                    >
                                        ⚡ PRAGMA Optimize
                                    </button>

                                    <button
                                        type="button"
                                        className="btn btn-outline"
                                        style={{ color: "var(--danger)", borderColor: "rgba(239,68,68,0.3)" }}
                                        disabled={!isAdmin || dbActionRunning}
                                        onClick={() => handleDbMaintenance("prune")}
                                        title="Prunes resolved/dismissed alerts older than 30 days and old audit logs"
                                    >
                                        🗑️ Prune Stale Alerts (&gt;30d)
                                    </button>
                                </div>
                            </div>
                        </div>

                        <div className="panel">
                            <div className="panel-header">
                                <div>
                                    <h2>⚙️ Retention & Checkpoint Policies</h2>
                                    <p className="panel-header-sub">Automated database housekeeping settings</p>
                                </div>
                            </div>

                            <div className="form-group" style={{ marginBottom: "14px" }}>
                                <label className="form-label">Auto-Checkpoint Interval (minutes)</label>
                                <input
                                    className="form-input"
                                    type="number"
                                    value={settings.db_auto_checkpoint_minutes || 30}
                                    onChange={e => handleSettingChange("db_auto_checkpoint_minutes", parseInt(e.target.value) || 5)}
                                    disabled={!isAdmin}
                                />
                                <span style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
                                    Periodic interval for background WAL journal flushing into the main database file.
                                </span>
                            </div>

                            <div className="form-group" style={{ marginBottom: "14px" }}>
                                <label className="form-label">Alert Retention Period (days)</label>
                                <input
                                    className="form-input"
                                    type="number"
                                    value={settings.db_alert_retention_days || 30}
                                    onChange={e => handleSettingChange("db_alert_retention_days", parseInt(e.target.value) || 7)}
                                    disabled={!isAdmin}
                                />
                                <span style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
                                    Resolved and false-positive alerts older than this are safely pruned to prevent database bloat.
                                </span>
                            </div>

                            <div className="form-group" style={{ marginBottom: "14px" }}>
                                <label className="form-label">Audit Log Retention Period (days)</label>
                                <input
                                    className="form-input"
                                    type="number"
                                    value={settings.db_audit_retention_days || 90}
                                    onChange={e => handleSettingChange("db_audit_retention_days", parseInt(e.target.value) || 14)}
                                    disabled={!isAdmin}
                                />
                                <span style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
                                    Days to preserve administrative audit log history.
                                </span>
                            </div>

                            <div className="form-group">
                                <label className="form-label">Maximum Alerts Storage Capacity</label>
                                <input
                                    className="form-input"
                                    type="number"
                                    value={settings.db_max_alerts_limit || 50000}
                                    onChange={e => handleSettingChange("db_max_alerts_limit", parseInt(e.target.value) || 1000)}
                                    disabled={!isAdmin}
                                />
                                <span style={{ fontSize: "11px", color: "var(--color-text-muted)" }}>
                                    Upper limit of total alerts stored in the local SQLite table before oldest resolved alerts are purged.
                                </span>
                            </div>
                        </div>
                    </div>
                )}
            </form>

            {/* ─── SECTION 5: Operator Accounts ─── */}
            {activeSection === "users" && (
                <div className="grid-2 animate-fade-up">
                    <div className="panel">
                        <div className="panel-header">
                            <div>
                                <h2>Registered Operator Accounts</h2>
                                <p className="panel-header-sub">Role-Based Access Control (RBAC) users</p>
                            </div>
                            <span className="chip">{users.length} user{users.length !== 1 ? "s" : ""}</span>
                        </div>
                        <div className="table-wrap">
                            <table className="data-table">
                                <thead>
                                    <tr>
                                        <th>Username</th>
                                        <th>Role</th>
                                        <th>Last Active</th>
                                        {isAdmin && <th>Action</th>}
                                    </tr>
                                </thead>
                                <tbody>
                                    {users.map(u => (
                                        <tr key={u.id}>
                                            <td style={{ fontWeight: 600 }}>{u.username}</td>
                                            <td>
                                                {isAdmin ? (
                                                    <select
                                                        className="form-select"
                                                        value={u.role}
                                                        onChange={e => handleRoleChange(u.username, e.target.value)}
                                                        style={{ padding: "2px 8px", fontSize: "12px" }}
                                                    >
                                                        <option value="admin">Admin 👑</option>
                                                        <option value="analyst">Analyst 🛡️</option>
                                                        <option value="viewer">Viewer 👁️</option>
                                                    </select>
                                                ) : (
                                                    <span className="chip">{u.role}</span>
                                                )}
                                            </td>
                                            <td className="table-mono">{u.last_login ? new Date(u.last_login).toLocaleTimeString() : "Never"}</td>
                                            {isAdmin && (
                                                <td>
                                                    <span style={{ fontSize: "12px", color: "var(--color-text-muted)" }}>
                                                        {u.username === currentUser?.username ? "(You)" : "Active"}
                                                    </span>
                                                </td>
                                            )}
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    {isAdmin && (
                        <div className="panel">
                            <div className="panel-header">
                                <div>
                                    <h2>➕ Create Operator Account</h2>
                                    <p className="panel-header-sub">Provision new access credentials</p>
                                </div>
                            </div>
                            <form onSubmit={handleCreateUser} style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                                <div className="form-group">
                                    <label className="form-label">Username</label>
                                    <input
                                        className="form-input"
                                        value={newUsername}
                                        onChange={e => setNewUsername(e.target.value)}
                                        placeholder="e.g. jdoe_soc"
                                        required
                                    />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Password</label>
                                    <input
                                        className="form-input"
                                        type="password"
                                        value={newPassword}
                                        onChange={e => setNewPassword(e.target.value)}
                                        placeholder="Min 6 characters"
                                        required
                                    />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Role Assignment</label>
                                    <select
                                        className="form-select"
                                        value={newRole}
                                        onChange={e => setNewRole(e.target.value)}
                                    >
                                        <option value="admin">Admin (Full System Controls)</option>
                                        <option value="analyst">Analyst (Triage & Rules)</option>
                                        <option value="viewer">Viewer (Read-Only Telemetry)</option>
                                    </select>
                                </div>
                                <button className="btn btn-primary" type="submit" style={{ marginTop: "6px" }}>
                                    Create Account
                                </button>
                                {userActionMsg && (
                                    <p style={{ fontSize: "12px", color: userActionMsg.startsWith("✓") ? "var(--color-safe)" : "var(--color-danger)" }}>
                                        {userActionMsg}
                                    </p>
                                )}
                            </form>
                        </div>
                    )}
                </div>
            )}

            {/* ─── SECTION 6: PCAP & Audit Logs ─── */}
            {activeSection === "forensics" && (
                <div className="grid-2 animate-fade-up">
                    <div className="panel">
                        <div className="panel-header">
                            <div>
                                <h2>🔬 Network PCAP Rolling Buffer</h2>
                                <p className="panel-header-sub">Forensic raw packet buffer for Wireshark inspection</p>
                            </div>
                        </div>
                        <div style={{ background: "rgba(255,255,255,0.03)", padding: "16px", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.08)", marginBottom: "16px" }}>
                            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                                <span>Buffer Utilization:</span>
                                <span style={{ fontWeight: 600 }}>{pcapStats?.packet_count || 0} / {pcapStats?.capacity || 1000} packets</span>
                            </div>
                            <div style={{ width: "100%", height: "6px", background: "rgba(255,255,255,0.1)", borderRadius: "3px", overflow: "hidden" }}>
                                <div style={{ width: `${Math.min(100, ((pcapStats?.packet_count || 0) / 1000) * 100)}%`, height: "100%", background: "var(--color-primary)" }} />
                            </div>
                        </div>
                        <button className="btn btn-primary" onClick={handleDownloadPcap} style={{ width: "100%" }}>
                            📥 Download Wireshark .pcap Capture
                        </button>
                    </div>

                    <div className="panel">
                        <div className="panel-header">
                            <div>
                                <h2>📜 System Audit Trail</h2>
                                <p className="panel-header-sub">Recent operator security and configuration actions</p>
                            </div>
                        </div>
                        <div className="table-wrap" style={{ maxHeight: "300px", overflowY: "auto" }}>
                            <table className="data-table">
                                <thead>
                                    <tr>
                                        <th>Operator</th>
                                        <th>Action</th>
                                        <th>Target</th>
                                        <th>Time</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {auditLogs.length === 0 ? (
                                        <tr><td colSpan={4} className="table-empty">No audit logs recorded yet</td></tr>
                                    ) : (
                                        auditLogs.map((log, i) => (
                                            <tr key={i}>
                                                <td style={{ fontWeight: 600 }}>{log.operator}</td>
                                                <td><span className="chip">{log.action}</span></td>
                                                <td className="table-mono" style={{ fontSize: "11px" }}>{log.target}</td>
                                                <td className="table-mono" style={{ fontSize: "11px" }}>{new Date(log.timestamp).toLocaleTimeString()}</td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
