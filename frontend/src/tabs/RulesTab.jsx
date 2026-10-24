import { useEffect, useState } from "react";
import { apiFetch } from "../services/api";

const EMPTY_RULE = { name: "", action: "allow", src_ip: "", dst_ip: "", src_port: "", dst_port: "", protocol: "", app_name: "", priority: "10", description: "" };
const EMPTY_ACL = { name: "", subject_type: "ip", subject_value: "", resource: "", action: "allow" };

export default function RulesTab({ currentUser }) {
    const [rules, setRules] = useState([]);
    const [aclEntries, setAclEntries] = useState([]);
    const [ruleForm, setRuleForm] = useState({ ...EMPTY_RULE });
    const [aclForm, setAclForm] = useState({ ...EMPTY_ACL });
    const [showRuleForm, setShowRuleForm] = useState(false);
    const [showAclForm, setShowAclForm] = useState(false);
    const [ruleStatus, setRuleStatus] = useState("");
    const [aclStatus, setAclStatus] = useState("");

    const isViewer = currentUser?.role === "viewer";

    const fetchRules = async () => {
        try {
            const res = await apiFetch("/api/rules");
            if (res.ok) setRules(await res.json());
        } catch {}
    };

    const fetchACL = async () => {
        try {
            const res = await apiFetch("/api/acl");
            if (res.ok) setAclEntries(await res.json());
        } catch {}
    };

    useEffect(() => { fetchRules(); fetchACL(); }, []);

    const handleCreateRule = async (e) => {
        e.preventDefault();
        setRuleStatus("");
        if (isViewer) {
            setRuleStatus("✗ Viewer role is read-only. Please sign in as Analyst or Admin.");
            return;
        }
        const body = {
            name: ruleForm.name,
            action: ruleForm.action,
            src_ip: ruleForm.src_ip || null,
            dst_ip: ruleForm.dst_ip || null,
            src_port: ruleForm.src_port ? parseInt(ruleForm.src_port) : null,
            dst_port: ruleForm.dst_port ? parseInt(ruleForm.dst_port) : null,
            protocol: ruleForm.protocol || null,
            app_name: ruleForm.app_name?.trim() || null,
            priority: parseInt(ruleForm.priority) || 10,
            description: ruleForm.description,
        };
        try {
            const res = await apiFetch("/api/rules", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            });
            if (!res.ok) throw new Error((await res.json())?.detail || "Failed to create rule");
            setRuleStatus("✓ Rule created successfully");
            setRuleForm({ ...EMPTY_RULE });
            setShowRuleForm(false);
            fetchRules();
        } catch (err) {
            setRuleStatus(`✗ ${err.message}`);
        }
    };

    const handleDeleteRule = async (id) => {
        if (isViewer) {
            alert("Viewer role is read-only.");
            return;
        }
        if (!window.confirm(`Delete rule #${id}?`)) return;
        try {
            await apiFetch(`/api/rules/${id}`, { method: "DELETE" });
            fetchRules();
        } catch {}
    };

    const handleCreateACL = async (e) => {
        e.preventDefault();
        setAclStatus("");
        if (isViewer) {
            setAclStatus("✗ Viewer role is read-only.");
            return;
        }
        try {
            const res = await apiFetch("/api/acl", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(aclForm),
            });
            if (!res.ok) throw new Error("Failed to create ACL entry");
            setAclStatus("✓ ACL entry created");
            setAclForm({ ...EMPTY_ACL });
            setShowAclForm(false);
            fetchACL();
        } catch (err) {
            setAclStatus(`✗ ${err.message}`);
        }
    };

    const actionBadge = (action) => {
        const cls = action === "allow" ? "badge-safe" : action === "deny" || action === "drop" || action === "reject" ? "badge-critical" : "badge-neutral";
        return <span className={`badge ${cls}`}>{action}</span>;
    };

    return (
        <div className="tab-content" key="rules">
            <div className="tab-header">
                <div className="tab-header-info">
                    <div className="tab-eyebrow">🛡️ Firewall Rules</div>
                    <h1>Rule & Access Control Management</h1>
                    <p className="tab-subtitle">
                        Create, inspect, and manage firewall rules and access control list entries with process-level precision. Rules are evaluated in priority order against every packet.
                    </p>
                </div>
                <div className="tab-header-actions">
                    <button className="btn" onClick={fetchRules}>↻ Refresh</button>
                </div>
            </div>

            {/* ─── Firewall Rules ─── */}
            <div className="panel animate-fade-up stagger-1">
                <div className="panel-header">
                    <div>
                        <h2>Firewall Rules</h2>
                        <p className="panel-header-sub">{rules.length} rule{rules.length !== 1 ? "s" : ""} configured</p>
                    </div>
                    <button className="btn btn-primary" onClick={() => setShowRuleForm(!showRuleForm)}>
                        {showRuleForm ? "Cancel" : "+ Add Rule"}
                    </button>
                </div>

                {showRuleForm && (
                    <form className="detail-box mb-md" onSubmit={handleCreateRule}>
                        <div className="form-row mb-sm">
                            <div className="form-group">
                                <label className="form-label">Rule Name</label>
                                <input className="form-input" required value={ruleForm.name} onChange={e => setRuleForm({ ...ruleForm, name: e.target.value })} placeholder="Block suspicious process" />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Action</label>
                                <select className="form-select" value={ruleForm.action} onChange={e => setRuleForm({ ...ruleForm, action: e.target.value })}>
                                    <option value="allow">Allow</option>
                                    <option value="deny">Deny</option>
                                    <option value="drop">Drop</option>
                                    <option value="reject">Reject</option>
                                </select>
                            </div>
                            <div className="form-group">
                                <label className="form-label">Priority</label>
                                <select className="form-select" value={ruleForm.priority} onChange={e => setRuleForm({ ...ruleForm, priority: e.target.value })}>
                                    <option value="1">Critical (1)</option>
                                    <option value="5">High (5)</option>
                                    <option value="10">Normal (10)</option>
                                    <option value="20">Low (20)</option>
                                </select>
                            </div>
                        </div>
                        <div className="form-row mb-sm">
                            <div className="form-group">
                                <label className="form-label">Application / Process</label>
                                <input className="form-input" value={ruleForm.app_name} onChange={e => setRuleForm({ ...ruleForm, app_name: e.target.value })} placeholder="e.g. curl.exe, ssh, python.exe" />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Source IP</label>
                                <input className="form-input" value={ruleForm.src_ip} onChange={e => setRuleForm({ ...ruleForm, src_ip: e.target.value })} placeholder="192.168.1.0/24" />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Dest IP</label>
                                <input className="form-input" value={ruleForm.dst_ip} onChange={e => setRuleForm({ ...ruleForm, dst_ip: e.target.value })} placeholder="10.0.0.1" />
                            </div>
                        </div>
                        <div className="form-row mb-sm">
                            <div className="form-group">
                                <label className="form-label">Src Port</label>
                                <input className="form-input" type="number" value={ruleForm.src_port} onChange={e => setRuleForm({ ...ruleForm, src_port: e.target.value })} placeholder="Any" />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Dst Port</label>
                                <input className="form-input" type="number" value={ruleForm.dst_port} onChange={e => setRuleForm({ ...ruleForm, dst_port: e.target.value })} placeholder="22" />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Protocol</label>
                                <select className="form-select" value={ruleForm.protocol} onChange={e => setRuleForm({ ...ruleForm, protocol: e.target.value })}>
                                    <option value="">Any</option>
                                    <option value="TCP">TCP</option>
                                    <option value="UDP">UDP</option>
                                    <option value="ICMP">ICMP</option>
                                </select>
                            </div>
                            <div className="form-group" style={{ gridColumn: "span 3" }}>
                                <label className="form-label">Description</label>
                                <input className="form-input" value={ruleForm.description} onChange={e => setRuleForm({ ...ruleForm, description: e.target.value })} placeholder="Optional description" />
                            </div>
                        </div>
                        <button className="btn btn-primary" type="submit">Create Rule</button>
                        {ruleStatus && <span style={{ marginLeft: 12 }} className={ruleStatus.startsWith("✓") ? "text-safe" : "text-danger"}>{ruleStatus}</span>}
                    </form>
                )}

                <div className="table-wrap">
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Name</th>
                                <th>Action</th>
                                <th>App / Process</th>
                                <th>Priority</th>
                                <th>Status</th>
                                <th style={{ width: 80 }}>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rules.length === 0 ? (
                                <tr><td colSpan={7} className="table-empty">No firewall rules configured</td></tr>
                            ) : (
                                rules.map(r => (
                                    <tr key={r.id}>
                                        <td className="table-mono">{r.id}</td>
                                        <td>{r.name}</td>
                                        <td>{actionBadge(r.action)}</td>
                                        <td>{r.app_name ? <span className="badge badge-info" style={{ fontFamily: "monospace" }}>{r.app_name}</span> : <span className="text-muted">Any</span>}</td>
                                        <td className="table-mono">{r.priority}</td>
                                        <td>{r.enabled ? <span className="badge badge-safe">Enabled</span> : <span className="badge badge-neutral">Disabled</span>}</td>
                                        <td>
                                            <button className="btn btn-sm btn-danger" onClick={() => handleDeleteRule(r.id)}>Delete</button>
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* ─── ACL Entries ─── */}
            <div className="panel animate-fade-up stagger-3">
                <div className="panel-header">
                    <div>
                        <h2>Access Control List</h2>
                        <p className="panel-header-sub">{aclEntries.length} ACL entr{aclEntries.length !== 1 ? "ies" : "y"}</p>
                    </div>
                    <button className="btn btn-primary" onClick={() => setShowAclForm(!showAclForm)}>
                        {showAclForm ? "Cancel" : "+ Add Entry"}
                    </button>
                </div>

                {showAclForm && (
                    <form className="detail-box mb-md" onSubmit={handleCreateACL}>
                        <div className="form-row mb-sm">
                            <div className="form-group">
                                <label className="form-label">Name</label>
                                <input className="form-input" required value={aclForm.name} onChange={e => setAclForm({ ...aclForm, name: e.target.value })} placeholder="Block Guest WiFi" />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Subject Type</label>
                                <select className="form-select" value={aclForm.subject_type} onChange={e => setAclForm({ ...aclForm, subject_type: e.target.value })}>
                                    <option value="ip">IP Address</option>
                                    <option value="user">User</option>
                                    <option value="group">Group</option>
                                    <option value="mac">MAC Address</option>
                                </select>
                            </div>
                            <div className="form-group">
                                <label className="form-label">Subject Value</label>
                                <input className="form-input" required value={aclForm.subject_value} onChange={e => setAclForm({ ...aclForm, subject_value: e.target.value })} placeholder="192.168.1.100" />
                            </div>
                        </div>
                        <div className="form-row mb-sm">
                            <div className="form-group">
                                <label className="form-label">Resource</label>
                                <input className="form-input" required value={aclForm.resource} onChange={e => setAclForm({ ...aclForm, resource: e.target.value })} placeholder="internal-servers" />
                            </div>
                            <div className="form-group">
                                <label className="form-label">Action</label>
                                <select className="form-select" value={aclForm.action} onChange={e => setAclForm({ ...aclForm, action: e.target.value })}>
                                    <option value="allow">Allow</option>
                                    <option value="deny">Deny</option>
                                </select>
                            </div>
                        </div>
                        <button className="btn btn-primary" type="submit">Create ACL Entry</button>
                        {aclStatus && <span style={{ marginLeft: 12 }} className={aclStatus.startsWith("✓") ? "text-safe" : "text-danger"}>{aclStatus}</span>}
                    </form>
                )}

                <div className="table-wrap">
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Name</th>
                                <th>Subject</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {aclEntries.length === 0 ? (
                                <tr><td colSpan={4} className="table-empty">No ACL entries configured</td></tr>
                            ) : (
                                aclEntries.map(e => (
                                    <tr key={e.id}>
                                        <td className="table-mono">{e.id}</td>
                                        <td>{e.name}</td>
                                        <td className="table-mono">{e.subject_type}</td>
                                        <td>{actionBadge(e.action)}</td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}
