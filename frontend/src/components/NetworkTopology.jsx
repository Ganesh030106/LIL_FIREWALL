import { useState, useMemo } from "react";
import DeviceProfileDrawer from "./DeviceProfileDrawer";

export default function NetworkTopology({ devices = [], sessions = [], onRefresh }) {
    const [selectedDevice, setSelectedDevice] = useState(null);
    const [selectedConnection, setSelectedConnection] = useState(null);
    const [protocolFilter, setProtocolFilter] = useState("all");
    const [searchIp, setSearchIp] = useState("");

    const PROTOCOLS = ["all", "TCP", "UDP", "DNS", "HTTP", "TLS"];

    // Dynamic node layout synthesis
    const topology = useMemo(() => {
        // Base infrastructure nodes
        const nodes = [
            { id: "FW-CORE", label: "Firewall Core", type: "firewall", x: 260, y: 170, risk: 5, ip: "127.0.0.1" },
            { id: "AI-SENSOR", label: "PyTorch AI Sensor", type: "sensor", x: 140, y: 80, risk: 10, ip: "127.0.0.1" },
            { id: "GW-EXT", label: "Edge Gateway", type: "gateway", x: 380, y: 80, risk: 15, ip: "10.0.0.1" },
        ];

        // Real device nodes mapped dynamically around perimeter
        const devList = Array.isArray(devices) ? [...devices] : [];

        // If active sessions contain IPs not in devList, dynamically enrich the topology
        if (Array.isArray(sessions) && sessions.length > 0) {
            const knownIps = new Set(devList.map(d => d.ip).filter(Boolean));
            sessions.forEach(s => {
                const sip = s.src_ip || s.src;
                if (sip && sip !== "127.0.0.1" && !knownIps.has(sip) && devList.length < 12) {
                    knownIps.add(sip);
                    devList.push({ ip: sip, risk_score: s.state === "blocked" ? 0.85 : 0.15, role: "Active Endpoint" });
                }
            });
        }

        const cx = 260;
        const cy = 200;
        const radius = 150;

        devList.slice(0, 10).forEach((d, idx) => {
            const angle = (idx / Math.max(1, Math.min(10, devList.length))) * 2 * Math.PI + 0.5;
            const x = Math.round(cx + radius * Math.cos(angle));
            const y = Math.round(cy + radius * Math.sin(angle));
            const risk = Math.round((Number(d.risk_score || d.risk || 0)) * 100);

            nodes.push({
                id: d.ip || (d.mac ? `Host-${d.mac.slice(-5)}` : `DEV-${idx}`),
                label: d.ip || (d.mac ? `Host-${d.mac.slice(-5)}` : `Host-${idx}`),
                type: "device",
                x: Math.max(60, Math.min(460, x)),
                y: Math.max(70, Math.min(310, y)),
                risk,
                deviceData: d,
                ip: d.ip,
            });
        });

        // Communication links mapped from live session pipeline
        const links = [
            { source: "AI-SENSOR", target: "FW-CORE", protocol: "TLS", packets: 128, status: "secure" },
        ];

        if (Array.isArray(sessions) && sessions.length > 0) {
            sessions.slice(0, 20).forEach((s) => {
                const sIp = s.src_ip || s.src;
                const targetNode = nodes.find(n => n.ip === sIp || n.id === sIp);
                if (targetNode) {
                    const isBlocked = s.state === "blocked" || targetNode.risk >= 70;
                    links.push({
                        source: targetNode.id,
                        target: "FW-CORE",
                        protocol: s.protocol || "TCP",
                        packets: s.packets_sent || s.packet_count || 1,
                        status: isBlocked ? "suspicious" : "active",
                        targetNode,
                    });
                }
            });
        }

        // If nodes exist but no specific session links, wire active devices to FW-CORE
        if (links.length <= 1 && nodes.some(n => n.type === "device")) {
            nodes.filter(n => n.type === "device").forEach(dn => {
                links.push({
                    source: "FW-CORE",
                    target: dn.id,
                    protocol: "IP",
                    packets: 1,
                    status: dn.risk >= 60 ? "suspicious" : "active",
                    targetNode: dn,
                });
            });
        }

        return { nodes, links };
    }, [devices, sessions]);

    const filteredNodes = useMemo(() => {
        if (!searchIp.trim()) return topology.nodes;
        const q = searchIp.toLowerCase().trim();
        return topology.nodes.map(n => ({
            ...n,
            highlighted: (n.ip && n.ip.toLowerCase().includes(q)) || n.label.toLowerCase().includes(q),
        }));
    }, [topology.nodes, searchIp]);

    const filteredLinks = useMemo(() => {
        if (protocolFilter === "all") return topology.links;
        return topology.links.filter(l => l.protocol.toUpperCase() === protocolFilter.toUpperCase());
    }, [topology.links, protocolFilter]);

    const nodeCoords = useMemo(() => {
        const map = {};
        topology.nodes.forEach(n => { map[n.id] = { x: n.x, y: n.y }; });
        return map;
    }, [topology.nodes]);

    return (
        <div className="panel animate-fade-up" style={{ position: "relative" }}>
            <div className="panel-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px" }}>
                <div>
                    <h2>🌐 Interactive Real-Time Network Topology</h2>
                    <p className="panel-header-sub">Live host graph, active communication conduits, and heuristic device risk mapping</p>
                </div>
                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                    <div style={{ position: "relative" }}>
                        <input
                            type="text"
                            className="form-input"
                            value={searchIp}
                            onChange={e => setSearchIp(e.target.value)}
                            placeholder="Highlight IP..."
                            style={{ padding: "4px 22px 4px 8px", fontSize: "0.78rem", width: "130px" }}
                        />
                        {searchIp && (
                            <button
                                onClick={() => setSearchIp("")}
                                style={{ position: "absolute", right: "6px", top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", fontSize: "0.75rem" }}
                            >
                                ✕
                            </button>
                        )}
                    </div>
                    {onRefresh && (
                        <button className="btn" onClick={onRefresh} style={{ padding: "4px 10px", fontSize: "0.78rem" }}>
                            ↻ Refresh
                        </button>
                    )}
                </div>
            </div>

            {/* Protocol Filters Bar */}
            <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", margin: "8px 0 14px 0", alignItems: "center" }}>
                <span style={{ fontSize: "0.74rem", color: "var(--text-muted)", marginRight: "4px" }}>Filter Protocol:</span>
                {PROTOCOLS.map(p => (
                    <button
                        key={p}
                        className={`filter-pill${protocolFilter === p ? " active" : ""}`}
                        style={{ padding: "3px 10px", fontSize: "0.74rem" }}
                        onClick={() => setProtocolFilter(p)}
                    >
                        {p.toUpperCase()}
                    </button>
                ))}
            </div>

            {/* SVG Visualizer Canvas */}
            <div style={{ background: "rgba(0, 0, 0, 0.28)", borderRadius: "10px", border: "1px solid var(--border)", padding: "8px", overflow: "hidden" }}>
                <svg viewBox="0 0 520 330" style={{ width: "100%", height: "300px", display: "block" }}>
                    <defs>
                        <radialGradient id="fwPulseGlow" cx="50%" cy="50%" r="50%">
                            <stop offset="0%" stopColor="#ef4444" stopOpacity="0.4" />
                            <stop offset="100%" stopColor="#ef4444" stopOpacity="0" />
                        </radialGradient>
                        <radialGradient id="safePulseGlow" cx="50%" cy="50%" r="50%">
                            <stop offset="0%" stopColor="#10b981" stopOpacity="0.35" />
                            <stop offset="100%" stopColor="#10b981" stopOpacity="0" />
                        </radialGradient>
                        <radialGradient id="sensorGlow" cx="50%" cy="50%" r="50%">
                            <stop offset="0%" stopColor="#00d2ff" stopOpacity="0.35" />
                            <stop offset="100%" stopColor="#00d2ff" stopOpacity="0" />
                        </radialGradient>
                    </defs>

                    {/* Connection Lines */}
                    {filteredLinks.map((link, idx) => {
                        const s = nodeCoords[link.source];
                        const t = nodeCoords[link.target];
                        if (!s || !t) return null;
                        const isSuspicious = link.status === "suspicious";
                        const strokeColor = isSuspicious ? "#ef4444" : "#00d2ff";
                        const strokeDash = isSuspicious ? "4,4" : "none";

                        return (
                            <g key={idx} style={{ cursor: "pointer" }} onClick={() => setSelectedConnection(link)}>
                                <line
                                    x1={s.x}
                                    y1={s.y}
                                    x2={t.x}
                                    y2={t.y}
                                    stroke={strokeColor}
                                    strokeWidth={isSuspicious ? 2.5 : 1.5}
                                    strokeOpacity={0.65}
                                    strokeDasharray={strokeDash}
                                />
                                {/* Protocol Badge Tag in center of line */}
                                <rect
                                    x={(s.x + t.x) / 2 - 14}
                                    y={(s.y + t.y) / 2 - 8}
                                    width="28"
                                    height="14"
                                    rx="3"
                                    fill="rgba(10, 16, 26, 0.9)"
                                    stroke={strokeColor}
                                    strokeWidth="0.8"
                                />
                                <text
                                    x={(s.x + t.x) / 2}
                                    y={(s.y + t.y) / 2 + 2}
                                    fill={strokeColor}
                                    fontSize="8"
                                    fontWeight="600"
                                    textAnchor="middle"
                                    fontFamily="var(--font-mono)"
                                >
                                    {link.protocol}
                                </text>
                            </g>
                        );
                    })}

                    {/* Nodes */}
                    {filteredNodes.map(node => {
                        const isFW = node.type === "firewall";
                        const isGW = node.type === "gateway";
                        const isSensor = node.type === "sensor";
                        const isCritical = node.risk >= 60;
                        const isSuspicious = node.risk >= 30;

                        let fillColor = "#10b981";
                        if (isFW) fillColor = "#ef4444";
                        else if (isSensor) fillColor = "#00d2ff";
                        else if (isGW) fillColor = "#f59e0b";
                        else if (isCritical) fillColor = "#ef4444";
                        else if (isSuspicious) fillColor = "#f59e0b";

                        const isHighlighted = node.highlighted;

                        return (
                            <g
                                key={node.id}
                                style={{ cursor: "pointer" }}
                                onClick={() => {
                                    if (node.deviceData) setSelectedDevice(node.deviceData);
                                    else setSelectedDevice({ ip: node.ip, role: node.label, risk_score: node.risk / 100 });
                                }}
                            >
                                {/* Outer Pulse Ring */}
                                <circle
                                    cx={node.x}
                                    cy={node.y}
                                    r={isFW ? 28 : (isHighlighted ? 24 : 18)}
                                    fill={fillColor}
                                    fillOpacity={isHighlighted ? 0.4 : 0.15}
                                />
                                {/* Core Node Circle */}
                                <circle
                                    cx={node.x}
                                    cy={node.y}
                                    r={isFW ? 16 : (isGW || isSensor ? 13 : 11)}
                                    fill="rgba(15, 23, 42, 0.95)"
                                    stroke={fillColor}
                                    strokeWidth={isHighlighted ? 3 : 2}
                                />
                                {/* Node Icon / Character */}
                                <text
                                    x={node.x}
                                    y={node.y + 4}
                                    textAnchor="middle"
                                    fill={fillColor}
                                    fontSize={isFW ? "12" : "10"}
                                    fontWeight="700"
                                >
                                    {isFW ? "🛡️" : (isSensor ? "AI" : (isGW ? "GW" : "💻"))}
                                </text>
                                {/* Node Label */}
                                <text
                                    x={node.x}
                                    y={node.y + (isFW ? 28 : 22)}
                                    textAnchor="middle"
                                    fill="var(--text)"
                                    fontSize="8.5"
                                    fontWeight={isHighlighted ? "700" : "500"}
                                    fontFamily="var(--font-mono)"
                                >
                                    {node.label}
                                </text>
                                {node.type === "device" && (
                                    <text
                                        x={node.x}
                                        y={node.y + 32}
                                        textAnchor="middle"
                                        fill={fillColor}
                                        fontSize="7.5"
                                        fontWeight="600"
                                    >
                                        Risk: {node.risk}%
                                    </text>
                                )}
                            </g>
                        );
                    })}
                </svg>
            </div>

            {/* Topology Legend & Connection Inspector Tray */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px", marginTop: "10px", fontSize: "0.75rem", color: "var(--text-muted)" }}>
                <div style={{ display: "flex", gap: "12px", alignItems: "center", flexWrap: "wrap" }}>
                    <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                        <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#ef4444", display: "inline-block" }} /> Core / Critical Risk
                    </span>
                    <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                        <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#f59e0b", display: "inline-block" }} /> Gateway / Elevated
                    </span>
                    <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                        <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#00d2ff", display: "inline-block" }} /> AI Sensor Pipeline
                    </span>
                    <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                        <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#10b981", display: "inline-block" }} /> Nominal Endpoint
                    </span>
                </div>
                <div style={{ fontSize: "0.72rem", fontStyle: "italic" }}>
                    Tip: Click any node to open its Device Intelligence Profile
                </div>
            </div>

            {/* Connection Detail Modal/Tray */}
            {selectedConnection && (
                <div style={{ marginTop: "12px", padding: "10px 14px", background: "rgba(0,0,0,0.35)", borderRadius: "8px", border: "1px solid var(--border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div>
                        <span style={{ fontWeight: 600, color: "var(--text)" }}>Conduit: {selectedConnection.source} ➔ {selectedConnection.target}</span>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "2px" }}>
                            Protocol: <strong>{selectedConnection.protocol}</strong> | Volume: {selectedConnection.packets} frames | Status: <span style={{ color: selectedConnection.status === "suspicious" ? "#ef4444" : "#10b981", fontWeight: 600 }}>{selectedConnection.status.toUpperCase()}</span>
                        </div>
                    </div>
                    <button className="btn" onClick={() => setSelectedConnection(null)} style={{ padding: "3px 8px", fontSize: "0.74rem" }}>
                        ✕ Dismiss
                    </button>
                </div>
            )}

            {/* Slide-out Device Profile Drawer */}
            {selectedDevice && (
                <DeviceProfileDrawer
                    device={selectedDevice}
                    onClose={() => setSelectedDevice(null)}
                    onActionComplete={onRefresh}
                />
            )}
        </div>
    );
}
