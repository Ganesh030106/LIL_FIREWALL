import { useEffect, useState } from "react";
import OverviewTab from "./Dashboard";
import IncidentsTab from "./tabs/IncidentsTab";
import AlertsTab from "./tabs/AlertsTab";
import RulesTab from "./tabs/RulesTab";
import NetworkTab from "./tabs/NetworkTab";
import ThreatIntelTab from "./tabs/ThreatIntelTab";
import ToolsTab from "./tabs/ToolsTab";
import HistoryTab from "./tabs/HistoryTab";
import SettingsTab from "./tabs/SettingsTab";
import ErrorBoundary from "./components/ErrorBoundary";
import { useRealtime } from "./hooks/useRealtime";

const TABS = [
    { id: "overview",     icon: "📊", label: "Overview" },
    { id: "incidents",    icon: "🚨", label: "Incidents" },
    { id: "alerts",       icon: "🔔", label: "Live Alerts" },
    { id: "rules",        icon: "🛡️", label: "Firewall Rules" },
    { id: "network",      icon: "🌐", label: "Network" },
    { id: "threat-intel", icon: "🧠", label: "AI Threat Intel" },
    { id: "tools",        icon: "🔧", label: "Security Tools" },
    { id: "history",      icon: "📜", label: "History" },
    { id: "settings",     icon: "⚙️", label: "Settings" },
];

function renderTab(activeTab, currentUser) {
    switch (activeTab) {
        case "overview":     return <OverviewTab currentUser={currentUser} />;
        case "incidents":    return <IncidentsTab currentUser={currentUser} />;
        case "alerts":       return <AlertsTab currentUser={currentUser} />;
        case "rules":        return <RulesTab currentUser={currentUser} />;
        case "network":      return <NetworkTab currentUser={currentUser} />;
        case "threat-intel": return <ThreatIntelTab currentUser={currentUser} />;
        case "tools":        return <ToolsTab currentUser={currentUser} />;
        case "history":      return <HistoryTab currentUser={currentUser} />;
        case "settings":     return <SettingsTab currentUser={currentUser} />;
        default:             return <OverviewTab currentUser={currentUser} />;
    }
}

export default function App() {
    const [activeTab, setActiveTab] = useState("overview");
    const [theme, setTheme] = useState("dark");
    const currentUser = { username: "operator", role: "admin" };

    // Global WebSocket real-time connection monitor
    const { connected: wsConnected } = useRealtime();

    useEffect(() => {
        const root = document.documentElement;
        root.dataset.theme = theme;
        root.style.colorScheme = theme === "dark" ? "dark" : "light";
    }, [theme]);

    return (
        <div className="app-layout">
            {/* ── Sidebar ── */}
            <aside className="sidebar">
                <div className="sidebar-brand" title="Volcano AI Firewall V5.0 — Autonomous SOC Platform">🌋</div>

                <nav className="sidebar-nav">
                    {TABS.map(tab => (
                        <button
                            key={tab.id}
                            className={`sidebar-tab${activeTab === tab.id ? " active" : ""}`}
                            data-tooltip={tab.label}
                            onClick={() => setActiveTab(tab.id)}
                            aria-label={tab.label}
                        >
                            {tab.icon}
                        </button>
                    ))}
                </nav>

                {/* Theme Toggle */}
                <button
                    type="button"
                    className="theme-toggle"
                    aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
                    title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
                    onClick={() => setTheme(current => current === "dark" ? "light" : "dark")}
                    style={{ marginTop: "8px" }}
                >
                    {theme === "dark" ? "☀️" : "🌙"}
                </button>

                <div className="sidebar-spacer" />

                {/* WebSocket Realtime Status Indicator */}
                <div
                    className={`sidebar-ws-badge ${wsConnected ? "online" : "offline"}`}
                    data-tooltip={wsConnected ? "Real-Time WebSocket: Live" : "WebSocket: Reconnecting (Polling Active)"}
                    title={wsConnected ? "Real-Time WebSocket: Live" : "WebSocket: Reconnecting (Polling Active)"}
                />
            </aside>

            {/* ── Main Content ── */}
            <main className="main-content" key={activeTab}>
                <ErrorBoundary resetKey={activeTab}>
                    {renderTab(activeTab, currentUser)}
                </ErrorBoundary>
            </main>
        </div>
    );
}
