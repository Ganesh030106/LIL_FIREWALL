import { useEffect, useState } from "react";
import OverviewTab from "./Dashboard";
import AlertsTab from "./tabs/AlertsTab";
import RulesTab from "./tabs/RulesTab";
import NetworkTab from "./tabs/NetworkTab";
import ThreatIntelTab from "./tabs/ThreatIntelTab";
import ToolsTab from "./tabs/ToolsTab";
import HistoryTab from "./tabs/HistoryTab";
import LoginModal from "./components/LoginModal";
import SettingsTab from "./tabs/SettingsTab";
import { getUser, clearAuth } from "./services/api";
import { useRealtime } from "./hooks/useRealtime";

const TABS = [
    { id: "overview",    icon: "📊", label: "Overview" },
    { id: "alerts",      icon: "🔔", label: "Live Alerts" },
    { id: "rules",       icon: "🛡️", label: "Firewall Rules" },
    { id: "network",     icon: "🌐", label: "Network" },
    { id: "threat-intel", icon: "🧠", label: "AI Threat Intel" },
    { id: "tools",       icon: "🔧", label: "Security Tools" },
    { id: "history",     icon: "📜", label: "History" },
    { id: "settings",    icon: "⚙️", label: "Settings" },
];

function renderTab(activeTab, currentUser) {
    switch (activeTab) {
        case "overview":     return <OverviewTab currentUser={currentUser} />;
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
    const [currentUser, setCurrentUser] = useState(() => getUser());
    const [isLoginOpen, setIsLoginOpen] = useState(false);

    // Global WebSocket real-time connection monitor
    const { connected: wsConnected } = useRealtime();

    useEffect(() => {
        const root = document.documentElement;
        root.dataset.theme = theme;
        root.style.colorScheme = theme === "dark" ? "dark" : "light";
    }, [theme]);

    const handleUserClick = () => {
        if (currentUser) {
            if (window.confirm(`Logged in as ${currentUser.username} (${currentUser.role}). Do you want to sign out?`)) {
                clearAuth();
                setCurrentUser(null);
            }
        } else {
            setIsLoginOpen(true);
        }
    };

    const getRoleIcon = (role) => {
        if (role === "admin") return "👑";
        if (role === "analyst") return "🛡️";
        return "👁️";
    };

    return (
        <div className="app-layout">
            {/* ── Sidebar ── */}
            <aside className="sidebar">
                <div className="sidebar-brand" title="AI-Powered Contextual Firewall for Traffic Anomaly Detection">CF</div>

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

                {/* Operator Profile Button */}
                <button
                    type="button"
                    className={`sidebar-user-btn${currentUser ? " logged-in" : ""}`}
                    onClick={handleUserClick}
                    data-tooltip={
                        currentUser
                            ? `${currentUser.username} [${currentUser.role}] (Click to sign out)`
                            : "Operator Sign In"
                    }
                    aria-label="User Account"
                >
                    {currentUser ? getRoleIcon(currentUser.role) : "🔑"}
                </button>

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
                {renderTab(activeTab, currentUser)}
            </main>

            {/* ── Operator Login Modal ── */}
            <LoginModal
                isOpen={isLoginOpen}
                onClose={() => setIsLoginOpen(false)}
                onLoginSuccess={(user) => setCurrentUser(user)}
            />
        </div>
    );
}
