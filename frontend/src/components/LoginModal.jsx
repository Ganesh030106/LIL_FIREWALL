import { useState } from "react";
import { apiFetch, setAuth } from "../services/api";

export default function LoginModal({ isOpen, onClose, onLoginSuccess }) {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

    if (!isOpen) return null;

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError("");
        setLoading(true);

        try {
            const res = await apiFetch("/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username: username.trim(), password }),
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || "Authentication failed.");
            }

            const data = await res.json();
            setAuth(data.access_token, data.user);
            if (onLoginSuccess) onLoginSuccess(data.user);
            onClose();
        } catch (err) {
            setError(err.message || "Login failed.");
        } finally {
            setLoading(false);
        }
    };

    const fillDemo = (user, pass) => {
        setUsername(user);
        setPassword(pass);
        setError("");
    };

    return (
        <div className="modal-backdrop" onClick={onClose}>
            <div className="modal-card" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h3 className="modal-title">🔐 Operator Authentication</h3>
                    <button className="modal-close-btn" onClick={onClose} aria-label="Close">✕</button>
                </div>

                <form onSubmit={handleSubmit} className="modal-form">
                    {error && <div className="auth-error-badge">{error}</div>}

                    <div className="form-group">
                        <label className="form-label">Username</label>
                        <input
                            type="text"
                            className="form-input"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            placeholder="e.g. admin"
                            required
                            autoFocus
                        />
                    </div>

                    <div className="form-group">
                        <label className="form-label">Password</label>
                        <input
                            type="password"
                            className="form-input"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="Enter password"
                            required
                        />
                    </div>

                    <button type="submit" className="btn-primary" disabled={loading} style={{ width: "100%", marginTop: "1rem" }}>
                        {loading ? "Authenticating..." : "Sign In"}
                    </button>

                    <div className="demo-accounts-box">
                        <span className="demo-title">Demo Credentials:</span>
                        <div className="demo-btn-group">
                            <button type="button" className="btn-chip" onClick={() => fillDemo("admin", "admin123")}>
                                Admin
                            </button>
                            <button type="button" className="btn-chip" onClick={() => fillDemo("analyst", "analyst123")}>
                                Analyst
                            </button>
                            <button type="button" className="btn-chip" onClick={() => fillDemo("viewer", "viewer123")}>
                                Viewer
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    );
}
