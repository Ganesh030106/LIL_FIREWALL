import React from "react";

export default class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null, errorInfo: null };
    }

    static getDerivedStateFromError(error) {
        return { hasError: true, error };
    }

    componentDidCatch(error, errorInfo) {
        console.error("SOC Console Uncaught Boundary Error:", error, errorInfo);
        this.setState({ errorInfo });
    }

    componentDidUpdate(prevProps) {
        if (prevProps.resetKey !== this.props.resetKey && this.state.hasError) {
            this.setState({ hasError: false, error: null, errorInfo: null });
        }
    }

    handleReset = () => {
        this.setState({ hasError: false, error: null, errorInfo: null });
        if (this.props.onReset) {
            this.props.onReset();
        }
    };

    render() {
        if (this.state.hasError) {
            return (
                <div className="panel animate-fade-in" style={{ margin: "40px auto", maxWidth: "640px", padding: "32px", textAlign: "center" }}>
                    <div style={{ fontSize: "2.8rem", marginBottom: "12px" }}>🛡️</div>
                    <h2 style={{ color: "var(--critical)", marginBottom: "8px" }}>Module Display Recovered</h2>
                    <p style={{ color: "var(--text-secondary)", fontSize: "13px", marginBottom: "16px", lineHeight: "1.5" }}>
                        An unexpected data format or rendering condition was caught by the SOC boundary protector. The rest of the console and tabs remain fully active.
                    </p>
                    {this.state.error && (
                        <div style={{
                            padding: "10px 14px",
                            borderRadius: "6px",
                            background: "rgba(239, 68, 68, 0.08)",
                            border: "1px solid rgba(239, 68, 68, 0.25)",
                            fontSize: "12px",
                            fontFamily: "var(--font-mono)",
                            color: "var(--critical)",
                            textAlign: "left",
                            marginBottom: "18px",
                            wordBreak: "break-all"
                        }}>
                            {String(this.state.error?.message || this.state.error)}
                        </div>
                    )}
                    <button
                        type="button"
                        className="btn btn-primary"
                        onClick={this.handleReset}
                        style={{ padding: "8px 24px" }}
                    >
                        🔄 Reload View
                    </button>
                </div>
            );
        }
        return this.props.children;
    }
}

