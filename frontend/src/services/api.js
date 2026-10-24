/**
 * Central API client with JWT authentication and WebSocket URL resolver.
 */

export const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";

export function getToken() {
    return localStorage.getItem("volcano_token") || "";
}

export function getUser() {
    try {
        const u = localStorage.getItem("volcano_user");
        return u ? JSON.parse(u) : null;
    } catch {
        return null;
    }
}

export function setAuth(token, user) {
    if (token) {
        localStorage.setItem("volcano_token", token);
    } else {
        localStorage.removeItem("volcano_token");
    }
    if (user) {
        localStorage.setItem("volcano_user", JSON.stringify(user));
    } else {
        localStorage.removeItem("volcano_user");
    }
}

export function clearAuth() {
    localStorage.removeItem("volcano_token");
    localStorage.removeItem("volcano_user");
}

export async function apiFetch(endpoint, options = {}) {
    const headers = { ...(options.headers || {}) };
    const token = getToken();
    if (token && !headers["Authorization"]) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    const url = endpoint.startsWith("http") ? endpoint : `${API_BASE}${endpoint}`;
    return fetch(url, { ...options, headers });
}

export function getWebSocketUrl() {
    if (API_BASE) {
        const wsBase = API_BASE.replace(/^http:/, "ws:").replace(/^https:/, "wss:");
        return `${wsBase}/ws/events`;
    }
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.hostname || "127.0.0.1";
    // Dev default is backend on port 8000
    const port = window.location.port === "5173" ? "8000" : (window.location.port || "8000");
    return `${protocol}//${host}:${port}/ws/events`;
}
