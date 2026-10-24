import { useEffect, useRef, useState } from "react";
import { getWebSocketUrl } from "../services/api";

export function useRealtime(onEvent) {
    const [connected, setConnected] = useState(false);
    const wsRef = useRef(null);
    const onEventRef = useRef(onEvent);
    onEventRef.current = onEvent;

    useEffect(() => {
        let isMounted = true;
        let reconnectTimeout = null;

        function connect() {
            if (!isMounted) return;
            try {
                const url = getWebSocketUrl();
                const ws = new WebSocket(url);
                wsRef.current = ws;

                ws.onopen = () => {
                    if (isMounted) setConnected(true);
                };

                ws.onmessage = (event) => {
                    try {
                        const parsed = JSON.parse(event.data);
                        if (onEventRef.current) {
                            onEventRef.current(parsed);
                        }
                    } catch (err) {
                        console.error("[WebSocket] Parse error:", err);
                    }
                };

                ws.onclose = () => {
                    if (isMounted) {
                        setConnected(false);
                        reconnectTimeout = setTimeout(connect, 3000);
                    }
                };

                ws.onerror = () => {
                    if (isMounted) setConnected(false);
                    try {
                        ws.close();
                    } catch {}
                };
            } catch (e) {
                if (isMounted) {
                    setConnected(false);
                    reconnectTimeout = setTimeout(connect, 4000);
                }
            }
        }

        connect();

        // Keepalive ping every 25s
        const pingInterval = setInterval(() => {
            if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
                wsRef.current.send("ping");
            }
        }, 25000);

        return () => {
            isMounted = false;
            clearInterval(pingInterval);
            if (reconnectTimeout) clearTimeout(reconnectTimeout);
            if (wsRef.current) {
                try {
                    wsRef.current.close();
                } catch {}
            }
        };
    }, []);

    return { connected };
}
