import { useEffect, useRef, useState } from 'react';
import type { QueryEvent } from '@/lib/api';

interface UseWebSocketOpts {
  onQuery?: (event: QueryEvent) => void;
  onError?: (error: string) => void;
  autoReconnect?: boolean;
}

export function useWebSocket(path: string, opts: UseWebSocketOpts = {}) {
  const { onQuery, onError, autoReconnect = true } = opts;
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const onQueryRef = useRef(onQuery);
  const onErrorRef = useRef(onError);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reconnectAttempts = useRef(0);
  const maxReconnectAttempts = 10;

  useEffect(() => { onQueryRef.current = onQuery; }, [onQuery]);
  useEffect(() => { onErrorRef.current = onError; }, [onError]);

  useEffect(() => {
    let cancelled = false;

    const connect = () => {
      if (cancelled) return;
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = `${proto}//${location.host}${path}`;

      // Browser WebSocket API automatically sends cookies with the upgrade request.
      // The server reads the ndns_token from the cookie in authMiddleware.
      const ws = new WebSocket(url);
      wsRef.current = ws;
      ws.onopen = () => { if (!cancelled) { setConnected(true); setError(null); reconnectAttempts.current = 0; } };
      ws.onclose = (e) => {
        if (!cancelled) {
          setConnected(false);
          // Provide meaningful error messages
          if (e.code === 1006) {
            // Abnormal closure - likely auth failure
            setError('Connection closed: authentication may have failed');
          } else if (e.code !== 1000) {
            setError(`Connection closed (code ${e.code})`);
          }
          // Reconnect with backoff, max 10 attempts
          if (autoReconnect && reconnectAttempts.current < maxReconnectAttempts) {
            reconnectAttempts.current++;
            const delay = Math.min(3000 * Math.pow(1.5, reconnectAttempts.current - 1), 30000);
            reconnectTimer.current = setTimeout(connect, delay);
          } else if (reconnectAttempts.current >= maxReconnectAttempts) {
            setError('Connection failed after multiple attempts. Please refresh the page.');
          }
        }
      };
      ws.onerror = () => {
        setError('WebSocket error: connection failed');
        if (onErrorRef.current) onErrorRef.current('WebSocket connection failed');
      };
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === 'query' && onQueryRef.current) onQueryRef.current(msg.event);
        } catch { /* ignore non-JSON messages */ }
      };
    };

    connect();
    return () => {
      cancelled = true;
      wsRef.current?.close();
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    };
  }, [path, autoReconnect]);

  return { connected, error };
}
