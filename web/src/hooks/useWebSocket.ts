import { useEffect, useRef, useState } from 'react';
import type { QueryEvent } from '@/lib/api';

interface UseWebSocketOpts {
  onQuery?: (event: QueryEvent) => void;
  autoReconnect?: boolean;
}

export function useWebSocket(path: string, opts: UseWebSocketOpts = {}) {
  const { onQuery, autoReconnect = true } = opts;
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const onQueryRef = useRef(onQuery);
  const [connected, setConnected] = useState(false);

  useEffect(() => { onQueryRef.current = onQuery; }, [onQuery]);

  useEffect(() => {
    let cancelled = false;

    const connect = () => {
      if (cancelled) return;
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = `${proto}//${location.host}${path}`;

      const ws = new WebSocket(url);
      wsRef.current = ws;
      ws.onopen = () => { if (!cancelled) setConnected(true); };
      ws.onclose = () => {
        if (!cancelled) {
          setConnected(false);
          if (autoReconnect) reconnectTimer.current = setTimeout(connect, 3000);
        }
      };
      ws.onerror = () => ws.close();
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

  return { connected };
}
