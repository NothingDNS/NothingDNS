package dashboard

import (
	"embed"
	"io/fs"
	"net/http"
)

// Embed static files
//
//go:embed static/*
var staticFS embed.FS

// StaticHandler returns an http.Handler for serving static files
func StaticHandler() http.Handler {
	subFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		return http.NotFoundHandler()
	}
	return http.FileServer(http.FS(subFS))
}

// GetIndexHTML returns the dashboard HTML
func GetIndexHTML() string {
	return indexHTML
}

var indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NothingDNS Dashboard</title>
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --success: #22c55e;
            --error: #ef4444;
            --border: #475569;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 30px;
        }
        .logo { display: flex; align-items: center; gap: 12px; }
        .logo h1 { font-size: 24px; font-weight: 600; }
        .status-badge {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            background: var(--bg-secondary);
            border-radius: 20px;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            background: var(--success);
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
        .card {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 24px;
            border: 1px solid var(--border);
        }
        .card-title { font-size: 14px; color: var(--text-secondary); text-transform: uppercase; }
        .card-value { font-size: 32px; font-weight: 700; margin: 16px 0 4px; }
        .card-subtitle { font-size: 13px; color: var(--text-secondary); }
        .section {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 24px;
            border: 1px solid var(--border);
            margin-bottom: 30px;
        }
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .section-title { font-size: 18px; font-weight: 600; }
        .query-list { max-height: 400px; overflow-y: auto; }
        .query-item {
            display: flex;
            align-items: center;
            padding: 12px;
            border-bottom: 1px solid var(--border);
            font-size: 14px;
        }
        .query-item:hover { background: rgba(255,255,255,0.05); }
        .query-time { color: var(--text-secondary); width: 80px; }
        .query-domain { flex: 1; margin-left: 16px; }
        .query-type { width: 60px; text-align: center; }
        .query-status { width: 80px; text-align: center; }
        .query-duration { width: 80px; text-align: right; color: var(--text-secondary); }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
        }
        .badge-success { background: rgba(34, 197, 94, 0.2); color: var(--success); }
        .badge-error { background: rgba(239, 68, 68, 0.2); color: var(--error); }
        .badge-info { background: rgba(59, 130, 246, 0.2); color: var(--accent); }
        @media (max-width: 1024px) { .grid { grid-template-columns: repeat(2, 1fr); } }
        @media (max-width: 640px) { .grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <h1>🌐 NothingDNS</h1>
            </div>
            <div class="status-badge">
                <span class="status-dot"></span>
                <span id="status">Connected</span>
            </div>
        </header>

        <div class="grid">
            <div class="card">
                <div class="card-title">Total Queries</div>
                <div class="card-value" id="queriesTotal">0</div>
                <div class="card-subtitle" id="queriesPerSec">0 q/s</div>
            </div>
            <div class="card">
                <div class="card-title">Cache Hit Rate</div>
                <div class="card-value" id="cacheHitRate">0%</div>
                <div class="card-subtitle">Efficiency</div>
            </div>
            <div class="card">
                <div class="card-title">Blocked</div>
                <div class="card-value" id="blockedQueries">0</div>
                <div class="card-subtitle">Ad/malware</div>
            </div>
            <div class="card">
                <div class="card-title">Zones</div>
                <div class="card-value" id="zoneCount">0</div>
                <div class="card-subtitle">Active</div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2 class="section-title">Live Query Stream</h2>
            </div>
            <div class="query-list" id="queryList">
                <div style="padding: 20px; text-align: center; color: var(--text-secondary);">
                    Waiting for queries...
                </div>
            </div>
        </div>
    </div>

    <script>
        let queries = [];
        const maxQueries = 50;

        function connect() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const ws = new WebSocket(protocol + '//' + window.location.host + '/ws');

            ws.onopen = () => { document.getElementById('status').textContent = 'Connected'; };
            ws.onclose = () => {
                document.getElementById('status').textContent = 'Disconnected';
                setTimeout(connect, 3000);
            };
            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                if (data.type === 'query') addQuery(data.event);
            };
            ws.onerror = () => { document.getElementById('status').textContent = 'Error'; };
        }

        function addQuery(q) {
            queries.unshift(q);
            if (queries.length > maxQueries) queries.pop();
            renderQueries();
        }

        function renderQueries() {
            const list = document.getElementById('queryList');
            list.innerHTML = queries.map(q => {
                const time = new Date(q.timestamp).toLocaleTimeString();
                const statusClass = q.blocked ? 'badge-error' : q.cached ? 'badge-success' : 'badge-info';
                const statusText = q.blocked ? 'BLOCKED' : q.cached ? 'CACHED' : q.responseCode || 'OK';
                return '<div class="query-item">' +
                    '<span class="query-time">' + time + '</span>' +
                    '<span class="query-domain">' + (q.domain || 'unknown') + '</span>' +
                    '<span class="query-type"><span class="badge badge-info">' + (q.queryType || 'A') + '</span></span>' +
                    '<span class="query-status"><span class="badge ' + statusClass + '">' + statusText + '</span></span>' +
                    '<span class="query-duration">' + (q.duration || 0) / 1000 + 'ms</span>' +
                '</div>';
            }).join('');
        }

        async function fetchStats() {
            try {
                const resp = await fetch('/api/dashboard/stats');
                const stats = await resp.json();
                document.getElementById('queriesTotal').textContent = stats.queriesTotal.toLocaleString();
                document.getElementById('queriesPerSec').textContent = stats.queriesPerSec.toFixed(1) + ' q/s';
                document.getElementById('cacheHitRate').textContent = stats.cacheHitRate.toFixed(1) + '%';
                document.getElementById('blockedQueries').textContent = stats.blockedQueries.toLocaleString();
                document.getElementById('zoneCount').textContent = stats.zoneCount;
            } catch (e) {
                console.error('Failed to fetch stats:', e);
            }
        }

        connect();
        fetchStats();
        setInterval(fetchStats, 5000);
    </script>
</body>
</html>
`
