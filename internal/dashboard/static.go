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
            --bg-tertiary: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --success: #22c55e;
            --error: #ef4444;
            --warning: #f59e0b;
            --border: #475569;
            --radius: 8px;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        .app { display: flex; min-height: 100vh; }
        .sidebar {
            width: 220px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border);
            padding: 20px 0;
            flex-shrink: 0;
        }
        .sidebar-logo { padding: 0 20px 20px; border-bottom: 1px solid var(--border); margin-bottom: 12px; }
        .sidebar-logo h1 { font-size: 18px; font-weight: 700; }
        .sidebar-logo p { font-size: 11px; color: var(--text-secondary); margin-top: 4px; }
        .nav-item {
            display: flex; align-items: center; gap: 10px; padding: 10px 20px;
            color: var(--text-secondary); cursor: pointer; font-size: 14px; text-decoration: none;
        }
        .nav-item:hover { background: rgba(255,255,255,0.05); color: var(--text-primary); }
        .nav-item.active { color: var(--accent); background: rgba(59,130,246,0.1); border-right: 3px solid var(--accent); }
        .main { flex: 1; padding: 24px; overflow-y: auto; max-height: 100vh; }
        .page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
        .page-title { font-size: 22px; font-weight: 600; }
        .page-actions { display: flex; gap: 8px; }
        .btn {
            display: inline-flex; align-items: center; gap: 6px; padding: 8px 16px;
            border: none; border-radius: var(--radius); font-size: 13px; font-weight: 500; cursor: pointer;
        }
        .btn-primary { background: var(--accent); color: white; }
        .btn-primary:hover { background: var(--accent-hover); }
        .btn-secondary { background: var(--bg-tertiary); color: var(--text-primary); }
        .btn-secondary:hover { background: var(--border); }
        .btn-danger { background: rgba(239,68,68,0.15); color: var(--error); }
        .btn-danger:hover { background: rgba(239,68,68,0.25); }
        .btn-sm { padding: 4px 10px; font-size: 12px; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: var(--bg-secondary); border-radius: var(--radius); padding: 20px; border: 1px solid var(--border); }
        .stat-label { font-size: 12px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; }
        .stat-value { font-size: 28px; font-weight: 700; margin: 8px 0 2px; }
        .stat-sub { font-size: 12px; color: var(--text-secondary); }
        .table-container { background: var(--bg-secondary); border-radius: var(--radius); border: 1px solid var(--border); overflow: hidden; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; padding: 12px 16px; font-size: 12px; color: var(--text-secondary); text-transform: uppercase; background: var(--bg-tertiary); border-bottom: 1px solid var(--border); }
        td { padding: 10px 16px; font-size: 13px; border-bottom: 1px solid rgba(71,85,105,0.4); }
        tr:hover td { background: rgba(255,255,255,0.02); }
        .mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 12px; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
        .badge-success { background: rgba(34,197,94,0.15); color: var(--success); }
        .badge-error { background: rgba(239,68,68,0.15); color: var(--error); }
        .badge-info { background: rgba(59,130,246,0.15); color: var(--accent); }
        .badge-warning { background: rgba(245,158,11,0.15); color: var(--warning); }
        .form-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }
        .form-group { margin-bottom: 16px; }
        .form-group label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 6px; color: var(--text-secondary); }
        .form-group input, .form-group select, .form-group textarea {
            width: 100%; padding: 8px 12px; background: var(--bg-primary); border: 1px solid var(--border);
            border-radius: var(--radius); color: var(--text-primary); font-size: 13px; outline: none;
        }
        .form-group input:focus, .form-group select:focus { border-color: var(--accent); }
        .modal-overlay {
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; z-index: 100;
        }
        .modal {
            background: var(--bg-secondary); border-radius: 12px; border: 1px solid var(--border);
            padding: 24px; width: 100%; max-width: 480px; max-height: 80vh; overflow-y: auto;
        }
        .modal-title { font-size: 18px; font-weight: 600; margin-bottom: 20px; }
        .modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 20px; }
        .toast-container { position: fixed; top: 20px; right: 20px; z-index: 200; }
        .toast {
            background: var(--bg-secondary); border: 1px solid var(--border); border-radius: var(--radius);
            padding: 12px 16px; margin-bottom: 8px; font-size: 13px; animation: slideIn 0.3s ease; min-width: 280px;
        }
        .toast-success { border-left: 3px solid var(--success); }
        .toast-error { border-left: 3px solid var(--error); }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        .empty-state { text-align: center; padding: 48px 24px; color: var(--text-secondary); }
        .empty-state h3 { font-size: 16px; margin-bottom: 8px; color: var(--text-primary); }
        .empty-state p { font-size: 13px; margin-bottom: 16px; }
        .zone-header {
            background: var(--bg-secondary); border-radius: var(--radius); border: 1px solid var(--border);
            padding: 20px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: flex-start;
        }
        .zone-info h2 { font-size: 18px; font-weight: 600; margin-bottom: 8px; }
        .zone-meta { display: flex; gap: 24px; }
        .zone-meta-item { font-size: 13px; color: var(--text-secondary); }
        .zone-meta-item strong { color: var(--text-primary); }
        .record-actions { display: flex; gap: 4px; }
        .breadcrumb { font-size: 13px; color: var(--text-secondary); margin-bottom: 16px; }
        .breadcrumb a { color: var(--accent); text-decoration: none; }
        .breadcrumb a:hover { text-decoration: underline; }
        .add-row td { background: rgba(59,130,246,0.05); }
        .add-row input, .add-row select {
            padding: 6px 8px; background: var(--bg-primary); border: 1px solid var(--border);
            border-radius: 4px; color: var(--text-primary); font-size: 12px; width: 100%;
        }
        @media (max-width: 1024px) { .stats-grid { grid-template-columns: repeat(2, 1fr); } }
        @media (max-width: 768px) {
            .app { flex-direction: column; }
            .sidebar { width: 100%; border-right: none; border-bottom: 1px solid var(--border); padding: 10px 0; }
            .sidebar-logo { display: none; }
            .stats-grid { grid-template-columns: 1fr 1fr; }
            .form-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="app">
        <nav class="sidebar">
            <div class="sidebar-logo">
                <h1>NothingDNS</h1>
                <p>Authoritative DNS Server</p>
            </div>
            <a class="nav-item active" data-page="dashboard" onclick="navigate('dashboard')">
                Dashboard
            </a>
            <a class="nav-item" data-page="zones" onclick="navigate('zones')">
                Zones
            </a>
            <a class="nav-item" data-page="settings" onclick="navigate('settings')">
                Settings
            </a>
        </nav>
        <div class="main" id="mainContent"></div>
    </div>
    <div class="toast-container" id="toastContainer"></div>

    <script>
    var currentPage = 'dashboard';
    var currentZone = null;
    var addingRecord = false;

    function navigate(page, zoneName) {
        currentPage = page;
        currentZone = zoneName || null;
        addingRecord = false;
        document.querySelectorAll('.nav-item').forEach(function(n) { n.classList.remove('active'); });
        var activeNav = document.querySelector('[data-page="' + page + '"]');
        if (activeNav) activeNav.classList.add('active');
        render();
    }

    function render() {
        var main = document.getElementById('mainContent');
        switch (currentPage) {
            case 'dashboard': renderDashboard(main); break;
            case 'zones': renderZones(main); break;
            case 'zone-detail': renderZoneDetail(main); break;
            case 'settings': renderSettings(main); break;
            default: renderDashboard(main);
        }
    }

    function api(method, path, body) {
        var opts = { method: method, headers: { 'Content-Type': 'application/json' } };
        if (body) opts.body = JSON.stringify(body);
        return fetch(path, opts).then(function(resp) {
            return resp.json().then(function(data) {
                if (!resp.ok) throw new Error(data.error || 'Request failed');
                return data;
            });
        });
    }

    function toast(msg, type) {
        type = type || 'success';
        var el = document.createElement('div');
        el.className = 'toast toast-' + type;
        el.textContent = msg;
        document.getElementById('toastContainer').appendChild(el);
        setTimeout(function() { el.remove(); }, 3000);
    }

    // --- Dashboard ---
    function renderDashboard(el) {
        el.innerHTML = '<div class="page-header"><h1 class="page-title">Dashboard</h1></div>' +
            '<div class="stats-grid">' +
                '<div class="stat-card"><div class="stat-label">Total Queries</div><div class="stat-value" id="sTotal">-</div><div class="stat-sub" id="sQps">-</div></div>' +
                '<div class="stat-card"><div class="stat-label">Cache Hit Rate</div><div class="stat-value" id="sCache">-</div><div class="stat-sub">Efficiency</div></div>' +
                '<div class="stat-card"><div class="stat-label">Blocked</div><div class="stat-value" id="sBlocked">-</div><div class="stat-sub">Ad/malware</div></div>' +
                '<div class="stat-card"><div class="stat-label">Zones</div><div class="stat-value" id="sZones">-</div><div class="stat-sub">Active</div></div>' +
            '</div>';
        api('GET', '/api/dashboard/stats').then(function(stats) {
            var el = function(id) { return document.getElementById(id); };
            if (el('sTotal')) el('sTotal').textContent = (stats.queriesTotal || 0).toLocaleString();
            if (el('sQps')) el('sQps').textContent = (stats.queriesPerSec || 0).toFixed(1) + ' q/s';
            if (el('sCache')) el('sCache').textContent = (stats.cacheHitRate || 0).toFixed(1) + '%';
            if (el('sBlocked')) el('sBlocked').textContent = (stats.blockedQueries || 0).toLocaleString();
            if (el('sZones')) el('sZones').textContent = stats.zoneCount || 0;
        }).catch(function(e) { console.error('Stats:', e); });
    }

    // --- Zones ---
    var zonesCache = [];

    function renderZones(el) {
        el.innerHTML = '<div class="page-header"><h1 class="page-title">DNS Zones</h1>' +
            '<div class="page-actions"><button class="btn btn-primary" onclick="showCreateZone()">+ Create Zone</button></div></div>' +
            '<div class="table-container" id="zonesTable"><div class="empty-state"><p>Loading zones...</p></div></div>';
        api('GET', '/api/v1/zones').then(function(data) {
            zonesCache = data.zones || [];
            renderZonesTable();
        }).catch(function(e) {
            document.getElementById('zonesTable').innerHTML = '<div class="empty-state"><h3>Error</h3><p>' + e.message + '</p></div>';
        });
    }

    function renderZonesTable() {
        var container = document.getElementById('zonesTable');
        if (!zonesCache.length) {
            container.innerHTML = '<div class="empty-state"><h3>No zones configured</h3><p>Create your first DNS zone to get started.</p>' +
                '<button class="btn btn-primary" onclick="showCreateZone()">Create Zone</button></div>';
            return;
        }
        var html = '<table><thead><tr><th>Zone</th><th>Serial</th><th>Records</th><th style="text-align:right">Actions</th></tr></thead><tbody>';
        zonesCache.forEach(function(z) {
            html += '<tr><td class="mono"><a href="#" onclick="navigate(\'zone-detail\',\'' + z.name + '\');return false" style="color:var(--accent);text-decoration:none">' + z.name + '</a></td>' +
                '<td class="mono">' + (z.serial || '-') + '</td><td>' + z.records + '</td>' +
                '<td style="text-align:right"><button class="btn btn-secondary btn-sm" onclick="navigate(\'zone-detail\',\'' + z.name + '\')">Manage</button> ' +
                '<button class="btn btn-danger btn-sm" onclick="deleteZone(\'' + z.name + '\')">Delete</button></td></tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
    }

    function showCreateZone() {
        var overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.id = 'modalOverlay';
        overlay.innerHTML = '<div class="modal">' +
            '<div class="modal-title">Create New Zone</div>' +
            '<div class="form-group"><label>Zone Name</label><input type="text" id="czName" placeholder="example.com."></div>' +
            '<div class="form-grid"><div class="form-group"><label>Default TTL</label><input type="number" id="czTTL" value="3600"></div>' +
            '<div class="form-group"><label>Admin Email</label><input type="text" id="czEmail" placeholder="admin.example.com."></div></div>' +
            '<div class="form-group"><label>Nameservers (one per line)</label><textarea id="czNS" rows="3" placeholder="ns1.example.com.\nns2.example.com." style="width:100%;padding:8px 12px;background:var(--bg-primary);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:13px;resize:vertical"></textarea></div>' +
            '<div class="modal-actions"><button class="btn btn-secondary" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="createZone()">Create Zone</button></div></div>';
        overlay.onclick = function(e) { if (e.target === overlay) closeModal(); };
        document.body.appendChild(overlay);
        document.getElementById('czName').focus();
    }

    function closeModal() { var m = document.getElementById('modalOverlay'); if (m) m.remove(); }

    function createZone() {
        var name = document.getElementById('czName').value.trim();
        var ttl = parseInt(document.getElementById('czTTL').value) || 3600;
        var email = document.getElementById('czEmail').value.trim();
        var nsText = document.getElementById('czNS').value.trim();
        var nameservers = nsText.split('\n').map(function(s) { return s.trim(); }).filter(function(s) { return s; });
        if (!name) { toast('Zone name is required', 'error'); return; }
        if (!nameservers.length) { toast('At least one nameserver is required', 'error'); return; }
        api('POST', '/api/v1/zones', { name: name, ttl: ttl, admin_email: email, nameservers: nameservers }).then(function() {
            closeModal();
            toast('Zone ' + name + ' created');
            renderZones(document.getElementById('mainContent'));
        }).catch(function(e) { toast(e.message, 'error'); });
    }

    function deleteZone(name) {
        if (!confirm('Delete zone ' + name + '? This cannot be undone.')) return;
        api('DELETE', '/api/v1/zones/' + encodeURIComponent(name)).then(function() {
            toast('Zone ' + name + ' deleted');
            renderZones(document.getElementById('mainContent'));
        }).catch(function(e) { toast(e.message, 'error'); });
    }

    // --- Zone Detail ---
    function renderZoneDetail(el) {
        el.innerHTML = '<div class="breadcrumb"><a href="#" onclick="navigate(\'zones\');return false">Zones</a> / ' + currentZone + '</div>' +
            '<div id="zoneDetailContent"><div class="empty-state"><p>Loading...</p></div></div>';
        Promise.all([
            api('GET', '/api/v1/zones/' + encodeURIComponent(currentZone)),
            api('GET', '/api/v1/zones/' + encodeURIComponent(currentZone) + '/records')
        ]).then(function(results) {
            renderZoneDetailContent(results[0], results[1].records || []);
        }).catch(function(e) {
            document.getElementById('zoneDetailContent').innerHTML = '<div class="empty-state"><h3>Error</h3><p>' + e.message + '</p></div>';
        });
    }

    function renderZoneDetailContent(zoneData, records) {
        var el = document.getElementById('zoneDetailContent');
        var serial = zoneData.serial || (zoneData.soa && zoneData.soa.serial) || '-';

        var html = '<div class="zone-header"><div class="zone-info">' +
            '<h2>' + currentZone + '</h2>' +
            '<div class="zone-meta"><span class="zone-meta-item">Serial: <strong>' + serial + '</strong></span>' +
            '<span class="zone-meta-item">Records: <strong>' + records.length + '</strong></span></div></div>' +
            '<div class="page-actions"><button class="btn btn-secondary" onclick="exportZone()">Export Zone</button></div></div>';

        html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">' +
            '<select id="typeFilter" onchange="filterRecords()" style="padding:6px 10px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:4px;color:var(--text-primary);font-size:12px">' +
            '<option value="">All Types</option><option value="A">A</option><option value="AAAA">AAAA</option><option value="CNAME">CNAME</option>' +
            '<option value="MX">MX</option><option value="NS">NS</option><option value="TXT">TXT</option><option value="SRV">SRV</option><option value="SOA">SOA</option></select>' +
            '<button class="btn btn-primary btn-sm" onclick="toggleAddRow()">+ Add Record</button></div>';

        html += '<div class="table-container"><table><thead><tr><th>Name</th><th>Type</th><th>TTL</th><th>Data</th><th style="text-align:right">Actions</th></tr></thead><tbody>';

        if (addingRecord) {
            html += '<tr class="add-row">' +
                '<td><input type="text" id="arName" placeholder="www"></td>' +
                '<td><select id="arType"><option>A</option><option>AAAA</option><option>CNAME</option><option>MX</option><option>NS</option><option>TXT</option><option>SRV</option></select></td>' +
                '<td><input type="number" id="arTTL" value="3600" style="width:70px"></td>' +
                '<td><input type="text" id="arData" placeholder="192.168.1.1"></td>' +
                '<td style="text-align:right"><button class="btn btn-primary btn-sm" onclick="addRecord()">Save</button> <button class="btn btn-secondary btn-sm" onclick="toggleAddRow()">Cancel</button></td></tr>';
        }

        records.forEach(function(r) {
            var typeBadge = r.type === 'SOA' ? 'badge-warning' : r.type === 'NS' ? 'badge-info' : 'badge-success';
            var isSOA = r.type === 'SOA';
            var escapedData = (r.data || '').replace(/'/g, "\\'");
            var escapedName = r.name.replace(/'/g, "\\'");
            html += '<tr data-type="' + r.type + '">' +
                '<td class="mono">' + r.name + '</td>' +
                '<td><span class="badge ' + typeBadge + '">' + r.type + '</span></td>' +
                '<td class="mono">' + r.ttl + '</td>' +
                '<td class="mono" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + escapedData.replace(/"/g, '&quot;') + '">' + escapedData + '</td>' +
                '<td style="text-align:right" class="record-actions">' +
                (isSOA ? '<span style="color:var(--text-secondary);font-size:12px">auto</span>' :
                '<button class="btn btn-secondary btn-sm" onclick="editRecord(\'' + escapedName + '\',\'' + r.type + '\',' + r.ttl + ',\'' + escapedData + '\')">Edit</button> ' +
                '<button class="btn btn-danger btn-sm" onclick="deleteRecord(\'' + escapedName + '\',\'' + r.type + '\')">Del</button>') +
                '</td></tr>';
        });

        if (!records.length && !addingRecord) {
            html += '<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--text-secondary)">No records yet.</td></tr>';
        }

        html += '</tbody></table></div>';
        el.innerHTML = html;
    }

    function filterRecords() {
        var filter = document.getElementById('typeFilter').value;
        document.querySelectorAll('#zoneDetailContent tbody tr[data-type]').forEach(function(tr) {
            tr.style.display = (!filter || tr.dataset.type === filter) ? '' : 'none';
        });
    }

    function toggleAddRow() { addingRecord = !addingRecord; renderZoneDetail(document.getElementById('mainContent')); }

    function addRecord() {
        var name = document.getElementById('arName').value.trim();
        var type = document.getElementById('arType').value;
        var ttl = parseInt(document.getElementById('arTTL').value) || 3600;
        var data = document.getElementById('arData').value.trim();
        if (!name || !data) { toast('Name and data are required', 'error'); return; }
        api('POST', '/api/v1/zones/' + encodeURIComponent(currentZone) + '/records', { name: name, type: type, ttl: ttl, data: data }).then(function() {
            toast(type + ' record added');
            addingRecord = false;
            renderZoneDetail(document.getElementById('mainContent'));
        }).catch(function(e) { toast(e.message, 'error'); });
    }

    function editRecord(name, type, ttl, data) {
        var overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.id = 'modalOverlay';
        overlay.innerHTML = '<div class="modal">' +
            '<div class="modal-title">Edit Record</div>' +
            '<div class="form-group"><label>Name</label><input type="text" id="erName" value="' + name + '" readonly style="opacity:0.6"></div>' +
            '<div class="form-group"><label>Type</label><input type="text" id="erType" value="' + type + '" readonly style="opacity:0.6"></div>' +
            '<div class="form-grid"><div class="form-group"><label>TTL</label><input type="number" id="erTTL" value="' + ttl + '"></div>' +
            '<div class="form-group"><label>Data</label><input type="text" id="erData" value="' + data.replace(/"/g, '&quot;') + '"></div></div>' +
            '<div class="modal-actions"><button class="btn btn-secondary" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="updateRecord()">Save</button></div></div>';
        overlay.onclick = function(e) { if (e.target === overlay) closeModal(); };
        document.body.appendChild(overlay);
    }

    function updateRecord() {
        var name = document.getElementById('erName').value;
        var type = document.getElementById('erType').value;
        var ttl = parseInt(document.getElementById('erTTL').value) || 3600;
        var data = document.getElementById('erData').value.trim();
        api('PUT', '/api/v1/zones/' + encodeURIComponent(currentZone) + '/records', { name: name, type: type, ttl: ttl, data: data }).then(function() {
            closeModal();
            toast('Record updated');
            renderZoneDetail(document.getElementById('mainContent'));
        }).catch(function(e) { toast(e.message, 'error'); });
    }

    function deleteRecord(name, type) {
        if (!confirm('Delete ' + type + ' record for ' + name + '?')) return;
        api('DELETE', '/api/v1/zones/' + encodeURIComponent(currentZone) + '/records', { name: name, type: type }).then(function() {
            toast('Record deleted');
            renderZoneDetail(document.getElementById('mainContent'));
        }).catch(function(e) { toast(e.message, 'error'); });
    }

    function exportZone() {
        window.location.href = '/api/v1/zones/' + encodeURIComponent(currentZone) + '/export';
    }

    // --- Settings ---
    function renderSettings(el) {
        el.innerHTML = '<div class="page-header"><h1 class="page-title">Settings</h1></div><div id="settingsContent"><div class="empty-state"><p>Loading...</p></div></div>';
        api('GET', '/api/v1/status').then(function(status) {
            var html = '<div class="table-container" style="margin-bottom:16px">' +
                '<div style="padding:16px;border-bottom:1px solid var(--border)"><h3 style="font-size:15px;font-weight:600">Server Status</h3></div>' +
                '<table><tbody>' +
                '<tr><td style="color:var(--text-secondary)">Status</td><td><span class="badge badge-success">' + status.status + '</span></td></tr>' +
                '<tr><td style="color:var(--text-secondary)">Version</td><td class="mono">' + (status.version || '-') + '</td></tr>' +
                '<tr><td style="color:var(--text-secondary)">Timestamp</td><td class="mono">' + status.timestamp + '</td></tr>';
            if (status.cache) {
                html += '<tr><td style="color:var(--text-secondary)">Cache Size</td><td>' + status.cache.size + ' / ' + status.cache.capacity + '</td></tr>' +
                    '<tr><td style="color:var(--text-secondary)">Hit Ratio</td><td>' + (status.cache.hit_ratio * 100).toFixed(1) + '%</td></tr>';
            }
            if (status.cluster) {
                html += '<tr><td style="color:var(--text-secondary)">Cluster</td><td><span class="badge ' + (status.cluster.enabled ? 'badge-success' : 'badge-info') + '">' + (status.cluster.enabled ? 'Enabled' : 'Disabled') + '</span></td></tr>';
            }
            html += '</tbody></table></div>';
            html += '<div class="table-container"><div style="padding:16px;border-bottom:1px solid var(--border)"><h3 style="font-size:15px;font-weight:600">Actions</h3></div>' +
                '<div style="padding:16px;display:flex;gap:8px">' +
                '<button class="btn btn-secondary" onclick="flushCache()">Flush Cache</button>' +
                '<button class="btn btn-secondary" onclick="reloadConfig()">Reload Config</button></div></div>';
            document.getElementById('settingsContent').innerHTML = html;
        }).catch(function(e) {
            document.getElementById('settingsContent').innerHTML = '<div class="empty-state"><h3>Error</h3><p>' + e.message + '</p></div>';
        });
    }

    function flushCache() {
        api('POST', '/api/v1/cache/flush').then(function() { toast('Cache flushed'); }).catch(function(e) { toast(e.message, 'error'); });
    }
    function reloadConfig() {
        api('POST', '/api/v1/config/reload').then(function() { toast('Config reloaded'); }).catch(function(e) { toast(e.message, 'error'); });
    }

    // --- Init ---
    navigate('dashboard');
    setInterval(function() {
        if (currentPage === 'dashboard') {
            api('GET', '/api/dashboard/stats').then(function(stats) {
                var el = function(id) { return document.getElementById(id); };
                if (el('sTotal')) el('sTotal').textContent = (stats.queriesTotal || 0).toLocaleString();
                if (el('sQps')) el('sQps').textContent = (stats.queriesPerSec || 0).toFixed(1) + ' q/s';
                if (el('sCache')) el('sCache').textContent = (stats.cacheHitRate || 0).toFixed(1) + '%';
                if (el('sBlocked')) el('sBlocked').textContent = (stats.blockedQueries || 0).toLocaleString();
                if (el('sZones')) el('sZones').textContent = stats.zoneCount || 0;
            }).catch(function() {});
        }
    }, 5000);
    </script>
</body>
</html>
`

// GetLoginHTML returns the login page HTML.
func GetLoginHTML() string {
	return loginHTML
}

var loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NothingDNS - Login</title>
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --error: #ef4444;
            --border: #475569;
            --success: #22c55e;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            background: var(--bg-secondary);
            border-radius: 16px;
            padding: 48px;
            border: 1px solid var(--border);
            width: 100%;
            max-width: 420px;
            box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5);
        }
        .logo { text-align: center; margin-bottom: 32px; }
        .logo h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
        .logo p { color: var(--text-secondary); font-size: 14px; }
        .form-group { margin-bottom: 24px; }
        .form-group label { display: block; font-size: 14px; font-weight: 500; margin-bottom: 8px; color: var(--text-secondary); }
        .form-group input {
            width: 100%; padding: 12px 16px; background: var(--bg-primary); border: 1px solid var(--border);
            border-radius: 8px; color: var(--text-primary); font-size: 15px; outline: none;
        }
        .form-group input:focus { border-color: var(--accent); }
        .form-group input.error { border-color: var(--error); }
        .btn {
            width: 100%; padding: 12px; background: var(--accent); color: white; border: none;
            border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer;
        }
        .btn:hover { background: var(--accent-hover); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .error-msg { color: var(--error); font-size: 13px; margin-top: 8px; display: none; }
        .error-msg.visible { display: block; }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="logo">
            <h1>NothingDNS</h1>
            <p>Enter your access token to continue</p>
        </div>
        <form id="loginForm">
            <div class="form-group">
                <label for="token">Access Token</label>
                <input type="password" id="token" name="token" placeholder="Enter auth token" autocomplete="current-password" autofocus>
                <div class="error-msg" id="errorMsg">Invalid token. Please try again.</div>
            </div>
            <button type="submit" class="btn" id="loginBtn">Sign In</button>
        </form>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            var btn = document.getElementById('loginBtn');
            var input = document.getElementById('token');
            var errorEl = document.getElementById('errorMsg');
            var token = input.value.trim();
            if (!token) return;
            btn.disabled = true;
            btn.textContent = 'Signing in...';
            errorEl.classList.remove('visible');
            input.classList.remove('error');
            try {
                var resp = await fetch('/api/v1/status', { headers: { 'Authorization': 'Bearer ' + token } });
                if (resp.ok) {
                    document.cookie = 'ndns_token=' + encodeURIComponent(token) + '; path=/; max-age=86400; SameSite=Strict';
                    window.location.href = '/';
                    return;
                }
                errorEl.classList.add('visible');
                input.classList.add('error');
                input.select();
            } catch (err) {
                errorEl.textContent = 'Connection error. Please try again.';
                errorEl.classList.add('visible');
            } finally {
                btn.disabled = false;
                btn.textContent = 'Sign In';
            }
        });
    </script>
</body>
</html>
`
