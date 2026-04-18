package dashboard

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// Embed the React SPA build output.
//
//go:embed all:static/dist
var staticFS embed.FS

// distFS is the embedded React SPA filesystem rooted at "static/dist".
var distFS, _ = fs.Sub(staticFS, "static/dist")

// DistFS exposes the embedded filesystem for use by the API server.
var DistFS = distFS

// SPAHandler returns an http.Handler that serves the React SPA.
// Static assets are served from /assets/. All other non-API, non-WebSocket
// routes return index.html for client-side routing.
func SPAHandler() http.Handler {
	fileServer := http.FileServer(http.FS(distFS))
	indexHTML, _ := fs.ReadFile(distFS, "index.html")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Serve static assets directly
		if strings.HasPrefix(path, "/assets/") {
			fileServer.ServeHTTP(w, r)
			return
		}

		// Serve known static files
		if strings.HasSuffix(path, ".svg") || strings.HasSuffix(path, ".png") ||
			strings.HasSuffix(path, ".ico") || strings.HasSuffix(path, ".js") ||
			strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".woff2") {
			fileServer.ServeHTTP(w, r)
			return
		}

		// All other routes: serve index.html for SPA client-side routing
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
}

// GetLoginHTML returns the login page HTML (legacy fallback).
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
                    document.cookie = 'ndns_token=' + encodeURIComponent(token) + '; path=/; max-age=86400; SameSite=Strict; Secure';
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
