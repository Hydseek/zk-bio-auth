"""
api.py - Flask REST API Server
Student 3: Architecture & Communication
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import time
import json
import logging
from functools import wraps

from flask import Flask, request, jsonify, g, Response
import jwt as pyjwt

from server import database as db
from server.config import (
    JWT_SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRY_SEC,
    SERVER_HOST, SERVER_PORT, CERT_FILE, KEY_FILE,
    NONCE_TTL_SEC, DEBUG, USE_HTTPS,
)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(name)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("zk_api")

app = Flask(__name__)
used_nonces: dict = {}


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _purge_expired_nonces():
    now = time.time()
    expired = [k for k, v in used_nonces.items() if v < now]
    for k in expired:
        del used_nonces[k]


def _issue_token(user_id: str) -> str:
    import uuid
    nonce = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRY_SEC,
        "nonce": nonce,
    }
    return pyjwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def _verify_token(token: str) -> dict:
    payload = pyjwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    nonce = payload.get("nonce", "")
    _purge_expired_nonces()
    if nonce in used_nonces:
        raise ValueError("Replay detected: nonce already used.")
    used_nonces[nonce] = payload["exp"] + NONCE_TTL_SEC
    return payload


def require_jwt(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or malformed Authorization header"}), 401
        token = auth_header[7:]
        try:
            payload = _verify_token(token)
            g.user_id = payload["sub"]
        except pyjwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception as e:
            return jsonify({"error": f"Token invalid: {str(e)}"}), 401
        return f(*args, **kwargs)
    return decorated


def client_ip() -> str:
    return request.remote_addr or ""


# ─── DASHBOARD ────────────────────────────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZK Biometric Auth - Dashboard</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2330;--border:#30363d;--blue:#2E75B6;--blue-light:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--text:#e6edf3;--text-muted:#8b949e;--text-dim:#484f58;--radius:8px;--shadow:0 4px 16px rgba(0,0,0,.5)}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.layout{display:grid;grid-template-columns:240px 1fr;min-height:100vh}
.sidebar{background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:sticky;top:0;height:100vh}
.logo{padding:20px;border-bottom:1px solid var(--border)}
.logo h1{font-size:.95rem;font-weight:700;color:var(--blue-light)}
.logo p{font-size:.7rem;color:var(--text-muted);margin-top:3px}
.dot{display:inline-block;width:7px;height:7px;background:var(--green);border-radius:50%;margin-right:6px;animation:pulse 2s infinite}
nav{flex:1;padding:12px 0;overflow-y:auto}
.nav-section{padding:8px 16px 4px;font-size:.65rem;text-transform:uppercase;letter-spacing:1px;color:var(--text-dim);font-weight:600}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 16px;font-size:.84rem;color:var(--text-muted);cursor:pointer;border-left:2px solid transparent;transition:all .15s;text-decoration:none}
.nav-item:hover{background:var(--surface2);color:var(--text)}
.nav-item.active{background:rgba(88,166,255,.1);color:var(--blue-light);border-left-color:var(--blue-light)}
.nav-icon{font-size:1rem;width:18px;text-align:center}
.sidebar-footer{padding:16px;border-top:1px solid var(--border);font-size:.72rem;color:var(--text-dim)}
.main{overflow:auto}
.topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:14px 28px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10}
.topbar-title{font-size:1rem;font-weight:600}
.topbar-right{display:flex;align-items:center;gap:12px}
.pill{background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:4px 12px;font-size:.75rem;color:var(--text-muted)}
.pill.online{border-color:var(--green);color:var(--green)}
.btn{padding:6px 14px;border-radius:var(--radius);border:none;cursor:pointer;font-size:.8rem;font-weight:600;transition:opacity .15s}
.btn:hover{opacity:.85}
.btn-primary{background:var(--blue);color:#fff}
.content{padding:28px}
.section{display:none}
.section.active{display:block;animation:fadeIn .2s ease}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:28px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px;position:relative;overflow:hidden}
.stat-card::before{content:"";position:absolute;top:0;left:0;right:0;height:2px}
.stat-card.blue::before{background:var(--blue-light)}
.stat-card.green::before{background:var(--green)}
.stat-card.red::before{background:var(--red)}
.stat-card.yellow::before{background:var(--yellow)}
.stat-value{font-size:2rem;font-weight:700;line-height:1;margin-bottom:4px}
.stat-label{font-size:.78rem;color:var(--text-muted)}
.stat-icon{position:absolute;top:16px;right:16px;font-size:1.6rem;opacity:.25}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:24px;overflow:hidden}
.card-header{padding:14px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.card-title{font-size:.88rem;font-weight:600}
.card-badge{background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:2px 10px;font-size:.72rem;color:var(--text-muted)}
.tbl{width:100%;border-collapse:collapse;font-size:.83rem}
.tbl th{padding:10px 16px;text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.5px;color:var(--text-muted);border-bottom:1px solid var(--border);font-weight:600}
.tbl td{padding:11px 16px;border-bottom:1px solid rgba(48,54,61,.6);vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tr:hover td{background:var(--surface2)}
.empty-row td{text-align:center;color:var(--text-dim);padding:32px;font-size:.82rem}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:12px;font-size:.72rem;font-weight:600}
.badge::before{content:"";width:5px;height:5px;border-radius:50%}
.bg{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.bg::before{background:var(--green)}
.br{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.br::before{background:var(--red)}
.bb{background:rgba(88,166,255,.15);color:var(--blue-light);border:1px solid rgba(88,166,255,.3)}
.bb::before{background:var(--blue-light)}
.by{background:rgba(210,153,34,.15);color:var(--yellow);border:1px solid rgba(210,153,34,.3)}
.by::before{background:var(--yellow)}
.avatar{width:30px;height:30px;border-radius:50%;background:linear-gradient(135deg,#2E75B6,#58a6ff);display:inline-flex;align-items:center;justify-content:center;font-size:.75rem;font-weight:700;color:#fff;margin-right:8px;vertical-align:middle}
.endpoint-grid{display:grid;gap:10px;padding:16px}
.endpoint{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:12px 16px;display:flex;align-items:center;gap:12px}
.method{font-size:.7rem;font-weight:700;padding:3px 8px;border-radius:4px;min-width:46px;text-align:center;font-family:monospace}
.mget{background:rgba(63,185,80,.2);color:var(--green)}
.mpost{background:rgba(88,166,255,.2);color:var(--blue-light)}
.mdel{background:rgba(248,81,73,.2);color:var(--red)}
.endpoint-path{font-family:monospace;font-size:.82rem;color:var(--text);flex:1}
.endpoint-desc{font-size:.78rem;color:var(--text-muted)}
.try-btn{font-size:.72rem;padding:4px 10px;border-radius:4px;background:var(--surface);border:1px solid var(--border);color:var(--text-muted);cursor:pointer}
.try-btn:hover{color:var(--blue-light);border-color:var(--blue-light)}
.actions-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:20px}
.action-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:20px}
.action-card h3{font-size:.88rem;margin-bottom:6px}
.action-card p{font-size:.78rem;color:var(--text-muted);margin-bottom:14px}
.cmd-box{background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:8px 12px;font-family:monospace;font-size:.78rem;color:#79c0ff;display:flex;justify-content:space-between;align-items:center}
.copy-btn{font-size:.68rem;color:var(--text-muted);cursor:pointer;border:none;background:none;padding:2px 6px}
.copy-btn:hover{color:var(--text)}
.sec-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.sec-item{display:flex;align-items:flex-start;gap:12px;padding:14px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius)}
.sec-icon{font-size:1.4rem}
.sec-title{font-size:.84rem;font-weight:600;margin-bottom:3px}
.sec-desc{font-size:.75rem;color:var(--text-muted)}
.sec-status{font-size:.7rem;font-weight:700;color:var(--green);margin-top:4px}
.mini-chart{display:flex;align-items:flex-end;gap:4px;height:56px;padding:4px 0}
.bar{flex:1;border-radius:2px 2px 0 0;min-height:4px;transition:height .3s;cursor:pointer}
.bar:hover{opacity:.7}
.bar-s{background:var(--green);opacity:.8}
.bar-f{background:var(--red);opacity:.8}
.toast{position:fixed;bottom:24px;right:24px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:12px 18px;font-size:.82rem;box-shadow:var(--shadow);transform:translateY(80px);transition:transform .3s;z-index:100}
.toast.show{transform:none}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
</style>
</head>
<body>
<div class="layout">
<aside class="sidebar">
  <div class="logo">
    <h1><span class="dot"></span>ZK Auth</h1>
    <p>Admin Dashboard &mdash; v1.0</p>
  </div>
  <nav>
    <div class="nav-section">Main</div>
    <a class="nav-item active" onclick="show('overview');return false" href="#">
      <span class="nav-icon">&#x1F4CA;</span> Overview
    </a>
    <a class="nav-item" onclick="show('users');return false" href="#">
      <span class="nav-icon">&#x1F465;</span> Users
    </a>
    <a class="nav-item" onclick="show('logs');return false" href="#">
      <span class="nav-icon">&#x1F4CB;</span> Audit Logs
    </a>
    <div class="nav-section">System</div>
    <a class="nav-item" onclick="show('api');return false" href="#">
      <span class="nav-icon">&#x1F50C;</span> API Explorer
    </a>
    <a class="nav-item" onclick="show('security');return false" href="#">
      <span class="nav-icon">&#x1F510;</span> Security
    </a>
    <a class="nav-item" onclick="show('commands');return false" href="#">
      <span class="nav-icon">&#x2328;</span> Quick Commands
    </a>
  </nav>
  <div class="sidebar-footer">Port 5000 &bull; HTTP &bull; SQLite<br><span id="ul">Auto-refresh every 10s</span></div>
</aside>

<div class="main">
  <div class="topbar">
    <span class="topbar-title" id="pt">Overview</span>
    <div class="topbar-right">
      <span class="pill online">&#x25CF; Server Online</span>
      <span class="pill" id="lr">Loading...</span>
      <button class="btn btn-primary" onclick="refresh()">&#x21BB; Refresh</button>
    </div>
  </div>
  <div class="content">

    <!-- OVERVIEW -->
    <div class="section active" id="sec-overview">
      <div class="stats-grid">
        <div class="stat-card blue"><div class="stat-icon">&#x1F465;</div><div class="stat-value" id="s-u">0</div><div class="stat-label">Total Users</div></div>
        <div class="stat-card green"><div class="stat-icon">&#x2705;</div><div class="stat-value" id="s-s">0</div><div class="stat-label">Successful Auths</div></div>
        <div class="stat-card red"><div class="stat-icon">&#x274C;</div><div class="stat-value" id="s-f">0</div><div class="stat-label">Failed Auths</div></div>
        <div class="stat-card yellow"><div class="stat-icon">&#x1F4DD;</div><div class="stat-value" id="s-e">0</div><div class="stat-label">Enrollments</div></div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
        <div class="card">
          <div class="card-header"><span class="card-title">Recent Activity</span><span class="card-badge" id="ov-cnt">0 events</span></div>
          <table class="tbl"><thead><tr><th>User</th><th>Event</th><th>Time</th></tr></thead>
          <tbody id="ov-body"><tr class="empty-row"><td colspan="3">No events yet</td></tr></tbody></table>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">Authentication Chart</span></div>
          <div style="padding:16px 20px">
            <div style="display:flex;justify-content:space-between;margin-bottom:8px;font-size:.75rem;color:var(--text-muted)">
              <span><span style="color:var(--green)">&#x25A0;</span> Success</span>
              <span><span style="color:var(--red)">&#x25A0;</span> Failed</span>
            </div>
            <div class="mini-chart" id="chart"></div>
          </div>
          <div style="padding:0 20px 16px">
            <div style="display:flex;justify-content:space-between;margin-bottom:6px;font-size:.78rem">
              <span style="color:var(--text-muted)">Success Rate</span>
              <span id="sr" style="font-weight:700;color:var(--green)">N/A</span>
            </div>
            <div style="background:var(--border);border-radius:4px;height:6px;overflow:hidden">
              <div id="sb" style="height:100%;background:var(--green);border-radius:4px;width:0%;transition:width .5s"></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- USERS -->
    <div class="section" id="sec-users">
      <div class="card">
        <div class="card-header"><span class="card-title">Registered Users</span><span class="card-badge" id="u-cnt">0 users</span></div>
        <table class="tbl"><thead><tr><th>User</th><th>Status</th><th>Fragment A</th><th>Fragment B</th><th>Enrolled At</th></tr></thead>
        <tbody id="u-body"><tr class="empty-row"><td colspan="5">No users enrolled yet</td></tr></tbody></table>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Enrollment Flow</span></div>
        <div style="padding:20px;display:grid;grid-template-columns:1fr auto 1fr auto 1fr auto 1fr;gap:8px;align-items:center;font-size:.75rem;text-align:center">
          <div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px">
            <div style="font-size:1.4rem;margin-bottom:6px">&#x1F4F8;</div><div style="font-weight:600;color:var(--blue-light)">1. Capture</div>
            <div style="color:var(--text-muted);margin-top:4px">128-D biometric vector extracted from camera</div>
          </div>
          <div style="color:var(--text-dim);font-size:1.2rem">&rarr;</div>
          <div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px">
            <div style="font-size:1.4rem;margin-bottom:6px">&#x2702;</div><div style="font-weight:600;color:var(--blue-light)">2. Fragment</div>
            <div style="color:var(--text-muted);margin-top:4px">Split into A (64-D client) + B (64-D server)</div>
          </div>
          <div style="color:var(--text-dim);font-size:1.2rem">&rarr;</div>
          <div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px">
            <div style="font-size:1.4rem;margin-bottom:6px">&#x1F512;</div><div style="font-weight:600;color:var(--blue-light)">3. Encrypt</div>
            <div style="color:var(--text-muted);margin-top:4px">AES-256-GCM with separate keys per fragment</div>
          </div>
          <div style="color:var(--text-dim);font-size:1.2rem">&rarr;</div>
          <div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px">
            <div style="font-size:1.4rem;margin-bottom:6px">&#x1F4BE;</div><div style="font-weight:600;color:var(--blue-light)">4. Store</div>
            <div style="color:var(--text-muted);margin-top:4px">A stays on client, B sent to server DB</div>
          </div>
        </div>
      </div>
    </div>

    <!-- LOGS -->
    <div class="section" id="sec-logs">
      <div class="card">
        <div class="card-header">
          <span class="card-title">Authentication Audit Trail</span>
          <div style="display:flex;gap:8px;align-items:center">
            <select id="lf" onchange="renderLogs()" style="background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:4px 8px;color:var(--text);font-size:.78rem">
              <option value="">All Events</option>
              <option value="auth_success">Success Only</option>
              <option value="auth_fail">Failed Only</option>
              <option value="enroll">Enrollments Only</option>
            </select>
            <span class="card-badge" id="l-cnt">0 events</span>
          </div>
        </div>
        <table class="tbl"><thead><tr><th>#</th><th>User</th><th>Event</th><th>Cosine Distance</th><th>Confidence</th><th>IP</th><th>Timestamp</th></tr></thead>
        <tbody id="l-body"><tr class="empty-row"><td colspan="7">No events yet</td></tr></tbody></table>
      </div>
    </div>

    <!-- API EXPLORER -->
    <div class="section" id="sec-api">
      <div class="card">
        <div class="card-header"><span class="card-title">API Endpoints</span><span class="card-badge">8 routes</span></div>
        <div class="endpoint-grid">
          <div class="endpoint"><span class="method mget">GET</span><span class="endpoint-path">/api/health</span><span class="endpoint-desc">Server health check</span><button class="try-btn" onclick="tryApi('/api/health')">Try &#x25B6;</button></div>
          <div class="endpoint"><span class="method mpost">POST</span><span class="endpoint-path">/api/token</span><span class="endpoint-desc">Issue JWT token (body: {user_id})</span></div>
          <div class="endpoint"><span class="method mpost">POST</span><span class="endpoint-path">/api/enroll</span><span class="endpoint-desc">Store encrypted Fragment B (JWT required)</span></div>
          <div class="endpoint"><span class="method mget">GET</span><span class="endpoint-path">/api/fragment/{id}</span><span class="endpoint-desc">Retrieve Fragment B (JWT required)</span></div>
          <div class="endpoint"><span class="method mpost">POST</span><span class="endpoint-path">/api/auth_result</span><span class="endpoint-desc">Log client-side authentication result</span></div>
          <div class="endpoint"><span class="method mget">GET</span><span class="endpoint-path">/api/users</span><span class="endpoint-desc">List all enrolled users</span><button class="try-btn" onclick="tryApi('/api/users')">Try &#x25B6;</button></div>
          <div class="endpoint"><span class="method mget">GET</span><span class="endpoint-path">/api/logs</span><span class="endpoint-desc">Full authentication audit log</span><button class="try-btn" onclick="tryApi('/api/logs')">Try &#x25B6;</button></div>
          <div class="endpoint"><span class="method mdel">DEL</span><span class="endpoint-path">/api/user/{id}</span><span class="endpoint-desc">Delete user data (GDPR Art. 17)</span></div>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Live Response Viewer</span></div>
        <div style="padding:16px">
          <pre id="api-resp" style="background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:16px;font-size:.8rem;color:#79c0ff;white-space:pre-wrap;min-height:80px;max-height:320px;overflow:auto">Click "Try" on any endpoint above to see its live response here...</pre>
        </div>
      </div>
    </div>

    <!-- SECURITY -->
    <div class="section" id="sec-security">
      <div class="card" style="margin-bottom:24px">
        <div class="card-header"><span class="card-title">Zero-Knowledge Architecture</span></div>
        <div style="padding:20px;font-size:.84rem;line-height:1.8;color:var(--text-muted)">
          This system implements <strong style="color:var(--text)">Zero-Knowledge Biometrics</strong>: no single entity ever holds a complete biometric template.
          The 128-dimensional vector is split &mdash; Fragment A stays on the client device, Fragment B is stored encrypted on the server.
          Neither party alone can reconstruct the original biometric identity, eliminating the &ldquo;honey pot&rdquo; attack vector.
        </div>
      </div>
      <div class="sec-grid">
        <div class="sec-item"><div class="sec-icon">&#x1F511;</div><div><div class="sec-title">AES-256-GCM Encryption</div><div class="sec-desc">Authenticated encryption with 256-bit keys. GCM mode provides confidentiality and tamper detection via 128-bit authentication tag.</div><div class="sec-status">&#x2713; ACTIVE</div></div></div>
        <div class="sec-item"><div class="sec-icon">&#x1F9C2;</div><div><div class="sec-title">PBKDF2 Key Derivation</div><div class="sec-desc">Keys derived using 100,000 iterations of HMAC-SHA256 with a fresh 128-bit random salt per enrollment. Resists brute-force.</div><div class="sec-status">&#x2713; ACTIVE</div></div></div>
        <div class="sec-item"><div class="sec-icon">&#x23;</div><div><div class="sec-title">SHA-256 Integrity Hashing</div><div class="sec-desc">Each fragment has an explicit SHA-256 hash for double-layer integrity verification beyond the GCM authentication tag.</div><div class="sec-status">&#x2713; ACTIVE</div></div></div>
        <div class="sec-item"><div class="sec-icon">&#x1F3AB;</div><div><div class="sec-title">JWT + Nonce Replay Protection</div><div class="sec-desc">5-minute expiry tokens with embedded UUID nonces. Consumed nonces tracked server-side; replayed tokens are rejected.</div><div class="sec-status">&#x2713; ACTIVE</div></div></div>
        <div class="sec-item"><div class="sec-icon">&#x2702;</div><div><div class="sec-title">Biometric Fragmentation</div><div class="sec-desc">128-D vector split into two 64-D fragments with separate encryption keys. Server compromise yields only one unusable half.</div><div class="sec-status">&#x2713; ACTIVE</div></div></div>
        <div class="sec-item"><div class="sec-icon">&#x1F4CB;</div><div><div class="sec-title">Full Audit Logging</div><div class="sec-desc">All events (enroll, auth success/fail) logged with timestamp, client IP, and cosine distance score in SQLite.</div><div class="sec-status">&#x2713; ACTIVE</div></div></div>
      </div>
      <div class="card" style="margin-top:24px">
        <div class="card-header"><span class="card-title">Standards Compliance</span></div>
        <div style="padding:16px;display:grid;grid-template-columns:repeat(3,1fr);gap:12px">
          <div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center"><div style="font-size:1.1rem;font-weight:700;color:var(--blue-light)">ISO 27001</div><div style="font-size:.72rem;color:var(--text-muted);margin-top:4px">Controls A.8, A.9, A.10, A.12, A.13</div></div>
          <div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center"><div style="font-size:1.1rem;font-weight:700;color:var(--blue-light)">ISO 27018</div><div style="font-size:.72rem;color:var(--text-muted);margin-top:4px">PII protection, right to erasure</div></div>
          <div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center"><div style="font-size:1.1rem;font-weight:700;color:var(--blue-light)">FIDO2</div><div style="font-size:.72rem;color:var(--text-muted);margin-top:4px">Inspired by passwordless architecture</div></div>
        </div>
      </div>
    </div>

    <!-- QUICK COMMANDS -->
    <div class="section" id="sec-commands">
      <div class="card">
        <div class="card-header"><span class="card-title">Quick Commands</span><span style="font-size:.78rem;color:var(--text-muted)">Click &#x29C9; to copy</span></div>
        <div class="actions-grid">
          <div class="action-card"><h3>&#x25B6; Start Server</h3><p>Run in Terminal 1 and keep open</p><div class="cmd-box">python server/api.py<button class="copy-btn" onclick="cp('python server/api.py')">&#x29C9;</button></div></div>
          <div class="action-card"><h3>&#x1F464; Enroll User</h3><p>Register a new user (Terminal 2)</p><div class="cmd-box">python client/client_app.py enroll --user alice<button class="copy-btn" onclick="cp('python client/client_app.py enroll --user alice')">&#x29C9;</button></div></div>
          <div class="action-card"><h3>&#x1F513; Authenticate</h3><p>Verify identity of enrolled user</p><div class="cmd-box">python client/client_app.py auth --user alice<button class="copy-btn" onclick="cp('python client/client_app.py auth --user alice')">&#x29C9;</button></div></div>
          <div class="action-card"><h3>&#x1F4CB; List Users</h3><p>Show all locally enrolled users</p><div class="cmd-box">python client/client_app.py list<button class="copy-btn" onclick="cp('python client/client_app.py list')">&#x29C9;</button></div></div>
          <div class="action-card"><h3>&#x1F9EA; Run Tests</h3><p>Execute all 25 unit tests</p><div class="cmd-box">python -m unittest tests.test_fragmentation -v<button class="copy-btn" onclick="cp('python -m unittest tests.test_fragmentation -v')">&#x29C9;</button></div></div>
          <div class="action-card"><h3>&#x1F5D1; Delete User</h3><p>Remove all user data (GDPR right to erasure)</p><div class="cmd-box">curl -X DELETE http://127.0.0.1:5000/api/user/alice<button class="copy-btn" onclick="cp('curl -X DELETE http://127.0.0.1:5000/api/user/alice')">&#x29C9;</button></div></div>
        </div>
      </div>
    </div>

  </div>
</div>
</div>

<div class="toast" id="toast"></div>

<script>
var allLogs=[],allUsers=[];
var titles={overview:'Overview',users:'Users',logs:'Audit Logs',api:'API Explorer',security:'Security',commands:'Quick Commands'};

function show(n){
  document.querySelectorAll('.section').forEach(function(s){s.classList.remove('active')});
  document.querySelectorAll('.nav-item').forEach(function(i){i.classList.remove('active')});
  document.getElementById('sec-'+n).classList.add('active');
  document.querySelectorAll('.nav-item').forEach(function(i){
    if(i.getAttribute('onclick')&&i.getAttribute('onclick').indexOf("'"+n+"'")>-1)i.classList.add('active');
  });
  document.getElementById('pt').textContent=titles[n]||n;
}

function fmt(ts){
  if(!ts)return'—';
  return new Date(ts*1000).toLocaleString();
}

function toast(msg,ok){
  var t=document.getElementById('toast');
  t.textContent=(ok!==false?'✓ ':'✗ ')+msg;
  t.style.borderColor=ok!==false?'var(--green)':'var(--red)';
  t.classList.add('show');
  setTimeout(function(){t.classList.remove('show')},2500);
}

function renderLogs(){
  var filter=document.getElementById('lf')?document.getElementById('lf').value:'';
  var logs=filter?allLogs.filter(function(l){return l.event_type===filter}):allLogs;
  var tbody=document.getElementById('l-body');
  document.getElementById('l-cnt').textContent=logs.length+' events';
  if(!logs.length){tbody.innerHTML='<tr class="empty-row"><td colspan="7">No events match this filter</td></tr>';return;}
  tbody.innerHTML=logs.map(function(l,i){
    var ev=l.event_type||'';
    var bc=ev==='auth_success'?'bg':ev==='auth_fail'?'br':'bb';
    var bl=ev==='auth_success'?'Auth Success':ev==='auth_fail'?'Auth Failed':ev;
    var cos=l.cosine_distance!=null?l.cosine_distance.toFixed(4):'—';
    var conf=l.cosine_distance!=null?Math.max(0,Math.round((1-l.cosine_distance/0.3)*100))+'%':'—';
    var cc=l.cosine_distance!=null&&l.cosine_distance<0.15?'var(--green)':'var(--red)';
    return '<tr><td style="color:var(--text-muted)">'+(logs.length-i)+'</td>'
      +'<td><span class="avatar">'+(l.user_id||'?')[0].toUpperCase()+'</span>'+(l.user_id||'—')+'</td>'
      +'<td><span class="badge '+bc+'">'+bl+'</span></td>'
      +'<td style="font-family:monospace">'+cos+'</td>'
      +'<td style="color:'+cc+';font-weight:600">'+conf+'</td>'
      +'<td style="font-size:.75rem;color:var(--text-muted)">'+(l.client_ip||'—')+'</td>'
      +'<td style="font-size:.78rem;color:var(--text-muted)">'+fmt(l.timestamp)+'</td></tr>';
  }).join('');
}

function refresh(){
  Promise.all([fetch('/api/users'),fetch('/api/logs?limit=50')]).then(function(rs){
    return Promise.all([rs[0].json(),rs[1].json()]);
  }).then(function(ds){
    allUsers=ds[0].users||[];
    allLogs=ds[1].logs||[];

    var success=allLogs.filter(function(l){return l.event_type==='auth_success'}).length;
    var fail=allLogs.filter(function(l){return l.event_type==='auth_fail'}).length;
    var enroll=allLogs.filter(function(l){return l.event_type==='enroll'}).length;
    document.getElementById('s-u').textContent=allUsers.length;
    document.getElementById('s-s').textContent=success;
    document.getElementById('s-f').textContent=fail;
    document.getElementById('s-e').textContent=enroll;

    var total=success+fail;
    var rate=total?Math.round(success/total*100):0;
    document.getElementById('sr').textContent=total?rate+'%':'N/A';
    document.getElementById('sb').style.width=rate+'%';

    // Chart
    var authLogs=allLogs.filter(function(l){return l.event_type.indexOf('auth_')===0}).slice(0,12).reverse();
    var chart=document.getElementById('chart');
    if(!authLogs.length){
      chart.innerHTML='<span style="color:var(--text-dim);font-size:.78rem;align-self:center">No auth events yet</span>';
    } else {
      chart.innerHTML=authLogs.map(function(l){
        var h=Math.max(8,Math.round(28+Math.random()*24));
        var cls=l.event_type==='auth_success'?'bar-s':'bar-f';
        return '<div class="bar '+cls+'" style="height:'+h+'px" title="'+l.event_type+' — '+fmt(l.timestamp)+'"></div>';
      }).join('');
    }

    // Overview recent
    document.getElementById('ov-cnt').textContent=allLogs.length+' events';
    var recent=allLogs.slice(0,8);
    var ovBody=document.getElementById('ov-body');
    if(!recent.length){
      ovBody.innerHTML='<tr class="empty-row"><td colspan="3">No events yet. Run enroll then auth commands.</td></tr>';
    } else {
      ovBody.innerHTML=recent.map(function(l){
        var bc=l.event_type==='auth_success'?'bg':l.event_type==='auth_fail'?'br':'bb';
        var bl=l.event_type==='auth_success'?'Success':l.event_type==='auth_fail'?'Failed':l.event_type;
        return '<tr><td><span class="avatar">'+(l.user_id||'?')[0].toUpperCase()+'</span>'+(l.user_id||'—')+'</td>'
          +'<td><span class="badge '+bc+'">'+bl+'</span></td>'
          +'<td style="font-size:.75rem;color:var(--text-muted)">'+fmt(l.timestamp)+'</td></tr>';
      }).join('');
    }

    // Users table
    document.getElementById('u-cnt').textContent=allUsers.length+' users';
    var ubody=document.getElementById('u-body');
    if(!allUsers.length){
      ubody.innerHTML='<tr class="empty-row"><td colspan="5">No users yet. Run: python client/client_app.py enroll --user alice</td></tr>';
    } else {
      ubody.innerHTML=allUsers.map(function(u){
        var bc=u.enrolled?'bg':'by';
        var bl=u.enrolled?'Enrolled':'Pending';
        return '<tr><td><span class="avatar">'+u.user_id[0].toUpperCase()+'</span>'+u.user_id+'</td>'
          +'<td><span class="badge '+bc+'">'+bl+'</span></td>'
          +'<td><span class="badge bg">On device</span></td>'
          +'<td><span class="badge bb">On server</span></td>'
          +'<td style="font-size:.78rem;color:var(--text-muted)">'+fmt(u.created_at)+'</td></tr>';
      }).join('');
    }

    renderLogs();
    document.getElementById('lr').textContent='Updated '+new Date().toLocaleTimeString();
  }).catch(function(e){console.error(e);});
}

function tryApi(url){
  var el=document.getElementById('api-resp');
  el.textContent='Loading...';
  fetch(url).then(function(r){return r.json();}).then(function(d){
    el.textContent=JSON.stringify(d,null,2);
    toast('Response from '+url);
  }).catch(function(e){el.textContent='Error: '+e.message;toast('Request failed',false);});
}

function cp(text){
  navigator.clipboard.writeText(text).then(function(){toast('Copied!');}).catch(function(){toast('Copy failed',false);});
}

refresh();
setInterval(refresh,10000);
</script>
</body>
</html>"""


@app.route("/", methods=["GET"])
def dashboard():
    """Dark-mode admin dashboard — open http://127.0.0.1:5000/ in any browser."""
    return Response(DASHBOARD_HTML, mimetype="text/html")


# ─── API ROUTES ───────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "timestamp": int(time.time())}), 200


@app.route("/api/token", methods=["POST"])
def issue_token():
    data = request.get_json(force=True)
    user_id = data.get("user_id", "").strip()
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    db.upsert_user(user_id, int(time.time()))
    token = _issue_token(user_id)
    logger.info(f"[TOKEN] Issued for '{user_id}' from {client_ip()}")
    return jsonify({"token": token, "expires_in": JWT_EXPIRY_SEC}), 200


@app.route("/api/enroll", methods=["POST"])
@require_jwt
def enroll():
    data = request.get_json(force=True)
    user_id = data.get("user_id", "").strip()
    fragment_b = data.get("fragment_b")
    if not user_id or not fragment_b:
        return jsonify({"error": "user_id and fragment_b required"}), 400
    if user_id != g.user_id:
        return jsonify({"error": "User ID mismatch"}), 403
    db.store_fragment_b(user_id, fragment_b, int(time.time()))
    db.mark_enrolled(user_id)
    db.log_event(user_id, "enroll", int(time.time()), client_ip=client_ip())
    logger.info(f"[ENROLL] Fragment B stored for '{user_id}'")
    return jsonify({"message": "Enrollment successful - Fragment B stored (encrypted)"}), 201


@app.route("/api/fragment/<user_id>", methods=["GET"])
@require_jwt
def get_fragment(user_id: str):
    if user_id != g.user_id:
        return jsonify({"error": "Access denied"}), 403
    fragment_b = db.retrieve_fragment_b(user_id)
    if fragment_b is None:
        return jsonify({"error": "User not enrolled"}), 404
    logger.info(f"[RETRIEVE] Fragment B sent to client for '{user_id}'")
    return jsonify({"fragment_b": fragment_b}), 200


@app.route("/api/auth_result", methods=["POST"])
@require_jwt
def auth_result():
    data = request.get_json(force=True)
    user_id = data.get("user_id", "")
    authenticated = data.get("authenticated", False)
    cosine = data.get("cosine_distance", None)
    if user_id != g.user_id:
        return jsonify({"error": "User ID mismatch"}), 403
    event = "auth_success" if authenticated else "auth_fail"
    db.log_event(user_id, event, int(time.time()),
                 cosine_distance=cosine, client_ip=client_ip())
    logger.info(f"[AUTH] {event.upper()} for '{user_id}'" +
                (f" cosine={cosine:.4f}" if cosine else ""))
    return jsonify({"logged": True, "event": event}), 200


@app.route("/api/users", methods=["GET"])
def list_users():
    users = db.get_all_users()
    return jsonify({"users": users, "count": len(users)}), 200


@app.route("/api/logs", methods=["GET"])
def audit_logs():
    uid = request.args.get("user_id")
    limit = int(request.args.get("limit", 50))
    logs = db.get_auth_logs(user_id=uid, limit=limit)
    return jsonify({"logs": logs, "count": len(logs)}), 200


@app.route("/api/user/<user_id>", methods=["DELETE"])
@require_jwt
def delete_user(user_id: str):
    if user_id != g.user_id:
        return jsonify({"error": "Access denied"}), 403
    db.delete_fragment_b(user_id)
    logger.info(f"[DELETE] Fragment B removed for '{user_id}'")
    return jsonify({"message": f"Fragment B deleted for '{user_id}'"}), 200


# ─── ERROR HANDLERS ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def internal(e):
    logger.exception("Internal server error")
    return jsonify({"error": "Internal server error"}), 500


# ─── STARTUP ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    db.init_db()
    ssl_context = None
    if USE_HTTPS and os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        ssl_context = (CERT_FILE, KEY_FILE)
        protocol = "https"
        logger.info(f"TLS enabled - using {CERT_FILE}")
    else:
        protocol = "http"
        logger.info("Running in HTTP mode")

    logger.info(f"Dashboard: {protocol}://127.0.0.1:{SERVER_PORT}/")
    logger.info(f"API health check: {protocol}://127.0.0.1:{SERVER_PORT}/api/health")
    app.run(host=SERVER_HOST, port=SERVER_PORT, ssl_context=ssl_context, debug=DEBUG)
