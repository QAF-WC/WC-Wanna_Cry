#!/usr/bin/env python3
import os
import sys
import subprocess
from flask import Flask, render_template, request, redirect, url_for, session
import re
import threading
import time
import inspect
from werkzeug.security import generate_password_hash, check_password_hash

# Create required directories
os.makedirs('templates', exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs('uploads', exist_ok=True)

# Create all HTML template files
def create_templates():
    templates = {
        'home.html': '''<!DOCTYPE html>
<html>
<head>
    <title>WANNACRY Toolkit</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0a0a2a; color: #e0e0ff; }
        .card { background-color: #1a1a4a; border: 1px solid #30305a; }
        .card-title { color: #4d94ff; }
        .btn-red { background-color: #cc0000; border-color: #ff3333; }
        .btn-blue { background-color: #0066cc; border-color: #3399ff; }
        .btn-soc { background-color: #00cc99; border-color: #33ffcc; }
        .btn-help { background-color: #cc9900; border-color: #ffcc00; }
        .admin-link { color: #ff9900; text-decoration: none; float: right; }
    </style>
</head>
<body>
    <div class="container py-5">
        <div class="text-center mb-5">
            <h1 class="display-4" style="font-family: 'Courier New', monospace; color: #cc0000;">
                WANNACRY Toolkit
            </h1>
            <p class="lead">Choose Your Side</p>
            <a href="#" class="admin-link" onclick="showAdminPrompt()">Admin Access</a>
        </div>
        {% if missing_tools %}
        <div class="alert alert-danger">
            <h4>Missing Tools:</h4>
            <ul>
                {% for tool in missing_tools %}
                <li>{{ tool }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        <div class="row">
            <div class="col-md-3 mb-4">
                <div class="card h-100">
                    <div class="card-body text-center">
                        <h3 class="card-title">Red Team</h3>
                        <p class="card-text">Offensive Security Tools</p>
                        <a href="/red-team" class="btn btn-red w-100">Enter</a>
                    </div>
                </div>
            </div>
            <div class="col-md-3 mb-4">
                <div class="card h-100">
                    <div class="card-body text-center">
                        <h3 class="card-title">Blue Team</h3>
                        <p class="card-text">Defensive Security Tools</p>
                        <a href="/blue-team" class="btn btn-blue w-100">Enter</a>
                    </div>
                </div>
            </div>
            <div class="col-md-3 mb-4">
                <div class="card h-100">
                    <div class="card-body text-center">
                        <h3 class="card-title">SOC Mode</h3>
                        <p class="card-text">Monitoring & Response</p>
                        <a href="/soc-mode" class="btn btn-soc w-100">Enter</a>
                    </div>
                </div>
            </div>
            <div class="col-md-3 mb-4">
                <div class="card h-100">
                    <div class="card-body text-center">
                        <h3 class="card-title">Source Help</h3>
                        <p class="card-text">Function Documentation</p>
                        <a href="/source-help" class="btn btn-help w-100">View</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script>
        function showAdminPrompt() {
            const password = prompt("Enter Admin Password:");
            if (password) {
                window.location.href = `/admin-login?password=${encodeURIComponent(password)}`;
            }
        }
    </script>
</body>
</html>''',

        'red_team.html': '''<!DOCTYPE html>
<html>
<head>
    <title>Red Team Toolkit</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #1a0000; color: #ffcccc; }
        .card { background-color: #330000; border: 1px solid #660000; }
        .card-title { color: #ff4d4d; }
        .btn-tool { background-color: #cc0000; border-color: #ff3333; }
        .back-link { color: #ff9999; }
    </style>
</head>
<body>
    <div class="container py-4">
        <a href="/" class="back-link mb-3 d-inline-block">&larr; Back to Home</a>
        <h1 class="text-center mb-4" style="font-family: 'Courier New', monospace;">
            <span style="color: #ff4d4d;">RED TEAM</span> Toolkit
        </h1>
        <div class="row">
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h3 class="card-title">Port Scanner</h3>
                        <form action="/run-scan" method="post">
                            <div class="mb-3">
                                <label class="form-label">Target IP/Domain</label>
                                <input type="text" name="target" class="form-control" placeholder="e.g., 192.168.1.1" required>
                            </div>
                            <button type="submit" class="btn btn-tool w-100">Run Scan</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h3 class="card-title">DDoS Test</h3>
                        <form action="/run-ddos" method="post">
                            <div class="mb-3">
                                <label class="form-label">Target IP</label>
                                <input type="text" name="target" class="form-control" placeholder="e.g., 192.168.1.1" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Packet Count</label>
                                <input type="number" name="count" class="form-control" value="1000">
                            </div>
                            <button type="submit" class="btn btn-tool w-100">Launch Attack</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h3 class="card-title">Website Scanner</h3>
                        <form action="/run-gobuster" method="post">
                            <div class="mb-3">
                                <label class="form-label">Website URL</label>
                                <input type="text" name="website" class="form-control" placeholder="e.g., example.com" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Wordlist Path</label>
                                <input type="text" name="wordlist" class="form-control" value="/usr/share/wordlists/dirb/common.txt">
                            </div>
                            <button type="submit" class="btn btn-tool w-100">Scan Website</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h3 class="card-title">Brute Force Attack</h3>
                        <form action="/run-hydra" method="post">
                            <div class="mb-3">
                                <label class="form-label">Service</label>
                                <select name="service" class="form-select">
                                    <option value="1">SSH</option>
                                    <option value="2">FTP</option>
                                    <option value="3">HTTP Login</option>
                                </select>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Target IP</label>
                                <input type="text" name="target" class="form-control" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Username</label>
                                <input type="text" name="user" class="form-control" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Password Wordlist</label>
                                <input type="text" name="wordlist" class="form-control" required>
                            </div>
                            <button type="submit" class="btn btn-tool w-100">Start Attack</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        <div class="text-center mt-4">
            <a href="/view-logs" class="btn btn-outline-light">View All Logs</a>
        </div>
    </div>
</body>
</html>''',

        'blue_team.html': '''<!DOCTYPE html>
<html>
<head>
    <title>Blue Team Toolkit</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #000033; color: #ccccff; }
        .card { background-color: #000066; border: 1px solid #333399; }
        .card-title { color: #4d79ff; }
        .btn-tool { background-color: #0066cc; border-color: #3399ff; }
        .back-link { color: #9999ff; }
    </style>
</head>
<body>
    <div class="container py-4">
        <a href="/" class="back-link mb-3 d-inline-block">&larr; Back to Home</a>
        <h1 class="text-center mb-4" style="font-family: 'Courier New', monospace;">
            <span style="color: #4d79ff;">BLUE TEAM</span> Toolkit
        </h1>
        <div class="alert alert-info">
            <strong>Local Network:</strong> {{ subnet }}
        </div>
        <div class="row">
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h3 class="card-title">Local Machine Scan</h3>
                        <p class="card-text">Scan localhost for open ports</p>
                        <form action="/run-local-scan" method="post">
                            <button type="submit" class="btn btn-tool w-100">Run Scan</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h3 class="card-title">Network Host Discovery</h3>
                        <p class="card-text">Find live hosts on local network</p>
                        <form action="/run-network-scan" method="post">
                            <button type="submit" class="btn btn-tool w-100">Scan Network</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h3 class="card-title">Active Services</h3>
                        <p class="card-text">Show listening services</p>
                        <pre class="bg-dark text-light p-3">{{ active_services }}</pre>
                    </div>
                </div>
            </div>
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h3 class="card-title">System Logs</h3>
                        <p class="card-text">View recent system logs</p>
                        <pre class="bg-dark text-light p-3">{{ system_logs }}</pre>
                    </div>
                </div>
            </div>
        </div>
        <div class="text-center mt-4">
            <a href="/view-logs" class="btn btn-outline-light">View All Logs</a>
        </div>
    </div>
</body>
</html>''',

        'soc_mode.html': '''<!DOCTYPE html>
<html>
<head>
    <title>SOC Mode</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #001a00; color: #ccffcc; }
        .card { background-color: #003300; border: 1px solid #006600; }
        .card-title { color: #00ff00; }
        .btn-tool { background-color: #00cc99; border-color: #33ffcc; }
        .back-link { color: #99ff99; }
    </style>
</head>
<body>
    <div class="container py-4">
        <a href="/" class="back-link mb-3 d-inline-block">&larr; Back to Home</a>
        <h1 class="text-center mb-4" style="font-family: 'Courier New', monospace;">
            <span style="color: #00ff00;">SOC MODE</span> - Monitoring & Response
        </h1>
        <div class="row">
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h3 class="card-title">Live Network Traffic</h3>
                        <form action="/run-tcpdump" method="post">
                            <div class="mb-3">
                                <label class="form-label">Interface</label>
                                <input type="text" name="interface" class="form-control" placeholder="e.g., eth0" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Packet Count</label>
                                <input type="number" name="count" class="form-control" value="100">
                            </div>
                            <button type="submit" class="btn btn-tool w-100">Start Capture</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h3 class="card-title">Log Monitoring</h3>
                        <form action="/monitor-logs" method="post">
                            <div class="mb-3">
                                <label class="form-label">Log File</label>
                                <select name="logfile" class="form-select">
                                    <option value="/var/log/syslog">System Log</option>
                                    <option value="/var/log/auth.log">Auth Log</option>
                                    <option value="/var/log/kern.log">Kernel Log</option>
                                </select>
                            </div>
                            <button type="submit" class="btn btn-tool w-100">Monitor Logs</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h3 class="card-title">Active Connections</h3>
                        <pre class="bg-dark text-light p-3">{{ active_connections }}</pre>
                    </div>
                </div>
            </div>
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-body">
                        <h3 class="card-title">System Status</h3>
                        <pre class="bg-dark text-light p-3">{{ system_status }}</pre>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>''',

        'source_help.html': '''<!DOCTYPE html>
<html>
<head>
    <title>Source Help</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0a0a2a; color: #e0e0ff; }
        .function-list { max-height: 300px; overflow-y: auto; }
        .source-code { background-color: #1a1a3a; padding: 15px; border-radius: 5px; }
        pre { color: #e0e0ff; margin: 0; }
    </style>
</head>
<body>
    <div class="container py-4">
        <a href="/" class="d-block mb-4">&larr; Back to Home</a>
        <h1 class="text-center mb-4">Source Help</h1>
        <div class="row">
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">Available Functions</div>
                    <div class="card-body function-list">
                        <div class="list-group">
                            {% for func in functions %}
                            <a href="/source-help/{{ func }}" class="list-group-item list-group-item-action">
                                {{ func }}
                            </a>
                            {% endfor %}
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">Source Code</div>
                    <div class="card-body">
                        {% if selected_function %}
                            <h4>{{ selected_function }}</h4>
                            <div class="source-code">
                                <pre>{{ source_code }}</pre>
                            </div>
                        {% else %}
                            <p>Select a function to view its source code</p>
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>''',

        'running.html': '''<!DOCTYPE html>
<html>
<head>
    <title>Tool Running</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0a1929; color: #cce5ff; }
        .progress { height: 30px; }
        .log-output { max-height: 400px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="container py-5">
        <div class="text-center mb-4">
            <h1>{{ tool_name }} Running</h1>
            <p class="lead">Target: {{ target }}</p>
        </div>
        <div class="card mb-4">
            <div class="card-header">Command</div>
            <div class="card-body">
                <code>{{ command }}</code>
            </div>
        </div>
        <div class="card mb-4">
            <div class="card-header">Progress</div>
            <div class="card-body">
                <div class="progress mb-3">
                    <div class="progress-bar progress-bar-striped progress-bar-animated" 
                         id="progress-bar" style="width: 0%"></div>
                </div>
                <div id="progress-text">Initializing...</div>
            </div>
        </div>
        <div class="text-center">
            <a href="/view-log/{{ logfile.split('/')[-1] }}" class="btn btn-primary" id="view-log-btn" style="display:none;">
                View Full Log
            </a>
            <a href="{{ return_url }}" class="btn btn-secondary">Back</a>
        </div>
    </div>
    <script>
        const toolName = "{{ tool_name.split(' ')[0].toLowerCase() }}";
        const logFilename = "{{ logfile.split('/')[-1] }}";
        
        function updateProgress() {
            fetch(`/tool-status/${toolName}`)
                .then(response => response.json())
                .then(data => {
                    document.getElementById('progress-text').textContent = data.progress;
                    if (data.running) {
                        document.getElementById('progress-bar').style.width = '70%';
                        setTimeout(updateProgress, 3000);
                    } else {
                        document.getElementById('progress-bar').style.width = '100%';
                        document.getElementById('progress-bar').classList.remove('progress-bar-animated');
                        document.getElementById('view-log-btn').style.display = 'inline-block';
                    }
                });
        }
        setTimeout(updateProgress, 2000);
    </script>
</body>
</html>''',

        'view_logs.html': '''<!DOCTYPE html>
<html>
<head>
    <title>Log Files</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0a0a2a; color: #e0e0ff; }
        .log-item:hover { background-color: #2a2a4a; }
    </style>
</head>
<body>
    <div class="container py-4">
        <a href="/" class="d-block mb-4">&larr; Back to Home</a>
        <h1 class="text-center mb-4">Log Files</h1>
        {% if logs %}
        <div class="list-group">
            {% for log in logs %}
            <a href="/view-log/{{ log.name }}" class="list-group-item list-group-item-action log-item">
                <div class="d-flex w-100 justify-content-between">
                    <h5 class="mb-1">{{ log.name }}</h5>
                    <small>{{ log.modified }}</small>
                </div>
                <p class="mb-1">Size: {{ log.size }} bytes</p>
            </a>
            {% endfor %}
        </div>
        {% else %}
        <div class="alert alert-info">
            No log files found
        </div>
        {% endif %}
    </div>
</body>
</html>''',

        'view_log.html': '''<!DOCTYPE html>
<html>
<head>
    <title>Log: {{ filename }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0a0a2a; color: #e0e0ff; }
        .log-content { 
            background-color: #1a1a3a; 
            padding: 20px; 
            border-radius: 5px;
            font-family: monospace;
            white-space: pre-wrap;
        }
    </style>
</head>
<body>
    <div class="container py-4">
        <a href="/view-logs" class="d-block mb-4">&larr; Back to Logs</a>
        <h1 class="text-center mb-4">Log: {{ filename }}</h1>
        <div class="log-content mb-4">
            {{ content|safe }}
        </div>
        <div class="text-center">
            <a href="/view-logs" class="btn btn-primary">Back to Logs</a>
            <a href="/" class="btn btn-secondary">Home</a>
        </div>
    </div>
</body>
</html>''',

        'admin_login.html': '''<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0a0a2a; color: #e0e0ff; }
        .login-box { 
            max-width: 400px; 
            margin: 100px auto;
            background-color: #1a1a4a;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 100, 255, 0.3);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <h2 class="text-center mb-4">Admin Access</h2>
            {% if error %}
            <div class="alert alert-danger">{{ error }}</div>
            {% endif %}
            <form method="POST" action="/admin-login">
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Authenticate</button>
            </form>
        </div>
    </div>
</body>
</html>''',

        'advanced_mode.html': '''<!DOCTYPE html>
<html>
<head>
    <title>Advanced Mode</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0a0a2a; color: #e0e0ff; }
        .card { background-color: #1a1a4a; border: 1px solid #30305a; }
        .card-title { color: #ff9900; }
        .btn-admin { background-color: #cc9900; border-color: #ffcc00; }
    </style>
</head>
<body>
    <div class="container py-5">
        <div class="text-center mb-5">
            <h1 class="display-4" style="font-family: 'Courier New', monospace; color: #ff9900;">
                ADVANCED MODE
            </h1>
            <p class="lead">Privileged Access Toolkit</p>
        </div>
        <div class="alert alert-warning">
            <strong>Warning:</strong> This mode contains advanced penetration testing tools. Use responsibly.
        </div>
        <div class="row">
            <div class="col-md-4 mb-4">
                <div class="card h-100">
                    <div class="card-body text-center">
                        <h3 class="card-title">Metasploit Console</h3>
                        <p class="card-text">Launch Metasploit framework</p>
                        <a href="/run-advanced-tool/metasploit" class="btn btn-admin w-100">Launch</a>
                    </div>
                </div>
            </div>
            <div class="col-md-4 mb-4">
                <div class="card h-100">
                    <div class="card-body text-center">
                        <h3 class="card-title">Privilege Escalation</h3>
                        <p class="card-text">Check for system vulnerabilities</p>
                        <a href="/run-advanced-tool/privilege_escalation" class="btn btn-admin w-100">Run Checks</a>
                    </div>
                </div>
            </div>
            <div class="col-md-4 mb-4">
                <div class="card h-100">
                    <div class="card-body text-center">
                        <h3 class="card-title">Wireless Tools</h3>
                        <p class="card-text">WiFi scanning and attacks</p>
                        <a href="/run-advanced-tool/wireless_tools" class="btn btn-admin w-100">Access</a>
                    </div>
                </div>
            </div>
            <div class="col-md-4 mb-4">
                <div class="card h-100">
                    <div class="card-body text-center">
                        <h3 class="card-title">Forensics Toolkit</h3>
                        <p class="card-text">Memory and disk analysis</p>
                        <a href="/run-advanced-tool/forensics" class="btn btn-admin w-100">Analyze</a>
                    </div>
                </div>
            </div>
            <div class="col-md-4 mb-4">
                <div class="card h-100">
                    <div class="card-body text-center">
                        <h3 class="card-title">Malware Analysis</h3>
                        <p class="card-text">Sandbox and reverse engineering</p>
                        <a href="/run-advanced-tool/malware_analysis" class="btn btn-admin w-100">Examine</a>
                    </div>
                </div>
            </div>
            <div class="col-md-4 mb-4">
                <div class="card h-100">
                    <div class="card-body text-center">
                        <h3 class="card-title">Reporting Suite</h3>
                        <p class="card-text">Generate comprehensive reports</p>
                        <a href="/run-advanced-tool/reporting" class="btn btn-admin w-100">Create Report</a>
                    </div>
                </div>
            </div>
        </div>
        <div class="text-center mt-4">
            <a href="/" class="btn btn-outline-light">Back to Home</a>
        </div>
    </div>
</body>
</html>'''
    }
    
    for filename, content in templates.items():
        with open(f'templates/{filename}', 'w') as f:
            f.write(content)

# Create template files if they don't exist
if not os.path.exists('templates/home.html'):
    create_templates()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['LOG_FOLDER'] = 'logs'

# Required tools list
REQUIRED_TOOLS = [
    'figlet', 'lolcat', 'nmap', 'hping3', 'gobuster', 
    'hydra', 'ss', 'journalctl', 'tail', 'find', 'ip',
    'tcpdump', 'netstat'
]

# Tool status tracking
tool_status = {}

# Admin password (hashed)
ADMIN_PASSWORD = generate_password_hash('supersecret')

# Advanced mode tools
ADVANCED_TOOLS = {
    'metasploit': {
        'command': 'msfconsole',
        'description': 'Metasploit Framework Console'
    },
    'privilege_escalation': {
        'command': 'sudo linpeas.sh',
        'description': 'Privilege Escalation Check'
    },
    'wireless_tools': {
        'command': 'sudo airodump-ng wlan0',
        'description': 'Wireless Network Scanner'
    },
    'forensics': {
        'command': 'sudo autopsy',
        'description': 'Forensics Toolkit'
    },
    'malware_analysis': {
        'command': 'sudo r2 -AAA',
        'description': 'Malware Analysis'
    },
    'reporting': {
        'command': 'sudo dradis',
        'description': 'Reporting Suite'
    }
}

def check_tools():
    missing = []
    for tool in REQUIRED_TOOLS:
        if not subprocess.run(['which', tool], capture_output=True).stdout:
            missing.append(tool)
    return missing

def get_local_subnet():
    try:
        result = subprocess.run(['ip', '-4', 'addr', 'show', 'scope', 'global'], 
                              capture_output=True, text=True)
        ip_line = result.stdout.split('\n')[2].strip()
        return ip_line.split()[1]
    except:
        return ""

def run_tool(command, logfile, tool_name):
    tool_status[tool_name] = {'running': True, 'progress': 'Starting...'}
    try:
        with open(logfile, 'w') as f:
            process = subprocess.Popen(command, shell=True, stdout=f, stderr=subprocess.STDOUT)
            
            # Monitor progress
            while process.poll() is None:
                time.sleep(5)
                try:
                    with open(logfile, 'r') as log:
                        lines = len(log.readlines())
                        tool_status[tool_name]['progress'] = f"Processed {lines} lines"
                except:
                    pass
                    
        tool_status[tool_name] = {'running': False, 'progress': 'Completed'}
    except Exception as e:
        tool_status[tool_name] = {'running': False, 'progress': f'Error: {str(e)}'}

@app.route('/')
def home():
    missing_tools = check_tools()
    return render_template('home.html', missing_tools=missing_tools)

@app.route('/red-team')
def red_team():
    return render_template('red_team.html', subnet=get_local_subnet())

@app.route('/blue-team')
def blue_team():
    # Get active services
    active_services = subprocess.run(['ss', '-tuln'], capture_output=True, text=True).stdout
    # Get recent system logs
    system_logs = subprocess.run(['journalctl', '-xe', '-n', '50'], capture_output=True, text=True).stdout
    return render_template('blue_team.html', 
                         subnet=get_local_subnet(),
                         active_services=active_services,
                         system_logs=system_logs)

@app.route('/soc-mode')
def soc_mode():
    # Get active connections
    active_connections = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True).stdout
    # Get system status
    system_status = subprocess.run(['top', '-b', '-n', '1'], capture_output=True, text=True).stdout
    return render_template('soc_mode.html',
                         active_connections=active_connections,
                         system_status=system_status)

@app.route('/run-tcpdump', methods=['POST'])
def run_tcpdump():
    interface = request.form.get('interface')
    count = request.form.get('count', '100')
    logfile = os.path.join(app.config['LOG_FOLDER'], f'tcpdump_{int(time.time())}.txt')
    command = f"sudo tcpdump -i {interface} -c {count}"
    
    threading.Thread(target=run_tool, args=(command, logfile, 'tcpdump')).start()
    
    return render_template('running.html', 
                         tool_name="Packet Capture", 
                         logfile=logfile,
                         target=interface,
                         command=command,
                         return_url="/soc-mode")

@app.route('/monitor-logs', methods=['POST'])
def monitor_logs():
    logfile = request.form.get('logfile')
    logfile_path = os.path.join(app.config['LOG_FOLDER'], f'logmonitor_{int(time.time())}.txt')
    command = f"sudo tail -f {logfile}"
    
    threading.Thread(target=run_tool, args=(command, logfile_path, 'logmonitor')).start()
    
    return render_template('running.html', 
                         tool_name="Log Monitor", 
                         logfile=logfile_path,
                         target=logfile,
                         command=command,
                         return_url="/soc-mode")

@app.route('/source-help')
@app.route('/source-help/<function_name>')
def source_help(function_name=None):
    # Get all functions in the current module
    functions = []
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isfunction(obj) and not name.startswith('_'):
            functions.append(name)
    
    source_code = ""
    if function_name:
        try:
            func = getattr(sys.modules[__name__], function_name)
            source_code = inspect.getsource(func)
        except:
            source_code = "Function not found or source unavailable"
    
    return render_template('source_help.html',
                         functions=functions,
                         selected_function=function_name,
                         source_code=source_code)

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password')
        if check_password_hash(ADMIN_PASSWORD, password):
            session['admin'] = True
            return redirect(url_for('advanced_mode'))
        return render_template('admin_login.html', error='Invalid password')
    
    # Handle GET request with password parameter
    password = request.args.get('password')
    if password:
        if check_password_hash(ADMIN_PASSWORD, password):
            session['admin'] = True
            return redirect(url_for('advanced_mode'))
        return render_template('admin_login.html', error='Invalid password')
    
    return render_template('admin_login.html')

@app.route('/advanced-mode')
def advanced_mode():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    return render_template('advanced_mode.html')

@app.route('/run-advanced-tool/<tool_name>')
def run_advanced_tool(tool_name):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    if tool_name not in ADVANCED_TOOLS:
        return "Tool not found", 404
    
    tool = ADVANCED_TOOLS[tool_name]
    logfile = os.path.join(app.config['LOG_FOLDER'], f'{tool_name}_{int(time.time())}.txt')
    command = tool['command']
    
    threading.Thread(target=run_tool, args=(command, logfile, tool_name)).start()
    
    return render_template('running.html', 
                         tool_name=tool['description'], 
                         logfile=logfile,
                         target="Advanced Tool",
                         command=command,
                         return_url="/advanced-mode")

@app.route('/run-scan', methods=['POST'])
def run_scan():
    target = request.form.get('target')
    logfile = os.path.join(app.config['LOG_FOLDER'], f'nmap_scan_{int(time.time())}.txt')
    command = f"nmap -sC -sV -p- {target} -T4"
    
    threading.Thread(target=run_tool, args=(command, logfile, 'nmap')).start()
    
    return render_template('running.html', 
                         tool_name="Port Scan", 
                         logfile=logfile,
                         target=target,
                         command=command,
                         return_url="/red-team")

@app.route('/run-ddos', methods=['POST'])
def run_ddos():
    target = request.form.get('target')
    count = request.form.get('count', '1000')
    logfile = os.path.join(app.config['LOG_FOLDER'], f'ddos_{int(time.time())}.txt')
    command = f"sudo hping3 -S --flood -c {count} {target}"
    
    threading.Thread(target=run_tool, args=(command, logfile, 'hping3')).start()
    
    return render_template('running.html', 
                         tool_name="DDoS Test", 
                         logfile=logfile,
                         target=target,
                         command=command,
                         return_url="/red-team")

@app.route('/run-gobuster', methods=['POST'])
def run_gobuster():
    website = request.form.get('website')
    wordlist = request.form.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
    
    if not website.startswith('http'):
        website = f"http://{website}"
    
    logfile = os.path.join(app.config['LOG_FOLDER'], f'gobuster_{int(time.time())}.txt')
    command = f"gobuster dir -u {website} -w {wordlist} -q"
    
    threading.Thread(target=run_tool, args=(command, logfile, 'gobuster')).start()
    
    return render_template('running.html', 
                         tool_name="Website Scan", 
                         logfile=logfile,
                         target=website,
                         command=command,
                         return_url="/red-team")

@app.route('/run-hydra', methods=['POST'])
def run_hydra():
    service_map = {'1': 'ssh', '2': 'ftp', '3': 'http-get'}
    service = service_map.get(request.form.get('service'))
    target = request.form.get('target')
    user = request.form.get('user')
    wordlist = request.form.get('wordlist')
    
    logfile = os.path.join(app.config['LOG_FOLDER'], f'hydra_{int(time.time())}.txt')
    command = f"hydra -l {user} -P {wordlist} {target} {service}"
    
    threading.Thread(target=run_tool, args=(command, logfile, 'hydra')).start()
    
    return render_template('running.html', 
                         tool_name="Brute Force Attack", 
                         logfile=logfile,
                         target=f"{service}://{target}",
                         command=command,
                         return_url="/red-team")

@app.route('/run-local-scan', methods=['POST'])
def run_local_scan():
    logfile = os.path.join(app.config['LOG_FOLDER'], f'local_scan_{int(time.time())}.txt')
    command = "sudo nmap -sS -T4 localhost"
    
    threading.Thread(target=run_tool, args=(command, logfile, 'local_scan')).start()
    
    return render_template('running.html', 
                         tool_name="Local Port Scan", 
                         logfile=logfile,
                         target="localhost",
                         command=command,
                         return_url="/blue-team")

@app.route('/run-network-scan', methods=['POST'])
def run_network_scan():
    subnet = get_local_subnet()
    logfile = os.path.join(app.config['LOG_FOLDER'], f'network_scan_{int(time.time())}.txt')
    command = f"sudo nmap -sn {subnet}"
    
    threading.Thread(target=run_tool, args=(command, logfile, 'network_scan')).start()
    
    return render_template('running.html', 
                         tool_name="Network Scan", 
                         logfile=logfile,
                         target=subnet,
                         command=command,
                         return_url="/blue-team")

@app.route('/view-logs')
def view_logs():
    logs = []
    for filename in os.listdir(app.config['LOG_FOLDER']):
        if filename.endswith('.txt'):
            path = os.path.join(app.config['LOG_FOLDER'], filename)
            logs.append({
                'name': filename,
                'size': os.path.getsize(path),
                'modified': time.ctime(os.path.getmtime(path))
            })
    logs.sort(key=lambda x: os.path.getmtime(os.path.join(app.config['LOG_FOLDER'], x['name'])), reverse=True)
    return render_template('view_logs.html', logs=logs)

@app.route('/view-log/<filename>')
def view_log(filename):
    log_path = os.path.join(app.config['LOG_FOLDER'], filename)
    if not os.path.exists(log_path):
        return "Log file not found", 404
    
    with open(log_path, 'r') as f:
        content = f.read()
    
    # Simple formatting for common tools
    if 'nmap' in filename:
        content = re.sub(r'(Nmap scan report for .+)', r'<strong>\1</strong>', content)
        content = re.sub(r'(\d+/tcp\s+open\s+.+)', r'<span class="text-success">\1</span>', content)
    elif 'hydra' in filename:
        content = re.sub(r'(\[STATUS\]\s+.+)', r'<span class="text-info">\1</span>', content)
        content = re.sub(r'(host:|login:|password:)', r'<strong>\1</strong>', content)
    
    return render_template('view_log.html', 
                         filename=filename, 
                         content=content,
                         tool_status=tool_status.get(filename.split('_')[0], {}))

@app.route('/tool-status/<tool>')
def get_tool_status(tool):
    return tool_status.get(tool, {'running': False, 'progress': 'Not running'})

if __name__ == '__main__':
    # Check if running as root
    if os.geteuid() != 0:
        print("Warning: Some tools require root privileges. Consider running with sudo.")
    
    # Check for required tools
    missing = check_tools()
    if missing:
        print(f"Missing tools: {', '.join(missing)}")
        print("Install them before using all features")
    
    print("Starting WANNACRY Toolkit...")
    print("Access the GUI at: http://localhost:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)
