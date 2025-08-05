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

# ==================== UTILITY FUNCTIONS ====================

def check_tools():
    """Check if required tools are installed"""
    missing = []
    for tool in REQUIRED_TOOLS:
        if not subprocess.run(['which', tool], capture_output=True).stdout:
            missing.append(tool)
    return missing

def get_local_subnet():
    """Get the local subnet address"""
    try:
        result = subprocess.run(['ip', '-4', 'addr', 'show', 'scope', 'global'], 
                              capture_output=True, text=True)
        ip_line = result.stdout.split('\n')[2].strip()
        return ip_line.split()[1]
    except:
        return ""

def run_tool(command, logfile, tool_name):
    """Run a system tool and monitor its progress"""
    tool_status[tool_name] = {'running': True, 'progress': 'Starting...'}
    try:
        with open(logfile, 'w') as f:
            process = subprocess.Popen(command, shell=True, stdout=f, stderr=subprocess.STDOUT)
            
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

# ==================== SYSTEM INITIALIZATION ====================

# Define all required directories and their structures
REQUIRED_DIRS = {
    'templates': [],
    'logs': [],
    'uploads': [],
    'static': ['css', 'js', 'images']
}

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

def create_directories():
    """Create all required directories and subdirectories"""
    for directory, subdirs in REQUIRED_DIRS.items():
        os.makedirs(directory, exist_ok=True)
        for subdir in subdirs:
            os.makedirs(os.path.join(directory, subdir), exist_ok=True)

def create_templates():
    """Create all template files if they don't exist"""
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
    <!-- [Rest of home.html content] -->
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
    <!-- [Rest of soc_mode.html content] -->
</body>
</html>''',
        # [Include all other templates here]
    }

    os.makedirs('templates', exist_ok=True)
    for filename, content in templates.items():
        filepath = os.path.join('templates', filename)
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            with open(filepath, 'w') as f:
                f.write(content)

def verify_system_requirements():
    """Verify all system requirements are met"""
    create_directories()
    create_templates()
    
    missing_tools = check_tools()
    if missing_tools:
        print("WARNING: Missing required tools:")
        for tool in missing_tools:
            print(f" - {tool}")
        print("Some features may not work properly without these tools.")

# ==================== FLASK APPLICATION ====================

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['LOG_FOLDER'] = 'logs'

@app.route('/')
def home():
    missing_tools = check_tools()
    return render_template('home.html', missing_tools=missing_tools)

@app.route('/soc-mode')
def soc_mode():
    active_connections = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True).stdout
    system_status = subprocess.run(['top', '-b', '-n', '1'], capture_output=True, text=True).stdout
    return render_template('soc_mode.html',
                         active_connections=active_connections,
                         system_status=system_status)

# [Add all other route handlers here]

# ==================== MAIN EXECUTION ====================

if __name__ == '__main__':
    # Verify everything is in place before starting
    verify_system_requirements()
    
    if os.geteuid() != 0:
        print("Warning: Some tools require root privileges. Consider running with sudo.")
    
    print("Starting WANNACRY Toolkit...")
    print("Access the GUI at: http://localhost:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)
