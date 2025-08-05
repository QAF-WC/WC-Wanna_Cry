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

# Define all required directories and their structures
REQUIRED_DIRS = {
    'templates': [],
    'logs': [],
    'uploads': [],
    'static': ['css', 'js', 'images']
}

# Create all required directories and subdirectories
def create_directories():
    for directory, subdirs in REQUIRED_DIRS.items():
        os.makedirs(directory, exist_ok=True)
        for subdir in subdirs:
            os.makedirs(os.path.join(directory, subdir), exist_ok=True)

# Create all HTML template files with thorough checks
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
        # [Rest of your template content remains the same...]
        # Include all other templates from your original code here
    }

    # Ensure templates directory exists
    os.makedirs('templates', exist_ok=True)

    # Create each template file if it doesn't exist or is empty
    for filename, content in templates.items():
        filepath = os.path.join('templates', filename)
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"Created template: {filepath}")
        else:
            print(f"Template exists: {filepath}")

def verify_system_requirements():
    """Verify all system requirements are met"""
    # Check directories
    for directory, subdirs in REQUIRED_DIRS.items():
        if not os.path.exists(directory):
            print(f"Creating missing directory: {directory}")
            os.makedirs(directory, exist_ok=True)
        
        for subdir in subdirs:
            subdir_path = os.path.join(directory, subdir)
            if not os.path.exists(subdir_path):
                print(f"Creating missing subdirectory: {subdir_path}")
                os.makedirs(subdir_path, exist_ok=True)
    
    # Check templates
    required_templates = [
        'home.html', 'red_team.html', 'blue_team.html',
        'soc_mode.html', 'source_help.html', 'running.html',
        'view_logs.html', 'view_log.html', 'admin_login.html',
        'advanced_mode.html'
    ]
    
    for template in required_templates:
        template_path = os.path.join('templates', template)
        if not os.path.exists(template_path):
            print(f"Missing template detected: {template_path}")
            create_templates()  # Regenerate all templates if any are missing
            break
    
    # Check for required tools
    missing_tools = check_tools()
    if missing_tools:
        print("WARNING: Missing required tools:")
        for tool in missing_tools:
            print(f" - {tool}")
        print("Some features may not work properly without these tools.")

# Initialize the system
verify_system_requirements()
create_directories()

# [Rest of your Flask application code remains the same...]
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

# [Continue with the rest of your original code...]

if __name__ == '__main__':
    # Verify everything is in place before starting
    verify_system_requirements()
    
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
