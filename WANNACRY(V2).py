#!/usr/bin/env python3
import os
import sys
import subprocess
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import re
import threading
import time
import shutil
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

# =============================================
# Configuration and Initialization
# =============================================

# Create required directories
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs('uploads', exist_ok=True)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['LOG_FOLDER'] = 'logs'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max upload size

# Required tools list
REQUIRED_TOOLS = [
    'nmap', 'netstat', 'tcpdump', 'ps', 'top', 'ss', 'lsof',
    'hping3', 'gobuster', 'hydra', 'journalctl', 'df', 'ip',
    'airodump-ng', 'strings'
]

# Tool status tracking
active_commands = {}
command_history = []

# Admin password (hashed)
ADMIN_PASSWORD = generate_password_hash('supersecret')

# =============================================
# Utility Functions
# =============================================

def check_tools():
    missing = []
    for tool in REQUIRED_TOOLS:
        if not shutil.which(tool):
            missing.append(tool)
    return missing

def get_local_subnet():
    try:
        result = subprocess.run(['ip', '-4', 'route'], capture_output=True, text=True)
        output = result.stdout
        subnet = output.split('src')[0].split(' ')[0]
        return subnet
    except:
        return "192.168.1.0/24"

def get_system_status():
    try:
        cpu_mem = subprocess.run(['top', '-b', '-n', '1'], capture_output=True, text=True).stdout
        disk = subprocess.run(['df', '-h'], capture_output=True, text=True).stdout
        uptime = subprocess.run(['uptime'], capture_output=True, text=True).stdout
        return f"=== CPU/Memory Usage ===\n{cpu_mem}\n\n=== Disk Usage ===\n{disk}\n\n=== System Uptime ===\n{uptime}"
    except Exception as e:
        return f"Error getting system status: {str(e)}"

def get_active_connections():
    try:
        connections = subprocess.run(['netstat', '-tulnp'], capture_output=True, text=True).stdout
        return connections
    except Exception as e:
        return f"Error getting connections: {str(e)}"

def get_process_list(filter=None, limit=20):
    try:
        cmd = ['ps', 'aux']
        if filter:
            cmd_str = ' '.join(cmd) + f' | grep {filter} | head -n {limit}'
            result = subprocess.run(cmd_str, shell=True, capture_output=True, text=True)
        else:
            cmd_str = ' '.join(cmd) + f' | head -n {limit}'
            result = subprocess.run(cmd_str, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error getting processes: {str(e)}"

def run_tool(command, logfile, tool_name, return_url):
    tool_id = str(int(time.time()))
    active_commands[tool_id] = {
        'id': tool_id,
        'command': command,
        'logfile': logfile,
        'tool_name': tool_name,
        'return_url': return_url,
        'status': 'running',
        'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'progress': 'Starting...',
        'output': '',
        'pid': None
    }
    
    try:
        with open(logfile, 'w') as f:
            process = subprocess.Popen(
                command, 
                shell=True, 
                stdout=f, 
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid
            )
            active_commands[tool_id]['pid'] = process.pid
            
            while True:
                time.sleep(1)
                if process.poll() is not None:
                    break
                
                # Update progress
                with open(logfile, 'r') as log:
                    output = log.read()
                    active_commands[tool_id]['output'] = output
                    lines = len(output.splitlines())
                    active_commands[tool_id]['progress'] = f"Running... {lines} lines output"
            
            # Command completed
            active_commands[tool_id]['status'] = 'completed'
            active_commands[tool_id]['end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            active_commands[tool_id]['progress'] = 'Completed successfully'
            active_commands[tool_id]['exit_code'] = process.returncode
            
            # Move to history
            command_history.append(active_commands[tool_id])
            if len(command_history) > 50:  # Keep only last 50 commands
                command_history.pop(0)
            
    except Exception as e:
        active_commands[tool_id]['status'] = 'error'
        active_commands[tool_id]['progress'] = f'Error: {str(e)}'
        active_commands[tool_id]['end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        command_history.append(active_commands[tool_id])

# =============================================
# Template Creation
# =============================================

def create_templates():
    templates = {
        'home.html': '''<!DOCTYPE html>
<html>
<head>
    <title>Security Toolkit</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0a0a2a; color: #e0e0ff; }
        .card { background-color: #1a1a4a; border: 1px solid #30305a; }
        .card-title { color: #4d94ff; }
        .btn-red { background-color: #cc0000; border-color: #ff3333; }
        .btn-blue { background-color: #0066cc; border-color: #3399ff; }
        .btn-soc { background-color: #00cc99; border-color: #33ffcc; }
        .btn-admin { background-color: #cc9900; border-color: #ffcc00; }
        .admin-link { color: #ff9900; text-decoration: none; float: right; }
    </style>
</head>
<body>
    <!-- Home template content -->
</body>
</html>''',
        # [All other templates from original code...]
    }
    
    for filename, content in templates.items():
        with open(f'templates/{filename}', 'w') as f:
            f.write(content)

# Create template files
create_templates()

# =============================================
# Web Routes
# =============================================

@app.route('/')
def home():
    missing_tools = check_tools()
    return render_template('home.html', missing_tools=missing_tools)

@app.route('/red-team')
def red_team():
    return render_template('red_team.html', subnet=get_local_subnet())

@app.route('/blue-team')
def blue_team():
    active_services = subprocess.run(['ss', '-tuln'], capture_output=True, text=True).stdout
    system_logs = subprocess.run(['journalctl', '-xe', '-n', '50'], capture_output=True, text=True).stdout
    return render_template('blue_team.html', 
                         subnet=get_local_subnet(),
                         active_services=active_services,
                         system_logs=system_logs)

@app.route('/soc-mode')
def soc_mode():
    system_status = get_system_status()
    active_connections = get_active_connections()
    process_list = get_process_list("", 20)
    return render_template('soc_mode.html',
                         system_status=system_status,
                         active_connections=active_connections,
                         process_list=process_list)

# Command execution endpoints
@app.route('/execute-command', methods=['POST'])
def execute_command():
    try:
        data = request.get_json()
        command = data.get('command')
        tool_name = data.get('tool_name', 'Custom Command')
        return_url = data.get('return_url', '/')
        
        if not command:
            return jsonify({'error': 'No command provided'}), 400
        
        logfile = os.path.join(app.config['LOG_FOLDER'], f'command_{int(time.time())}.log')
        
        threading.Thread(
            target=run_tool,
            args=(command, logfile, tool_name, return_url)
        ).start()
        
        tool_id = max(active_commands.keys()) if active_commands else None
        return jsonify({
            'status': 'started',
            'tool_id': tool_id,
            'logfile': logfile
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/command-status/<tool_id>')
def get_command_status(tool_id):
    if tool_id in active_commands:
        return jsonify(active_commands[tool_id])
    else:
        for cmd in reversed(command_history):
            if cmd['id'] == tool_id:
                return jsonify(cmd)
        return jsonify({'error': 'Command not found'}), 404

@app.route('/stop-command/<tool_id>', methods=['POST'])
def stop_command(tool_id):
    if tool_id in active_commands:
        try:
            cmd = active_commands[tool_id]
            if cmd['pid']:
                os.killpg(os.getpgid(cmd['pid']), 9)
            cmd['status'] = 'stopped'
            cmd['end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cmd['progress'] = 'Manually stopped'
            command_history.append(cmd)
            return jsonify({'status': 'stopped'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'Command not found'}), 404

# Tool-specific routes
@app.route('/run-nmap-scan', methods=['POST'])
def run_nmap_scan():
    target = request.form.get('target')
    scan_type = request.form.get('scan_type', 'quick')
    
    if scan_type == 'quick':
        command = f"nmap -T4 -F {target}"
    elif scan_type == 'full':
        command = f"nmap -sV -sC -p- {target}"
    else:
        command = f"nmap {target}"
    
    logfile = os.path.join(app.config['LOG_FOLDER'], f'nmap_{int(time.time())}.log')
    threading.Thread(target=run_tool, args=(command, logfile, 'Nmap Scan', '/red-team')).start()
    
    return jsonify({'status': 'started', 'logfile': logfile})

@app.route('/run-gobuster', methods=['POST'])
def run_gobuster():
    website = request.form.get('website')
    wordlist = request.form.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
    
    if not website.startswith('http'):
        website = f"http://{website}"
    
    command = f"gobuster dir -u {website} -w {wordlist}"
    logfile = os.path.join(app.config['LOG_FOLDER'], f'gobuster_{int(time.time())}.log')
    
    threading.Thread(target=run_tool, args=(command, logfile, 'Gobuster Scan', '/red-team')).start()
    
    return jsonify({'status': 'started', 'logfile': logfile})

# [All other tool routes from original code...]

@app.route('/view-logs')
def view_logs():
    logs = []
    for filename in os.listdir(app.config['LOG_FOLDER']):
        if filename.endswith('.log'):
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
    
    if 'nmap' in filename:
        content = re.sub(r'(Nmap scan report for .+)', r'<strong>\1</strong>', content)
        content = re.sub(r'(\d+/tcp\s+open\s+.+)', r'<span class="text-success">\1</span>', content)
    elif 'hydra' in filename:
        content = re.sub(r'(\[STATUS\]\s+.+)', r'<span class="text-info">\1</span>', content)
        content = re.sub(r'(host:|login:|password:)', r'<strong>\1</strong>', content)
    
    return render_template('view_log.html', 
                         filename=filename, 
                         content=content)

# =============================================
# Main Execution
# =============================================

if __name__ == '__main__':
    missing = check_tools()
    if missing:
        print(f"Warning: Missing tools: {', '.join(missing)}")
        print("Some features may not work without these tools")
    
    print("Starting Security Toolkit...")
    print("Access the web interface at: http://localhost:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)
