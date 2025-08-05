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
        # ... [previous templates remain the same until soc_mode.html] ...
        
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

        # ... [rest of the templates remain the same] ...
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

# ... [previous route functions remain the same until soc_mode] ...

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
                          command=command)

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
                          command=command)

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
                          command=command)

# ... [rest of the code remains the same] ...

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
