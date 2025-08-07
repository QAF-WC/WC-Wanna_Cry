#!/usr/bin/env python3
import os
import sys
import subprocess
from flask import Flask, render_template, request, redirect, url_for, session, flash
import re
import threading
import time
import shutil
from werkzeug.security import generate_password_hash, check_password_hash

# Create required directories
os.makedirs('templates', exist_ok=True)
os.makedirs('logs', exist_ok=True)
os.makedirs('uploads', exist_ok=True)

# [Previous template creation code remains exactly the same...]

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
tool_status = {}

# Admin password (hashed)
ADMIN_PASSWORD = generate_password_hash('supersecret')

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
    """Get comprehensive system status"""
    try:
        # Get CPU and memory info
        cpu_mem = subprocess.run(['top', '-b', '-n', '1'], capture_output=True, text=True).stdout
        # Get disk usage
        disk = subprocess.run(['df', '-h'], capture_output=True, text=True).stdout
        # Get uptime
        uptime = subprocess.run(['uptime'], capture_output=True, text=True).stdout
        
        return f"=== CPU/Memory Usage ===\n{cpu_mem}\n\n=== Disk Usage ===\n{disk}\n\n=== System Uptime ===\n{uptime}"
    except Exception as e:
        return f"Error getting system status: {str(e)}"

def get_active_connections():
    """Get all active network connections"""
    try:
        # Get all connections
        connections = subprocess.run(['netstat', '-tulnp'], capture_output=True, text=True).stdout
        return connections
    except Exception as e:
        return f"Error getting connections: {str(e)}"

def get_process_list(filter=None, limit=20):
    """Get running processes with optional filter"""
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

def run_tool(command, logfile, tool_name):
    """Run a system tool and log its output"""
    tool_status[tool_name] = {'running': True, 'progress': 'Starting...'}
    try:
        with open(logfile, 'w') as f:
            process = subprocess.Popen(command, shell=True, stdout=f, stderr=subprocess.STDOUT)
            
            while process.poll() is None:
                time.sleep(3)
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
    system_status = get_system_status()
    active_connections = get_active_connections()
    process_list = get_process_list("", 20)
    return render_template('soc_mode.html',
                         system_status=system_status,
                         active_connections=active_connections,
                         process_list=process_list)

@app.route('/refresh-system-status', methods=['POST'])
def refresh_system_status():
    system_status = get_system_status()
    active_connections = get_active_connections()
    process_list = get_process_list("", 20)
    return render_template('soc_mode.html',
                         system_status=system_status,
                         active_connections=active_connections,
                         process_list=process_list)

@app.route('/refresh-connections', methods=['POST'])
def refresh_connections():
    active_connections = get_active_connections()
    system_status = get_system_status()
    process_list = get_process_list("", 20)
    return render_template('soc_mode.html',
                         system_status=system_status,
                         active_connections=active_connections,
                         process_list=process_list)

@app.route('/monitor-processes', methods=['POST'])
def monitor_processes():
    filter = request.form.get('filter')
    limit = request.form.get('limit', 20)
    process_list = get_process_list(filter, int(limit))
    system_status = get_system_status()
    active_connections = get_active_connections()
    return render_template('soc_mode.html',
                         system_status=system_status,
                         active_connections=active_connections,
                         process_list=process_list)

@app.route('/run-tcpdump', methods=['POST'])
def run_tcpdump():
    interface = request.form.get('interface', 'eth0')
    count = request.form.get('count', '100')
    logfile = os.path.join(app.config['LOG_FOLDER'], f'tcpdump_{int(time.time())}.log')
    command = f"sudo tcpdump -i {interface} -c {count}"
    
    threading.Thread(target=run_tool, args=(command, logfile, 'tcpdump')).start()
    
    return redirect(url_for('soc_mode'))

@app.route('/monitor-logs', methods=['POST'])
def monitor_logs():
    logfile = request.form.get('logfile', '/var/log/syslog')
    logfile_out = os.path.join(app.config['LOG_FOLDER'], f'logmonitor_{int(time.time())}.log')
    command = f"sudo tail -f {logfile} > {logfile_out}"
    
    threading.Thread(target=run_tool, args=(command, logfile_out, 'logmonitor')).start()
    
    return redirect(url_for('soc_mode'))

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

@app.route('/run-wireless-scan', methods=['POST'])
def run_wireless_scan():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    interface = request.form.get('interface', 'wlan0')
    duration = request.form.get('duration', '10')
    logfile = os.path.join(app.config['LOG_FOLDER'], f'wireless_scan_{int(time.time())}.log')
    command = f"sudo timeout {duration} airodump-ng {interface}"
    
    threading.Thread(target=run_tool, args=(command, logfile, 'airodump')).start()
    
    return redirect(url_for('advanced_mode'))

@app.route('/run-forensics', methods=['POST'])
def run_forensics():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    
    if 'file' not in request.files:
        flash('No file uploaded')
        return redirect(url_for('advanced_mode'))
        
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('advanced_mode'))
        
    # Save the uploaded file
    filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filename)
    
    logfile = os.path.join(app.config['LOG_FOLDER'], f'forensics_{int(time.time())}.log')
    command = f"strings {filename} | head -n 1000"
    
    threading.Thread(target=run_tool, args=(command, logfile, 'forensics')).start()
    
    return redirect(url_for('advanced_mode'))

@app.route('/run-scan', methods=['POST'])
def run_scan():
    target = request.form.get('target')
    logfile = os.path.join(app.config['LOG_FOLDER'], f'nmap_scan_{int(time.time())}.log')
    command = f"sudo nmap -sC -sV -p- {target} -T4"
    
    threading.Thread(target=run_tool, args=(command, logfile, 'nmap')).start()
    
    return redirect(url_for('red_team'))

@app.route('/run-ddos', methods=['POST'])
def run_ddos():
    target = request.form.get('target')
    count = request.form.get('count', '1000')
    logfile = os.path.join(app.config['LOG_FOLDER'], f'ddos_{int(time.time())}.log')
    command = f"sudo hping3 -S --flood -c {count} {target}"
    
    threading.Thread(target=run_tool, args=(command, logfile, 'hping3')).start()
    
    return redirect(url_for('red_team'))

@app.route('/run-gobuster', methods=['POST'])
def run_gobuster():
    website = request.form.get('website')
    wordlist = request.form.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
    
    if not website.startswith('http'):
        website = f"http://{website}"
    
    logfile = os.path.join(app.config['LOG_FOLDER'], f'gobuster_{int(time.time())}.log')
    command = f"sudo gobuster dir -u {website} -w {wordlist} -q"
    
    threading.Thread(target=run_tool, args=(command, logfile, 'gobuster')).start()
    
    return redirect(url_for('red_team'))

@app.route('/run-hydra', methods=['POST'])
def run_hydra():
    service = request.form.get('service')
    target = request.form.get('target')
    user = request.form.get('user')
    wordlist = request.form.get('wordlist')
    
    logfile = os.path.join(app.config['LOG_FOLDER'], f'hydra_{int(time.time())}.log')
    command = f"sudo hydra -l {user} -P {wordlist} {target} {service}"
    
    threading.Thread(target=run_tool, args=(command, logfile, 'hydra')).start()
    
    return redirect(url_for('red_team'))

@app.route('/run-local-scan', methods=['POST'])
def run_local_scan():
    logfile = os.path.join(app.config['LOG_FOLDER'], f'local_scan_{int(time.time())}.log')
    command = "sudo nmap -sS -T4 localhost"
    
    threading.Thread(target=run_tool, args=(command, logfile, 'local_scan')).start()
    
    return redirect(url_for('blue_team'))

@app.route('/run-network-scan', methods=['POST'])
def run_network_scan():
    subnet = get_local_subnet()
    logfile = os.path.join(app.config['LOG_FOLDER'], f'network_scan_{int(time.time())}.log')
    command = f"sudo nmap -sn {subnet}"
    
    threading.Thread(target=run_tool, args=(command, logfile, 'network_scan')).start()
    
    return redirect(url_for('blue_team'))

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
    
    # Simple formatting for common tools
    if 'nmap' in filename:
        content = re.sub(r'(Nmap scan report for .+)', r'<strong>\1</strong>', content)
        content = re.sub(r'(\d+/tcp\s+open\s+.+)', r'<span class="text-success">\1</span>', content)
    elif 'hydra' in filename:
        content = re.sub(r'(\[STATUS\]\s+.+)', r'<span class="text-info">\1</span>', content)
        content = re.sub(r'(host:|login:|password:)', r'<strong>\1</strong>', content)
    
    return render_template('view_log.html', 
                         filename=filename, 
                         content=content)

@app.route('/tool-status/<tool>')
def get_tool_status(tool):
    return tool_status.get(tool, {'running': False, 'progress': 'Not running'})

if __name__ == '__main__':
    # Check for required tools
    missing = check_tools()
    if missing:
        print(f"Missing tools: {', '.join(missing)}")
        print("Install them before using all features")
    
    print("Starting WANNACRY Toolkit...")
    print("Access the GUI at: http://localhost:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)
