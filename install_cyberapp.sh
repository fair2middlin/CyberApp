#!/bin/bash
set -e

APP_DIR="/opt/cyberapp"
APP_FILE="${APP_DIR}/cyber_dashboard.py"
SUDOERS_FILE="/etc/sudoers.d/flaskmonitor"
FLASK_USER="flaskuser"
SERVICE_NAME="cyber_dashboard.service"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME"

echo "=== CyberApp System Monitoring Dashboard Installer ==="

# --- Create directories ---
mkdir -p "$APP_DIR" /var/log/cyberapp
echo "[OK] Created directories."

# --- Install required packages ---
apt update -y
# Install core Python/Flask/Apache dependencies for WSGI deployment
apt install -y python3 python3-pip python3-flask apache2 libapache2-mod-wsgi-py3 curl net-tools procps gawk grep coreutils systemd sudo sed

# Ensure Flask is installed in the default environment for the WSGI user
apt install -y python3-flask

echo "[OK] Installed dependencies."
if [ -n "$FLASK_USER" ] && ! id "$FLASK_USER" >/dev/null 2>&1; then
    useradd -r -s /sbin/nologin "$FLASK_USER"
    echo "[OK] Created user $FLASK_USER"
fi

# --- Setup sudo permissions for safe commands ---
# Permissions for all commands used in the Python script
cat <<EOF > "$SUDOERS_FILE"
$FLASK_USER ALL=(ALL) NOPASSWD: /usr/bin/w, /usr/bin/ps, /usr/bin/df, /usr/bin/journalctl, /usr/bin/grep, /usr/bin/awk, /usr/bin/sort, /usr/bin/head, /usr/bin/tail, /usr/bin/cat, /usr/bin/uptime, /usr/bin/egrep, /usr/bin/sed, /usr/bin/who, /usr/bin/uniq, /usr/bin/cut, /usr/bin/ss
EOF
chmod 440 "$SUDOERS_FILE"
echo "[OK] Configured sudoers for read-only monitoring."

# --- Create Flask Application (WSGI Ready) ---
cat <<PYCODE > "$APP_FILE"
#!/usr/bin/env python3
import subprocess
from flask import Flask, render_template_string
from datetime import datetime
import sys
import os
import getpass

# Standard Flask application object
app = Flask(__name__)
# WSGI entry point required by Apache mod_wsgi
application = app

# Version and Debug Flag
VERSION = "3.4-WSGI-NO-PROXY"
DIAGNOSTIC_MODE = False 

def run_cmd(cmd):
    """Executes a shell command via sudo and returns stdout, or 'COMMAND FAILED' on error."""
    try:
        # Executes command as 'flaskuser' due to WSGI config, using the granted sudo permissions
        out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
        raw_output = out.strip()
        
        # DEBUG HOOK: Print raw command and output for the target functions
        global DIAGNOSTIC_MODE
        if DIAGNOSTIC_MODE and ('w | awk' in cmd or 'sudo: ' in cmd):
            print(f"| --- DEBUG: Raw Command Output ---")
            print(f"| Command: {cmd}")
            print(f"| Raw Output:")
            for line in raw_output.splitlines():
                print(f"| >>> {line}")
            print(f"| --- END DEBUG ---")
        
        return raw_output
    except subprocess.CalledProcessError:
        return "COMMAND FAILED"

def get_current_user_id():
    """Returns the username the process is currently running as."""
    try:
        return getpass.getuser()
    except Exception:
        return f"Unknown UID {os.geteuid()}"


def get_logged_users():
    # FIXED: Use absolute path for /usr/bin/sudo
    cmd = "/usr/bin/sudo /usr/bin/w | /usr/bin/awk 'NR > 2 {print \$1}' | /usr/bin/sort | /usr/bin/uniq"
    users = [u.strip() for u in run_cmd(cmd).splitlines() if u.strip()]
    return users if users else ["No logged users (COMMAND FAILED/EMPTY)"]

def get_sudo_users():
    # FIXED: Use absolute path for /usr/bin/sudo
    cmd = "/usr/bin/sudo /usr/bin/grep 'sudo: ' /var/log/auth.log 2>/dev/null | /usr/bin/awk '{print \$11}' | /usr/bin/grep uid | /usr/bin/sort | /usr/bin/uniq"
    
    raw_output = run_cmd(cmd).splitlines()
    
    users = set()
    for line in raw_output:
        line = line.strip()
        if '(' in line:
            username = line.split('(')[0].strip()
            if username:
                users.add(username)

    final_users = sorted(list(users))
    return final_users if final_users else ["No sudo activity detected in logs (COMMAND FAILED/EMPTY)"]

def get_cpu_processes():
    # FIXED: Use absolute path for /usr/bin/sudo
    cmd = "/usr/bin/sudo /usr/bin/ps -eo pid,comm,pcpu --sort=-pcpu | /usr/bin/head -n 6"
    return run_cmd(cmd).splitlines()

def get_mem_processes():
    # FIXED: Use absolute path for /usr/bin/sudo
    cmd = "/usr/bin/sudo /usr/bin/ps -eo pid,comm,pmem --sort=-pmem | /usr/bin/head -n 6"
    return run_cmd(cmd).splitlines()

def get_disk_usage():
    # FIXED: Use absolute path for /usr/bin/sudo
    cmd = "/usr/bin/sudo /usr/bin/df -h --output=target,pcent | /usr/bin/tail -n +2"
    return run_cmd(cmd).splitlines()

def get_uptime():
    # FIXED: Use absolute path for /usr/bin/sudo
    cmd = "/usr/bin/sudo /usr/bin/uptime -p"
    return run_cmd(cmd)

def get_httpd_error_ips():
    # FIXED: Use absolute path for /usr/bin/sudo
    cmd = "/usr/bin/sudo /usr/bin/grep 'error' /var/log/apache2/error.log 2>/dev/null | /usr/bin/awk '{print \$1}' | /usr/bin/sort | /usr/bin/uniq -c | /usr/bin/sort -nr | /usr/bin/head -n 10"
    return run_cmd(cmd).splitlines() or ["No Apache errors"]

def get_httpd_error_urls():
    # FIXED: Use absolute path for /usr/bin/sudo
    cmd = "/usr/bin/sudo /usr/bin/grep 'error' /var/log/apache2/error.log 2>/dev/null | /usr/bin/awk '{print \$NF}' | /usr/bin/sort | /usr/bin/uniq -c | /usr/bin/sort -nr | /usr/bin/head -n 10"
    return run_cmd(cmd).splitlines() or ["No error URLs"]

def get_journal_errors():
    # FIXED: Use absolute path for /usr/bin/sudo
    cmd = "/usr/bin/sudo /usr/bin/journalctl -p 3 -n 10 --no-pager"
    return run_cmd(cmd).splitlines() or ["No critical system errors"]

def get_network_connections():
    # FIXED: Use absolute path for /usr/bin/sudo
    cmd = "/usr/bin/sudo /usr/bin/ss -tuna | /usr/bin/awk '{print \$5}' | /usr/bin/cut -d: -f1 | /usr/bin/sort | /usr/bin/uniq -c | /usr/bin/sort -nr | /usr/bin/head -n 10"
    return run_cmd(cmd).splitlines() or ["No active outbound connections"]

def print_diagnostics():
    """Gathers and prints all monitoring data for debugging."""
    print("\n\n--- CYBERAPP DIAGNOSTIC OUTPUT (Pre-Deployment Check) ---")
    print(f"[VERSION] {VERSION}")
    # The current user running this diagnostic is the installer user (likely root)
    print(f"[RUNNING USER] {get_current_user_id()} (Expected: root/installer user)")

    data = {
        "users": get_logged_users(),
        "sudo_users": get_sudo_users(),
        "cpu": get_cpu_processes(),
        "mem": get_mem_processes(),
        "disk": get_disk_usage(),
        "uptime": get_uptime(),
        "http_ips": get_httpd_error_ips(),
        "http_urls": get_httpd_error_urls(),
        "journal": get_journal_errors(),
        "net": get_network_connections(),
    }

    for key, value in data.items():
        print(f"\n[VARIABLE: {key.upper()}]")
        if isinstance(value, list):
            for line in value:
                print(f"| {line}")
        else:
            print(f"| {value}")
            
    print("\n--- END OF DIAGNOSTICS ---\n")

@app.route("/")
def dashboard():
    ctx = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "app_version": VERSION,
        "run_user": get_current_user_id(),
        "uptime": get_uptime(),
        "users": get_logged_users(),
        "sudo_users": get_sudo_users(),
        "cpu": get_cpu_processes(),
        "mem": get_mem_processes(),
        "disk": get_disk_usage(),
        "http_ips": get_httpd_error_ips(),
        "http_urls": get_httpd_error_urls(),
        "journal": get_journal_errors(),
        "net": get_network_connections()
    }

    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <script src="https://cdn.tailwindcss.com"></script>
      <title>CyberApp Security Dashboard</title>
      <style>
        /* Ensures pre text doesn't overflow */
        pre { white-space: pre-wrap; word-wrap: break-word; }
      </style>
    </head>
    <body class="bg-gray-900 text-gray-100 p-6">
      <div class="max-w-7xl mx-auto bg-gray-800 p-6 rounded-xl shadow-lg">
        <h1 class="text-3xl font-bold text-cyan-400 mb-6 border-b border-gray-700 pb-2">CyberApp Dashboard</h1>
        
        <div class="text-sm text-gray-400 mb-4 flex justify-between">
            <span>Last updated: {{ time }} | {{ uptime }}</span>
            <span class="text-yellow-400">Version: {{ app_version }} | Running as: <span class="font-bold">{{ run_user }}</span></span>
        </div>

        <div class="grid md:grid-cols-3 gap-6">
          <div class="bg-gray-700 p-4 rounded-lg">
            <h2 class="text-xl font-semibold text-teal-300 mb-2">Logged Users </h2>
            <ul>{% for u in users %}<li>{{u}}</li>{% endfor %}</ul>
          </div>

          <div class="bg-gray-700 p-4 rounded-lg">
            <h2 class="text-xl font-semibold text-yellow-300 mb-2">Sudo Activity (Log Parsing)</h2>
            <ul>{% for u in sudo_users %}<li>{{u}}</li>{% endfor %}</ul>
          </div>

          <div class="bg-gray-700 p-4 rounded-lg">
            <h2 class="text-xl font-semibold text-lime-300 mb-2">Disk Usage</h2>
            <ul>{% for d in disk %}<li>{{d}}</li>{% endfor %}</ul>
          </div>
        </div>

        <div class="mt-8 grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          <div class="bg-gray-700 p-4 rounded-lg"><h3 class="text-lg text-orange-300 mb-2">Top CPU</h3><pre class="text-xs">{{ cpu|join('\n') }}</pre></div>
          <div class="bg-gray-700 p-4 rounded-lg"><h3 class="text-lg text-pink-300 mb-2">Top Memory</h3><pre class="text-xs">{{ mem|join('\n') }}</pre></div>
          <div class="bg-gray-700 p-4 rounded-lg"><h3 class="text-lg text-emerald-300 mb-2">Outbound Connections</h3><pre class="text-xs">{{ net|join('\n') }}</pre></div>
          <div class="bg-gray-700 p-4 rounded-lg"><h3 class="text-lg text-sky-300 mb-2">Apache Error IPs</h3><pre class="text-xs">{{ http_ips|join('\n') }}</pre></div>
          <div class="bg-gray-700 p-4 rounded-lg"><h3 class="text-lg text-rose-300 mb-2">Apache Error URLs</h3><pre class="text-xs">{{ http_urls|join('\n') }}</pre></div>
          <div class="bg-gray-700 p-4 rounded-lg"><h3 class="text-lg text-red-300 mb-2">Critical System Errors</h3><pre class="text-xs">{{ journal|join('\n') }}</pre></div>
        </div>
      </div>
    </body></html>
    """
    return render_template_string(html, **ctx)

if __name__ == "__main__":
    # Check if the script is run with 'diagnose' argument for testing
    if len(sys.argv) > 1 and sys.argv[1] == 'diagnose':
        DIAGNOSTIC_MODE = True
        print_diagnostics()
        sys.exit(0) 
    
    # This block is ignored by WSGI deployment.
    app.run(host="0.0.0.0", port=8080)
PYCODE

chmod +x "$APP_FILE"
chown -R "$FLASK_USER":"$FLASK_USER" "$APP_DIR"

echo "[OK] Flask app created and secured."

# --- Cleanup old service (ENSURES a clean WSGI deployment) ---
echo "[INFO] Starting cleanup of old unstable systemd service..."
# Check if the old systemd service file exists and stop/disable it
if systemctl list-unit-files --full -all | grep -F "$SERVICE_NAME"; then
    echo "[INFO] Found old service: $SERVICE_NAME. Stopping and disabling."
    systemctl stop "$SERVICE_NAME" || true
    systemctl disable "$SERVICE_NAME" || true
    
    if [ -f "$SERVICE_FILE" ]; then
        rm -f "$SERVICE_FILE"
        echo "[INFO] Removed $SERVICE_FILE."
    fi
else
    echo "[INFO] Old service $SERVICE_NAME not found. Skipping cleanup."
fi

# Reload systemd daemon to recognize the removal (important if it was disabled)
echo "[INFO] Reloading systemd daemon configuration."
systemctl daemon-reload

echo "[OK] Cleaned up previous service artifacts."

# --- Apache WSGI Configuration (FIX APPLIED HERE) ---
echo "[OK] Configuring Apache for stable WSGI deployment..."

# Enable necessary Apache modules (ensure they are on)
a2enmod wsgi || true
a2enmod rewrite || true

# CRITICAL FIX: Disable proxy modules. 
a2dismod proxy || true
a2dismod proxy_http || true

a2dissite 000-default.conf || true # Disable default site

cat <<EOF > /etc/apache2/sites-available/cyberapp.conf
# Define a WSGI Daemon Process Group to run the application securely as the flaskuser
# FIX: The system user 'flaskuser' lacks a home directory. We explicitly set 'home' 
# to the application's directory ($APP_DIR) to prevent the WSGI crash.
WSGIDaemonProcess cyberapp user=$FLASK_USER group=$FLASK_USER threads=5 home=$APP_DIR

<VirtualHost *:80>
    ServerName localhost
    
    # Alias the entire root path / to the Python file, pointing to the 'application' variable
    WSGIScriptAlias / $APP_FILE

    <Directory $APP_DIR>
        # Assign the application to the secure daemon process group
        WSGIProcessGroup cyberapp
        WSGIApplicationGroup %{GLOBAL}
        Require all granted
    </Directory>
</VirtualHost>
EOF

a2ensite cyberapp.conf

# NEW STEP: Touch the app file to signal WSGI to reload the Python module immediately
echo "[INFO] Forcing WSGI daemon reload..."
touch "$APP_FILE"

systemctl restart apache2

echo "=== Installation Complete ==="
echo "--------------------------------------------------------"
echo ">> ACCESS THE DASHBOARD HERE: http://localhost/"
echo "--------------------------------------------------------"
