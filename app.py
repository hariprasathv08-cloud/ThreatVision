import os
import sys
import time
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash

# Import our database and monitoring modules
from database import Database
from modules.event_monitor import EventMonitorThread
from modules.usb_monitor import USBMonitorThread
from modules.fim import FIMThread
from modules.process_monitor import ProcessMonitorThread
from modules.network_monitor import NetworkMonitorThread
from modules.firewall_monitor import FirewallMonitorThread
from modules.report_generator import generate_pdf, generate_csv, REPORTS_DIR

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("CyberSIEM.App")

app = Flask(__name__)
app.secret_key = "cybersiem-super-secret-key-1337-security"

# Custom jinja filter to extract basename of filepaths
@app.template_filter('basename')
def basename_filter(path):
    return os.path.basename(path)

# Set session timeout
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# Set up Login Manager
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, user_id, username, role):
        self.id = user_id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    db = Database()
    u = db.get_user_by_id(user_id)
    if u:
        return User(u["id"], u["username"], u["role"])
    return None

# Background threads reference holder
bg_threads = {}

def start_background_monitoring():
    """Starts all operational background threads in a thread-safe once-only check."""
    # If running with Werkzeug reloader (debug mode), only start in child process
    if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        logger.info("Main reloader process detected. Skipping background thread startup.")
        return

    logger.info("Starting background security monitoring threads...")
    
    threads = {
        "event_monitor": EventMonitorThread(),
        "usb_monitor": USBMonitorThread(),
        "fim_monitor": FIMThread(),
        "process_monitor": ProcessMonitorThread(),
        "network_monitor": NetworkMonitorThread(),
        "firewall_monitor": FirewallMonitorThread()
    }
    
    for name, thread in threads.items():
        thread.start()
        bg_threads[name] = thread
        logger.info(f"Thread '{name}' started successfully.")

# Initialize database
db = Database()

# ----------------- VIEW ROUTES -----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
        
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip_addr = request.remote_addr
        
        user_record = db.get_user_by_username(username)
        
        if user_record and check_password_hash(user_record["password_hash"], password):
            user = User(user_record["id"], user_record["username"], user_record["role"])
            login_user(user)
            
            # Log successful login history
            db.execute(
                "INSERT INTO login_history (username, ip_address, status, details) VALUES (?, ?, ?, ?)",
                (username, ip_addr, "Success", f"Logged in as {user_record['role']}")
            )
            flash("Successfully logged in!", "success")
            return redirect(url_for("dashboard"))
        else:
            # Log failed login history
            db.execute(
                "INSERT INTO login_history (username, ip_address, status, details) VALUES (?, ?, ?, ?)",
                (username, ip_addr, "Failed", "Invalid credentials entered")
            )
            flash("Invalid username or password.", "danger")
            
    # Get last successful logins to display on the login page (as design decoration or last login stats)
    last_logins = db.query(
        "SELECT timestamp, username, ip_address FROM login_history WHERE status = 'Success' ORDER BY timestamp DESC LIMIT 3"
    )
    return render_template("login.html", last_logins=last_logins)

@app.route("/logout")
@login_required
def logout():
    db.execute(
        "INSERT INTO login_history (username, ip_address, status, details) VALUES (?, ?, ?, ?)",
        (current_user.username, request.remote_addr, "Logout", "User logged out")
    )
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    # Fetch initial statistics
    stats = get_dashboard_summary()
    
    # Get last login details for this user
    last_login = db.query(
        "SELECT timestamp, ip_address FROM login_history WHERE username = ? AND status = 'Success' ORDER BY timestamp DESC LIMIT 1 OFFSET 1",
        (current_user.username,), one=True
    )
    
    # Get system metadata
    import platform
    import psutil
    uptime_seconds = time.time() - psutil.boot_time()
    uptime_days = int(uptime_seconds // 86400)
    uptime_hours = int((uptime_seconds % 86400) // 3600)
    uptime_mins = int((uptime_seconds % 3600) // 60)
    uptime_str = f"{uptime_days}d {uptime_hours}h {uptime_mins}m"
    
    system_info = {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()} ({platform.architecture()[0]})",
        "uptime": uptime_str,
        "logged_user": current_user.username,
        "ip_address": socket_get_ip(),
        "dotnet_framework": "4.8.09240" if sys.platform.startswith("win") else "N/A", # Sim/Heuristic OS val
        "python_version": platform.python_version()
    }
    
    return render_template(
        "dashboard.html", 
        stats=stats, 
        last_login=last_login, 
        system_info=system_info
    )

@app.route("/events")
@login_required
def events():
    return render_template("events.html")

@app.route("/alerts")
@login_required
def alerts():
    return render_template("alerts.html")

@app.route("/correlation")
@login_required
def correlation():
    # Rules list to show
    rules = [
        {"name": "Brute Force Detection", "condition": "More than 5 failed logins within 5 minutes", "severity": "Critical"},
        {"name": "Account Abuse Detection", "condition": "Multiple user account creations in 10 minutes", "severity": "High"},
        {"name": "Privilege Escalation Detection", "condition": "Special privilege assignments (Event 4672)", "severity": "High"},
        {"name": "Log Tampering Detection", "condition": "Audit log cleared event (Event 1102)", "severity": "Critical"},
        {"name": "Suspicious Activity Detection", "condition": "Spikes exceeding 50 events in 1 minute", "severity": "Medium"}
    ]
    return render_template("correlation.html", rules=rules)

@app.route("/fim")
@login_required
def fim():
    paths = db.get_setting("fim_monitored_paths", "")
    return render_template("fim.html", monitored_paths=paths)

@app.route("/usb")
@login_required
def usb():
    return render_template("usb.html")

@app.route("/processes")
@login_required
def processes():
    return render_template("processes.html")

@app.route("/network")
@login_required
def network():
    return render_template("network.html")

@app.route("/firewall")
@login_required
def firewall():
    return render_template("firewall.html")

@app.route("/reports")
@login_required
def reports():
    reports_list = db.query("SELECT * FROM reports ORDER BY generated_at DESC")
    return render_template("reports.html", reports=reports_list)

@app.route("/users")
@login_required
def users():
    if current_user.role != "Administrator":
        flash("Access denied. Admin role required.", "danger")
        return redirect(url_for("dashboard"))
    users_list = db.query("SELECT id, username, role, created_at FROM users")
    login_history = db.query("SELECT * FROM login_history ORDER BY timestamp DESC LIMIT 50")
    return render_template("users.html", users=users_list, history=login_history)

@app.route("/settings")
@login_required
def settings():
    settings_data = {
        "gmail_sender": db.get_setting("gmail_sender", ""),
        "gmail_app_password": db.get_setting("gmail_app_password", ""),
        "gmail_recipients": db.get_setting("gmail_recipients", ""),
        "fim_monitored_paths": db.get_setting("fim_monitored_paths", ""),
        "email_notifications_enabled": db.get_setting("email_notifications_enabled", "1")
    }
    return render_template("settings.html", settings=settings_data)


# ----------------- ACTION & API ENDPOINTS -----------------

@app.route("/api/stats")
@login_required
def api_stats():
    summary = get_dashboard_summary()
    return jsonify(summary)

@app.route("/api/events")
@login_required
def api_events():
    limit = request.args.get("limit", 100, type=int)
    search = request.args.get("search", "", type=str)
    level = request.args.get("level", "", type=str)
    
    query = "SELECT * FROM events WHERE 1=1"
    params = []
    
    if search:
        query += " AND (message LIKE ? OR source LIKE ? OR event_id LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    if level:
        query += " AND level = ?"
        params.append(level)
        
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    
    rows = db.query(query, tuple(params))
    return jsonify([dict(r) for r in rows])

@app.route("/api/alerts")
@login_required
def api_alerts():
    severity = request.args.get("severity", "", type=str)
    status = request.args.get("status", "", type=str)
    
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if status:
        query += " AND status = ?"
        params.append(status)
        
    query += " ORDER BY timestamp DESC LIMIT 200"
    
    rows = db.query(query, tuple(params))
    return jsonify([dict(r) for r in rows])

@app.route("/api/alerts/feed")
@login_required
def api_alerts_feed():
    import json
    def event_stream():
        import time
        db_stream = Database()
        # Start scanning for alerts from 2 seconds ago
        last_check = (datetime.now() - timedelta(seconds=2)).strftime("%Y-%m-%d %H:%M:%S")
        while True:
            new_alerts = db_stream.query(
                "SELECT * FROM alerts WHERE timestamp > ? ORDER BY timestamp ASC",
                (last_check,)
            )
            if new_alerts:
                # Update last check pointer to the timestamp of the last processed alert
                last_check = new_alerts[-1]["timestamp"]
                for alert in new_alerts:
                    yield f"data: {json.dumps(dict(alert))}\n\n"
            time.sleep(1)
    return Response(event_stream(), mimetype="text/event-stream")

@app.route("/api/realtime/feed")
@login_required
def api_realtime_feed():
    import json
    def event_stream():
        import time
        db_stream = Database()
        
        def get_max_id(table_name):
            try:
                res = db_stream.query(f"SELECT MAX(id) as max_id FROM {table_name}", one=True)
                return res["max_id"] if res and res["max_id"] is not None else 0
            except Exception:
                return 0

        last_ids = {
            "alerts": get_max_id("alerts"),
            "events": get_max_id("events"),
            "file_events": get_max_id("file_events"),
            "usb_events": get_max_id("usb_events"),
            "firewall_events": get_max_id("firewall_events"),
            "network_events": get_max_id("network_events"),
            "system_health": get_max_id("system_health")
        }

        while True:
            # Check alerts
            new_alerts = db_stream.query(
                "SELECT * FROM alerts WHERE id > ? ORDER BY id ASC",
                (last_ids["alerts"],)
            )
            if new_alerts:
                last_ids["alerts"] = new_alerts[-1]["id"]
                for alert in new_alerts:
                    yield f"event: alert\ndata: {json.dumps(dict(alert))}\n\n"

            # Check events
            new_events = db_stream.query(
                "SELECT * FROM events WHERE id > ? ORDER BY id ASC",
                (last_ids["events"],)
            )
            if new_events:
                last_ids["events"] = new_events[-1]["id"]
                for evt in new_events:
                    yield f"event: event\ndata: {json.dumps(dict(evt))}\n\n"

            # Check FIM
            new_fim = db_stream.query(
                "SELECT * FROM file_events WHERE id > ? ORDER BY id ASC",
                (last_ids["file_events"],)
            )
            if new_fim:
                last_ids["file_events"] = new_fim[-1]["id"]
                for fim_evt in new_fim:
                    yield f"event: fim\ndata: {json.dumps(dict(fim_evt))}\n\n"

            # Check USB
            new_usb = db_stream.query(
                "SELECT * FROM usb_events WHERE id > ? ORDER BY id ASC",
                (last_ids["usb_events"],)
            )
            if new_usb:
                last_ids["usb_events"] = new_usb[-1]["id"]
                for usb_evt in new_usb:
                    yield f"event: usb\ndata: {json.dumps(dict(usb_evt))}\n\n"

            # Check Firewall
            new_fw = db_stream.query(
                "SELECT * FROM firewall_events WHERE id > ? ORDER BY id ASC",
                (last_ids["firewall_events"],)
            )
            if new_fw:
                last_ids["firewall_events"] = new_fw[-1]["id"]
                for fw_evt in new_fw:
                    yield f"event: firewall\ndata: {json.dumps(dict(fw_evt))}\n\n"

            # Check Network
            new_net = db_stream.query(
                "SELECT * FROM network_events WHERE id > ? ORDER BY id ASC",
                (last_ids["network_events"],)
            )
            if new_net:
                last_ids["network_events"] = new_net[-1]["id"]
                for net_evt in new_net:
                    yield f"event: network\ndata: {json.dumps(dict(net_evt))}\n\n"

            # Check System Health
            new_health = db_stream.query(
                "SELECT * FROM system_health WHERE id > ? ORDER BY id ASC",
                (last_ids["system_health"],)
            )
            if new_health:
                last_ids["system_health"] = new_health[-1]["id"]
                latest_health = new_health[-1]
                yield f"event: health\ndata: {json.dumps(dict(latest_health))}\n\n"

            time.sleep(1)
            
    return Response(event_stream(), mimetype="text/event-stream")

@app.route("/api/alerts/update_status", methods=["POST"])
@login_required
def api_alerts_update_status():
    alert_id = request.json.get("alert_id")
    status = request.json.get("status")
    if alert_id and status in ["Open", "Investigating", "Resolved"]:
        db.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Invalid arguments"}), 400

@app.route("/api/health_history")
@login_required
def api_health_history():
    # Returns last 30 readings of CPU/RAM/Disk for Chart.js updates
    rows = db.query(
        "SELECT cpu_usage, memory_usage, disk_usage, network_connections, timestamp FROM system_health ORDER BY timestamp DESC LIMIT 30"
    )
    # Return chronologically
    rows.reverse()
    return jsonify([dict(r) for r in rows])

@app.route("/api/processes")
@login_required
def api_processes():
    # Real-time list of running processes query
    # Check if process_monitor thread is active, retrieve list
    p_thread = bg_threads.get("process_monitor")
    if p_thread:
        procs = p_thread.check_processes()
        # Sort by CPU usage descending
        procs.sort(key=lambda x: x["cpu"], reverse=True)
        return jsonify(procs[:100]) # return top 100
    return jsonify([])

@app.route("/process/kill/<int:pid>", methods=["POST"])
@login_required
def kill_process(pid):
    try:
        import psutil
        p = psutil.Process(pid)
        name = p.name()
        p.terminate()
        
        # Log to db
        db.execute(
            "INSERT INTO events (event_id, log_name, source, message, level, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (9999, "Application", "Process Manager", f"Process '{name}' (PID {pid}) was terminated by admin user.", "Warning", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        flash(f"Process {name} (PID: {pid}) terminated successfully.", "success")
    except Exception as e:
        flash(f"Failed to terminate process: {str(e)}", "danger")
        
    return redirect(url_for("processes"))

@app.route("/api/network")
@login_required
def api_network():
    conns = db.query("SELECT * FROM network_events ORDER BY remote_ip DESC")
    return jsonify([dict(c) for c in conns])

@app.route("/api/network/scan", methods=["POST"])
@login_required
def api_network_scan():
    import socket
    import psutil
    import platform
    import concurrent.futures
    import subprocess
    
    # 1. Resolve local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"

    # 2. Extract subnet prefix
    prefix = "192.168.1"
    if local_ip and local_ip != "127.0.0.1":
        parts = local_ip.split(".")
        if len(parts) == 4:
            prefix = ".".join(parts[:3])
            
    # 3. Fast Ping Sweep function
    def ping_ip(target_ip):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        timeout_val = '300' if platform.system().lower() == 'windows' else '1'
        
        try:
            command = ['ping', param, '1', timeout_param, timeout_val, target_ip]
            creationflags = subprocess.CREATE_NO_WINDOW if platform.system().lower() == 'windows' else 0
            res = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5, creationflags=creationflags)
            return target_ip, res.returncode == 0
        except Exception:
            return target_ip, False

    # Ping all 254 addresses in parallel using a ThreadPoolExecutor (max workers = 120)
    ips_to_scan = [f"{prefix}.{i}" for i in range(1, 255)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=120) as executor:
        executor.map(ping_ip, ips_to_scan)
        
    # 4. Parse the populated system ARP table
    raw_devices = []
    try:
        res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == 'windows' else 0)
        if res.returncode == 0:
            current_interface = None
            for line in res.stdout.splitlines():
                line_stripped = line.strip()
                if "Interface:" in line_stripped:
                    current_interface = line_stripped.split()[1]
                elif line_stripped and not line_stripped.startswith("Internet Address"):
                    parts = line_stripped.split()
                    if len(parts) >= 3:
                        device_ip = parts[0]
                        mac = parts[1]
                        conn_type = parts[2]
                        
                        # Exclude multicast and broadcast addresses
                        if not device_ip.startswith("224.") and not device_ip.startswith("239.") and device_ip != "255.255.255.255" and mac != "ff-ff-ff-ff-ff-ff" and "-" in mac:
                            raw_devices.append({
                                "ip": device_ip,
                                "mac": mac.upper(),
                                "type": conn_type.capitalize(),
                                "interface": current_interface or "Local Subnet"
                            })
    except Exception as e:
        logger.error(f"Error executing ARP scan: {e}")
        
    # 5. Resolve hostnames in parallel to prevent blocking the request
    def resolve_hostname(dev):
        try:
            hostname = socket.gethostbyaddr(dev["ip"])[0]
            dev["hostname"] = hostname
        except Exception:
            dev["hostname"] = "Unknown"
        return dev

    devices = []
    if raw_devices:
        with concurrent.futures.ThreadPoolExecutor(max_workers=80) as resolver_executor:
            devices = list(resolver_executor.map(resolve_hostname, raw_devices))
            
    # Insert the local host adapter into the results list if not already present
    server_hostname = socket.gethostname()
    if not any(d["ip"] == local_ip for d in devices):
        devices.insert(0, {
            "ip": local_ip,
            "mac": "LOCAL-INTERFACE",
            "type": "Static",
            "hostname": server_hostname,
            "interface": "localhost"
        })
        
    return jsonify(devices)

@app.route("/api/firewall")
@login_required
def api_firewall():
    # Returns latest firewall events
    events = db.query("SELECT * FROM firewall_events ORDER BY timestamp DESC LIMIT 50")
    # Query current profile statuses
    fw_thread = bg_threads.get("firewall_monitor")
    profiles = fw_thread.get_firewall_profiles() if fw_thread else {"Domain": "ON", "Private": "ON", "Public": "ON"}
    return jsonify({
        "profiles": profiles,
        "events": [dict(e) for e in events]
    })

@app.route("/api/usb")
@login_required
def api_usb():
    events = db.query("SELECT * FROM usb_events ORDER BY timestamp DESC LIMIT 50")
    # Connected drives list
    usb_thread = bg_threads.get("usb_monitor")
    drives = list(usb_thread.connected_drives.values()) if usb_thread else []
    return jsonify({
        "drives": drives,
        "events": [dict(e) for e in events]
    })

@app.route("/api/fim")
@login_required
def api_fim():
    events = db.query("SELECT * FROM file_events ORDER BY timestamp DESC LIMIT 100")
    return jsonify([dict(e) for e in events])

@app.route("/settings/update", methods=["POST"])
@login_required
def update_settings():
    gmail_sender = request.form.get("gmail_sender", "").strip()
    gmail_app_password = request.form.get("gmail_app_password", "")
    gmail_recipients = request.form.get("gmail_recipients", "").strip()
    fim_paths = request.form.get("fim_monitored_paths", "").strip()
    email_notifications_enabled = request.form.get("email_notifications_enabled", "0")
    
    db.set_setting("gmail_sender", gmail_sender)
    if gmail_app_password:  # Only update if password input is filled
        db.set_setting("gmail_app_password", gmail_app_password)
    db.set_setting("gmail_recipients", gmail_recipients)
    db.set_setting("fim_monitored_paths", fim_paths)
    db.set_setting("email_notifications_enabled", email_notifications_enabled)
    
    flash("Settings updated successfully.", "success")
    return redirect(url_for("settings"))

@app.route("/users/add", methods=["POST"])
@login_required
def add_user():
    if current_user.role != "Administrator":
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
        
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "Operator")
    
    if not username or not password:
        flash("Username and Password are required.", "danger")
        return redirect(url_for("users"))
        
    success = db.add_user(username, password, role)
    if success:
        flash(f"User '{username}' added successfully.", "success")
    else:
        flash(f"User '{username}' already exists.", "danger")
        
    return redirect(url_for("users"))

@app.route("/users/delete/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if current_user.role != "Administrator":
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
        
    # Prevent deleting yourself
    if current_user.id == user_id:
        flash("You cannot delete your own admin account.", "danger")
        return redirect(url_for("users"))
        
    db.delete_user(user_id)
    flash("User deleted successfully.", "success")
    return redirect(url_for("users"))

@app.route("/reports/generate", methods=["POST"])
@login_required
def generate_report():
    report_type = request.form.get("report_type", "Daily")
    report_format = request.form.get("report_format", "PDF")
    
    # Define date range based on report type
    now = datetime.now()
    if report_type == "Daily":
        start_date = (now - timedelta(days=1)).strftime("%Y-%m-%d 00:00:00")
    elif report_type == "Weekly":
        start_date = (now - timedelta(days=7)).strftime("%Y-%m-%d 00:00:00")
    else: # Monthly
        start_date = (now - timedelta(days=30)).strftime("%Y-%m-%d 00:00:00")
        
    end_date = now.strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        if report_format == "PDF":
            filepath, filename = generate_pdf(report_type, start_date, end_date)
        else:
            filepath, filename = generate_csv(report_type, start_date, end_date)
            
        flash(f"{report_type} report ({report_format}) generated successfully.", "success")
    except Exception as e:
        flash(f"Failed to generate report: {str(e)}", "danger")
        
    return redirect(url_for("reports"))


# ----------------- DATA HELPERS -----------------

def get_dashboard_summary():
    """Gathers operational statistics to populate dashboard metric cards."""
    # 1. Total Windows Security log count
    total_events = db.query("SELECT COUNT(*) as count FROM events", one=True)["count"]
    
    # 2. Alerts counts by severity
    critical_alerts = db.query("SELECT COUNT(*) as count FROM alerts WHERE severity = 'Critical'", one=True)["count"]
    high_alerts = db.query("SELECT COUNT(*) as count FROM alerts WHERE severity = 'High'", one=True)["count"]
    medium_alerts = db.query("SELECT COUNT(*) as count FROM alerts WHERE severity = 'Medium'", one=True)["count"]
    low_alerts = db.query("SELECT COUNT(*) as count FROM alerts WHERE severity = 'Low'", one=True)["count"]
    
    # 3. Unique active logins tracked in history (distinct users that had logins in last 1 day)
    one_day_ago = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    active_users = db.query(
        "SELECT COUNT(DISTINCT username) as count FROM login_history WHERE status = 'Success' AND timestamp >= ?",
        (one_day_ago,), one=True
    )["count"]
    # Fallback to at least 1 (the current user)
    active_users = max(active_users, 1)

    # 4. Overall system resource health parameters
    health = db.query("SELECT cpu_usage, memory_usage, disk_usage, network_connections FROM system_health ORDER BY timestamp DESC LIMIT 1", one=True)
    if health:
        cpu = health["cpu_usage"]
        memory = health["memory_usage"]
        disk = health["disk_usage"]
        net_conns = health["network_connections"]
    else:
        # Fallback values
        cpu = 0.0
        memory = 0.0
        disk = 0.0
        net_conns = 0

    return {
        "total_events": total_events,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
        "active_users": active_users,
        "cpu_usage": cpu,
        "memory_usage": memory,
        "disk_usage": disk,
        "net_connections": net_conns
    }

def socket_get_ip():
    """Retrieves local IP address of system."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't need to connect, just opens socket path
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ----------------- MAIN RUNNER -----------------

if __name__ == "__main__":
    import socket
    # Ensure reports folders exist
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
        
    # Start background threads
    start_background_monitoring()
    
    # Run the web server
    logger.info("Starting Flask dashboard application...")
    # Clean run on port 5000
    app.run(host="0.0.0.0", port=5000, debug=False)
