import sqlite3
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybersiem.db")

class Database:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self.init_db()

    def get_connection(self):
        # Always connect with check_same_thread=False for multi-threaded setups, 
        # but manage short-lived connections inside context managers for safety.
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 2. Login history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS login_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    ip_address TEXT,
                    status TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    details TEXT
                )
            """)

            # 3. Events table (Windows Event Logs)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER,
                    log_name TEXT,
                    source TEXT,
                    message TEXT,
                    level TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    mitre_technique TEXT
                )
            """)

            # 4. Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    details TEXT NOT NULL,
                    recommended_action TEXT,
                    status TEXT DEFAULT 'Open',
                    mitre_technique TEXT
                )
            """)

            # Run migrations for existing databases
            try:
                cursor.execute("ALTER TABLE events ADD COLUMN mitre_technique TEXT")
            except sqlite3.OperationalError:
                pass
            try:
                cursor.execute("ALTER TABLE alerts ADD COLUMN mitre_technique TEXT")
            except sqlite3.OperationalError:
                pass

            # 5. Reports table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_type TEXT NOT NULL,
                    filepath TEXT NOT NULL,
                    format TEXT NOT NULL,
                    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 6. USB events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS usb_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_name TEXT,
                    vendor TEXT,
                    event_type TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 7. File events table (FIM)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filepath TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 8. Firewall events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS firewall_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 9. Network events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS network_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    local_ip TEXT,
                    local_port INTEGER,
                    remote_ip TEXT,
                    remote_port INTEGER,
                    protocol TEXT,
                    state TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 10. System health table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_health (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cpu_usage REAL,
                    memory_usage REAL,
                    disk_usage REAL,
                    network_connections INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 11. Configuration Settings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

            # Seed default settings
            default_settings = {
                "gmail_sender": "",
                "gmail_app_password": "",
                "gmail_recipients": "",
                "fim_monitored_paths": os.path.dirname(os.path.abspath(__file__)),
                "brute_force_limit": "5",
                "brute_force_window_mins": "5",
                "admin_email": ""
            }

            for key, val in default_settings.items():
                cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, val))

            # Seed default admin user if none exists
            cursor.execute("SELECT COUNT(*) as count FROM users")
            if cursor.fetchone()["count"] == 0:
                admin_pw_hash = generate_password_hash("adminpassword")
                cursor.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    ("admin", admin_pw_hash, "Administrator")
                )
            
            conn.commit()

    def query(self, sql, params=(), one=False):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            rv = cursor.fetchall()
            return (rv[0] if rv else None) if one else rv

    def execute(self, sql, params=()):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            conn.commit()
            return cursor.lastrowid

    def get_setting(self, key, default=None):
        res = self.query("SELECT value FROM settings WHERE key = ?", (key,), one=True)
        return res["value"] if res else default

    def set_setting(self, key, value):
        self.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))

    # User Management Helpers
    def get_user_by_username(self, username):
        return self.query("SELECT * FROM users WHERE username = ?", (username,), one=True)

    def get_user_by_id(self, user_id):
        return self.query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)

    def add_user(self, username, password, role):
        pw_hash = generate_password_hash(password)
        try:
            self.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (username, pw_hash, role))
            return True
        except sqlite3.IntegrityError:
            return False

    def update_user_password(self, username, new_password):
        pw_hash = generate_password_hash(new_password)
        self.execute("UPDATE users SET password_hash = ? WHERE username = ?", (pw_hash, username))

    def delete_user(self, user_id):
        self.execute("DELETE FROM users WHERE id = ?", (user_id,))
