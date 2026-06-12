import threading
import time
import psutil
import os
import logging
from datetime import datetime, timedelta
from database import Database
from modules.correlation_engine import trigger_alert

# Configure logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("CyberSIEM.ProcessMonitor")

class ProcessMonitorThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.running = True
        self.db = Database()
        self.suspicious_names = [
            "mimikatz", "psexec", "nmap", "nc.exe", "netcat", "wireshark",
            "pwdump", "gsecdump", "hydra", "john.exe", "hashcat", "responder"
        ]
        self.last_running_processes = {}  # Tracks PID -> Name to detect process terminations

    def get_system_health(self):
        """Gather current overall system stats."""
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            
            # Disk usage (C:)
            try:
                disk = psutil.disk_usage("C:").percent
            except Exception:
                disk = psutil.disk_usage("/").percent
                
            # Number of connections
            try:
                conns = len(psutil.net_connections(kind="inet"))
            except Exception:
                conns = 0
                
            return cpu, mem, disk, conns
        except Exception as e:
            logger.error(f"Error gathering system health: {e}")
            return 0.0, 0.0, 0.0, 0

    def check_processes(self):
        """Poll and inspect running processes."""
        processes_list = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'exe', 'cmdline']):
            try:
                info = proc.info
                pid = info['pid']
                name = info['name'] or ""
                username = info['username'] or "N/A"
                cpu_percent = info['cpu_percent'] or 0.0
                mem_percent = info['memory_percent'] or 0.0
                exe_path = info['exe'] or ""
                cmdline = info['cmdline'] or []
                cmdline_str = " ".join(cmdline)
                
                is_suspicious = False
                reasons = []

                # Rule 1: Suspicious filename signature
                name_lower = name.lower()
                for bad_name in self.suspicious_names:
                    if bad_name in name_lower or bad_name in cmdline_str.lower():
                        is_suspicious = True
                        reasons.append(f"Matched threat keyword '{bad_name}'")

                # Rule 2: Running from Temp directory
                if exe_path:
                    exe_path_lower = exe_path.lower()
                    if "\\temp\\" in exe_path_lower or "\\appdata\\local\\temp" in exe_path_lower:
                        is_suspicious = True
                        reasons.append("Running from temporary directory (Temp)")

                # Rule 3: PowerShell execution monitoring
                if "powershell" in name_lower or "pwsh" in name_lower or "powershell" in cmdline_str.lower():
                    cmd_lower = cmdline_str.lower()
                    suspicious_flags = ["-enc", "-encodedcommand", "-nop", "-noni", "-w hidden", "-windowstyle hidden", "-bypass", "iex", "downloadstring", "downloadfile", "invoke-webrequest"]
                    matched_flags = [flag for flag in suspicious_flags if flag in cmd_lower]
                    
                    if matched_flags:
                        is_suspicious = True
                        reasons.append(f"Suspicious PowerShell execution flags: {', '.join(matched_flags)}")
                    else:
                        # Alert for standard PowerShell execution audits (Medium severity)
                        # To prevent continuous duplicate alerting, we check if we already raised it recently
                        recent_alert = self.db.query(
                            "SELECT COUNT(*) as count FROM alerts WHERE source = 'Process Monitor' AND details LIKE ? AND timestamp >= ?",
                            (f"%PowerShell Execution Monitored%PID: {pid}%", (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")),
                            one=True
                        )
                        if recent_alert and recent_alert["count"] == 0:
                            trigger_alert(
                                severity="Medium",
                                source="Process Monitor",
                                details=f"PowerShell Execution Monitored: '{name}' (PID: {pid}) was launched by {username}. Cmdline: '{cmdline_str}'",
                                recommended_action="Review script execution arguments to ensure compliance with organization security policy.",
                                mitre_technique="T1059.001 - Command and Scripting Interpreter: PowerShell"
                            )

                # Rule 4: High resource usage detection per process (ignoring Idle/System processes)
                if cpu_percent > 70.0 and pid not in [0, 4] and "idle" not in name_lower:
                    trigger_alert(
                        severity="Medium",
                        source="Process Monitor",
                        details=f"High CPU Usage: Process '{name}' (PID: {pid}) is using {cpu_percent}% CPU.",
                        recommended_action=f"Inspect if the process is authorized. If it's a runaway thread, terminate the process (PID: {pid}).",
                        mitre_technique="T1496 - Resource Hijacking"
                    )
                if mem_percent > 20.0 and pid not in [0, 4] and "idle" not in name_lower: # 20% of total system memory is a lot for one process
                    trigger_alert(
                        severity="Medium",
                        source="Process Monitor",
                        details=f"High Memory Usage: Process '{name}' (PID: {pid}) is consuming {mem_percent:.2f}% of RAM.",
                        recommended_action=f"Inspect memory allocations. Terminate if it is leaking resources.",
                        mitre_technique="T1496 - Resource Hijacking"
                    )

                if is_suspicious:
                    details_str = ", ".join(reasons)
                    trigger_alert(
                        severity="High",
                        source="Process Monitor",
                        details=f"Suspicious Process Execution: '{name}' (PID: {pid}, Path: '{exe_path}'). Reason: {details_str}.",
                        recommended_action=f"Immediately analyze process lineage, inspect cmdline arguments: '{cmdline_str}', and terminate the process.",
                        mitre_technique="T1204.002 - User Execution: Malicious File" if "mimikatz" not in name_lower else "T1003 - OS Credential Dumping"
                    )

                processes_list.append({
                    "pid": pid,
                    "name": name,
                    "username": username,
                    "cpu": cpu_percent,
                    "memory": mem_percent,
                    "path": exe_path,
                    "cmdline": cmdline_str,
                    "suspicious": 1 if is_suspicious else 0
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
        return processes_list

    def run(self):
        logger.info("Process Monitor thread active.")
        
        while self.running:
            try:
                # 1. Inspect running processes
                current_procs = self.check_processes()
                
                # Check for process terminations
                current_map = {p["pid"]: p["name"] for p in current_procs}
                if self.last_running_processes:
                    for pid, name in self.last_running_processes.items():
                        if pid not in current_map:
                            name_lower = name.lower()
                            # Check if the terminated process is highly critical to system safety or our platform
                            is_critical = any(c in name_lower for c in [
                                "msmpeng", "lsass", "svchost", "services", "explorer",
                                "taskmgr", "firewallcontrolpanel", "python"
                            ])
                            
                            severity = "High" if is_critical else "Low"
                            mitre = "T1562.001 - Impair Defenses: Disable or Modify Tools" if is_critical else "T1489 - Service Stop"
                            
                            trigger_alert(
                                severity=severity,
                                source="Process Monitor",
                                details=f"Process Terminated: '{name}' (PID: {pid}) exited or was killed.",
                                recommended_action="Verify if the process termination was administrative. If it is a core system or security component, review crash dumps.",
                                mitre_technique=mitre
                            )
                self.last_running_processes = current_map
                
                # 2. Gather system health and log to database
                cpu, mem, disk, conns = self.get_system_health()
                
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.db.execute(
                    "INSERT INTO system_health (cpu_usage, memory_usage, disk_usage, network_connections, timestamp) VALUES (?, ?, ?, ?, ?)",
                    (cpu, mem, disk, conns, timestamp)
                )
                
                # Prune old health records (keep last 200 to save space and query time)
                self.db.execute(
                    "DELETE FROM system_health WHERE id NOT IN (SELECT id FROM system_health ORDER BY timestamp DESC LIMIT 200)"
                )
                
                # Alert on overall high resource consumption
                if cpu > 90.0:
                    trigger_alert(
                        severity="High",
                        source="System Health",
                        details=f"Critical overall system CPU spike: {cpu}%",
                        recommended_action="Inspect running processes for high utilization, look for CPU hogs, or scale hardware.",
                        mitre_technique="T1496 - Resource Hijacking"
                    )
                if mem > 90.0:
                    trigger_alert(
                        severity="High",
                        source="System Health",
                        details=f"Critical overall system RAM consumption: {mem}%",
                        recommended_action="Check for memory leaks or shut down unnecessary services.",
                        mitre_technique="T1496 - Resource Hijacking"
                    )

                time.sleep(5)
            except Exception as e:
                logger.error(f"Error in Process Monitor loop: {e}")
                time.sleep(5)

    def stop(self):
        self.running = False
