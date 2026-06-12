import threading
import time
import subprocess
import os
import logging
import sys
from datetime import datetime
from database import Database
from modules.correlation_engine import trigger_alert

# Configure logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("CyberSIEM.FirewallMonitor")

class FirewallMonitorThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.running = True
        self.db = Database()
        self.last_states = {"Domain": "ON", "Private": "ON", "Public": "ON"}
        self.last_rule_count = 0
        self.is_windows = sys.platform.startswith("win")

    def get_firewall_profiles(self):
        """Queries netsh for firewall profile states."""
        states = {"Domain": "ON", "Private": "ON", "Public": "ON"}
        if not self.is_windows:
            return states
            
        try:
            res = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles"],
                capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            if res.returncode == 0:
                profile = None
                for line in res.stdout.splitlines():
                    line_stripped = line.strip()
                    if "Profile Settings:" in line_stripped:
                        profile = line_stripped.split("Profile")[0].strip()
                    elif "State" in line_stripped and profile in states:
                        parts = line_stripped.split()
                        if len(parts) >= 2:
                            state = parts[1].strip().upper()
                            states[profile] = "ON" if "ON" in state else "OFF"
        except Exception as e:
            logger.debug(f"Error querying firewall state via netsh: {e}")
            
        return states

    def get_firewall_rule_count(self):
        """Queries netsh for the count of firewall rules."""
        if not self.is_windows:
            return 0
            
        try:
            # Note: show rule name=all displays all rules. We just count the lines in the output as a heuristic
            res = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            if res.returncode == 0:
                # Count lines starting with "Rule Name:" to get a direct rule count
                count = sum(1 for line in res.stdout.splitlines() if line.strip().startswith("Rule Name:"))
                return count
        except Exception as e:
            logger.debug(f"Error counting firewall rules: {e}")
            
        return 0

    def run(self):
        logger.info("Firewall monitoring thread active.")
        
        # Initial state setup
        self.last_states = self.get_firewall_profiles()
        self.last_rule_count = self.get_firewall_rule_count()
        
        # Log initial states to database if empty
        existing = self.db.query("SELECT COUNT(*) as count FROM firewall_events", one=True)
        if existing and existing["count"] == 0:
            for p, state in self.last_states.items():
                self.db.execute(
                    "INSERT INTO firewall_events (action, details, timestamp) VALUES (?, ?, ?)",
                    ("Status Check", f"Firewall profile {p} is {state}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                )

        sim_loop_counter = 0
        while self.running:
            try:
                if self.is_windows:
                    # Query current states
                    current_states = self.get_firewall_profiles()
                    current_rule_count = self.get_firewall_rule_count()
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    # Check for profile state changes (ON -> OFF)
                    for profile, state in current_states.items():
                        last_state = self.last_states.get(profile)
                        if last_state != state:
                            # Log the change
                            action = "Profile Disable" if state == "OFF" else "Profile Enable"
                            details = f"Firewall Profile '{profile}' changed from {last_state} to {state}."
                            
                            self.db.execute(
                                "INSERT INTO firewall_events (action, details, timestamp) VALUES (?, ?, ?)",
                                (action, details, timestamp)
                            )
                            logger.info(f"Firewall state change: {details}")

                            # Trigger alerts
                            severity = "Critical" if state == "OFF" else "Low"
                            trigger_alert(
                                severity=severity,
                                source="Firewall Monitor",
                                details=f"Firewall profile '{profile}' is now {state.upper()}.",
                                recommended_action="Enable the firewall immediately via administrative commands: 'netsh advfirewall set allprofiles state on'.",
                                mitre_technique="T1562.004 - Impair Defenses: Disable or Modify System Firewall"
                            )

                    # Check for rule additions/deletions
                    if self.last_rule_count > 0 and current_rule_count > 0 and self.last_rule_count != current_rule_count:
                        diff = current_rule_count - self.last_rule_count
                        action = "Rules Added" if diff > 0 else "Rules Removed"
                        details = f"Firewall rules count changed by {diff} (Previous: {self.last_rule_count}, Current: {current_rule_count})."
                        
                        self.db.execute(
                            "INSERT INTO firewall_events (action, details, timestamp) VALUES (?, ?, ?)",
                            (action, details, timestamp)
                        )
                        logger.info(f"Firewall rules change: {details}")
                        
                        trigger_alert(
                            severity="Medium",
                            source="Firewall Monitor",
                            details=f"Windows Firewall rules modified. {action}: {abs(diff)} rules.",
                            recommended_action="Review recently modified Windows Defender Firewall inbound/outbound rules to identify potential rule injections.",
                            mitre_technique="T1562.004 - Impair Defenses: Disable or Modify System Firewall"
                        )

                    self.last_states = current_states
                    self.last_rule_count = current_rule_count
                else:
                    # Simulated changes on non-Windows/sandbox platforms
                    sim_loop_counter += 1
                    # 2% chance of a mock firewall change
                    if sim_loop_counter % 30 == 0:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        profile = "Public"
                        state = "OFF"
                        
                        self.db.execute(
                            "INSERT INTO firewall_events (action, details, timestamp) VALUES (?, ?, ?)",
                            ("Profile Disable", f"[SIMULATED] Firewall Profile '{profile}' was disabled.", timestamp)
                        )
                        
                        trigger_alert(
                            severity="Critical",
                            source="Firewall Monitor",
                            details=f"[SIMULATED] Firewall profile '{profile}' disabled.",
                            recommended_action="Reinstate Windows Firewall profile configuration.",
                            mitre_technique="T1562.004 - Impair Defenses: Disable or Modify System Firewall"
                        )

                time.sleep(4)
            except Exception as e:
                logger.error(f"Error in Firewall Monitor loop: {e}")
                time.sleep(5)

    def stop(self):
        self.running = False
