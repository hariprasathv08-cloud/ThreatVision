import threading
import time
import logging
import random
from datetime import datetime, timedelta
from database import Database
from modules.correlation_engine import analyze_event

# Configure logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("CyberSIEM.EventMonitor")

# Try to import pywin32 event log utilities
PYWIN32_AVAILABLE = False
try:
    import win32evtlog
    import win32evtlogutil
    PYWIN32_AVAILABLE = True
except ImportError:
    logger.warning("pywin32 (win32evtlog) is not available. Using simulated events fallback.")

class EventMonitorThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.running = True
        self.db = Database()
        # Monitor standard log channels and classic PowerShell execution logs
        self.last_records = {"Security": 0, "System": 0, "Application": 0, "Windows PowerShell": 0}
        self.target_ids = [4625, 4624, 4720, 4726, 4723, 4740, 4672, 1102, 104, 7036, 4104, 4103]

    def init_log_heads(self):
        if not PYWIN32_AVAILABLE:
            return
            
        for log_name in self.last_records.keys():
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)
                num_records = win32evtlog.GetNumberOfEventLogRecords(hand)
                oldest = win32evtlog.GetOldestEventLogRecord(hand)
                self.last_records[log_name] = oldest + num_records - 1
                win32evtlog.CloseEventLog(hand)
                logger.info(f"Initialized {log_name} log head to record {self.last_records[log_name]}")
            except Exception as e:
                logger.warning(f"Unable to initialize {log_name} log head: {e}. Might lack Administrator privileges or log channel is not present.")

    def poll_log(self, log_name):
        if not PYWIN32_AVAILABLE:
            return
            
        last_rec = self.last_records[log_name]
        try:
            hand = win32evtlog.OpenEventLog(None, log_name)
        except Exception as e:
            logger.debug(f"Could not open {log_name} log: {e}")
            return
            
        try:
            num_records = win32evtlog.GetNumberOfEventLogRecords(hand)
            if num_records == 0:
                return
                
            oldest = win32evtlog.GetOldestEventLogRecord(hand)
            current_newest = oldest + num_records - 1
            
            if last_rec == 0:
                self.last_records[log_name] = current_newest
                return
                
            # Log cleared checks
            if current_newest < last_rec:
                logger.warning(f"Windows Event Log '{log_name}' was cleared or reset. Resetting parsing pointers.")
                self.last_records[log_name] = current_newest
                
                # Insert log cleared alert
                from modules.correlation_engine import trigger_alert
                trigger_alert(
                    severity="Critical",
                    source="Event Log Monitor",
                    details=f"Windows Event Log channel '{log_name}' was cleared. Event ID reset detected.",
                    recommended_action="Investigate console access logs, review administrators actions, and check for event backups.",
                    mitre_technique="T1562.002 - Impair Defenses: Disable or Modify Windows Event Logging"
                )
                return
                
            if current_newest <= last_rec:
                return  # No new events
                
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
            offset = last_rec + 1
            
            # Read first block using SEEK_READ
            events = win32evtlog.ReadEventLog(hand, flags, offset)
            # Subsequent reads in this cycle use SEQUENTIAL_READ to prevent infinite looping at the same seek index
            seq_flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            while events:
                for event in events:
                    rec_num = event.RecordNumber
                    if rec_num <= last_rec:
                        continue
                    self.last_records[log_name] = rec_num
                    last_rec = rec_num
                    
                    event_id = event.EventID & 0xFFFF
                    
                    # Determine Event Level
                    level_str = "Information"
                    if event.EventType == win32evtlog.EVENTLOG_ERROR_TYPE:
                        level_str = "Error"
                    elif event.EventType == win32evtlog.EVENTLOG_WARNING_TYPE:
                        level_str = "Warning"
                    elif event.EventType == win32evtlog.EVENTLOG_INFORMATION_TYPE:
                        level_str = "Information"
                    elif event.EventType == win32evtlog.EVENTLOG_AUDIT_SUCCESS:
                        level_str = "Audit Success"
                    elif event.EventType == win32evtlog.EVENTLOG_AUDIT_FAILURE:
                        level_str = "Audit Failure"
                        
                    source = event.SourceName
                    timestamp_str = event.TimeGenerated.Format()
                    
                    try:
                        dt = datetime.strptime(timestamp_str, "%a %b %d %H:%M:%S %Y")
                    except Exception:
                        dt = datetime.now()
                        
                    # Safely retrieve full formatted message string
                    message = ""
                    try:
                        message = win32evtlogutil.SafeFormatMessage(event, log_name)
                    except Exception:
                        pass
                        
                    if not message:
                        msg_inserts = event.StringInserts
                        message = " | ".join([str(s) for s in msg_inserts]) if msg_inserts else f"Windows log event from {source} (ID {event_id})"
                    
                    # We store the logs if they are target Event IDs or are warnings/errors
                    if event_id in self.target_ids or level_str in ["Error", "Warning", "Audit Failure"]:
                        mitre_tech = None
                        if event_id == 4625:
                            mitre_tech = "T1110 - Brute Force"
                        elif event_id == 4624:
                            mitre_tech = "T1078 - Valid Accounts"
                        elif event_id == 4720:
                            mitre_tech = "T1136.001 - Create Account: Local Account"
                        elif event_id == 4726:
                            mitre_tech = "T1098.001 - Account Manipulation"
                        elif event_id == 4672:
                            mitre_tech = "T1134 - Access Token Manipulation"
                        elif event_id in [1102, 104]:
                            mitre_tech = "T1562.002 - Impair Defenses: Disable or Modify Windows Event Logging"
                        elif event_id == 7036:
                            mitre_tech = "T1489 - Service Stop"
                        elif event_id in [4103, 4104]:
                            mitre_tech = "T1059.001 - Command and Scripting Interpreter: PowerShell"

                        self.db.execute(
                            "INSERT INTO events (event_id, log_name, source, message, level, timestamp, mitre_technique) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (event_id, log_name, source, message[:1000], level_str, dt.strftime("%Y-%m-%d %H:%M:%S"), mitre_tech)
                        )
                        
                        event_dict = {
                            "event_id": event_id,
                            "log_name": log_name,
                            "source": source,
                            "message": message,
                            "level": level_str,
                            "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S"),
                            "mitre_technique": mitre_tech
                        }
                        analyze_event(event_dict)
                        
                events = win32evtlog.ReadEventLog(hand, seq_flags, 0)
        except Exception as e:
            logger.error(f"Error reading event log {log_name}: {e}")
        finally:
            try:
                win32evtlog.CloseEventLog(hand)
            except Exception:
                pass

    def generate_simulated_event(self):
        """Generates random simulated Windows Security/System events for dashboard display when not run as Admin."""
        sim_events = [
            # Successful Logon
            {
                "event_id": 4624,
                "log_name": "Security",
                "source": "Microsoft-Windows-Security-Auditing",
                "message": "An account was successfully logged on. Subject: Security ID: SYSTEM, Account Name: SYSTEM. New Logon: Security ID: S-1-5-21, Account Name: admin, Logon Type: 2 (Interactive). Source Address: 127.0.0.1",
                "level": "Audit Success"
            },
            # Failed Logon
            {
                "event_id": 4625,
                "log_name": "Security",
                "source": "Microsoft-Windows-Security-Auditing",
                "message": f"An account failed to log on. Subject: Security ID: S-1-5-18, Account Name: WORKGROUP. Logon Type: 3. Account For Which Logon Failed: Account Name: administrator, Domain: DESKTOP. Failure Information: Failure Reason: Unknown user name or bad password. Source Network Address: {random.choice(['192.168.1.105', '10.0.0.12', '192.168.1.200'])}",
                "level": "Audit Failure"
            },
            # Special Privileges Assigned
            {
                "event_id": 4672,
                "log_name": "Security",
                "source": "Microsoft-Windows-Security-Auditing",
                "message": "Special privileges assigned to new logon. Subject: Security ID: S-1-5-21, Account Name: admin. Privileges: SeSecurityPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege",
                "level": "Audit Success"
            },
            # Account Created
            {
                "event_id": 4720,
                "log_name": "Security",
                "source": "Microsoft-Windows-Security-Auditing",
                "message": "A user account was created. Subject: Security ID: SYSTEM, Account Name: admin. New Account: Security ID: S-1-5-21-39, Account Name: temp_support, User Principal Name: -",
                "level": "Audit Success"
            },
            # User Deleted
            {
                "event_id": 4726,
                "log_name": "Security",
                "source": "Microsoft-Windows-Security-Auditing",
                "message": "A user account was deleted. Subject: Security ID: SYSTEM, Account Name: admin. Target Account: Security ID: S-1-5-21-39, Account Name: temp_support",
                "level": "Audit Success"
            },
            # Service Stopped
            {
                "event_id": 7036,
                "log_name": "System",
                "source": "Service Control Manager",
                "message": "The Windows Firewall service entered the stopped state.",
                "level": "Warning"
            },
            # General System Log warning
            {
                "event_id": 10016,
                "log_name": "System",
                "source": "DistributedCOM",
                "message": "The permission-default settings do not grant Local Activation permission for the COM Server application with CLSID.",
                "level": "Warning"
            },
            # General App Log Error
            {
                "event_id": 1000,
                "log_name": "Application",
                "source": "Application Error",
                "message": "Faulting application name: explorer.exe, version: 10.0.19041.123, time stamp: 0x5f22e831",
                "level": "Error"
            }
        ]
        
        # Select an event
        evt = random.choice(sim_events)
        dt = datetime.now()
        
        mitre_tech = None
        id_map = {
            4625: "T1110 - Brute Force",
            4624: "T1078 - Valid Accounts",
            4672: "T1134 - Access Token Manipulation",
            4720: "T1136.001 - Create Account: Local Account",
            4726: "T1098.001 - Account Manipulation",
            7036: "T1489 - Service Stop"
        }
        mitre_tech = id_map.get(evt["event_id"], None)
        
        # Write to DB
        self.db.execute(
            "INSERT INTO events (event_id, log_name, source, message, level, timestamp, mitre_technique) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (evt["event_id"], evt["log_name"], evt["source"], evt["message"], evt["level"], dt.strftime("%Y-%m-%d %H:%M:%S"), mitre_tech)
        )
        
        # Analyze in correlation
        evt["timestamp"] = dt.strftime("%Y-%m-%d %H:%M:%S")
        evt["mitre_technique"] = mitre_tech
        analyze_event(evt)
        
        logger.info(f"Simulated Event Log generated: ID {evt['event_id']} ({evt['log_name']})")

    def run(self):
        self.init_log_heads()
        
        # Check if we can read the Security log. If not, we run in simulated mode
        security_readable = True
        if PYWIN32_AVAILABLE:
            try:
                hand = win32evtlog.OpenEventLog(None, "Security")
                win32evtlog.CloseEventLog(hand)
            except Exception:
                security_readable = False
                logger.warning("Security Log is NOT readable (requires Administrator privileges). CyberSIEM will run with fallbacks and simulated events.")
        else:
            security_readable = False
            
        logger.info("Windows Event Log polling active.")
        
        loop_counter = 0
        while self.running:
            try:
                if PYWIN32_AVAILABLE:
                    # Poll real logs
                    self.poll_log("System")
                    self.poll_log("Application")
                    self.poll_log("Windows PowerShell")
                    if security_readable:
                        self.poll_log("Security")
                
                # If Security Log is not readable, or pywin32 is not installed,
                # let's periodically inject simulated events to demonstrate dashboard capability.
                if not security_readable:
                    # Inject simulated event occasionally
                    if loop_counter % 12 == 0:
                        self.generate_simulated_event()
                
                loop_counter += 1
                time.sleep(3)
            except Exception as e:
                logger.error(f"Error in Event Monitor thread loop: {e}")
                time.sleep(5)

    def stop(self):
        self.running = False
