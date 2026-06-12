from datetime import datetime, timedelta
import logging
from database import Database
from modules.notifier import notify_alert

# Configure logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("CyberSIEM.CorrelationEngine")

def trigger_alert(severity, source, details, recommended_action, mitre_technique=None):
    db = Database()
    
    # Centralized alert deduplication/throttling guard to prevent DB bloating and UI lag
    dedup_query = details
    if "is using" in details and "CPU" in details:
        parts = details.split("is using")
        dedup_query = parts[0] + "is using%"
    elif "is consuming" in details and "RAM" in details:
        parts = details.split("is consuming")
        dedup_query = parts[0] + "is consuming%"
    elif "overall system CPU spike" in details:
        dedup_query = "Critical overall system CPU spike:%"
    elif "overall system RAM consumption" in details:
        dedup_query = "Critical overall system RAM consumption:%"
    elif "File Integrity Violation" in details:
        parts = details.split("Details:")
        dedup_query = parts[0] + "Details:%"
    elif "PowerShell Execution Monitored" in details:
        parts = details.split("Cmdline:")
        dedup_query = parts[0] + "%"

    # Check if a similar alert from this source was logged in the last 3 minutes
    three_mins_ago = (datetime.now() - timedelta(minutes=3)).strftime("%Y-%m-%d %H:%M:%S")
    recent = db.query(
        "SELECT COUNT(*) as count FROM alerts WHERE source = ? AND details LIKE ? AND timestamp >= ?",
        (source, dedup_query, three_mins_ago),
        one=True
    )
    if recent and recent["count"] > 0:
        logger.debug(f"Throttled duplicate alert for source={source}: {details[:80]}...")
        return

    # Heuristic fallback resolution for MITRE technique mapping if not explicitly supplied
    if not mitre_technique:
        details_lower = details.lower()
        if "brute force" in details_lower or "failed logins" in details_lower:
            mitre_technique = "T1110 - Brute Force"
        elif "log tampering" in details_lower or "audit log" in details_lower:
            mitre_technique = "T1562.002 - Impair Defenses: Disable or Modify Windows Event Logging"
        elif "privilege escalation" in details_lower:
            mitre_technique = "T1134 - Access Token Manipulation"
        elif "firewall" in details_lower:
            mitre_technique = "T1562.004 - Impair Defenses: Disable or Modify System Firewall"
        elif "usb" in details_lower:
            mitre_technique = "T1200 - Hardware Additions"
        elif "file integrity" in details_lower or "file" in details_lower:
            mitre_technique = "T1222 - File and Directory Permissions Modification"
        elif "port scanning" in details_lower or "port scan" in details_lower:
            mitre_technique = "T1046 - Network Service Discovery"
        elif "powershell" in details_lower:
            mitre_technique = "T1059.001 - Command and Scripting Interpreter: PowerShell"
        elif "rdp" in details_lower or "remote desktop" in details_lower:
            mitre_technique = "T1021.001 - Remote Services: Remote Desktop Protocol"
        elif "service stop" in details_lower or "service start" in details_lower or "service" in details_lower:
            mitre_technique = "T1489 - Service Stop"
        elif "process termination" in details_lower or "kill" in details_lower:
            mitre_technique = "T1562.001 - Impair Defenses: Disable or Modify Tools"
        elif "suspicious process" in details_lower:
            mitre_technique = "T1204.002 - User Execution: Malicious File"
        elif "cpu" in details_lower or "memory" in details_lower or "ram" in details_lower:
            mitre_technique = "T1496 - Resource Hijacking"
            
    # 1. Insert alert into DB
    alert_id = db.execute(
        "INSERT INTO alerts (severity, source, details, recommended_action, status, mitre_technique) VALUES (?, ?, ?, ?, ?, ?)",
        (severity, source, details, recommended_action, "Open", mitre_technique)
    )
    
    # Get the inserted alert
    alert = db.query("SELECT * FROM alerts WHERE id = ?", (alert_id,), one=True)
    if not alert:
        return
        
    alert_dict = dict(alert)
    logger.info(f"[{severity.upper()}] Alert Triggered: {details} (MITRE: {mitre_technique or 'N/A'})")

    # 2. Email notification conditions:
    # - Critical alerts
    # - Brute force attacks
    # - Privilege escalation
    # - Audit logs cleared
    # - Firewall Disabled
    should_email = (
        severity == "Critical" or
        "Brute Force" in details or
        "Privilege Escalation" in details or
        "Audit Log" in details or
        "Firewall Disabled" in details
    )
    
    if should_email:
        # Send mail in a separate non-blocking way, or run directly
        # Since it's a background thread, direct running is fine.
        notify_alert(alert_dict)

def analyze_event(event):
    """
    Analyzes an event dict.
    event has: { 'event_id': int, 'log_name': str, 'source': str, 'message': str, 'level': str, 'timestamp': datetime/str }
    """
    db = Database()
    event_id = event.get("event_id")
    message = event.get("message", "")
    source = event.get("source", "")
    
    # Parse event time
    now = datetime.now()
    
    # Rule 1: Failed Login Attempts (Event ID 4625) & Brute Force Detection
    if event_id == 4625:
        # Check if RDP failed login
        is_rdp = False
        import re
        match = re.search(r"logon type:\s*(\d+)", message.lower())
        if (match and match.group(1) == "10") or " | 10 | " in message or "logon type: 10" in message.lower():
            is_rdp = True
            
        severity = "High" if is_rdp else "Medium"
        details_str = "Failed RDP Logon Attempt" if is_rdp else "Failed User Logon Attempt"
        trigger_alert(
            severity=severity,
            source="Security Log Monitor",
            details=f"{details_str}: Event ID 4625. Message: {message[:300]}",
            recommended_action="Inspect the login username and origin network IP. Check for pattern logs.",
            mitre_technique="T1021.001 - Remote Services: Remote Desktop Protocol" if is_rdp else "T1110 - Brute Force"
        )
        
        # Count failed logins in the last 5 minutes
        five_mins_ago = (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
        res = db.query(
            "SELECT COUNT(*) as count FROM events WHERE event_id = 4625 AND timestamp >= ?",
            (five_mins_ago,),
            one=True
        )
        count = res["count"] if res else 0
        if count >= 5:
            # Check if we already sent a Brute Force alert in the last 5 minutes to prevent spamming
            recent_alert = db.query(
                "SELECT COUNT(*) as count FROM alerts WHERE source = 'Correlation Engine' AND details LIKE '%Brute Force%' AND timestamp >= ?",
                (five_mins_ago,),
                one=True
            )
            if recent_alert and recent_alert["count"] == 0:
                trigger_alert(
                    severity="Critical",
                    source="Correlation Engine",
                    details=f"Brute Force Attack Detected: {count} failed logins in the last 5 minutes.",
                    recommended_action="Temporarily disable the targeted account, block the source IP in firewall, and inspect active connections.",
                    mitre_technique="T1110 - Brute Force"
                )

    # Rule 2: Successful Logins (Event ID 4624) & RDP successful logins
    elif event_id == 4624:
        is_rdp = False
        import re
        match = re.search(r"logon type:\s*(\d+)", message.lower())
        if (match and match.group(1) == "10") or " | 10 | " in message or "logon type: 10" in message.lower():
            is_rdp = True
            
        severity = "High" if is_rdp else "Low"
        details_str = "Successful RDP Logon" if is_rdp else "Successful User Logon"
        trigger_alert(
            severity=severity,
            source="Security Log Monitor",
            details=f"{details_str}: Event ID 4624. Message: {message[:300]}",
            recommended_action="Verify if the user is authorized to logon at this time or from this endpoint.",
            mitre_technique="T1021.001 - Remote Services: Remote Desktop Protocol" if is_rdp else "T1078 - Valid Accounts"
        )

    # Rule 3: Account Creation & Abuse Detection (Event ID 4720)
    elif event_id == 4720:
        trigger_alert(
            severity="High",
            source="Security Log Monitor",
            details=f"User Account Created: Event ID 4720. Message: {message[:300]}",
            recommended_action="Verify if this user account creation was authorized by management or IT support.",
            mitre_technique="T1136.001 - Create Account: Local Account"
        )
        
        # Count user account creations in last 10 minutes
        ten_mins_ago = (now - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
        res = db.query(
            "SELECT COUNT(*) as count FROM events WHERE event_id = 4720 AND timestamp >= ?",
            (ten_mins_ago,),
            one=True
        )
        count = res["count"] if res else 0
        if count >= 3:
            recent_alert = db.query(
                "SELECT COUNT(*) as count FROM alerts WHERE source = 'Correlation Engine' AND details LIKE '%Multiple user account creations%' AND timestamp >= ?",
                (ten_mins_ago,),
                one=True
            )
            if recent_alert and recent_alert["count"] == 0:
                trigger_alert(
                    severity="High",
                    source="Correlation Engine",
                    details=f"Account Abuse Detected: {count} user accounts created in the last 10 minutes.",
                    recommended_action="Verify if these accounts are authorized, review the creator user account, and inspect logs.",
                    mitre_technique="T1136.001 - Create Account: Local Account"
                )

    # Rule 4: User Account Deletion (Event ID 4726)
    elif event_id == 4726:
        trigger_alert(
            severity="High",
            source="Security Log Monitor",
            details=f"User Account Deleted: Event ID 4726. Message: {message[:300]}",
            recommended_action="Ensure this user account deletion was scheduled and is part of offboarding processes.",
            mitre_technique="T1098.001 - Account Manipulation"
        )

    # Rule 5: Privilege Escalation Detection (Event ID 4672 - Special Privileges Assigned)
    elif event_id == 4672:
        trigger_alert(
            severity="High",
            source="Correlation Engine",
            details=f"Privilege Escalation Detected: Special privileges assigned (Event ID 4672) to user logon. Message: {message[:300]}",
            recommended_action="Check if the user should have administrator privileges and audit their activity.",
            mitre_technique="T1134 - Access Token Manipulation"
        )

    # Rule 6: Log Tampering Detection (Event ID 1102 - Security Log Cleared, 104 - System/Other Log Cleared)
    elif event_id in [1102, 104]:
        log_name = "Security" if event_id == 1102 else "System/Other"
        trigger_alert(
            severity="Critical",
            source="Correlation Engine",
            details=f"Log Tampering Detected: Windows {log_name} Audit Log was cleared (Event ID {event_id}).",
            recommended_action="Investigate immediately. Determine which user account cleared the logs, check console connections, and restore backup logs.",
            mitre_technique="T1562.002 - Impair Defenses: Disable or Modify Windows Event Logging"
        )

    # Rule 7: Service State Change (Event ID 7036)
    elif event_id == 7036:
        msg_lower = message.lower()
        is_stopped = "stopped" in msg_lower or "entered the stopped state" in msg_lower
        status_word = "Stopped" if is_stopped else "Started"
        severity = "Medium" if is_stopped else "Low"
        
        trigger_alert(
            severity=severity,
            source="System Log Monitor",
            details=f"Windows Service {status_word} (Event ID 7036): {message[:300]}",
            recommended_action="Verify if this service change is planned maintenance or unauthorized.",
            mitre_technique="T1489 - Service Stop" if is_stopped else "T1569.002 - System Services: Service Execution"
        )

    # Rule 8: Suspicious Activity Detection (Spike in events)
    # Check overall events spike in last 1 minute
    one_min_ago = (now - timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")
    res_spike = db.query("SELECT COUNT(*) as count FROM events WHERE timestamp >= ?", (one_min_ago,), one=True)
    spike_count = res_spike["count"] if res_spike else 0
    if spike_count >= 50:
        recent_alert = db.query(
            "SELECT COUNT(*) as count FROM alerts WHERE source = 'Correlation Engine' AND details LIKE '%Unusual event spike%' AND timestamp >= ?",
            (one_min_ago,),
            one=True
        )
        if recent_alert and recent_alert["count"] == 0:
            trigger_alert(
                severity="Medium",
                source="Correlation Engine",
                details=f"Suspicious Activity Detected: Unusual event spike ({spike_count} events in the last 1 minute).",
                recommended_action="Analyze the event log table to identify the source of the traffic burst.",
                mitre_technique="T1043 - Commonly Used Port"
            )
