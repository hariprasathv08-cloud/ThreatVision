import os
import csv
import logging
from datetime import datetime
from database import Database

# ReportLab imports
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.colors import HexColor

# Configure logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("CyberSIEM.ReportGenerator")

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "reports")
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR)

def get_report_statistics(start_date, end_date):
    """Gathers all statistics from the database for the given date range."""
    db = Database()
    
    # 1. Total events
    total_events = db.query(
        "SELECT COUNT(*) as count FROM events WHERE timestamp BETWEEN ? AND ?",
        (start_date, end_date), one=True
    )["count"]

    # 2. Alert stats
    alerts = db.query(
        "SELECT severity, COUNT(*) as count FROM alerts WHERE timestamp BETWEEN ? AND ? GROUP BY severity",
        (start_date, end_date)
    )
    alert_stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for row in alerts:
        sev = row["severity"]
        if sev in alert_stats:
            alert_stats[sev] = row["count"]

    # 3. Failed logins
    failed_logins = db.query(
        "SELECT COUNT(*) as count FROM events WHERE event_id = 4625 AND timestamp BETWEEN ? AND ?",
        (start_date, end_date), one=True
    )["count"]

    # 4. USB events
    usb_events = db.query(
        "SELECT COUNT(*) as count FROM usb_events WHERE timestamp BETWEEN ? AND ?",
        (start_date, end_date), one=True
    )["count"]

    # 5. File events
    file_events = db.query(
        "SELECT COUNT(*) as count FROM file_events WHERE timestamp BETWEEN ? AND ?",
        (start_date, end_date), one=True
    )["count"]

    # 6. Firewall events
    firewall_events = db.query(
        "SELECT COUNT(*) as count FROM firewall_events WHERE timestamp BETWEEN ? AND ?",
        (start_date, end_date), one=True
    )["count"]

    # Recent critical/high alerts
    recent_alerts = db.query(
        "SELECT timestamp, severity, source, details, mitre_technique FROM alerts WHERE timestamp BETWEEN ? AND ? AND severity IN ('Critical', 'High') ORDER BY timestamp DESC LIMIT 10",
        (start_date, end_date)
    )

    return {
        "total_events": total_events,
        "alert_stats": alert_stats,
        "failed_logins": failed_logins,
        "usb_events": usb_events,
        "file_events": file_events,
        "firewall_events": firewall_events,
        "recent_alerts": recent_alerts
    }

def generate_pdf(report_type, start_date, end_date):
    """Generates a polished PDF security report using reportlab."""
    filename = f"{report_type.lower()}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)
    
    stats = get_report_statistics(start_date, end_date)
    
    doc = SimpleDocTemplate(filepath, pagesize=letter,
                            rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    story = []
    
    # Styles
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=HexColor('#0b132b'),
        spaceAfter=15,
        alignment=0
    )
    
    subtitle_style = ParagraphStyle(
        'ReportSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        textColor=colors.gray,
        spaceAfter=25
    )
    
    heading2_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=15,
        textColor=HexColor('#1c3144'),
        spaceBefore=15,
        spaceAfter=10,
        borderPadding=2
    )

    body_style = ParagraphStyle(
        'BodyText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10.5,
        leading=14,
        spaceAfter=8
    )

    bold_body_style = ParagraphStyle(
        'BoldBodyText',
        parent=body_style,
        fontName='Helvetica-Bold'
    )

    # 1. Header block
    story.append(Paragraph("CyberSIEM Security Report", title_style))
    story.append(Paragraph(f"Type: {report_type} Security Summary | Scope: {start_date} to {end_date} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    
    # 2. Executive Summary
    story.append(Paragraph("1. Executive Summary", heading2_style))
    exec_summary_text = (
        f"During the reporting period from {start_date} to {end_date}, CyberSIEM monitored host security logs, network sockets, "
        f"firewall profiles, USB storage endpoints, and system resource metrics. A total of <b>{stats['total_events']}</b> Windows security/system logs "
        f"were processed. The event correlation engine registered <b>{sum(stats['alert_stats'].values())}</b> total alerts, including "
        f"<b>{stats['alert_stats']['Critical']}</b> CRITICAL severity alerts and <b>{stats['alert_stats']['High']}</b> HIGH severity alerts requiring immediate response."
    )
    story.append(Paragraph(exec_summary_text, body_style))
    story.append(Spacer(1, 10))
    
    # 3. Alert Metrics Table
    story.append(Paragraph("2. Threat Statistics & Alerts", heading2_style))
    
    data = [
        [Paragraph("<b>Severity</b>", bold_body_style), Paragraph("<b>Triggered Count</b>", bold_body_style), Paragraph("<b>Status Description</b>", bold_body_style)],
        [Paragraph("Critical", body_style), str(stats['alert_stats']['Critical']), "Immediate actions sent via Email"],
        [Paragraph("High", body_style), str(stats['alert_stats']['High']), "Urgent operational investigations"],
        [Paragraph("Medium", body_style), str(stats['alert_stats']['Medium']), "Standard monitoring metrics"],
        [Paragraph("Low", body_style), str(stats['alert_stats']['Low']), "Informational logs / audit marks"]
    ]
    
    t = Table(data, colWidths=[120, 100, 310])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), HexColor('#111a2e')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('BACKGROUND', (0,1), (-1,1), HexColor('#ffe6e6')), # light red for critical
        ('BACKGROUND', (0,2), (-1,2), HexColor('#fff2e6')), # light orange for high
        ('BACKGROUND', (0,3), (-1,-1), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
        ('PADDING', (0,0), (-1,-1), 6)
    ]))
    story.append(t)
    story.append(Spacer(1, 15))

    # 4. Detailed Component Summaries
    story.append(Paragraph("3. Operational Monitoring Summary", heading2_style))
    
    details_data = [
        [Paragraph("<b>Monitoring Component</b>", bold_body_style), Paragraph("<b>Metric Summary</b>", bold_body_style)],
        ["Failed Login Attempts (Event ID 4625)", f"{stats['failed_logins']} attempts detected"],
        ["File Integrity Modifications (FIM)", f"{stats['file_events']} file modifications logged"],
        ["USB Storage Device Events", f"{stats['usb_events']} insertions/removals"],
        ["Windows Defender Firewall Events", f"{stats['firewall_events']} policy state shifts"]
    ]
    t_details = Table(details_data, colWidths=[240, 290])
    t_details.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), HexColor('#0b132b')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
        ('PADDING', (0,0), (-1,-1), 6)
    ]))
    story.append(t_details)
    story.append(Spacer(1, 15))

    # 5. Recent Alerts
    story.append(Paragraph("4. Recent High/Critical Threats Details", heading2_style))
    if stats["recent_alerts"]:
        alert_data = [
            [
                Paragraph("<b>Time</b>", bold_body_style),
                Paragraph("<b>Severity</b>", bold_body_style),
                Paragraph("<b>MITRE ATT&CK</b>", bold_body_style),
                Paragraph("<b>Details</b>", bold_body_style)
            ]
        ]
        for alert in stats["recent_alerts"]:
            alert_data.append([
                alert["timestamp"],
                alert["severity"],
                Paragraph(alert["mitre_technique"] or "N/A", body_style),
                Paragraph(alert["details"], body_style)
            ])
            
        t_alerts = Table(alert_data, colWidths=[110, 60, 110, 250])
        t_alerts.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), HexColor('#1c3144')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('PADDING', (0,0), (-1,-1), 5)
        ]))
        story.append(t_alerts)
    else:
        story.append(Paragraph("No Critical or High severity alerts were recorded in this period.", body_style))
    story.append(Spacer(1, 15))

    # 6. Security Recommendations
    story.append(Paragraph("5. Hardening & Security Recommendations", heading2_style))
    
    recs = [
        "<b>Failed Logins:</b> Monitor failed login sources. If failures target a specific user, enforce password resets or MFA policies.",
        "<b>USB Hardware Restrictions:</b> Restrict USB mass storage devices via Windows Group Policy Objects (GPO) to prevent data exfiltration.",
        "<b>File Integrity:</b> Regularly audit modifications in critical application directories. Investigate any unapproved execution files.",
        "<b>Firewall Profile Stability:</b> Ensure public/private host firewall states are maintained as 'ON'. Auto-remediate disabling actions."
    ]
    for r in recs:
        story.append(Paragraph(f"• {r}", body_style))
        
    doc.build(story)
    
    # Save database record for this report
    db = Database()
    db.execute(
        "INSERT INTO reports (report_type, filepath, format) VALUES (?, ?, ?)",
        (report_type, filepath, "PDF")
    )
    
    logger.info(f"PDF Report generated successfully: {filepath}")
    return filepath, filename

def generate_csv(report_type, start_date, end_date):
    """Generates a detailed CSV security report containing all logs."""
    filename = f"{report_type.lower()}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = os.path.join(REPORTS_DIR, filename)
    
    db = Database()
    alerts = db.query(
        "SELECT id, timestamp, severity, source, details, status, mitre_technique FROM alerts WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC",
        (start_date, end_date)
    )
    
    try:
        with open(filepath, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Write Header
            writer.writerow(["Report Name", f"{report_type} Security Summary"])
            writer.writerow(["Timeframe", f"{start_date} to {end_date}"])
            writer.writerow(["Generated At", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            writer.writerow([])
            
            # Write Alerts
            writer.writerow(["ALERT LOGS"])
            writer.writerow(["Alert ID", "Timestamp", "Severity", "Source Component", "MITRE ATT&CK Technique", "Details / Rule Match", "Status"])
            for alert in alerts:
                writer.writerow([
                    alert["id"],
                    alert["timestamp"],
                    alert["severity"],
                    alert["source"],
                    alert["mitre_technique"] or "N/A",
                    alert["details"],
                    alert["status"]
                ])
                
            writer.writerow([])
            # Write USB Events
            usb = db.query("SELECT device_name, vendor, event_type, timestamp FROM usb_events WHERE timestamp BETWEEN ? AND ?", (start_date, end_date))
            writer.writerow(["USB DISK LOGS"])
            writer.writerow(["Device Name", "Vendor", "Action Type", "Timestamp"])
            for row in usb:
                writer.writerow([row["device_name"], row["vendor"], row["event_type"], row["timestamp"]])
                
            writer.writerow([])
            # Write FIM events
            fim = db.query("SELECT filepath, event_type, details, timestamp FROM file_events WHERE timestamp BETWEEN ? AND ?", (start_date, end_date))
            writer.writerow(["FILE INTEGRITY MONITORING LOGS"])
            writer.writerow(["File Path", "Modification Type", "Details", "Timestamp"])
            for row in fim:
                writer.writerow([row["filepath"], row["event_type"], row["details"], row["timestamp"]])

            writer.writerow([])
            # Write Firewall Events
            firewall = db.query("SELECT action, details, timestamp FROM firewall_events WHERE timestamp BETWEEN ? AND ?", (start_date, end_date))
            writer.writerow(["FIREWALL CHANGES LOGS"])
            writer.writerow(["Action Taken", "Details", "Timestamp"])
            for row in firewall:
                writer.writerow([row["action"], row["details"], row["timestamp"]])

        # Save report database log
        db.execute(
            "INSERT INTO reports (report_type, filepath, format) VALUES (?, ?, ?)",
            (report_type, filepath, "CSV")
        )
        logger.info(f"CSV Report generated successfully: {filepath}")
        return filepath, filename
    except Exception as e:
        logger.error(f"Failed to generate CSV report: {e}")
        raise e
