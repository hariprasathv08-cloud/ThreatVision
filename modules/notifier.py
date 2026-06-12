import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import os
import logging
from database import Database

# Configure logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("CyberSIEM.Notifier")

def send_email(subject, body_html, attachment_path=None):
    db = Database()
    
    # Retrieve configuration from DB
    sender = db.get_setting("gmail_sender", "")
    app_password = db.get_setting("gmail_app_password", "")
    recipients_raw = db.get_setting("gmail_recipients", "")
    
    if not sender or not app_password or not recipients_raw:
        logger.warning("SMTP configuration is incomplete. Skipping email notification. Please configure SMTP in Settings.")
        return False
        
    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    if not recipients:
        logger.warning("No recipient email addresses found.")
        return False

    try:
        # Create message container
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)
        
        # Attach HTML body
        msg.attach(MIMEText(body_html, "html"))
        
        # Handle attachment if provided
        if attachment_path and os.path.exists(attachment_path):
            filename = os.path.basename(attachment_path)
            with open(attachment_path, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    f"attachment; filename= {filename}",
                )
                msg.attach(part)
        
        # Connect to Gmail SMTP
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10)
        server.login(sender, app_password)
        server.sendmail(sender, recipients, msg.as_string())
        server.quit()
        logger.info(f"Email notification sent successfully to: {recipients}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email notification: {str(e)}")
        return False

def notify_alert(alert):
    """
    Format and send an alert notification email.
    alert is a dict or sqlite3.Row containing details about the alert.
    """
    db = Database()
    if db.get_setting("email_notifications_enabled", "1") == "0":
        logger.info("Email notifications are disabled by user configuration. Skipping alert email.")
        return False

    subject = f"[CyberSIEM Alert] [{alert['severity'].upper()}] - {alert['source']}"
    
    severity_color = {
        "Critical": "#ff4d4d",
        "High": "#ff944d",
        "Medium": "#ffcc00",
        "Low": "#33cc33"
    }.get(alert["severity"], "#999999")

    body_html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; color: #333; }}
            .container {{ width: 100%; max-width: 600px; margin: 0 auto; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }}
            .header {{ background-color: #0b132b; color: #fff; padding: 20px; text-align: center; }}
            .content {{ padding: 20px; }}
            .severity {{ display: inline-block; padding: 5px 10px; border-radius: 4px; color: #fff; font-weight: bold; background-color: {severity_color}; }}
            .details-table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            .details-table td {{ padding: 8px; border-bottom: 1px solid #eee; }}
            .details-table td.label {{ font-weight: bold; width: 30%; }}
            .footer {{ background-color: #f5f5f5; text-align: center; padding: 10px; font-size: 12px; color: #777; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>CyberSIEM Real-Time Security Alert</h2>
            </div>
            <div class="content">
                <p>The CyberSIEM monitoring service has detected a suspicious activity event:</p>
                <div class="severity">{alert['severity'].upper()} ALERT</div>
                
                <table class="details-table">
                    <tr>
                        <td class="label">Alert ID:</td>
                        <td>{alert.get('id', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td class="label">Timestamp:</td>
                        <td>{alert['timestamp']}</td>
                    </tr>
                    <tr>
                        <td class="label">Source Component:</td>
                        <td>{alert['source']}</td>
                    </tr>
                    <tr>
                        <td class="label">Details:</td>
                        <td>{alert['details']}</td>
                    </tr>
                    <tr>
                        <td class="label">Recommended Action:</td>
                        <td>{alert['recommended_action']}</td>
                    </tr>
                    <tr>
                        <td class="label">Status:</td>
                        <td>{alert['status']}</td>
                    </tr>
                </table>
            </div>
            <div class="footer">
                This is an automated message from CyberSIEM Security Operations Center.
            </div>
        </div>
    </body>
    </html>
    """
    
    return send_email(subject, body_html)

def notify_report(report_type, filepath):
    subject = f"[CyberSIEM Report] {report_type} Security Report"
    body_html = f"""
    <html>
    <body>
        <h2>CyberSIEM Security Report</h2>
        <p>Please find attached the generated <strong>{report_type}</strong> security summary report.</p>
        <p>Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <br>
        <p>Best Regards,</p>
        <p>CyberSIEM System Administrator</p>
    </body>
    </html>
    """
    return send_email(subject, body_html, attachment_path=filepath)
