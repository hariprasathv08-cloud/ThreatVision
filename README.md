# 🛡️ ThreatVision

**ThreatVision** is a local Security Information and Event Management (SIEM) dashboard designed for Windows systems. It monitors system health, active processes, file system integrity, USB connections, network traffic, and firewall status, providing a central interface to track alerts and generate security reports.

---

## 🚀 Features

- **📊 Centralized Security Dashboard**: Visualizes system health metrics (CPU, RAM, Disk, active connections) and active alert counts.
- **🛡️ Windows Event Log Monitoring**: Tracks critical Windows security events like failed logins, account creations, and privilege assignments.
- **📂 File Integrity Monitoring (FIM)**: Tracks real-time modifications, additions, and deletions across monitored directories.
- **🔌 USB Device Tracking**: Monitors USB connections and removals with historical event logging.
- **🌐 Network & Firewall Inspection**: Audits network connections and logs active firewall profile states (Domain, Private, Public).
- **⚙️ Process Management**: Monitors running processes in real-time, highlighting high CPU/memory consumption with administrative kill capabilities.
- **🔔 Security Alert Correlation**: Uses pre-configured correlation rules to detect threat patterns (e.g., brute-force login attempts, audit log clearing).
- **📈 PDF/CSV Report Generation**: Generates daily, weekly, or monthly security reports for compliance and archiving.
- **📧 Email Notifications**: Configurable alerts integrated with Gmail for instant notifications on critical severity events.

---

## 🛠️ Tech Stack

- **Backend**: Python, Flask, Flask-Login, SQLite
- **Frontend**: HTML5, Vanilla CSS, JS (Chart.js for analytics)
- **Monitoring Libraries**: `psutil` (system & processes), `watchdog` (FIM), `pywin32` (Windows events)

---

## 📦 Installation & Setup

1. **Clone the Repository** (or download the files):
   ```bash
   git clone https://github.com/your-username/ThreatVision.git
   cd ThreatVision
   ```

2. **Create and Activate a Virtual Environment (Optional but Recommended)**:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements_new.txt
   ```

4. **Initialize and Run the Application**:
   ```bash
   python app.py
   ```
   *The application will start on `http://127.0.0.1:5000`.*

---

## 🔒 Security Configuration

- Update the monitoring settings, monitored paths, and alert notification receivers in the **Settings** panel of the application.
- Uses role-based access control supporting **Administrator** and **Operator** profiles.
