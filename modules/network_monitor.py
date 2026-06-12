import threading
import time
import psutil
import socket
import logging
from datetime import datetime, timedelta
from database import Database
from modules.correlation_engine import trigger_alert

# Configure logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("CyberSIEM.NetworkMonitor")

class NetworkMonitorThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.running = True
        self.db = Database()
        # Track connections per IP: remote_ip -> set(local_ports) for port scanning
        self.port_scan_tracker = {}
        self.port_scan_reset_time = datetime.now()

    def run(self):
        logger.info("Network monitoring thread active.")
        
        while self.running:
            try:
                # Reset port scanning check every 1 minute to avoid slow accumulated hits triggering alerts
                if datetime.now() - self.port_scan_reset_time > timedelta(minutes=1):
                    self.port_scan_tracker.clear()
                    self.port_scan_reset_time = datetime.now()

                connections = []
                try:
                    connections = psutil.net_connections(kind="inet")
                except Exception as e:
                    logger.warning(f"Failed to query network connections: {e}. Might lack Administrator privileges.")
                    # Generate a few mock connections if real connections cannot be queried
                    connections = self.generate_mock_connections()

                # Clean the active connections log in db (we only keep a snapshot of active ones + recent history)
                self.db.execute("DELETE FROM network_events")
                
                remote_ip_counts = {}
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                for conn in connections:
                    # Determine protocol
                    proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                    
                    # Local address info
                    local_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
                    local_port = conn.laddr.port if conn.laddr else 0
                    
                    # Remote address info
                    remote_ip = "N/A"
                    remote_port = 0
                    if conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port

                    state = conn.status if proto == "TCP" else "NONE"
                    
                    # Insert current active connection
                    self.db.execute(
                        "INSERT INTO network_events (local_ip, local_port, remote_ip, remote_port, protocol, state, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (local_ip, local_port, remote_ip, remote_port, proto, state, timestamp)
                    )

                    # Correlation checks (exclude local or loopback IPs)
                    if remote_ip != "N/A" and remote_ip not in ["127.0.0.1", "::1", "0.0.0.0", "::"]:
                        # 1. Active RDP Connection Monitoring (Port 3389)
                        if proto == "TCP" and state == "ESTABLISHED" and (remote_port == 3389 or local_port == 3389):
                            recent_alert = self.db.query(
                                "SELECT COUNT(*) as count FROM alerts WHERE source = 'Network Monitor' AND details LIKE ? AND timestamp >= ?",
                                (f"%Active RDP Connection%from {remote_ip}%", (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")),
                                one=True
                            )
                            if recent_alert and recent_alert["count"] == 0:
                                trigger_alert(
                                    severity="High",
                                    source="Network Monitor",
                                    details=f"Active RDP Connection Established: from {remote_ip}:{remote_port} to local port {local_port}.",
                                    recommended_action="Verify user identity and terminal session authority immediately. Block host if unauthorized.",
                                    mitre_technique="T1021.001 - Remote Services: Remote Desktop Protocol"
                                )

                        # 2. Connection flooding check
                        remote_ip_counts[remote_ip] = remote_ip_counts.get(remote_ip, 0) + 1
                        
                        # 3. Port scanning check (connects to different local ports)
                        if remote_ip not in self.port_scan_tracker:
                            self.port_scan_tracker[remote_ip] = set()
                        self.port_scan_tracker[remote_ip].add(local_port)

                # Check thresholds
                # 1. Check for flooding
                for ip, count in remote_ip_counts.items():
                    if count >= 30:
                        # Ensure we don't alert continuously
                        recent_alert = self.db.query(
                            "SELECT COUNT(*) as count FROM alerts WHERE source = 'Network Monitor' AND details LIKE ? AND timestamp >= ?",
                            (f"%Excessive Connection Attempts from {ip}%", (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")),
                            one=True
                        )
                        if recent_alert and recent_alert["count"] == 0:
                            trigger_alert(
                                severity="Medium",
                                source="Network Monitor",
                                details=f"Excessive Connection Attempts from {ip}: established {count} active sockets.",
                                recommended_action=f"Block IP {ip} in Windows Defender Firewall and inspect active connection processes.",
                                mitre_technique="T1095 - Non-Application Layer Protocol"
                            )

                # 2. Check for port scanning
                for ip, local_ports in self.port_scan_tracker.items():
                    if len(local_ports) >= 12:
                        recent_alert = self.db.query(
                            "SELECT COUNT(*) as count FROM alerts WHERE source = 'Network Monitor' AND details LIKE ? AND timestamp >= ?",
                            (f"%Potential Port Scanning from {ip}%", (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")),
                            one=True
                        )
                        if recent_alert and recent_alert["count"] == 0:
                            trigger_alert(
                                severity="High",
                                source="Network Monitor",
                                details=f"Potential Port Scanning from {ip}: connected to {len(local_ports)} different local ports.",
                                recommended_action=f"Immediately block IP {ip} in Windows Firewall and monitor server socket activity.",
                                mitre_technique="T1046 - Network Service Discovery"
                            )

                time.sleep(3)
            except Exception as e:
                logger.error(f"Error in Network Monitor thread: {e}")
                time.sleep(5)

    def generate_mock_connections(self):
        """Generates mock socket connections for display when system API is restricted."""
        import random
        from collections import namedtuple
        MockConn = namedtuple("MockConn", ["type", "laddr", "raddr", "status"])
        Addr = namedtuple("Addr", ["ip", "port"])
        
        mock_list = [
            MockConn(socket.SOCK_STREAM, Addr("192.168.1.100", 443), Addr("52.114.77.33", 56641), "ESTABLISHED"),
            MockConn(socket.SOCK_STREAM, Addr("192.168.1.100", 80), Addr("192.168.1.105", 51234), "ESTABLISHED"),
            MockConn(socket.SOCK_STREAM, Addr("0.0.0.0", 445), None, "LISTEN"),
            MockConn(socket.SOCK_STREAM, Addr("0.0.0.0", 3389), None, "LISTEN"),
            MockConn(socket.SOCK_STREAM, Addr("0.0.0.0", 5000), None, "LISTEN"),
            MockConn(socket.SOCK_DGRAM, Addr("0.0.0.0", 123), None, "NONE"),
        ]
        
        # 5% chance to simulate a port scan event
        if random.random() < 0.05:
            scanner_ip = "185.220.101.12"
            for port in range(1001, 1015):
                mock_list.append(MockConn(socket.SOCK_STREAM, Addr("192.168.1.100", port), Addr(scanner_ip, 45112), "SYN_SENT"))
                
        # 5% chance to simulate an active RDP connection
        if random.random() < 0.05:
            mock_list.append(MockConn(socket.SOCK_STREAM, Addr("192.168.1.100", 3389), Addr("198.51.100.45", 54321), "ESTABLISHED"))
            
        return mock_list

    def stop(self):
        self.running = False
