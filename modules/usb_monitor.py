import threading
import time
import logging
from datetime import datetime
from database import Database
from modules.correlation_engine import trigger_alert

# Configure logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("CyberSIEM.USBMonitor")

WIN32_AVAILABLE = False
try:
    import win32api
    import win32file
    import win32com.client
    WIN32_AVAILABLE = True
except ImportError:
    logger.warning("pywin32 is not fully available for USB polling. Using simulation mode.")

class USBMonitorThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.running = True
        self.db = Database()
        self.connected_drives = {}  # Cache of drive_letter -> {volume_name, model, vendor}

    def get_usb_drives_details(self):
        """Returns details of all connected USB/removable drives."""
        usb_details = {}
        if not WIN32_AVAILABLE:
            return usb_details

        try:
            # 1. Get logical removable drives
            drives_str = win32api.GetLogicalDriveStrings()
            drives = [d.strip() for d in drives_str.split('\000') if d.strip()]
            
            # 2. Get USB details via WMI (if possible)
            wmi_drives = {}
            try:
                # Initialize COM for this thread
                import pythoncom
                pythoncom.CoInitialize()
                wmi = win32com.client.GetObject("winmgmts:")
                # Query Win32_DiskDrive for USB devices
                query = "SELECT * FROM Win32_DiskDrive WHERE InterfaceType = 'USB'"
                devices = wmi.ExecQuery(query)
                for device in devices:
                    model = getattr(device, "Model", "Generic USB Device")
                    manufacturer = getattr(device, "Manufacturer", "Generic Vendor")
                    # Try to map to partitions
                    device_id = device.DeviceID.replace("\\", "\\\\")
                    assoc_query = f"ASSOCIATORS OF {{Win32_DiskDrive.DeviceID='{device_id}'}} WHERE AssocClass = Win32_DiskDriveToDiskPartition"
                    partitions = wmi.ExecQuery(assoc_query)
                    for partition in partitions:
                        part_id = partition.DeviceID
                        logical_query = f"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{part_id}'}} WHERE AssocClass = Win32_LogicalDiskToPartition"
                        logical_disks = wmi.ExecQuery(logical_query)
                        for ld in logical_disks:
                            drive_letter = ld.DeviceID + "\\"
                            wmi_drives[drive_letter] = {
                                "model": model,
                                "vendor": manufacturer
                            }
            except Exception as wmi_err:
                logger.debug(f"WMI USB query error: {wmi_err}")

            for drive in drives:
                try:
                    drive_type = win32file.GetDriveType(drive)
                    if drive_type == win32file.DRIVE_REMOVABLE:
                        volume_name = "Removable Disk"
                        try:
                            volume_info = win32api.GetVolumeInformation(drive)
                            if volume_info and volume_info[0]:
                                volume_name = volume_info[0]
                        except Exception:
                            pass
                        
                        # Fallback details
                        wmi_info = wmi_drives.get(drive, {"model": "USB Storage Device", "vendor": "Generic Vendor"})
                        
                        usb_details[drive] = {
                            "volume_name": volume_name,
                            "model": wmi_info["model"],
                            "vendor": wmi_info["vendor"]
                        }
                except Exception as e:
                    logger.debug(f"Error checking drive {drive}: {e}")
        except Exception as e:
            logger.error(f"Error querying logical drives: {e}")
            
        return usb_details

    def run(self):
        logger.info("USB Monitoring thread active.")
        
        # Initialize initial state
        self.connected_drives = self.get_usb_drives_details()
        logger.info(f"Initial USB connected drives: {list(self.connected_drives.keys())}")
        
        # Seed initial drives as connected in database if not already logged
        for drive, info in self.connected_drives.items():
            self.db.execute(
                "INSERT INTO usb_events (device_name, vendor, event_type, timestamp) SELECT ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM usb_events WHERE device_name = ? AND event_type = 'Insertion')",
                (f"{info['model']} ({drive})", info["vendor"], "Insertion", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), f"{info['model']} ({drive})")
            )
        
        sim_trigger_counter = 0
        while self.running:
            try:
                if WIN32_AVAILABLE:
                    current_drives = self.get_usb_drives_details()
                    
                    # Check for insertions
                    for drive, info in current_drives.items():
                        if drive not in self.connected_drives:
                            device_name = f"{info['model']} ({drive})"
                            vendor = info["vendor"]
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            
                            # Log insertion
                            self.db.execute(
                                "INSERT INTO usb_events (device_name, vendor, event_type, timestamp) VALUES (?, ?, ?, ?)",
                                (device_name, vendor, "Insertion", timestamp)
                            )
                            logger.info(f"USB Device Inserted: {device_name} by {vendor}")
                            
                            # Trigger warning alert
                            trigger_alert(
                                severity="Medium",
                                source="USB Monitor",
                                details=f"USB Storage Device Inserted: {device_name} (Vendor: {vendor})",
                                recommended_action="Ensure the USB device is approved for corporate use, scan it for malware immediately, and inspect copied file logs.",
                                mitre_technique="T1200 - Hardware Additions / T1091 - Replication Through Removable Media"
                            )
                            
                    # Check for removals
                    for drive, info in self.connected_drives.items():
                        if drive not in current_drives:
                            device_name = f"{info['model']} ({drive})"
                            vendor = info["vendor"]
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            
                            # Log removal
                            self.db.execute(
                                "INSERT INTO usb_events (device_name, vendor, event_type, timestamp) VALUES (?, ?, ?, ?)",
                                (device_name, vendor, "Removal", timestamp)
                            )
                            logger.info(f"USB Device Removed: {device_name}")
                            
                            trigger_alert(
                                severity="Low",
                                source="USB Monitor",
                                details=f"USB Storage Device Removed: {device_name}",
                                recommended_action="No action required. Remind users to follow safe hardware removal practices.",
                                mitre_technique="T1200 - Hardware Additions"
                            )
                            
                    self.connected_drives = current_drives
                else:
                    # In simulation mode, we periodically mock a USB insertion/removal 
                    # if no drives are connected, say every 60-80 seconds, to keep the UI interactive.
                    sim_trigger_counter += 1
                    if sim_trigger_counter % 20 == 0:  # ~every 40-60 secs
                        action = "Insertion" if sim_trigger_counter % 40 == 0 else "Removal"
                        device_name = "Cruzer Blade (F:)"
                        vendor = "SanDisk"
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        
                        self.db.execute(
                            "INSERT INTO usb_events (device_name, vendor, event_type, timestamp) VALUES (?, ?, ?, ?)",
                            (device_name, vendor, action, timestamp)
                        )
                        logger.info(f"[SIMULATED] USB Device {action}: {device_name}")
                        
                        severity = "Medium" if action == "Insertion" else "Low"
                        trigger_alert(
                            severity=severity,
                            source="USB Monitor",
                            details=f"[SIMULATED] USB Storage Device {action}: {device_name} (Vendor: {vendor})",
                            recommended_action="Validate authorization of external USB devices on host system.",
                            mitre_technique="T1200 - Hardware Additions"
                        )

                time.sleep(2)
            except Exception as e:
                logger.error(f"Error in USB monitor thread: {e}")
                time.sleep(5)

    def stop(self):
        self.running = False
