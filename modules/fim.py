import threading
import time
import os
import logging
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from database import Database
from modules.correlation_engine import trigger_alert

# Configure logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("CyberSIEM.FIM")

class FIMHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.db = Database()

    def process_event(self, filepath, event_type, details=""):
        # Prevent logging database changes or log files of the app itself to avoid infinite loops
        basename = os.path.basename(filepath)
        if basename in ["cybersiem.db", "cybersiem.db-journal", "cybersiem.db-wal"]:
            return
        if ".system_generated" in filepath or "brain" in filepath or "\\venv\\" in filepath or "/venv/" in filepath:
            return
            
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Log to file_events table
        self.db.execute(
            "INSERT INTO file_events (filepath, event_type, details, timestamp) VALUES (?, ?, ?, ?)",
            (filepath, event_type, details or f"File {event_type.lower()}", timestamp)
        )
        
        logger.info(f"FIM Event: {event_type} - {filepath} ({details})")
        
        # Generate alert
        severity = "High" if event_type in ["Deleted", "Renamed"] else "Medium"
        mitre_tech = "T1485 - Data Destruction" if event_type == "Deleted" else "T1222 - File and Directory Permissions Modification"
        trigger_alert(
            severity=severity,
            source="File Integrity Monitor",
            details=f"File Integrity Violation: File '{basename}' was {event_type.lower()}. Details: {details or filepath}",
            recommended_action=f"Verify if this file change was authorized. If unexpected, inspect the host system and restore from backup if needed.",
            mitre_technique=mitre_tech
        )

    def on_created(self, event):
        if not event.is_directory:
            self.process_event(event.src_path, "Created")

    def on_deleted(self, event):
        if not event.is_directory:
            self.process_event(event.src_path, "Deleted")

    def on_modified(self, event):
        if not event.is_directory:
            # Watchdog sometimes emits multiple modification events, we just log them
            self.process_event(event.src_path, "Modified")

    def on_moved(self, event):
        if not event.is_directory:
            details = f"Renamed from {os.path.basename(event.src_path)} to {os.path.basename(event.dest_path)}"
            self.process_event(event.dest_path, "Renamed", details)


class FIMThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.running = True
        self.db = Database()
        self.observer = None
        self.current_paths_str = ""

    def get_configured_paths(self):
        """Retrieves and normalizes paths configured in DB settings."""
        paths_str = self.db.get_setting("fim_monitored_paths", "")
        if not paths_str:
            # Default to a folder called "monitored_files" in the app directory
            app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            default_path = os.path.join(app_dir, "monitored_files")
            if not os.path.exists(default_path):
                os.makedirs(default_path)
            self.db.set_setting("fim_monitored_paths", default_path)
            return [default_path], default_path
            
        paths = [p.strip() for p in paths_str.split(",") if p.strip()]
        valid_paths = []
        for path in paths:
            if os.path.exists(path):
                valid_paths.append(path)
            else:
                try:
                    os.makedirs(path)
                    valid_paths.append(path)
                    logger.info(f"Created configured FIM path that did not exist: {path}")
                except Exception as e:
                    logger.error(f"Configured FIM path does not exist and cannot be created: {path}. Error: {e}")
                    
        return valid_paths, paths_str

    def start_observer(self, paths):
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join()
            except Exception:
                pass
                
        self.observer = Observer()
        handler = FIMHandler()
        
        for path in paths:
            try:
                self.observer.schedule(handler, path, recursive=True)
                logger.info(f"Watching FIM path: {path}")
            except Exception as e:
                logger.error(f"Failed to schedule watchdog on path {path}: {e}")
                
        try:
            self.observer.start()
        except Exception as e:
            logger.error(f"Failed to start watchdog observer: {e}")

    def run(self):
        logger.info("File Integrity Monitor thread active.")
        
        # Initial check
        paths, paths_str = self.get_configured_paths()
        self.current_paths_str = paths_str
        if paths:
            self.start_observer(paths)
            
        while self.running:
            try:
                # Check for settings changes every 5 seconds
                time.sleep(5)
                _, latest_paths_str = self.get_configured_paths()
                if latest_paths_str != self.current_paths_str:
                    logger.info("FIM monitored paths updated. Restarting observer...")
                    paths, self.current_paths_str = self.get_configured_paths()
                    if paths:
                        self.start_observer(paths)
                    else:
                        if self.observer:
                            self.observer.stop()
                            self.observer = None
            except Exception as e:
                logger.error(f"Error in FIM monitoring loop: {e}")

    def stop(self):
        self.running = False
        if self.observer:
            self.observer.stop()
            self.observer.join()
