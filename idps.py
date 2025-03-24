import os
import sys
import time
import fnmatch
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from watchdog.events import FileCreatedEvent, FileDeletedEvent, FileMovedEvent, FileModifiedEvent

from monitor import monitor_network_connections, monitor_system_processes
from detector import AdvancedAnomalyDetector


class IDPSEventHandler(FileSystemEventHandler):
    def __init__(self, ignore_patterns=None, anomaly_detector=None):
        super().__init__()
        self.ignore_patterns = ignore_patterns or []
        self.anomaly_detector = anomaly_detector


    def _get_event_type(self, event):
        if isinstance(event, FileCreatedEvent):
            return 0
        elif isinstance(event, FileDeletedEvent):
            return 1
        elif isinstance(event, FileMovedEvent):
            return 2
        elif isinstance(event, FileModifiedEvent):
            return 3
        else:
            return -1

    def _get_event_vector(self, event):
        event_type = self._get_event_type(event)
        if event_type == -1:
            return None

        file_size = 0
        if os.path.exists(event.src_path):
            file_size = os.path.getsize(event.src_path)

        return [event_type, file_size]

    def should_ignore(self, path):
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False
    
    def log_event(self, event_type, path):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        with open("./logs/file_log.txt", "a") as log_file:
            log_file.write(f"{timestamp} - {event_type} - {path}\n")

    def on_created(self, event):
        if self.should_ignore(event.src_path):
            return
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector)
        print(f"Alert! {event.src_path} has been created.")
        self.log_event("created", event.src_path)

    def on_deleted(self, event):
        if self.should_ignore(event.src_path):
            return
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector)
        print(f"Alert! {event.src_path} has been deleted.")
        self.log_event("deleted", event.src_path)

    def on_moved(self, event):
        if self.should_ignore(event.src_path) and self.should_ignore(event.dest_path):
            return
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector)
        print(f"Alert! {event.src_path} has been moved to {event.dest_path}.")
        self.log_event("moved", f"{event.src_path} -> {event.dest_path}")

    def on_modified(self, event):
        if self.should_ignore(event.src_path):
            return
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector)
        print(f"Alert! {event.src_path} has been modified.")
        self.log_event("modified", event.src_path)


def main():
    paths = ["./lab"]
    ignore_patterns = ["*.tmp", "*.log"]
    anomaly_detector = AdvancedAnomalyDetector(threshold=10, time_window=60)
    event_handler = IDPSEventHandler(ignore_patterns=ignore_patterns, anomaly_detector=anomaly_detector)
    observer = Observer()

    # Create logs directory if it doesn't exist
    os.makedirs("./logs", exist_ok=True)
    
    print("Starting IDPS monitoring...")
    print(f"Monitoring directories: {paths}")
    print(f"Ignoring patterns: {ignore_patterns}")

    for path in paths:
        if not os.path.exists(path):
            print(f"Warning: Path {path} does not exist. Creating it...")
            os.makedirs(path, exist_ok=True)
        observer.schedule(event_handler, path, recursive=True)

    observer.start()
    print("File system observer started")

    print("Starting network monitoring...")
    network_monitor_thread = threading.Thread(target=monitor_network_connections)
    network_monitor_thread.daemon = True  # Make thread exit when main thread exits
    network_monitor_thread.start()
    print("Network monitoring started")

    print("Starting process monitoring...")
    process_monitor_thread = threading.Thread(target=monitor_system_processes)
    process_monitor_thread.daemon = True  # Make thread exit when main thread exits
    process_monitor_thread.start()
    print("Process monitoring started")

    # Create a test file to verify the monitoring is working
    test_file_path = os.path.join(paths[0], "test_file.txt")
    print(f"Creating test file at {test_file_path} to verify monitoring...")
    with open(test_file_path, "w") as f:
        f.write("This is a test file to verify the IDPS is working.")
    
    try:
        print("IDPS running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping IDPS...")
        observer.stop()
    observer.join()
    network_monitor_thread.join()
    process_monitor_thread.join()
    print("IDPS stopped.")


if __name__ == "__main__":
    main()