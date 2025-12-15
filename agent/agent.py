#!/usr/bin/env python3
import os
import sys
import time
import hashlib
import requests
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import platform

API_URL = "https://your-app.railway.app"  # Ganti dengan URL deploy

class CloudAVAgent:
    def __init__(self):
        self.threats_blocked = 0
        self.system = platform.system()
        print(f"🛡️ CloudAV Agent started on {self.system}")
    
    def compute_hash(self, file_path):
        h = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    h.update(chunk)
            return h.hexdigest()
        except:
            return None
    
    def scan_file(self, file_path):
        if os.path.getsize(file_path) > 10_000_000:  # Skip >10MB
            return
        
        file_hash = self.compute_hash(file_path)
        if not file_hash:
            return
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': f}
                resp = requests.post(f"{API_URL}/api/scan", files=files, timeout=10)
                result = resp.json()
                
                if result['status'] == 'INFECTED':
                    self.quarantine(file_path)
                    print(f"🛑 THREAT BLOCKED: {file_path} - {result['threats']}")
        except Exception as e:
            print(f"❌ Scan failed: {e}")
    
    def quarantine(self, file_path):
        quarantine_dir = Path.home() / ".cloudav_quarantine"
        quarantine_dir.mkdir(exist_ok=True)
        new_path = quarantine_dir / Path(file_path).name
        Path(file_path).rename(new_path)
        self.threats_blocked += 1

class Handler(FileSystemEventHandler):
    def __init__(self):
        self.agent = CloudAVAgent()
    
    def on_created(self, event):
        if not event.is_directory and not event.src_path.endswith(('.py', '.exe')):
            print(f"🔍 Scanning: {event.src_path}")
            self.agent.scan_file(event.src_path)

if __name__ == "__main__":
    # Monitor Downloads folder
    paths = []
    if platform.system() == "Windows":
        paths = [os.path.expanduser("~/Downloads")]
    else:
        paths = [os.path.expanduser("~/Downloads"), "/tmp"]
    
    event_handler = Handler()
    observer = Observer()
    
    for path in paths:
        if os.path.exists(path):
            observer.schedule(event_handler, path, recursive=False)
    
    observer.start()
    print(f"👁️ Monitoring: {' | '.join(paths)}")
    print("Press Ctrl+C to stop...")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
