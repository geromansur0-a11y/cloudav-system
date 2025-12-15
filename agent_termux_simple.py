#!/usr/bin/env python3
import os
import time
import hashlib
import requests
from pathlib import Path
import glob

API_URL = "http://127.0.0.1:8080"

class TermuxAVAgent:
    def __init__(self):
        self.last_scan = {}
        self.threats_blocked = 0
        print("🛡️ CloudAV Termux Agent (Polling Mode)")
    
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
        stat = os.stat(file_path)
        mtime = stat.st_mtime
        
        # Skip jika file belum berubah
        if self.last_scan.get(file_path) == mtime:
            return
        
        if stat.st_size > 5_000_000:  # Skip >5MB
            return
        
        print(f"🔍 Scanning: {os.path.basename(file_path)}")
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
                    print(f"🛑 THREAT BLOCKED: {result['threats']}")
                else:
                    print("✅ Clean")
                    
        except Exception as e:
            print(f"❌ Error: {e}")
        finally:
            self.last_scan[file_path] = mtime
    
    def monitor_folders(self):
        paths = [
            "/sdcard/Download/*.apk",
            "/sdcard/Download/*.zip", 
            "/sdcard/Download/*.exe",
            "/sdcard/Download/*.pdf"
        ]
        
        for pattern in paths:
            for file_path in glob.glob(pattern):
                if os.path.isfile(file_path):
                    self.scan_file(file_path)

# Jalankan
if __name__ == "__main__":
    agent = TermuxAVAgent()
    
    print("📁 Monitoring Download folder...")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            agent.monitor_folders()
            time.sleep(5)  # Scan setiap 5 detik
    except KeyboardInterrupt:
        print("\n🛑 Agent stopped")
