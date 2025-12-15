#!/usr/bin/env python3
import os
import time
import hashlib
import requests
from pathlib import Path
import glob

API_URL = "http://127.0.0.1:8080"
DOWNLOAD_PATH = "/sdcard/Download"

print("🛡️ CloudAV Termux Agent (Polling Mode)")
print("📁 Monitoring Download folder...")
print("Press Ctrl+C to stop")

def compute_hash(file_path):
    h = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

def scan_file(file_path):
    if os.path.getsize(file_path) > 10*1024*1024:  # Skip >10MB
        return
    
    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            resp = requests.post(f"{API_URL}/api/scan", files=files, timeout=15)
            result = resp.json()
            
            if result['status'] == 'INFECTED':
                print(f"🛑 THREAT: {os.path.basename(file_path)} - {result['threats'][0]}")
                # Quarantine
                quarantine_dir = Path.home() / ".cloudav_quar"
                quarantine_dir.mkdir(exist_ok=True)
                new_path = quarantine_dir / os.path.basename(file_path)
                Path(file_path).rename(new_path)
            else:
                print(f"✅ CLEAN: {os.path.basename(file_path)}")
    except Exception as e:
        print(f"❌ Error scanning {os.path.basename(file_path)}: {e}")

if __name__ == "__main__":
    last_files = set()
    
    while True:
        try:
            # Scan semua file di Download
            files = glob.glob(f"{DOWNLOAD_PATH}/*")
            new_files = set(files) - last_files
            
            for file_path in new_files:
                if os.path.isfile(file_path):
                    print(f"🔍 Scanning: {os.path.basename(file_path)}")
                    scan_file(file_path)
            
            last_files = set(files)
            time.sleep(5)  # Poll every 5 seconds
            
        except KeyboardInterrupt:
            print("\n👋 Agent stopped")
            break
        except Exception as e:
            print(f"❌ Polling error: {e}")
            time.sleep(10)
