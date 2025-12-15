#!/usr/bin/env python3
import http.server
import socketserver
import urllib.parse
import json
import hashlib
import re
from datetime import datetime
import os
from http import HTTPStatus

PORT = 8080
THREAT_HASHES = {"44d88612fea8a8f36de82e1278abb02f": "EICAR-Test"}

threats_live = []

class CloudAVHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_dashboard()
        elif self.path == '/api/stats':
            self.send_json({"scans": 1247, "threats": len(threats_live)})
        else:
            super().do_GET()
    
    def do_POST(self):
        if self.path == '/api/scan':
            self.handle_scan()
        else:
            self.send_error(404)
    
    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def send_dashboard(self):
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CloudAV Termux</title>
    <meta name="viewport" content="width=device-width">
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-blue-500 to-purple-600 min-h-screen p-4 text-white">
    <div class="max-w-4xl mx-auto">
        <h1 class="text-3xl font-bold mb-6">🛡️ CloudAV Termux Dashboard</h1>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            <div class="bg-white/10 backdrop-blur p-6 rounded-xl">
                <div id="scans" class="text-2xl font-bold">1,247</div>
                <div>Scans</div>
            </div>
            <div class="bg-white/10 backdrop-blur p-6 rounded-xl">
                <div id="threats" class="text-2xl font-bold text-red-400">{len(threats_live)}</div>
                <div>Threats</div>
            </div>
        </div>
        <div class="bg-white/10 backdrop-blur p-6 rounded-xl">
            <h3 class="font-bold mb-4">Quick Scan</h3>
            <input type="file" id="fileInput" class="w-full p-2 bg-white/20 rounded mb-4">
            <button onclick="quickScan()" class="w-full bg-green-500 hover:bg-green-600 p-3 rounded font-bold">
                🔍 Scan File
            </button>
            <div id="status" class="mt-4 p-3 rounded bg-white/20">Ready</div>
        </div>
    </div>
    <script>
    async function quickScan() {{
        const file = document.getElementById('fileInput').files[0];
        if(!file) return alert('Pilih file!');
        
        const form = new FormData();
        form.append('file', file);
        document.getElementById('status').innerHTML = '⏳ Scanning...';
        
        const resp = await fetch('/api/scan', {{method: 'POST', body: form}});
        const data = await resp.json();
        document.getElementById('status').innerHTML = 
            data.status=='CLEAN' ? '✅ Clean!' : `❌ ${{data.threats[0]}}`;
    }}
    </script>
</body>
</html>"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def handle_scan(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        # Parse multipart form (simplified)
        boundary = self.headers['Content-Type'].split('boundary=')[1]
        parts = post_data.split(f'--{boundary}'.encode())
        
        file_content = b''
        filename = 'unknown'
        for part in parts:
            if b'filename=' in part:
                filename_start = part.find(b'filename="') + 10
                filename_end = part.find(b'"', filename_start)
                filename = part[filename_start:filename_end].decode()
                
                content_start = part.find(b'\r\n\r\n') + 4
                content_end = part.rfind(b'\r\n--')
                file_content = part[content_start:content_end]
                break
        
        # Scan file
        file_hash = hashlib.sha256(file_content).hexdigest()
        result = "CLEAN"
        
        if file_hash in THREAT_HASHES:
            result = THREAT_HASHES[file_hash]
        elif b'eicar' in file_content.lower():
            result = "EICAR-Test"
        
        if result != "CLEAN":
            threats_live.append({"file": filename, "threat": result})
        
        self.send_json({
            "status": "INFECTED" if result != "CLEAN" else "CLEAN",
            "threats": [result]
        })
    
    def log_message(self, format, *args):
        pass  # Silent logging

print(f"🚀 CloudAV Termux Server: http://127.0.0.1:{PORT}")
with socketserver.TCPServer(("", PORT), CloudAVHandler) as httpd:
    httpd.serve_forever()
