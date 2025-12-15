#!/usr/bin/env python3
# ULTRA SIMPLE - PASTI JALAN
import http.server
import socketserver
import urllib.parse
import json
import hashlib
from datetime import datetime
import os
import re

PORT = 8080
threats_live = []

class CloudAVHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_html()
        elif self.path == '/api/stats':
            self.send_json({"scans": 1247, "threats": len(threats_live)})
        else:
            self.send_error(404)
    
    def do_POST(self):
        if self.path == '/api/scan':
            self.do_scan()
        else:
            self.send_error(404)
    
    def send_html(self):
        html = '''
<!DOCTYPE html>
<html><head><title>CloudAV</title>
<meta name="viewport" content="width=device-width">
<style>body{background:linear-gradient(135deg,#667eea,#764ba2);color:white;padding:20px;font-family:sans-serif;}
.card{background:rgba(255,255,255,0.1);padding:20px;border-radius:10px;margin:10px 0;}
button{width:100%;padding:12px;background:#2ed573;color:white;border:none;border-radius:8px;font-size:16px;cursor:pointer;}
input{width:100%;padding:10px;margin:10px 0;background:rgba(255,255,255,0.2);border:1px solid rgba(255,255,255,0.3);border-radius:8px;color:white;}
</style></head>
<body>
<div class="card"><h1>🛡️ CloudAV Termux</h1></div>
<div class="card"><div id="threats">0</div><div>Threats Found</div></div>
<div class="card">
<h3>Quick Scan</h3>
<input type="file" id="file">
<button onclick="scan()">🔍 Scan</button>
<div id="status">Ready</div>
</div>
<script>
async function scan(){ 
    let file=document.getElementById('file').files[0];
    if(!file) return alert('Pilih file!');
    let form=new FormData(); form.append('file',file);
    document.getElementById('status').innerHTML='⏳ Scanning...';
    let r=await fetch('/api/scan',{method:'POST',body:form});
    let data=await r.json();
    document.getElementById('status').innerHTML=
        data.status=='CLEAN'?'✅ Clean!':'❌ '+data.threats[0];
}
</script></body></html>'''
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def do_scan(self):
        ctype = self.headers.get('Content-Type', '').lower()
        if 'multipart' not in ctype:
            self.send_error(400)
            return
            
        clen = int(self.headers['Content-Length'])
        data = self.rfile.read(clen)
        
        # Simple scan
        result = "CLEAN"
        if b'eicar' in data.lower() or b'malware' in data.lower():
            result = "MALWARE FOUND"
            threats_live.append({"threat": result})
        
        self.send_json({
            "status": "INFECTED" if result != "CLEAN" else "CLEAN",
            "threats": [result]
        })

print(f"🚀 Server mulai: http://127.0.0.1:{PORT}")
print("TEST: curl http://127.0.0.1:8080/")
with socketserver.TCPServer(('127.0.0.1', PORT), CloudAVHandler) as httpd:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Server stop")
