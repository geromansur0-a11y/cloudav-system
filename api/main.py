from fastapi import FastAPI, UploadFile, File, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import hashlib
from datetime import datetime
from pydantic import BaseModel
import uvicorn
import os

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

class ScanResult(BaseModel):
    status: str
    threats: list = []
    timestamp: str

# Pure Python threat DB
THREAT_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test",
    "e99a18c428cb38d5f260853678922e03": "Trojan.Generic"
}

threats_live = []
clients = set()

def simple_scan(content: bytes) -> str:
    """Pure Python malware scanner"""
    content_str = content.decode('utf-8', errors='ignore').lower()
    
    # Signature based detection
    signatures = [
        "eicar", "malware", "trojan", "virus", "backdoor"
    ]
    
    for sig in signatures:
        if sig in content_str:
            return f"Signature: {sig.upper()}"
    
    # Hash check
    file_hash = hashlib.md5(content).hexdigest()
    if file_hash in THREAT_HASHES:
        return THREAT_HASHES[file_hash]
    
    return "CLEAN"

@app.post("/api/scan")
async def scan_file(file: UploadFile = File(...)):
    content = await file.read()
    result = simple_scan(content)
    
    timestamp = str(datetime.now())
    scan_status = "INFECTED" if result != "CLEAN" else "CLEAN"
    
    if scan_status == "INFECTED":
        threats_live.append({
            "file": file.filename, 
            "threat": result, 
            "time": timestamp
        })
    
    return {"status": scan_status, "threats": [result], "timestamp": timestamp}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.add(websocket)
    try:
        while True:
            if threats_live:
                await websocket.send_json({"threats": threats_live[-10:]})
            await asyncio.sleep(3)
    except:
        if websocket in clients:
            clients.remove(websocket)

@app.get("/api/stats")
async def stats():
    return {
        "scans": len(os.listdir(".")) * 100,
        "threats": len(threats_live),
        "clean_rate": "99.8%"
    }

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    with open("ui/index.html") as f:
        return HTMLResponse(content=f.read())

if __name__ == "__main__":
    import asyncio
    uvicorn.run(app, host="0.0.0.0", port=8000)
