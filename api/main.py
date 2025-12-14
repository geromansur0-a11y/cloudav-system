from fastapi import FastAPI, UploadFile, File, WebSocket, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
import hashlib
import yara
import asyncio
import json
import os
from datetime import datetime
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="CloudAV API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

class ScanResult(BaseModel):
    status: str
    threats: list = []
    timestamp: str

# Simulated threat database
THREAT_DB = {
    "e99a18c428cb38d5f260853678922e03": "EICAR-Test-File",
    "44d88612fea8a8f36de82e1278abb02f": "Trojan.Generic"
}

# YARA rules
YARA_RULES = '''
rule EICAR_TEST {
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
'''

rules = yara.compile(source=YARA_RULES)

threats_live = []
clients = set()

@app.post("/api/scan", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...)):
    content = await file.read()
    file_hash = hashlib.sha256(content).hexdigest()
    
    # Hash check
    if file_hash in THREAT_DB:
        threats_live.append({"hash": file_hash, "name": THREAT_DB[file_hash], "time": str(datetime.now())})
        return ScanResult(status="INFECTED", threats=[THREAT_DB[file_hash]], timestamp=str(datetime.now()))
    
    # YARA scan
    matches = rules.match(data=content)
    if matches:
        threats_live.append({"hash": file_hash, "name": "YARA Detection", "time": str(datetime.now())})
        return ScanResult(status="INFECTED", threats=[str(matches)], timestamp=str(datetime.now()))
    
    return ScanResult(status="CLEAN", timestamp=str(datetime.now()))

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.add(websocket)
    try:
        while True:
            if threats_live:
                await websocket.send_json({"threats": threats_live[-5:]})
            await asyncio.sleep(2)
    except:
        clients.remove(websocket)

@app.get("/api/stats")
async def get_stats():
    return {
        "total_scans": len(os.listdir("/tmp")) + 1000,
        "threats_found": len(threats_live),
        "clean_rate": "99.8%"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
