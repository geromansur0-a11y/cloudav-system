from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import hashlib
from datetime import datetime
from pydantic import BaseModel
import uvicorn

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Static files (HTML dashboard)
app.mount("/ui", StaticFiles(directory="."), name="ui")

class ScanResult(BaseModel):
    status: str
    threats: list = []
    timestamp: str

# Simple threat DB
THREAT_HASHES = {
    "e99a18c428cb38d5f260853678922e03": "EICAR-Test",
    "44d88612fea8a8f36de82e1278abb02f": "Trojan"
}

@app.post("/api/scan")
async def scan_file(file: UploadFile = File(...)):
    content = await file.read()
    file_hash = hashlib.sha256(content).hexdigest()
    
    if file_hash in THREAT_HASHES:
        return ScanResult(
            status="INFECTED", 
            threats=[THREAT_HASHES[file_hash]], 
            timestamp=str(datetime.now())
        )
    
    # Heuristic: suspicious file names
    suspicious = ['virus', 'trojan', 'malware', 'hack']
    name_lower = file.filename.lower()
    if any(s in name_lower for s in suspicious):
        return ScanResult(status="INFECTED", threats=["Heuristic match"])
    
    return ScanResult(status="CLEAN", timestamp=str(datetime.now())

@app.get("/")
async def root():
    return {"message": "CloudAV Termux Server - http://127.0.0.1:8080/ui/index.html"}

if __name__ == "__main__":
    print("🚀 CloudAV Termux Server: http://127.0.0.1:8080")
    uvicorn.run(app, host="0.0.0.0", port=8080)
