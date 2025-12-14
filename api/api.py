from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, WebSocket
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import hashlib, yara, asyncio, psutil, pickle, numpy as np
from sklearn.ensemble import IsolationForest
import uvicorn, jwt, os, json, time
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel
from datetime import datetime
import redis

app = FastAPI(title="CloudAV Pro API")
security = HTTPBearer()
Base = declarative_base()
redis_client = redis.Redis(host='localhost', port=6379, db=0)

# Database
engine = create_engine(os.getenv('DATABASE_URL', 'sqlite:///cloudav.db'))
SessionLocal = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    api_key = Column(String(64))

class Threat(Base):
    __tablename__ = 'threats'
    id = Column(Integer, primary_key=True)
    hash = Column(String(64), unique=True)
    name = Column(String(200))
    severity = Column(String(20))
    first_seen = Column(DateTime, default=datetime.utcnow)
    count = Column(Integer, default=1)

class ScanLog(Base):
    __tablename__ = 'scan_logs'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    filename = Column(String(200))
    status = Column(String(20))
    timestamp = Column(DateTime, default=datetime.utcnow)
    size = Column(Float)

Base.metadata.create_all(engine)

# ML Model (train on-the-fly)
ml_model = IsolationForest(contamination=0.1)
feature_history = []

class ScanResult(BaseModel):
    status: str
    threats: list = []
    confidence: float = 0.0
    ml_score: float = 0.0

# Load YARA rules
rules = yara.compile(filepath='threat_rules.yar')

SECRET_KEY = "cloudav-secret-2025"
ALGORITHM = "HS256"

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload['user_id']
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/api/register")
async def register(username: str):
    db = SessionLocal()
    api_key = hashlib.sha256(username.encode() + str(time.time()).encode()).hexdigest()[:32]
    user = User(username=username, api_key=api_key)
    db.add(user)
    db.commit()
    return {"api_key": api_key, "message": "User created"}

@app.post("/api/scan", response_model=ScanResult)
async def scan_file(
    file: UploadFile = File(...),
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    user_id = verify_token(credentials)
    content = await file.read()
    file_hash = hashlib.sha256(content).hexdigest()
    file_size = len(content)
    
    # Check threat database
    db = SessionLocal()
    threat = db.query(Threat).filter(Threat.hash == file_hash).first()
    
    if threat:
        threat.count += 1
        db.commit()
        return ScanResult(status="INFECTED", threats=[threat.name], confidence=1.0)
    
    # Multi-engine scan
    yara_matches = rules.match(data=content)
    
    # ML features: entropy, size, strings count
    entropy = -sum(p * np.log2(p) for p in np.unique(content, return_counts=True)[1]/len(content) if p > 0)
    features = np.array([[entropy, file_size/1e6, content.count(b'http')]])
    global feature_history, ml_model
    feature_history.append(features[0])
    
    if len(feature_history) > 1000:
        feature_history = feature_history[-1000:]
        ml_model.fit(np.array(feature_history))
    
    ml_score = ml_model.decision_function(features)[0] if len(feature_history) > 10 else 0
    
    threats = []
    if yara_matches:
        threats.append("YARA signature match")
    if ml_score < -0.1:
        threats.append("ML anomaly detected")
    
    # Log scan
    log = ScanLog(user_id=user_id, filename=file.filename, status="CLEAN" if not threats else "INFECTED", size=file_size)
    db.add(log)
    if threats:
        new_threat = Threat(hash=file_hash, name=f"Unknown-{len(threats)}", severity="MEDIUM")
        db.add(new_threat)
    db.commit()
    
    redis_client.incr("total_scans")
    redis_client.set(f"latest_threat:{file_hash}", json.dumps({"time": time.time(), "threats": threats}))
    
    return ScanResult(
        status="INFECTED" if threats else "CLEAN",
        threats=threats,
        confidence=0.95 if yara_matches else 0.75,
        ml_score=ml_score
    )

@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    await websocket.accept()
    while True:
        stats = {
            "total_scans": int(redis_client.get("total_scans") or 0),
            "threats_today": len(redis_client.keys("latest_threat:*")),
            "active_users": db.query(User).count()
        }
        await websocket.send_json(stats)
        await asyncio.sleep(2)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
