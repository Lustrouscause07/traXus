from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="ISMS Backend", version="0.1.0")

# Allow the React dev server
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"status": "ok", "service": "isms-backend"}

@app.get("/health")
def health():
    return {"ok": True}

from datetime import datetime

@app.get("/events")
def list_events():
    # sample data for UI parity (replace later with DB)
    return [
        {
            "id": "evt-001",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "failed_login",
            "source_ip": "203.0.113.10",
            "asset": "WIN-CLIENT-01",
            "risk": 55,
        },
        {
            "id": "evt-002",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "port_probe",
            "source_ip": "198.51.100.22",
            "asset": "WEB-SERVER-01",
            "risk": 78,
        },
    ]

@app.get("/alerts")
def list_alerts():
    # sample derived alerts (replace later with scoring + rules)
    return [
        {
            "id": "alrt-001",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "title": "Possible brute force attempt",
            "severity": "high",
            "related_event_id": "evt-001",
            "risk": 85,
        }
    ]
