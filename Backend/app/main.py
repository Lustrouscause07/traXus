from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from typing import Any, Dict, List
from datetime import datetime

# -----------------------------
# In-memory store (prototype)
# Later replace with DB
# -----------------------------
EVENTS: List[Dict[str, Any]] = []
MAX_EVENTS = 500  # keep last N events

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

# -----------------------------
# Basic endpoints
# -----------------------------
@app.get("/")
def root():
    return {"status": "ok", "service": "isms-backend"}

@app.get("/health")
def health():
    return {"ok": True}

# -----------------------------
# Ingestion endpoint
# Collector POSTs here
# -----------------------------
@app.post("/ingest")
def ingest_event(evt: Dict[str, Any]):
    """
    Accepts any JSON event payload.
    Collector is expected to include:
    id, timestamp, event_type, risk, source, raw, etc.
    """
    evt.setdefault("ingested_at", datetime.utcnow().isoformat() + "Z")
    EVENTS.append(evt)

    # Trim oldest
    if len(EVENTS) > MAX_EVENTS:
        del EVENTS[0 : len(EVENTS) - MAX_EVENTS]

    return {"ok": True, "count": len(EVENTS)}

# -----------------------------
# Query endpoints used by UI
# -----------------------------
@app.get("/events")
def list_events():
    # Return newest first
    return list(reversed(EVENTS))

@app.get("/alerts")
def list_alerts():
    """
    Simple derived alerts:
    If risk >= 70 => alert.
    risk >= 85 => high, else medium
    """
    alerts: List[Dict[str, Any]] = []

    for e in reversed(EVENTS):
        risk = int(e.get("risk", 0) or 0)
        if risk >= 70:
            alerts.append(
                {
                    "id": f"alrt-{e.get('record_id') or e.get('id') or 'na'}",
                    "timestamp": e.get("timestamp") or e.get("ingested_at"),
                    "title": e.get("event_type", "security_event"),
                    "severity": "high" if risk >= 85 else "medium",
                    "related_event_id": e.get("id"),
                    "risk": risk,
                    # Optional useful context:
                    "source": e.get("source"),
                    "provider": e.get("provider"),
                    "computer": e.get("computer"),
                    "event_id": e.get("event_id"),
                    "record_id": e.get("record_id"),
                    "level": e.get("level"),
                }
            )

        if len(alerts) >= 50:
            break

    return alerts
