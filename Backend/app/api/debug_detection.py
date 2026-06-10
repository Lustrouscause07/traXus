from typing import Any, Dict

from fastapi import APIRouter
from pydantic import BaseModel

from app.services.detector import process_event

router = APIRouter()


class DebugEventIn(BaseModel):
    event: Dict[str, Any]


@router.get("/sample/4625")
def detect_sample_failed_logon():
    sample_event = {
        "id": "evt-sample-4625",
        "source": "windows.security",
        "event_type": "security_event",
        "event_id": 4625,
        "timestamp": "2026-04-12T10:30:00Z",
        "actor": "test.user",
        "asset": "DESKTOP-TEST01",
        "ip": "192.168.1.25",
        "raw": {
            "TargetUserName": "test.user",
            "IpAddress": "192.168.1.25",
            "ComputerName": "DESKTOP-TEST01",
        },
    }
    return process_event(sample_event)


@router.get("/sample/4672")
def detect_sample_privileged_logon():
    sample_event = {
        "id": "evt-sample-4672",
        "source": "windows.security",
        "event_type": "security_event",
        "event_id": 4672,
        "timestamp": "2026-04-12T10:35:00Z",
        "actor": "admin.user",
        "asset": "DESKTOP-ADMIN01",
        "ip": "192.168.1.50",
        "raw": {
            "SubjectUserName": "admin.user",
            "IpAddress": "192.168.1.50",
            "ComputerName": "DESKTOP-ADMIN01",
        },
    }
    return process_event(sample_event)


@router.get("/sample/4688")
def detect_sample_suspicious_process():
    sample_event = {
        "id": "evt-sample-4688",
        "source": "windows.security",
        "event_type": "security_event",
        "event_id": 4688,
        "timestamp": "2026-04-12T10:40:00Z",
        "actor": "lab.user",
        "asset": "DESKTOP-LAB01",
        "ip": "192.168.1.77",
        "raw": {
            "SubjectUserName": "lab.user",
            "ComputerName": "DESKTOP-LAB01",
            "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
        },
    }
    return process_event(sample_event)


@router.post("/custom")
def detect_custom_event(payload: DebugEventIn):
    return process_event(payload.event)