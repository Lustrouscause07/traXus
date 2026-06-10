from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

from app.rules.file_rules import build_file_detections
from app.rules.network_rules import build_network_detections
from app.rules.process_rules import build_process_detections
from app.rules.windows_rules import build_windows_detections
from app.services.case_manager import build_case_from_detection
from app.services.correlator import correlate_event
from app.services.explainability import build_explainability


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def detect_event(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    detections: List[Dict[str, Any]] = []

    source = str(event.get("source") or "").lower()
    event_type = str(event.get("event_type") or "").lower()

    if source.startswith("windows") or "security" in event_type or "windows_event" in event_type:
        detections.extend(build_windows_detections(event))

    if source in ("host.process", "process", "psutil.process") or event_type in (
        "process_snapshot",
        "process_activity",
        "process_start",
    ):
        detections.extend(build_process_detections(event))

    if source in ("host.network", "network", "psutil.network") or event_type in (
        "network_connection",
        "network_snapshot",
        "net_conn",
    ):
        detections.extend(build_network_detections(event))

    if source in ("host.file", "file", "watchdog.file") or event_type in (
        "file_created",
        "file_modified",
        "file_deleted",
    ):
        detections.extend(build_file_detections(event))

    return detections


def build_alert_from_detection(
    event: Dict[str, Any],
    detection: Dict[str, Any],
) -> Dict[str, Any]:
    alert_id = f"alrt-{uuid4().hex[:12]}"
    explainability = build_explainability(event, detection)

    alert = {
        "id": alert_id,
        "title": str(detection.get("title") or "Security alert"),
        "severity": str(detection.get("severity") or "low"),
        "risk": int(detection.get("risk") or 0),
        "timestamp": str(event.get("timestamp") or event.get("ingested_at") or _utc_now_iso()),
        "related_event_id": str(event.get("id")) if event.get("id") is not None else None,
        "rule_id": str(detection.get("rule_id") or "GENERIC_RULE"),
        "source": str(event.get("source") or ""),
        "event_type": str(event.get("event_type") or ""),
        "summary": str(detection.get("reason") or "Backend detection generated."),
        "analysis": explainability,
    }

    result = {
        "alert": alert,
        "case": None,
        "analysis": explainability,
    }

    if not bool(detection.get("alert_only")):
        result["case"] = build_case_from_detection(event, detection, alert_id)

    return result


def process_event(event: Dict[str, Any]) -> Dict[str, Any]:
    detections = detect_event(event)
    correlations = correlate_event(event, detections)

    results: List[Dict[str, Any]] = []
    for detection in detections:
        results.append(build_alert_from_detection(event, detection))

    return {
        "event": event,
        "detections": detections,
        "correlations": correlations,
        "results": results,
    }