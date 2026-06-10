from typing import Any, Dict, List
from uuid import uuid4
from datetime import datetime, timezone


CASE_TITLE_MAP = {
    "WIN_AUTH_FAILED_LOGON": "Repeated failed login activity observed",
    "WIN_AUTH_SUCCESS_LOGON": "Successful login activity observed",
    "WIN_PRIVILEGED_LOGON": "Privileged account activity observed",
    "WIN_SUSPICIOUS_PROCESS_CREATION": "Suspicious process execution observed",
    "WIN_ACCOUNT_CREATED": "New account creation activity observed",
    "WIN_ACCOUNT_ENABLED": "User account enablement observed",
    "WIN_PASSWORD_RESET_ATTEMPT": "Password reset activity observed",
    "WIN_PRIVILEGED_GROUP_MEMBER_ADDED": "Privileged group membership change observed",
    "WIN_AUDIT_LOG_CLEARED": "Audit log tampering activity observed",
    "WIN_SERVICE_CREATED": "Service installation or persistence activity observed",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _human_case_title(detection: Dict[str, Any]) -> str:
    rule_id = _safe_str(detection.get("rule_id"))
    if rule_id in CASE_TITLE_MAP:
        return CASE_TITLE_MAP[rule_id]

    title = _safe_str(detection.get("title"), "Security incident observed").strip()
    if not title:
        return "Security incident observed"

    if title.lower().endswith("detected"):
        title = title[:-8].strip()

    return f"{title} observed"


def build_case_from_detection(
    event: Dict[str, Any],
    detection: Dict[str, Any],
    alert_id: str,
) -> Dict[str, Any]:
    severity = _safe_str(detection.get("severity"), "low")
    title = _human_case_title(detection)
    summary = _safe_str(
        detection.get("reason"),
        "Security incident detected by backend rule engine.",
    )

    event_id = event.get("id")
    linked_event_ids: List[str] = [str(event_id)] if event_id is not None else []

    signals = detection.get("signals") or {}
    asset = _safe_str(signals.get("asset") or event.get("asset") or "localhost")
    actor = _safe_str(signals.get("actor") or event.get("actor") or "")
    rule_id = _safe_str(detection.get("rule_id") or "GENERIC_RULE")

    aggregation_key = "|".join(
        [
            rule_id,
            asset.lower(),
            actor.lower(),
            severity.lower(),
        ]
    )

    now = _utc_now_iso()

    return {
        "case_id": f"case-{uuid4().hex[:12]}",
        "title": title,
        "severity": severity,
        "status": "open",
        "created_at": now,
        "last_updated_at": now,
        "linked_alert_ids": [str(alert_id)],
        "linked_event_ids": linked_event_ids,
        "notes": [],
        "recommended_actions": detection.get("recommended_actions") or [],
        "summary": summary,
        "occurrence_count": 1,
        "aggregation_key": aggregation_key,
        "rule_id": rule_id,
        "asset": asset,
        "actor": actor,
    }