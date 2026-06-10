from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from app.api.debug_detection import router as debug_detection_router
from app.services.detector import process_event

app = FastAPI(title="ISMS Backend", version="0.4.0")

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

app.include_router(debug_detection_router, prefix="/debug/detect", tags=["debug-detect"])

EVENTS: List[Dict[str, Any]] = []
EVENT_BY_ID: Dict[str, Dict[str, Any]] = {}

ALERTS: List[Dict[str, Any]] = []
ALERT_BY_ID: Dict[str, Dict[str, Any]] = {}

CASES: List[Dict[str, Any]] = []
CASE_BY_ID: Dict[str, Dict[str, Any]] = {}

MAX_EVENTS = 2000
MAX_ALERTS = 2000
MAX_CASES = 1000
CASE_WINDOW_SECONDS = 3600


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _to_epoch_seconds(ts: Optional[str]) -> float:
    if not ts:
        return 0.0
    try:
        t = str(ts).replace("Z", "+00:00")
        dt = datetime.fromisoformat(t)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0.0


def _event_time_key(e: Dict[str, Any]) -> float:
    return _to_epoch_seconds(e.get("timestamp")) or _to_epoch_seconds(e.get("ingested_at"))


def _alert_time_key(a: Dict[str, Any]) -> float:
    return _to_epoch_seconds(a.get("timestamp"))


def _case_time_key(c: Dict[str, Any]) -> float:
    return _to_epoch_seconds(c.get("last_updated_at")) or _to_epoch_seconds(c.get("created_at"))


def _clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _safe_str(x: Any, default: str = "") -> str:
    try:
        s = "" if x is None else str(x)
        return s
    except Exception:
        return default


def _severity_rank(sev: str) -> int:
    m = {"low": 0, "medium": 1, "high": 2}
    return m.get(str(sev).lower(), 0)


def _dedupe_list(values: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for v in values:
        s = _safe_str(v)
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _trim_store(items: List[Dict[str, Any]], index: Dict[str, Dict[str, Any]], max_len: int, id_field: str):
    if len(items) <= max_len:
        return

    overflow = len(items) - max_len
    old = items[:overflow]
    del items[:overflow]

    for o in old:
        oid = str(o.get(id_field))
        if oid in index and index.get(oid) is o:
            del index[oid]


def _find_mergeable_case(incoming_case: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    incoming_key = _safe_str(incoming_case.get("aggregation_key"))
    incoming_created = _to_epoch_seconds(incoming_case.get("created_at"))

    if not incoming_key:
        return None

    best = None
    best_ts = -1.0

    for existing in CASES:
        if _safe_str(existing.get("status")).lower() != "open":
            continue

        if _safe_str(existing.get("aggregation_key")) != incoming_key:
            continue

        existing_ts = _to_epoch_seconds(existing.get("last_updated_at") or existing.get("created_at"))
        if abs(incoming_created - existing_ts) > CASE_WINDOW_SECONDS:
            continue

        if existing_ts > best_ts:
            best_ts = existing_ts
            best = existing

    return best


def _merge_case(existing_case: Dict[str, Any], incoming_case: Dict[str, Any]) -> Dict[str, Any]:
    existing_case["last_updated_at"] = now_utc_iso()
    existing_case["occurrence_count"] = _safe_int(existing_case.get("occurrence_count"), 1) + _safe_int(
        incoming_case.get("occurrence_count"),
        1,
    )

    existing_case["linked_alert_ids"] = _dedupe_list(
        list(existing_case.get("linked_alert_ids") or []) + list(incoming_case.get("linked_alert_ids") or [])
    )
    existing_case["linked_event_ids"] = _dedupe_list(
        list(existing_case.get("linked_event_ids") or []) + list(incoming_case.get("linked_event_ids") or [])
    )
    existing_case["recommended_actions"] = _dedupe_list(
        list(existing_case.get("recommended_actions") or []) + list(incoming_case.get("recommended_actions") or [])
    )

    if _severity_rank(_safe_str(incoming_case.get("severity"))) > _severity_rank(_safe_str(existing_case.get("severity"))):
        existing_case["severity"] = incoming_case.get("severity", existing_case.get("severity"))

    if incoming_case.get("summary"):
        existing_case["summary"] = incoming_case["summary"]

    return existing_case


def _extract_ip(e: Dict[str, Any]) -> Optional[str]:
    for k in ("ip", "src_ip", "source_ip", "client_ip", "remote_ip"):
        v = e.get(k)
        if v:
            return _safe_str(v)

    raw = e.get("raw")
    if isinstance(raw, dict):
        for k in ("ip", "src_ip", "source_ip", "client_ip", "remote_ip"):
            v = raw.get(k)
            if v:
                return _safe_str(v)

    return None


def _extract_actor(e: Dict[str, Any]) -> Optional[str]:
    for k in ("actor", "user", "username", "account", "subject_user", "target_user"):
        v = e.get(k)
        if v:
            return _safe_str(v)

    raw = e.get("raw")
    if isinstance(raw, dict):
        for k in ("actor", "user", "username", "account", "subject_user", "target_user"):
            v = raw.get(k)
            if v:
                return _safe_str(v)

    return None


def _extract_resource(e: Dict[str, Any]) -> Optional[str]:
    for k in ("resource", "dst", "destination", "target", "path", "url", "port", "dst_port"):
        v = e.get(k)
        if v:
            return _safe_str(v)

    raw = e.get("raw")
    if isinstance(raw, dict):
        for k in ("resource", "dst", "destination", "target", "path", "url", "port", "dst_port"):
            v = raw.get(k)
            if v:
                return _safe_str(v)

    return None


def analyze_event(e: Dict[str, Any]) -> Dict[str, Any]:
    event_id = _safe_int(e.get("event_id"), 0)
    event_type = _safe_str(e.get("event_type", "unknown"))
    source = _safe_str(e.get("source", "unknown"))
    provider = _safe_str(e.get("provider", e.get("ProviderName", "")))
    message = _safe_str(e.get("message", ""))

    risk = _safe_int(e.get("risk", 0), 0)
    ip = _extract_ip(e)
    actor = _extract_actor(e)
    resource = _extract_resource(e)
    asset = _safe_str(e.get("asset", e.get("MachineName", "localhost")))

    rules: List[Dict[str, Any]] = []
    actions: List[str] = []
    reason = ""

    if "net_conn_allowed" in event_type.lower() or source.lower().startswith("network"):
        rules.append(
            {
                "id": "NET_RULE_allowed_connection",
                "title": "Allowed network connection observed",
                "why": "Connection was permitted (baseline telemetry)",
                "weight": 10,
            }
        )
        risk = min(risk or 10, 25) if risk == 0 else min(risk, 25)
        reason = "NET_RULE_allowed_connection → low risk"
        actions.extend(
            [
                "Confirm this destination/port is expected for the host or workload.",
                "Monitor for high frequency, unusual destination, or unexpected process linkage.",
                "If repeated with unusual ports or external IPs, escalate for investigation.",
            ]
        )

    if source.lower() in ("windows.security", "security") or event_type.lower() in (
        "failed_logon",
        "successful_logon",
        "privileged_logon",
        "account_lockout",
    ):
        if event_id == 4625 or event_type.lower() == "failed_logon":
            rules.append(
                {
                    "id": "WIN_SEC_4625_failed_logon",
                    "title": "Failed logon attempt",
                    "why": "EventID 4625 indicates authentication failure",
                    "weight": 85,
                }
            )
            risk = max(risk, 85)
            reason = "Repeated failed logons often indicate brute-force or credential misuse."
            actions.extend(
                [
                    "Check whether the username/account is valid and expected on this host.",
                    "Review the source IP and correlate with firewall/VPN logs.",
                    "If multiple failures in short time, block IP / apply rate limiting and reset credentials.",
                    "If this is an exposed service, verify MFA and harden remote access policies.",
                ]
            )

        elif event_id == 4740 or event_type.lower() == "account_lockout":
            rules.append(
                {
                    "id": "WIN_SEC_4740_account_lockout",
                    "title": "Account lockout",
                    "why": "EventID 4740 indicates lockout threshold reached",
                    "weight": 85,
                }
            )
            risk = max(risk, 85)
            reason = "Account lockout can be caused by brute-force, stale credentials, or misconfigured services."
            actions.extend(
                [
                    "Confirm whether lockout is legitimate (user typing wrong password) vs malicious attempts.",
                    "Identify the source machine causing lockouts (look for repeated failures).",
                    "Reset password and review MFA status if suspicious.",
                    "Check scheduled tasks/services using old credentials.",
                ]
            )

        elif event_id == 4672 or event_type.lower() == "privileged_logon":
            rules.append(
                {
                    "id": "WIN_SEC_4672_privileged_logon",
                    "title": "Privileged logon",
                    "why": "EventID 4672 indicates special privileges assigned",
                    "weight": 70,
                }
            )
            risk = max(risk, 70)
            reason = "Privileged logons should be monitored for unusual times/hosts."
            actions.extend(
                [
                    "Verify the account is authorized for privileged activity on this host.",
                    "Check if the logon time, host, or source IP is unusual for the account.",
                    "Correlate with process creation and admin tools execution.",
                ]
            )

        elif event_id == 4624 or event_type.lower() == "successful_logon":
            rules.append(
                {
                    "id": "WIN_SEC_4624_successful_logon",
                    "title": "Successful logon",
                    "why": "EventID 4624 indicates authentication success (context needed)",
                    "weight": 35,
                }
            )
            risk = max(risk, 35) if risk == 0 else max(risk, 35)
            reason = "Successful logon is normal but can be risky if unusual (new IP, odd hours, privileged account)."
            actions.extend(
                [
                    "Confirm whether the account and logon type match expected behavior.",
                    "If from an unfamiliar IP/host, correlate with VPN and device inventory.",
                    "If privileged account, ensure activity is approved and logged.",
                ]
            )

    if source.lower() in ("windows.application", "application"):
        msg_l = (message or "").lower()
        if "error" in msg_l or "critical" in msg_l or "failed" in msg_l:
            rules.append(
                {
                    "id": "WIN_APP_error_signal",
                    "title": "Application error/critical signal",
                    "why": "Message indicates error/critical/failure keywords",
                    "weight": 45,
                }
            )
            risk = max(risk, 45)
            if not reason:
                reason = "Application errors may indicate instability, misconfiguration, or security tool detections."
            actions.extend(
                [
                    "Identify the failing application/service and check recent changes/updates.",
                    "Review related logs around the same timestamp for cascading failures.",
                    "If security tools are involved (Defender/AV), confirm detection status and remediation steps.",
                ]
            )

    if not rules:
        rules.append(
            {
                "id": "GEN_base_telemetry",
                "title": "Baseline event telemetry",
                "why": "No high-confidence rule matched (v1)",
                "weight": max(10, risk or 10),
            }
        )
        if not reason:
            reason = "No specific detection rule matched; event recorded for monitoring."
        if not actions:
            actions = [
                "Review event context (source, host, user) and determine if expected.",
                "If suspicious, correlate with nearby events and endpoint/network telemetry.",
            ]
        if risk == 0:
            risk = 20

    seen = set()
    dedup_actions: List[str] = []
    for a in actions:
        k = a.strip().lower()
        if k and k not in seen:
            seen.add(k)
            dedup_actions.append(a)

    severity = "low"
    if risk >= 85:
        severity = "high"
    elif risk >= 70:
        severity = "medium"

    key_fields: Dict[str, Any] = {
        "Asset": asset or "-",
        "Source": source or "-",
        "Event Type": event_type or "-",
        "Event ID": event_id if event_id else "-",
    }

    if actor:
        key_fields["Actor"] = actor
    if ip:
        key_fields["IP"] = ip
    if resource:
        key_fields["Resource"] = resource
    if provider:
        key_fields["Provider"] = provider
    if e.get("timestamp") or e.get("ingested_at"):
        key_fields["Time (Local)"] = e.get("timestamp") or e.get("ingested_at")

    return {
        "event_id": e.get("id"),
        "title": f"{source} • {event_type}",
        "severity": severity,
        "risk": risk,
        "reason": reason,
        "rules_triggered": rules,
        "recommended_actions": dedup_actions,
        "key_fields": key_fields,
        "raw_event": e,
    }


@app.get("/")
def root():
    return {"status": "ok", "service": "isms-backend"}


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/status")
def status():
    return {
        "ok": True,
        "service": "isms-backend",
        "version": "0.4.0",
        "server_time_utc": now_utc_iso(),
        "events_buffered": len(EVENTS),
        "alerts_buffered": len(ALERTS),
        "cases_buffered": len(CASES),
        "max_events": MAX_EVENTS,
    }


@app.post("/ingest")
def ingest_event(evt: Dict[str, Any]):
    evt = dict(evt or {})
    evt.setdefault("id", f"evt-{int(datetime.now().timestamp() * 1000)}")
    evt.setdefault("event_type", "unknown")
    evt.setdefault("risk", 0)
    evt.setdefault("timestamp", now_utc_iso())
    evt.setdefault("ingested_at", now_utc_iso())

    eid = str(evt.get("id"))
    evt["id"] = eid

    EVENTS.append(evt)
    EVENT_BY_ID[eid] = evt

    processed = process_event(evt)

    created_cases = 0
    merged_cases = 0

    for item in processed.get("results", []):
        alert = item.get("alert")
        case = item.get("case")

        if isinstance(case, dict):
            merge_target = _find_mergeable_case(case)

            if merge_target is None:
                CASES.append(case)
                CASE_BY_ID[str(case.get("case_id"))] = case
                final_case = case
                created_cases += 1
            else:
                final_case = _merge_case(merge_target, case)
                merged_cases += 1

            case_id = str(final_case.get("case_id"))
        else:
            final_case = None
            case_id = None

        if isinstance(alert, dict):
            if case_id:
                alert["case_id"] = case_id
                if isinstance(alert.get("analysis"), dict):
                    alert["analysis"]["case_id"] = case_id

            ALERTS.append(alert)
            ALERT_BY_ID[str(alert.get("id"))] = alert

    _trim_store(EVENTS, EVENT_BY_ID, MAX_EVENTS, "id")
    _trim_store(ALERTS, ALERT_BY_ID, MAX_ALERTS, "id")
    _trim_store(CASES, CASE_BY_ID, MAX_CASES, "case_id")

    return {
        "ok": True,
        "event_id": eid,
        "detections": processed.get("detections", []),
        "alerts_created": len(processed.get("results", [])),
        "cases_created": created_cases,
        "cases_merged": merged_cases,
        "count": len(EVENTS),
    }


@app.get("/events")
def list_events(limit: int = 80):
    limit = _clamp(limit, 1, 500)
    items = list(EVENTS)
    items.sort(key=_event_time_key, reverse=True)
    return items[:limit]


@app.get("/alerts")
def list_alerts(limit: int = 50, min_risk: int = 0):
    limit = _clamp(limit, 1, 200)
    min_risk = _clamp(_safe_int(min_risk, 0), 0, 100)

    items = list(ALERTS)
    items.sort(key=_alert_time_key, reverse=True)

    out: List[Dict[str, Any]] = []
    for a in items:
        r = _safe_int(a.get("risk", 0), 0)
        if r >= min_risk:
            out.append(a)
        if len(out) >= limit:
            break

    return out


@app.get("/cases")
def list_cases(limit: int = 50):
    limit = _clamp(limit, 1, 200)
    items = list(CASES)
    items.sort(key=_case_time_key, reverse=True)
    return items[:limit]


@app.get("/analyze/{event_id}")
def analyze(event_id: str):
    e = EVENT_BY_ID.get(event_id)
    if not e:
        raise HTTPException(status_code=404, detail="event not found")
    return analyze_event(e)