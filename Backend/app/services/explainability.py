from typing import Any, Dict, List


def _s(value: Any, default: str = "-") -> str:
    if value is None:
        return default
    text = str(value)
    return text if text.strip() else default


def build_explainability(event: Dict[str, Any], detection: Dict[str, Any]) -> Dict[str, Any]:
    signals = detection.get("signals") or {}

    key_fields: List[List[str]] = [
        ["Asset", _s(signals.get("asset") or event.get("asset"))],
        ["Source", _s(event.get("source"))],
        ["Event Type", _s(event.get("event_type"))],
        ["Event ID", _s(event.get("event_id"))],
        ["Actor", _s(signals.get("actor") or event.get("username") or event.get("actor"))],
        ["Timestamp", _s(event.get("timestamp") or event.get("ingested_at"))],
    ]

    # Process-specific enrichment
    process_name = signals.get("process_name") or event.get("process_name")
    process_path = signals.get("process_path") or event.get("process_path")
    command_line = signals.get("command_line") or event.get("command_line")
    pid = signals.get("pid") or event.get("pid")
    cpu_percent = signals.get("cpu_percent") or event.get("cpu_percent")
    memory_mb = signals.get("memory_mb") or event.get("memory_mb")

    if process_name:
        key_fields.append(["Process Name", _s(process_name)])
    if process_path:
        key_fields.append(["Process Path", _s(process_path)])
    if command_line:
        key_fields.append(["Command Line", _s(command_line)])
    if pid:
        key_fields.append(["PID", _s(pid)])
    if cpu_percent is not None and str(cpu_percent) != "":
        key_fields.append(["CPU %", _s(cpu_percent)])
    if memory_mb is not None and str(memory_mb) != "":
        key_fields.append(["Memory MB", _s(memory_mb)])

    # Network-specific enrichment
    remote_ip = signals.get("remote_ip") or event.get("remote_ip")
    remote_port = signals.get("remote_port") or event.get("remote_port")
    local_ip = signals.get("local_ip") or event.get("local_ip")
    local_port = signals.get("local_port") or event.get("local_port")
    status = signals.get("status") or event.get("status")

    if remote_ip:
        key_fields.append(["Remote IP", _s(remote_ip)])
    if remote_port:
        key_fields.append(["Remote Port", _s(remote_port)])
    if local_ip:
        key_fields.append(["Local IP", _s(local_ip)])
    if local_port:
        key_fields.append(["Local Port", _s(local_port)])
    if status:
        key_fields.append(["Connection Status", _s(status)])

    # File-specific enrichment
    file_name = signals.get("file_name") or event.get("file_name")
    file_path = signals.get("file_path") or event.get("file_path")
    file_extension = signals.get("file_extension") or event.get("file_extension")
    file_event_type = signals.get("file_event_type") or event.get("event_type")

    if file_name:
        key_fields.append(["File Name", _s(file_name)])
    if file_path:
        key_fields.append(["File Path", _s(file_path)])
    if file_extension:
        key_fields.append(["Extension", _s(file_extension)])
    if file_event_type and str(event.get("source") or "").lower() in ("host.file", "file", "watchdog.file"):
        key_fields.append(["File Event Type", _s(file_event_type)])

    return {
        "severity": str(detection.get("severity") or "low"),
        "risk": int(detection.get("risk") or 0),
        "reason": str(detection.get("reason") or "Backend analysis generated."),
        "rules": [str(detection.get("rule_id") or "GENERIC_RULE")],
        "actions": list(detection.get("recommended_actions") or []),
        "key_fields": key_fields,
        "signals": {str(k): _s(v) for k, v in signals.items()},
        "raw_event": event,
    }