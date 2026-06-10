from typing import Any, Dict, List


IGNORED_ACTORS = {
    "",
    "-",
    "system",
    "local service",
    "network service",
    "anonymous logon",
    "dwm-1",
    "umfd-0",
    "umfd-1",
    "umfd-2",
    "umfd-3",
    "font driver host\\umfd-0",
    "font driver host\\umfd-1",
    "window manager\\dwm-1",
}

# Keep only meaningful user-facing logon types
MEANINGFUL_LOGON_TYPES = {2, 10, 11}
# 2 = Interactive
# 10 = RemoteInteractive / RDP
# 11 = CachedInteractive

NOISY_LOGON_TYPES = {3, 4, 5, 7, 8, 9}
# 3 = Network
# 4 = Batch
# 5 = Service
# 7 = Unlock
# 8 = NetworkCleartext
# 9 = NewCredentials


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _safe_raw_dict(event: Dict[str, Any]) -> Dict[str, Any]:
    raw = event.get("raw")
    if isinstance(raw, dict):
        return raw
    return {}


def _normalize_actor(actor: str) -> str:
    actor = (actor or "").strip().lower()
    return actor


def _is_ignored_actor(actor: str) -> bool:
    actor_norm = _normalize_actor(actor)

    if actor_norm in IGNORED_ACTORS:
        return True

    # machine accounts often end with $
    if actor_norm.endswith("$"):
        return True

    return False


def _extract_logon_type(raw: Dict[str, Any], event: Dict[str, Any]) -> int:
    return _safe_int(
        event.get("logon_type")
        or raw.get("LogonType")
        or raw.get("logon_type"),
        0,
    )


def build_windows_detections(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    detections: List[Dict[str, Any]] = []

    source = _safe_str(event.get("source")).lower()
    event_type = _safe_str(event.get("event_type")).lower()
    event_id = _safe_int(event.get("event_id"))
    raw = _safe_raw_dict(event)

    actor = _safe_str(
        event.get("actor")
        or raw.get("TargetUserName")
        or raw.get("SubjectUserName")
        or raw.get("user")
    )

    asset = _safe_str(
        event.get("asset")
        or raw.get("MachineName")
        or raw.get("ComputerName")
        or "localhost"
    )

    ip_address = _safe_str(
        event.get("ip")
        or raw.get("IpAddress")
        or raw.get("SourceIp")
        or raw.get("source_ip")
    )

    command_line = _safe_str(
        raw.get("CommandLine")
        or raw.get("ProcessCommandLine")
        or raw.get("command_line")
    ).lower()

    process_name = _safe_str(
        raw.get("NewProcessName")
        or raw.get("ProcessName")
        or raw.get("Image")
        or raw.get("process_name")
    ).lower()

    service_name = _safe_str(
        raw.get("ServiceName")
        or raw.get("service_name")
    )

    group_name = _safe_str(
        raw.get("GroupName")
        or raw.get("TargetSid")
        or raw.get("group_name")
    )

    logon_type = _extract_logon_type(raw, event)

    is_windows_security = "windows" in source or "security" in event_type

    if not is_windows_security:
        return detections

    actor_ignored = _is_ignored_actor(actor)

    if event_id == 4625:
        detections.append(
            {
                "rule_id": "WIN_AUTH_FAILED_LOGON",
                "title": "Windows failed logon",
                "severity": "medium",
                "risk": 72,
                "reason": "A Windows failed authentication event was detected.",
                "recommended_actions": [
                    "Review the affected username and source IP.",
                    "Check whether repeated failures are occurring.",
                    "Investigate for password spraying or brute-force attempts.",
                ],
                "signals": {
                    "event_id": event_id,
                    "actor": actor,
                    "asset": asset,
                    "ip": ip_address,
                    "logon_type": str(logon_type or "-"),
                },
            }
        )

    if event_id == 4624:
        # only keep meaningful user-facing successful logons
        if (not actor_ignored) and (logon_type in MEANINGFUL_LOGON_TYPES):
            detections.append(
                {
                    "rule_id": "WIN_AUTH_SUCCESS_LOGON",
                    "title": "Windows successful logon",
                    "severity": "low",
                    "risk": 35,
                    "reason": "A meaningful Windows successful logon event was recorded for a non-system account.",
                    "recommended_actions": [
                        "Validate whether the login was expected.",
                        "Correlate with earlier failures if this session looks suspicious.",
                    ],
                    "signals": {
                        "event_id": event_id,
                        "actor": actor,
                        "asset": asset,
                        "ip": ip_address,
                        "logon_type": str(logon_type or "-"),
                    },
                }
            )

    if event_id == 4672:
        # only keep privileged logons for real user/admin activity
        if (not actor_ignored) and (logon_type in MEANINGFUL_LOGON_TYPES):
            detections.append(
                {
                    "rule_id": "WIN_PRIVILEGED_LOGON",
                    "title": "Privileged logon detected",
                    "severity": "high",
                    "risk": 88,
                    "reason": "Special privileges were assigned during a meaningful user logon.",
                    "recommended_actions": [
                        "Confirm whether privileged access was expected.",
                        "Review nearby process creation and admin activity.",
                        "Escalate if the user or host is unusual.",
                    ],
                    "signals": {
                        "event_id": event_id,
                        "actor": actor,
                        "asset": asset,
                        "ip": ip_address,
                        "logon_type": str(logon_type or "-"),
                    },
                }
            )

    if event_id == 4688:
        suspicious_keywords = [
            "powershell",
            "cmd.exe",
            "encodedcommand",
            " -enc ",
            "wget",
            "curl",
            "certutil",
            "bitsadmin",
            "wmic",
            "rundll32",
            "mshta",
        ]

        matched = [
            keyword for keyword in suspicious_keywords
            if keyword in process_name or keyword in command_line
        ]

        if matched:
            detections.append(
                {
                    "rule_id": "WIN_SUSPICIOUS_PROCESS_CREATION",
                    "title": "Suspicious process creation",
                    "severity": "high",
                    "risk": 85,
                    "reason": "A suspicious command, script launcher, or LOLBin-like process was observed.",
                    "recommended_actions": [
                        "Inspect the process path and parent process.",
                        "Review the full command line.",
                        "Check whether the activity was administrative or malicious.",
                    ],
                    "signals": {
                        "event_id": event_id,
                        "actor": actor,
                        "asset": asset,
                        "process_name": process_name,
                        "command_line": command_line,
                        "matched_keywords": matched,
                    },
                }
            )

    if event_id == 4720:
        detections.append(
            {
                "rule_id": "WIN_ACCOUNT_CREATED",
                "title": "User account created",
                "severity": "high",
                "risk": 82,
                "reason": "A new local or domain account creation event was detected.",
                "recommended_actions": [
                    "Verify whether the account creation was authorized.",
                    "Check who created the account and from where.",
                    "Review subsequent login activity for the new account.",
                ],
                "signals": {
                    "event_id": event_id,
                    "actor": actor,
                    "asset": asset,
                },
            }
        )

    if event_id == 4722:
        detections.append(
            {
                "rule_id": "WIN_ACCOUNT_ENABLED",
                "title": "User account enabled",
                "severity": "medium",
                "risk": 74,
                "reason": "A previously disabled user account was enabled.",
                "recommended_actions": [
                    "Confirm whether the enable action was expected.",
                    "Review the account’s recent authentication history.",
                ],
                "signals": {
                    "event_id": event_id,
                    "actor": actor,
                    "asset": asset,
                },
            }
        )

    if event_id == 4724:
        detections.append(
            {
                "rule_id": "WIN_PASSWORD_RESET_ATTEMPT",
                "title": "Password reset attempt",
                "severity": "high",
                "risk": 83,
                "reason": "A password reset attempt was observed.",
                "recommended_actions": [
                    "Verify whether the reset was requested and approved.",
                    "Review the account for takeover indicators.",
                ],
                "signals": {
                    "event_id": event_id,
                    "actor": actor,
                    "asset": asset,
                },
            }
        )

    if event_id in (4728, 4732):
        detections.append(
            {
                "rule_id": "WIN_PRIVILEGED_GROUP_MEMBER_ADDED",
                "title": "User added to privileged group",
                "severity": "high",
                "risk": 90,
                "reason": "A user was added to a security-sensitive or privileged group.",
                "recommended_actions": [
                    "Validate whether the group membership change was authorized.",
                    "Review who made the change and the target group.",
                    "Escalate if this was unexpected.",
                ],
                "signals": {
                    "event_id": event_id,
                    "actor": actor,
                    "asset": asset,
                    "group_name": group_name,
                },
            }
        )

    if event_id == 1102:
        detections.append(
            {
                "rule_id": "WIN_AUDIT_LOG_CLEARED",
                "title": "Audit log cleared",
                "severity": "high",
                "risk": 95,
                "reason": "The Windows audit log was cleared, which may indicate anti-forensics.",
                "recommended_actions": [
                    "Treat this as highly suspicious unless clearly authorized.",
                    "Investigate preceding admin and process activity immediately.",
                    "Preserve available evidence from other sources.",
                ],
                "signals": {
                    "event_id": event_id,
                    "actor": actor,
                    "asset": asset,
                },
            }
        )

    if event_id in (4697, 7045):
        detections.append(
            {
                "rule_id": "WIN_SERVICE_CREATED",
                "title": "Service installed or created",
                "severity": "high",
                "risk": 86,
                "reason": "A Windows service creation/install event was detected.",
                "recommended_actions": [
                    "Validate whether the service is legitimate.",
                    "Check the binary path and startup behavior.",
                    "Review for persistence or malware installation.",
                ],
                "signals": {
                    "event_id": event_id,
                    "actor": actor,
                    "asset": asset,
                    "service_name": service_name,
                },
            }
        )

    return detections