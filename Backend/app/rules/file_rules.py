from pathlib import Path
from typing import Any, Dict, List


SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".js",
    ".vbs",
    ".hta",
    ".scr",
}

IMPORTANT_USER_FILE_EXTENSIONS = {
    ".txt",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".csv",
}

MONITORED_USER_PATH_KEYWORDS = [
    "\\desktop\\",
    "\\downloads\\",
    "\\documents\\",
    "/desktop/",
    "/downloads/",
    "/documents/",
]

IGNORED_FILE_NAMES = {
    "thumbs.db",
    "desktop.ini",
    "index.html",
    "dist.js",
}

IGNORED_PREFIXES = (
    "~$",
    ".~",
)

IGNORED_SUFFIXES = (
    ".tmp",
    ".temp",
    ".part",
    ".partial",
    ".crdownload",
    ".download",
    ".bak",
    ".cache",
    ".lnk",
    ".lock",
)

LOW_VALUE_PATH_KEYWORDS = [
    "\\appdata\\local\\temp\\",
    "\\temp\\",
    "\\tmp\\",
    "\\cache\\",
    "\\microsoft\\windows\\recent\\",
    "\\node_modules\\",
    "\\dist\\",
    "\\build\\",
    "\\.git\\",
    "\\frontend\\dist\\",
    "\\frontend\\node_modules\\",
]

# New: suppress self-noise from your own project/runtime paths
PROJECT_SELF_NOISE_KEYWORDS = [
    "\\isms\\backend\\",
    "\\isms\\frontend\\",
    "\\isms\\scripts\\",
    "\\backend\\.venv\\",
    "\\backend\\app\\",
    "\\frontend\\src\\",
    "\\frontend\\public\\",
    "\\frontend\\node_modules\\",
    "\\frontend\\dist\\",
]


def _s(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _normalize_path(path_text: str) -> str:
    return path_text.replace("/", "\\").lower()


def _file_name(path_text: str) -> str:
    try:
        return Path(path_text).name
    except Exception:
        return ""


def _file_suffix(path_text: str) -> str:
    try:
        return Path(path_text).suffix.lower()
    except Exception:
        return ""


def _should_ignore_file_event(file_path: str) -> bool:
    if not file_path:
        return True

    normalized = _normalize_path(file_path)
    name = _file_name(file_path).lower()

    if name in IGNORED_FILE_NAMES:
        return True

    if any(name.startswith(prefix) for prefix in IGNORED_PREFIXES):
        return True

    if any(name.endswith(suffix) for suffix in IGNORED_SUFFIXES):
        return True

    if any(keyword in normalized for keyword in LOW_VALUE_PATH_KEYWORDS):
        return True

    if any(keyword in normalized for keyword in PROJECT_SELF_NOISE_KEYWORDS):
        return True

    return False


def _is_in_monitored_user_path(file_path: str) -> bool:
    normalized = _normalize_path(file_path)
    return any(k in normalized for k in MONITORED_USER_PATH_KEYWORDS)


def build_file_detections(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    detections: List[Dict[str, Any]] = []

    file_path = _s(event.get("file_path"))
    event_type = _s(event.get("event_type")).lower()
    username = _s(event.get("username"))
    asset = _s(event.get("asset"), "localhost")

    if _should_ignore_file_event(file_path):
        return detections

    suffix = _file_suffix(file_path)
    name = _file_name(file_path)

    signals = {
        "asset": asset,
        "actor": username,
        "file_path": file_path or "-",
        "file_name": name or "-",
        "file_extension": suffix or "-",
        "file_event_type": event_type or "-",
    }

    in_user_path = _is_in_monitored_user_path(file_path)
    is_suspicious_ext = suffix in SUSPICIOUS_EXTENSIONS
    is_important_user_file = suffix in IMPORTANT_USER_FILE_EXTENSIONS

    if not in_user_path:
        return detections

    if event_type == "file_created":
        if is_suspicious_ext:
            detections.append(
                {
                    "rule_id": "FILE_CREATED_SUSPICIOUS",
                    "title": f"Suspicious file created: {name or 'unknown'}",
                    "severity": "medium",
                    "risk": 74,
                    "reason": "A file with a suspicious executable or script extension was created in a monitored user path.",
                    "recommended_actions": [
                        "Verify whether the file creation is expected for the user and host.",
                        "Inspect the file origin and related process activity.",
                        "If unknown, scan the file and correlate with process/network events.",
                    ],
                    "signals": signals,
                }
            )
        elif is_important_user_file:
            detections.append(
                {
                    "rule_id": "FILE_CREATED_USER_FILE",
                    "title": f"User file created in monitored path: {name or 'unknown'}",
                    "severity": "low",
                    "risk": 48,
                    "reason": "A user-relevant file was created in a monitored Desktop/Downloads/Documents path.",
                    "recommended_actions": [
                        "Confirm whether the file creation is expected.",
                        "If suspicious, review recent downloads and process activity.",
                    ],
                    "signals": signals,
                }
            )

    elif event_type == "file_modified":
        if is_suspicious_ext:
            detections.append(
                {
                    "rule_id": "FILE_MODIFIED_SUSPICIOUS",
                    "title": f"Suspicious file modified: {name or 'unknown'}",
                    "severity": "medium",
                    "risk": 70,
                    "reason": "A suspicious executable or script-like file was modified in a monitored user path.",
                    "recommended_actions": [
                        "Confirm whether the modification is expected.",
                        "Review recent process activity associated with the file.",
                        "If unexpected, inspect the file contents and origin.",
                    ],
                    "signals": signals,
                }
            )
        elif is_important_user_file:
            detections.append(
                {
                    "rule_id": "FILE_MODIFIED_USER_FILE",
                    "title": f"User file modified in monitored path: {name or 'unknown'}",
                    "severity": "low",
                    "risk": 52,
                    "reason": "A user-relevant file was modified in a monitored Desktop/Downloads/Documents path.",
                    "recommended_actions": [
                        "Confirm whether the modification is expected.",
                        "If suspicious, review related user and process activity.",
                    ],
                    "signals": signals,
                }
            )

    elif event_type == "file_deleted":
        if is_suspicious_ext:
            detections.append(
                {
                    "rule_id": "FILE_DELETED_SUSPICIOUS",
                    "title": f"Suspicious file deleted: {name or 'unknown'}",
                    "severity": "medium",
                    "risk": 72,
                    "reason": "A suspicious executable or script-like file was deleted in a monitored user path.",
                    "recommended_actions": [
                        "Confirm whether the deletion was intentional.",
                        "Check for cleanup/tampering behavior and related process activity.",
                    ],
                    "signals": signals,
                }
            )
        elif is_important_user_file:
            detections.append(
                {
                    "rule_id": "FILE_DELETED_USER_FILE",
                    "title": f"User file deleted in monitored path: {name or 'unknown'}",
                    "severity": "medium",
                    "risk": 64,
                    "reason": "A user-relevant file was deleted in a monitored Desktop/Downloads/Documents path.",
                    "recommended_actions": [
                        "Confirm whether the deletion was intentional.",
                        "Check recent user activity and recycle-bin/recovery context if needed.",
                    ],
                    "signals": signals,
                }
            )

    return detections