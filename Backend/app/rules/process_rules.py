from typing import Any, Dict, List


SUSPICIOUS_PROCESS_NAMES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wmic.exe",
    "bitsadmin.exe",
    "certutil.exe",
    "psexec.exe",
    "python.exe",
}

TEMP_PATH_KEYWORDS = [
    "\\temp\\",
    "/tmp/",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
]

HIGH_CPU_THRESHOLD = 80.0
HIGH_MEMORY_MB_THRESHOLD = 500.0


def _s(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _f(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _i(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def build_process_detections(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    detections: List[Dict[str, Any]] = []

    process_name = _s(event.get("process_name")).lower()
    process_path = _s(event.get("process_path")).lower()
    command_line = _s(event.get("command_line"))
    cpu_percent = _f(event.get("cpu_percent"), 0.0)
    memory_mb = _f(event.get("memory_mb"), 0.0)
    pid = _i(event.get("pid"), 0)
    username = _s(event.get("username"))
    asset = _s(event.get("asset"), "localhost")

    signals = {
        "asset": asset,
        "actor": username,
        "process_name": process_name or "-",
        "process_path": process_path or "-",
        "command_line": command_line or "-",
        "pid": str(pid) if pid else "-",
        "cpu_percent": str(cpu_percent),
        "memory_mb": str(memory_mb),
    }

    if process_name in SUSPICIOUS_PROCESS_NAMES:
        detections.append(
            {
                "rule_id": "PROC_SUSPICIOUS_EXECUTION",
                "title": f"Suspicious process execution: {process_name}",
                "severity": "medium",
                "risk": 72,
                "reason": f"Process {process_name} is commonly associated with script execution, LOLBins, or admin misuse.",
                "recommended_actions": [
                    "Verify whether this process execution is expected for the user and host.",
                    "Check parent process, command line, and recent authentication activity.",
                    "Correlate with file changes, network connections, or privilege escalation signals.",
                ],
                "signals": signals,
                "alert_only": True,
            }
        )

    if process_path and any(keyword in process_path for keyword in TEMP_PATH_KEYWORDS):
        detections.append(
            {
                "rule_id": "PROC_TEMP_PATH_EXECUTION",
                "title": "Process execution from temporary or suspicious path",
                "severity": "high",
                "risk": 86,
                "reason": "Executable launched from a temporary or low-trust directory, which is often suspicious.",
                "recommended_actions": [
                    "Inspect the executable path and verify file origin.",
                    "Check whether the file was recently dropped or downloaded.",
                    "If unknown, isolate the host and perform malware triage.",
                ],
                "signals": signals,
            }
        )

    if cpu_percent >= HIGH_CPU_THRESHOLD:
        detections.append(
            {
                "rule_id": "PROC_HIGH_CPU_SPIKE",
                "title": f"High CPU process activity: {process_name or 'unknown'}",
                "severity": "medium",
                "risk": 70,
                "reason": f"Process is consuming unusually high CPU ({cpu_percent:.1f}%).",
                "recommended_actions": [
                    "Confirm whether this CPU consumption is expected for the process.",
                    "Check if the process is looping, mining, or performing heavy scripted activity.",
                    "Correlate with user activity and recent file/network events.",
                ],
                "signals": signals,
                "alert_only": True,
            }
        )

    if memory_mb >= HIGH_MEMORY_MB_THRESHOLD:
        detections.append(
            {
                "rule_id": "PROC_HIGH_MEMORY_USAGE",
                "title": f"High memory process activity: {process_name or 'unknown'}",
                "severity": "low",
                "risk": 55,
                "reason": f"Process is consuming high memory ({memory_mb:.1f} MB).",
                "recommended_actions": [
                    "Confirm whether this memory usage is expected for the application.",
                    "Check for instability, memory leaks, or abuse by unwanted workloads.",
                ],
                "signals": signals,
                "alert_only": True,
            }
        )

    return detections