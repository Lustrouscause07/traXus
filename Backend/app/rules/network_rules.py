from ipaddress import ip_address
from typing import Any, Dict, List


SUSPICIOUS_PORTS = {
    21,
    23,
    135,
    445,
    1433,
    1521,
    3306,
    3389,
    4444,
    5555,
    5900,
}


def _s(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _i(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _is_private_ip(ip_text: str) -> bool:
    try:
        return ip_address(ip_text).is_private
    except Exception:
        return False


def _is_public_ip(ip_text: str) -> bool:
    try:
        ip = ip_address(ip_text)
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except Exception:
        return False


def build_network_detections(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    detections: List[Dict[str, Any]] = []

    remote_ip = _s(event.get("remote_ip"))
    remote_port = _i(event.get("remote_port"), 0)
    local_ip = _s(event.get("local_ip"))
    local_port = _i(event.get("local_port"), 0)
    process_name = _s(event.get("process_name")).lower()
    process_path = _s(event.get("process_path"))
    username = _s(event.get("username"))
    asset = _s(event.get("asset"), "localhost")
    status = _s(event.get("status"), "unknown")

    signals = {
        "asset": asset,
        "actor": username,
        "process_name": process_name or "-",
        "process_path": process_path or "-",
        "remote_ip": remote_ip or "-",
        "remote_port": str(remote_port) if remote_port else "-",
        "local_ip": local_ip or "-",
        "local_port": str(local_port) if local_port else "-",
        "status": status or "-",
    }

    if remote_ip and _is_public_ip(remote_ip):
        detections.append(
            {
                "rule_id": "NET_EXTERNAL_CONNECTION",
                "title": f"External network connection observed: {remote_ip}",
                "severity": "medium",
                "risk": 70,
                "reason": "Process established a connection to a public external IP address.",
                "recommended_actions": [
                    "Verify whether the remote IP and destination are expected for this host and process.",
                    "Check whether the process regularly communicates externally.",
                    "Correlate with process execution, downloads, and user activity.",
                ],
                "signals": signals,
                # Final decision: alert only, never case by default
                "alert_only": True,
            }
        )

    if remote_port in SUSPICIOUS_PORTS:
        detections.append(
            {
                "rule_id": "NET_SUSPICIOUS_PORT",
                "title": f"Connection to sensitive/suspicious port observed: {remote_port}",
                "severity": "medium",
                "risk": 74,
                "reason": "Process connected to a port commonly associated with remote admin, legacy exposure, or sensitive services.",
                "recommended_actions": [
                    "Confirm whether the remote service and port are expected.",
                    "Check if this port is allowed by policy for the process/user.",
                    "Investigate if the connection aligns with normal host behavior.",
                ],
                "signals": signals,
            }
        )

    if remote_ip and _is_private_ip(remote_ip) and remote_port in {3389, 445, 135, 5900}:
        detections.append(
            {
                "rule_id": "NET_LATERAL_SERVICE_CONNECTION",
                "title": f"Internal lateral-service connection observed: {remote_ip}:{remote_port}",
                "severity": "medium",
                "risk": 76,
                "reason": "Connection targets a private-network service commonly involved in remote administration or lateral movement.",
                "recommended_actions": [
                    "Verify whether the source process is allowed to access this internal service.",
                    "Check if the target host is expected for the current user/asset.",
                    "Correlate with authentication and privilege activity.",
                ],
                "signals": signals,
            }
        )

    return detections