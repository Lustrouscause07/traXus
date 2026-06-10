import os
import time
from datetime import datetime, timezone
from typing import Dict, Iterable, Set, Tuple

import psutil
import requests


API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
POLL_INTERVAL_SECONDS = float(os.getenv("NETWORK_POLL_INTERVAL_SECONDS", "8"))
ASSET_NAME = os.getenv("NETWORK_MONITOR_ASSET", os.getenv("COMPUTERNAME", "localhost")).strip() or "localhost"

SEEN_RECENT: Set[Tuple[int, str, int, str, int]] = set()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def iter_connection_snapshots() -> Iterable[Dict]:
    try:
        connections = psutil.net_connections(kind="inet")
    except Exception:
        return []

    for conn in connections:
        try:
            laddr = conn.laddr if conn.laddr else None
            raddr = conn.raddr if conn.raddr else None

            pid = conn.pid or 0
            process_name = ""
            process_path = ""
            username = ""

            if pid:
                try:
                    proc = psutil.Process(pid)
                    process_name = proc.name() or ""
                    process_path = proc.exe() or ""
                    username = proc.username() or ""
                except Exception:
                    pass

            yield {
                "pid": int(pid),
                "local_ip": getattr(laddr, "ip", "") if laddr else "",
                "local_port": getattr(laddr, "port", 0) if laddr else 0,
                "remote_ip": getattr(raddr, "ip", "") if raddr else "",
                "remote_port": getattr(raddr, "port", 0) if raddr else 0,
                "status": str(conn.status or ""),
                "process_name": process_name,
                "process_path": process_path,
                "username": username,
            }
        except Exception:
            continue


def should_emit(snapshot: Dict) -> bool:
    key = (
        int(snapshot.get("pid") or 0),
        str(snapshot.get("local_ip") or ""),
        int(snapshot.get("local_port") or 0),
        str(snapshot.get("remote_ip") or ""),
        int(snapshot.get("remote_port") or 0),
    )

    if key in SEEN_RECENT:
        return False

    SEEN_RECENT.add(key)
    return True


def trim_seen(max_items: int = 8000) -> None:
    global SEEN_RECENT
    if len(SEEN_RECENT) > max_items:
        SEEN_RECENT = set(list(SEEN_RECENT)[-max_items:])


def build_event(snapshot: Dict) -> Dict:
    pid = int(snapshot.get("pid") or 0)
    remote_ip = str(snapshot.get("remote_ip") or "")
    remote_port = int(snapshot.get("remote_port") or 0)

    return {
        "id": f"net-{pid}-{snapshot.get('local_ip')}-{snapshot.get('local_port')}-{remote_ip}-{remote_port}",
        "source": "host.network",
        "event_type": "network_connection",
        "timestamp": utc_now_iso(),
        "ingested_at": utc_now_iso(),
        "asset": ASSET_NAME,
        "pid": pid,
        "local_ip": str(snapshot.get("local_ip") or ""),
        "local_port": int(snapshot.get("local_port") or 0),
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "status": str(snapshot.get("status") or ""),
        "process_name": str(snapshot.get("process_name") or ""),
        "process_path": str(snapshot.get("process_path") or ""),
        "username": str(snapshot.get("username") or ""),
        "risk": 0,
        "raw": snapshot,
    }


def post_event(event: Dict) -> None:
    url = f"{API_BASE_URL}/ingest"
    response = requests.post(url, json=event, timeout=10)
    response.raise_for_status()


def main() -> None:
    print(f"[network_monitor] starting; API_BASE_URL={API_BASE_URL}, asset={ASSET_NAME}")

    while True:
        emitted = 0
        for snapshot in iter_connection_snapshots():
            if not snapshot.get("remote_ip"):
                continue
            if not should_emit(snapshot):
                continue

            event = build_event(snapshot)
            try:
                post_event(event)
                emitted += 1
            except Exception as exc:
                print(f"[network_monitor] failed to post network event: {exc}")

        trim_seen()
        print(f"[network_monitor] cycle complete; emitted={emitted}")
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()