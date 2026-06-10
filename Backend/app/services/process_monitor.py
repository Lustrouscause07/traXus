import os
import time
from datetime import datetime, timezone
from typing import Dict, Iterable, Set, Tuple

import psutil
import requests


API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
POLL_INTERVAL_SECONDS = float(os.getenv("PROCESS_POLL_INTERVAL_SECONDS", "8"))
ASSET_NAME = os.getenv("PROCESS_MONITOR_ASSET", os.getenv("COMPUTERNAME", "localhost")).strip() or "localhost"

SEEN_RECENT: Set[Tuple[int, float]] = set()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_cmdline_join(value) -> str:
    try:
        if not value:
            return ""
        if isinstance(value, (list, tuple)):
            return " ".join(str(x) for x in value if x is not None).strip()
        return str(value).strip()
    except Exception:
        return ""


def iter_process_snapshots() -> Iterable[Dict]:
    for proc in psutil.process_iter(
        [
            "pid",
            "name",
            "exe",
            "username",
            "create_time",
            "memory_info",
            "cpu_percent",
            "cmdline",
        ]
    ):
        try:
            info = proc.info
            mem_info = info.get("memory_info")
            rss_mb = round((mem_info.rss / (1024 * 1024)), 2) if mem_info else 0.0
            command_line = _safe_cmdline_join(info.get("cmdline"))

            yield {
                "pid": info.get("pid"),
                "process_name": info.get("name") or "",
                "process_path": info.get("exe") or "",
                "username": info.get("username") or "",
                "create_time": info.get("create_time") or 0,
                "memory_mb": rss_mb,
                "cpu_percent": float(info.get("cpu_percent") or 0.0),
                "command_line": command_line,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue


def build_event(snapshot: Dict) -> Dict:
    pid = snapshot.get("pid")
    process_name = snapshot.get("process_name") or "unknown"
    create_time = snapshot.get("create_time") or 0

    return {
        "id": f"proc-{pid}-{int(create_time)}",
        "source": "host.process",
        "event_type": "process_snapshot",
        "timestamp": utc_now_iso(),
        "ingested_at": utc_now_iso(),
        "asset": ASSET_NAME,
        "pid": pid,
        "process_name": process_name,
        "process_path": snapshot.get("process_path") or "",
        "username": snapshot.get("username") or "",
        "command_line": snapshot.get("command_line") or "",
        "cpu_percent": snapshot.get("cpu_percent") or 0.0,
        "memory_mb": snapshot.get("memory_mb") or 0.0,
        "risk": 0,
        "raw": snapshot,
    }


def should_emit(snapshot: Dict) -> bool:
    pid = snapshot.get("pid")
    create_time = snapshot.get("create_time") or 0
    key = (int(pid or 0), float(create_time))

    if key in SEEN_RECENT:
        return False

    SEEN_RECENT.add(key)
    return True


def trim_seen(max_items: int = 5000) -> None:
    global SEEN_RECENT
    if len(SEEN_RECENT) > max_items:
        SEEN_RECENT = set(list(SEEN_RECENT)[-max_items:])


def post_event(event: Dict) -> None:
    url = f"{API_BASE_URL}/ingest"
    response = requests.post(url, json=event, timeout=10)
    response.raise_for_status()


def main() -> None:
    print(f"[process_monitor] starting; API_BASE_URL={API_BASE_URL}, asset={ASSET_NAME}")

    while True:
        emitted = 0
        for snapshot in iter_process_snapshots():
            if not should_emit(snapshot):
                continue

            event = build_event(snapshot)
            try:
                post_event(event)
                emitted += 1
            except Exception as exc:
                print(f"[process_monitor] failed to post process event: {exc}")

        trim_seen()
        print(f"[process_monitor] cycle complete; emitted={emitted}")
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()