import os
import time
from datetime import datetime, timezone
from typing import Dict, Tuple

import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
ASSET_NAME = os.getenv("FILE_MONITOR_ASSET", os.getenv("COMPUTERNAME", "localhost")).strip() or "localhost"

USERPROFILE = os.environ.get("USERPROFILE", "")
WATCH_PATHS = [
    os.path.join(USERPROFILE, "Desktop"),
    os.path.join(USERPROFILE, "Downloads"),
    os.path.join(USERPROFILE, "Documents"),
]

EVENT_DEDUPE_SECONDS = 12
LAST_EMITTED: Dict[Tuple[str, str], float] = {}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_path(path_text: str) -> str:
    return str(path_text).replace("/", "\\").lower()


def _should_emit(event_type: str, file_path: str) -> bool:
    now = time.time()
    key = (event_type, _normalize_path(file_path))

    last_ts = LAST_EMITTED.get(key)
    if last_ts is not None and (now - last_ts) < EVENT_DEDUPE_SECONDS:
        return False

    LAST_EMITTED[key] = now

    # Trim map occasionally
    if len(LAST_EMITTED) > 5000:
        stale_before = now - (EVENT_DEDUPE_SECONDS * 5)
        old_keys = [k for k, v in LAST_EMITTED.items() if v < stale_before]
        for k in old_keys[:2000]:
            LAST_EMITTED.pop(k, None)

    return True


def post_event(event: Dict) -> None:
    url = f"{API_BASE_URL}/ingest"
    response = requests.post(url, json=event, timeout=10)
    response.raise_for_status()


def build_event(event_type: str, file_path: str) -> Dict:
    timestamp = utc_now_iso()
    return {
        "id": f"file-{event_type}-{abs(hash((file_path, timestamp)))}",
        "source": "host.file",
        "event_type": event_type,
        "timestamp": timestamp,
        "ingested_at": timestamp,
        "asset": ASSET_NAME,
        "file_path": file_path,
        "username": os.environ.get("USERNAME", ""),
        "risk": 0,
        "raw": {
            "file_path": file_path,
            "event_type": event_type,
        },
    }


class ISMSFileEventHandler(FileSystemEventHandler):
    def _emit(self, event_type: str, file_path: str) -> None:
        if not file_path:
            return

        if not _should_emit(event_type, file_path):
            return

        try:
            event = build_event(event_type, file_path)
            post_event(event)
            print(f"[file_monitor] emitted {event_type}: {file_path}")
        except Exception as exc:
            print(f"[file_monitor] failed to post file event: {exc}")

    def on_created(self, event):
        if event.is_directory:
            return
        self._emit("file_created", event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._emit("file_modified", event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._emit("file_deleted", event.src_path)


def main() -> None:
    observer = Observer()
    handler = ISMSFileEventHandler()

    print(f"[file_monitor] starting; API_BASE_URL={API_BASE_URL}, asset={ASSET_NAME}")

    active_paths = []
    for path in WATCH_PATHS:
        if path and os.path.exists(path):
            observer.schedule(handler, path, recursive=True)
            active_paths.append(path)
            print(f"[file_monitor] watching: {path}")

    if not active_paths:
        print("[file_monitor] no valid watch paths found")
        return

    observer.start()

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()
    finally:
        observer.join()


if __name__ == "__main__":
    main()