import json
import time
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

INGEST_URL = "http://127.0.0.1:8000/ingest"
CHANNELS = ["Application", "Security"]
POLL_SECONDS = 3
MAX_EVENTS_PER_POLL = 250  # per channel

SCRIPT_DIR = Path(__file__).resolve().parent
BOOKMARK_FILE = SCRIPT_DIR / "collector_bookmarks.json"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_bookmarks() -> Dict[str, str]:
    if BOOKMARK_FILE.exists():
        try:
            return json.loads(BOOKMARK_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_bookmarks(bm: Dict[str, str]) -> None:
    BOOKMARK_FILE.write_text(json.dumps(bm, indent=2), encoding="utf-8")


def post_json(url: str, payload: Dict[str, Any]) -> bool:
    data = json.dumps(payload)
    try:
        r = subprocess.run(
            ["curl", "-s", "-X", "POST", url, "-H", "Content-Type: application/json", "-d", data],
            capture_output=True,
            text=True,
            timeout=15
        )
        return r.returncode == 0
    except Exception:
        return False


def read_events_from_channel(channel: str, last_record_id: Optional[int]) -> List[Dict[str, Any]]:
    ps = f"""
$last = {last_record_id if last_record_id is not None else 0}
Get-WinEvent -LogName "{channel}" -MaxEvents {MAX_EVENTS_PER_POLL} |
    Where-Object {{ $_.RecordId -gt $last }} |
    Sort-Object RecordId |
    ForEach-Object {{
        [PSCustomObject]@{{
            RecordId = $_.RecordId
            TimeCreated = $_.TimeCreated.ToUniversalTime().ToString("o")
            Id = $_.Id
            ProviderName = $_.ProviderName
            LevelDisplayName = $_.LevelDisplayName
            MachineName = $_.MachineName
            LogName = "{channel}"
            Message = $_.Message
            Xml = $_.ToXml()
        }}
    }} | ConvertTo-Json -Depth 5
"""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=30
        )
        if out.returncode != 0:
            err = (out.stderr or "").strip()
            if err:
                print(f"[collector] {channel}: PowerShell error: {err}")
            return []

        if not out.stdout.strip():
            return []

        data = json.loads(out.stdout)
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
        return []
    except Exception as e:
        print(f"[collector] {channel}: exception reading events: {e}")
        return []


def risk_score(channel: str, event_id: int, level: str) -> int:
    if channel.lower() == "security":
        if event_id in (4625, 4740):
            return 85
        if event_id in (4672,):
            return 70
        if event_id in (4624,):
            return 40
        return 25

    if level and level.lower() in ("error", "critical"):
        return 45
    return 20


def main():
    print(f"[collector] ingest -> {INGEST_URL}")
    print(f"[collector] channels: {CHANNELS}")
    print(f"[collector] poll: {POLL_SECONDS}s")
    print(f"[collector] bookmark file: {BOOKMARK_FILE}")

    bookmarks = load_bookmarks()
    last_ids: Dict[str, int] = {}

    for ch in CHANNELS:
        try:
            last_ids[ch] = int(bookmarks.get(ch, "0"))
        except Exception:
            last_ids[ch] = 0

    while True:
        total_new = 0

        for ch in CHANNELS:
            last_id = last_ids.get(ch, 0)
            events = read_events_from_channel(ch, last_id)

            if not events:
                print(f"[collector] {ch}: 0 new events")
                continue

            sent = 0
            for ev in events:
                rid = int(ev.get("RecordId", 0) or 0)
                eid = int(ev.get("Id", 0) or 0)
                level = str(ev.get("LevelDisplayName", "") or "")
                ts = str(ev.get("TimeCreated", "") or utc_now_iso())
                machine = str(ev.get("MachineName", "") or "localhost")
                provider = str(ev.get("ProviderName", "") or "")

                payload = {
                    "id": f"win-{ch.lower()}-{rid}",
                    "timestamp": ts,
                    "event_type": "windows_event" if ch.lower() != "security" else "security_event",
                    "event_id": eid,
                    "source": f"windows.{ch.lower()}",
                    "asset": machine,
                    "provider": provider,
                    "level": level,
                    "message": (ev.get("Message") or "")[:5000],
                    "risk": risk_score(ch, eid, level),
                    "raw": ev.get("Xml") or ev.get("Message") or "",
                    "ingested_at": utc_now_iso(),
                }

                ok = post_json(INGEST_URL, payload)
                if ok:
                    sent += 1
                    if rid > last_ids.get(ch, 0):
                        last_ids[ch] = rid

            bookmarks[ch] = str(last_ids.get(ch, 0))
            save_bookmarks(bookmarks)

            print(f"[collector] {ch}: {sent} new events (bookmark -> {bookmarks[ch]})")
            total_new += sent

        print(f"[collector] cycle total: {total_new}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
