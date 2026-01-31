import json
import subprocess
import time
import urllib.request
from typing import Optional

BACKEND_INGEST_URL = "http://127.0.0.1:8000/ingest"
CHANNEL = "Application"  # later: "Security" (admin may be required)
POLL_SECONDS = 5
MAX_PER_POLL = 12

SEEN = set()
SEEN_MAX = 5000

def post_event(evt: dict) -> None:
    data = json.dumps(evt).encode("utf-8")
    req = urllib.request.Request(
        BACKEND_INGEST_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()

def query_events(channel: str, max_events: int) -> list[str]:
    cmd = ["wevtutil", "qe", channel, f"/c:{max_events}", "/rd:true", "/f:xml"]
    out = subprocess.check_output(
        cmd,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    parts = out.split("</Event>")
    events = []
    for p in parts:
        p = p.strip()
        if "<Event" in p:
            events.append(p + "</Event>")
    return events

def extract_tag(xml: str, tag: str) -> Optional[str]:
    """
    Extract value inside <Tag>value</Tag> even if attributes exist: <Tag attr="x">value</Tag>
    """
    open_tag = f"<{tag}"
    if open_tag not in xml:
        return None
    try:
        after = xml.split(open_tag, 1)[1]
        val = after.split(">", 1)[1].split("<", 1)[0].strip()
        return val if val else None
    except Exception:
        return None

def extract_attr(xml: str, tag: str, attr: str) -> Optional[str]:
    """
    Extract attribute value like: <Provider Name="...">
    """
    open_tag = f"<{tag}"
    if open_tag not in xml:
        return None
    try:
        chunk = xml.split(open_tag, 1)[1]
        head = chunk.split(">", 1)[0]
        key = f'{attr}="'
        if key not in head:
            return None
        return head.split(key, 1)[1].split('"', 1)[0]
    except Exception:
        return None

def fingerprint_event(xml: str) -> str:
    """
    Prefer EventRecordID for dedup (best). Fallback to EventID + provider + XML slice.
    """
    record_id = extract_tag(xml, "EventRecordID")
    event_id = extract_tag(xml, "EventID") or "unknown"
    provider = extract_attr(xml, "Provider", "Name") or "unknown"
    if record_id:
        return f"{CHANNEL}|rec:{record_id}|eid:{event_id}|prov:{provider}"
    return f"{CHANNEL}|eid:{event_id}|prov:{provider}|xml:{xml[:300]}"

def map_level(level: Optional[str]) -> str:
    # Windows "Level" numbers: 1=Critical,2=Error,3=Warning,4=Information,5=Verbose
    if not level:
        return "unknown"
    return {
        "1": "critical",
        "2": "error",
        "3": "warning",
        "4": "info",
        "5": "verbose",
    }.get(level.strip(), level.strip())

def risk_for(event_id: str, level_name: str) -> int:
    """
    Application logs vary; use heuristic:
    - errors/warnings raise baseline risk
    - security-like IDs still mapped if you later switch CHANNEL.
    """
    # Security mappings (useful later if CHANNEL=Security)
    if event_id == "4625":
        return 80
    if event_id == "4624":
        return 25
    if event_id == "4672":
        return 70
    if event_id == "4720":
        return 75
    if event_id == "4728":
        return 85

    # Application heuristic
    if level_name == "critical":
        return 70
    if level_name == "error":
        return 55
    if level_name == "warning":
        return 40
    if level_name == "info":
        return 20
    return 15

def normalize(xml_event: str, idx: int) -> dict:
    event_id = extract_tag(xml_event, "EventID") or "unknown"
    record_id = extract_tag(xml_event, "EventRecordID")
    computer = extract_tag(xml_event, "Computer")
    provider = extract_attr(xml_event, "Provider", "Name")
    level_num = extract_tag(xml_event, "Level")
    level_name = map_level(level_num)

    # Event type (simple)
    if event_id == "4625":
        event_type = "failed_login"
    elif event_id == "4624":
        event_type = "successful_login"
    else:
        event_type = "windows_event"

    risk = risk_for(event_id, level_name)

    return {
        "id": f"win-{int(time.time())}-{idx}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event_type": event_type,
        "event_id": event_id,
        "record_id": record_id,
        "provider": provider,
        "computer": computer,
        "level": level_name,
        "channel": CHANNEL,
        "source": f"windows.{CHANNEL.lower()}",
        "risk": risk,
        "raw": xml_event[:3000],  # keep more raw, but still capped
    }

def main() -> None:
    print(f"Collector running: channel={CHANNEL} -> {BACKEND_INGEST_URL}")
    print("Tip: If you switch CHANNEL='Security' and get access denied, run terminal as Administrator.\n")

    while True:
        try:
            raw_events = query_events(CHANNEL, MAX_PER_POLL)

            sent = 0
            for i, xml in enumerate(raw_events):
                fp = fingerprint_event(xml)
                if fp in SEEN:
                    continue

                SEEN.add(fp)
                if len(SEEN) > SEEN_MAX:
                    SEEN.clear()

                post_event(normalize(xml, i))
                sent += 1

            print(f"Ingested {sent} new events from {CHANNEL}")

        except subprocess.CalledProcessError as e:
            print("wevtutil error output:\n", e.output)
            print("If access denied: run terminal as Administrator OR set CHANNEL='Application'\n")

        except Exception as e:
            print("Error:", e)

        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    main()
