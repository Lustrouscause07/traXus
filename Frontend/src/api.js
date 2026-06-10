const BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

export async function getHealth() {
  const res = await fetch(`${BASE}/health`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function getEvents(limit) {
  const qs =
    typeof limit === "number"
      ? `?limit=${encodeURIComponent(String(limit))}`
      : "";
  const res = await fetch(`${BASE}/events${qs}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function getAlerts(limit) {
  const qs =
    typeof limit === "number"
      ? `?limit=${encodeURIComponent(String(limit))}`
      : "";
  const res = await fetch(`${BASE}/alerts${qs}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function getCases(limit) {
  const qs =
    typeof limit === "number"
      ? `?limit=${encodeURIComponent(String(limit))}`
      : "";
  const res = await fetch(`${BASE}/cases${qs}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function getEventAnalysis(eventId) {
  const res = await fetch(`${BASE}/analyze/${encodeURIComponent(String(eventId))}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}