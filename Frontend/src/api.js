const BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

export async function getHealth() {
  const res = await fetch(`${BASE}/health`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function getEvents() {
  const res = await fetch(`${BASE}/events`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function getAlerts() {
  const res = await fetch(`${BASE}/alerts`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
