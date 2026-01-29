import { useEffect, useState } from "react";
import { getHealth, getEvents, getAlerts } from "./api";

function Card({ title, children }) {
  return (
    <div style={{ border: "1px solid #333", borderRadius: 12, padding: 16, marginTop: 16 }}>
      <h2 style={{ marginTop: 0 }}>{title}</h2>
      {children}
    </div>
  );
}

function Table({ columns, rows }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c} style={{ textAlign: "left", padding: 10, borderBottom: "1px solid #333" }}>
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, idx) => (
            <tr key={idx}>
              {columns.map((c) => (
                <td key={c} style={{ padding: 10, borderBottom: "1px solid #222", opacity: 0.95 }}>
                  {String(r[c] ?? "")}
                </td>
              ))}
            </tr>
          ))}
          {!rows.length && (
            <tr>
              <td colSpan={columns.length} style={{ padding: 10, opacity: 0.7 }}>
                No data
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export default function App() {
  const baseUrl = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

  const [health, setHealth] = useState({ status: "checking...", data: null });
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    (async () => {
      try {
        const data = await getHealth();
        setHealth({ status: "connected ✅", data });
      } catch (e) {
        setHealth({ status: "disconnected ❌", data: { error: String(e) } });
      }

      try {
        setEvents(await getEvents());
      } catch {
        setEvents([]);
      }

      try {
        setAlerts(await getAlerts());
      } catch {
        setAlerts([]);
      }
    })();
  }, []);

  return (
    <div style={{ fontFamily: "system-ui", padding: 24, maxWidth: 1100, margin: "0 auto" }}>
      <h1 style={{ marginBottom: 6 }}>ISMS Dashboard (Dev)</h1>
      <div style={{ opacity: 0.8 }}>
        Backend URL: <code>{baseUrl}</code>
      </div>

      <Card title="Backend Status">
        <div style={{ fontSize: 18, marginBottom: 8 }}>{health.status}</div>
        <pre style={{ background: "#111", padding: 12, borderRadius: 12, overflow: "auto" }}>
{JSON.stringify(health.data, null, 2)}
        </pre>
      </Card>

      <Card title="Recent Events">
        <Table
          columns={["id", "timestamp", "event_type", "source_ip", "asset", "risk"]}
          rows={events}
        />
      </Card>

      <Card title="Active Alerts">
        <Table
          columns={["id", "timestamp", "title", "severity", "related_event_id", "risk"]}
          rows={alerts}
        />
      </Card>
    </div>
  );
}
