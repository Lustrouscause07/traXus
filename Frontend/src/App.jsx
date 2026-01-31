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

function ExpandableEventsTable({ rows }) {
  const [openId, setOpenId] = useState(null);

  const cols = ["timestamp", "event_type", "event_id", "level", "provider", "computer", "risk"];

  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr>
            <th style={{ width: 42, borderBottom: "1px solid #333" }}></th>
            {cols.map((c) => (
              <th key={c} style={{ textAlign: "left", padding: 10, borderBottom: "1px solid #333" }}>
                {c}
              </th>
            ))}
          </tr>
        </thead>

        <tbody>
          {rows.map((r) => {
            const rowKey = r.record_id || r.id; // prefer record_id if present
            const isOpen = openId === rowKey;

            return (
              <>
                <tr key={rowKey}>
                  <td style={{ padding: 10, borderBottom: "1px solid #222" }}>
                    <button
                      onClick={() => setOpenId(isOpen ? null : rowKey)}
                      style={{
                        cursor: "pointer",
                        border: "1px solid #333",
                        background: "transparent",
                        color: "inherit",
                        borderRadius: 8,
                        width: 28,
                        height: 28,
                        lineHeight: "26px",
                      }}
                      title={isOpen ? "Hide raw" : "Show raw"}
                    >
                      {isOpen ? "▾" : "▸"}
                    </button>
                  </td>

                  {cols.map((c) => (
                    <td key={c} style={{ padding: 10, borderBottom: "1px solid #222", opacity: 0.95 }}>
                      {String(r[c] ?? "")}
                    </td>
                  ))}
                </tr>

                {isOpen && (
                  <tr>
                    <td colSpan={cols.length + 1} style={{ padding: 12, borderBottom: "1px solid #222" }}>
                      <div style={{ display: "grid", gap: 12 }}>
                        <div>
                          <div style={{ opacity: 0.8, marginBottom: 6 }}>Normalized event (pretty)</div>
                          <pre style={{ background: "#111", padding: 12, borderRadius: 12, overflow: "auto" }}>
{JSON.stringify(r, null, 2)}
                          </pre>
                        </div>

                        <div>
                          <div style={{ opacity: 0.8, marginBottom: 6 }}>Raw XML (collapsed view)</div>
                          <pre style={{ background: "#0b0b0b", padding: 12, borderRadius: 12, overflow: "auto" }}>
{r.raw || ""}
                          </pre>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </>
            );
          })}

          {!rows.length && (
            <tr>
              <td colSpan={cols.length + 1} style={{ padding: 10, opacity: 0.7 }}>
                No events yet
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function SimpleTable({ columns, rows }) {
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
                <td key={c} style={{ padding: 10, borderBottom: "1px solid #222" }}>
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
    <div style={{ fontFamily: "system-ui", padding: 24, maxWidth: 1200, margin: "0 auto" }}>
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
        <ExpandableEventsTable rows={events} />
      </Card>

      <Card title="Active Alerts">
        <SimpleTable
          columns={["id", "timestamp", "title", "severity", "related_event_id", "risk"]}
          rows={alerts}
        />
      </Card>
    </div>
  );
}
