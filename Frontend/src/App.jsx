import { useEffect, useState } from "react";
import "./App.css";

export default function App() {
  const [status, setStatus] = useState("checking...");
  const [details, setDetails] = useState(null);

  const baseUrl = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

  useEffect(() => {
    const run = async () => {
      try {
        const res = await fetch(`${baseUrl}/health`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        setStatus("connected ✅");
        setDetails(data);
      } catch (e) {
        setStatus("disconnected ❌");
        setDetails({ error: String(e) });
      }
    };
    run();
  }, [baseUrl]);

  return (
    <div style={{ fontFamily: "system-ui", padding: 24 }}>
      <h1 style={{ marginBottom: 8 }}>ISMS Dashboard (Dev)</h1>
      <p style={{ marginTop: 0, opacity: 0.8 }}>
        Backend URL: <code>{baseUrl}</code>
      </p>

      <div
        style={{
          marginTop: 16,
          padding: 16,
          border: "1px solid #333",
          borderRadius: 12,
        }}
      >
        <h2 style={{ marginTop: 0 }}>Backend Status</h2>
        <p style={{ fontSize: 18 }}>{status}</p>

        <pre
          style={{
            background: "#111",
            padding: 12,
            borderRadius: 12,
            overflow: "auto",
          }}
        >
{JSON.stringify(details, null, 2)}
        </pre>
      </div>
    </div>
  );
}
