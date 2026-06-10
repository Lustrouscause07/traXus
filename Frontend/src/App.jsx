import React, { useEffect, useMemo, useRef, useState } from "react";
import "./App.css";
import "./styles.css";

import {
  ResponsiveContainer,
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

import {
  getAlerts,
  getCases,
  getEventAnalysis,
  getEvents,
  getHealth,
} from "./api";

function clamp(n, a, b) {
  return Math.max(a, Math.min(b, n));
}

function safeInt(x, d = 0) {
  const v = Number.parseInt(String(x ?? ""), 10);
  return Number.isFinite(v) ? v : d;
}

function toLocalDisplay(ts) {
  if (!ts) return "-";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts);
  return d.toLocaleString();
}

function toEpoch(ts) {
  const d = new Date(ts);
  const t = d.getTime();
  return Number.isNaN(t) ? 0 : t;
}

function riskToSeverity(risk) {
  const r = safeInt(risk, 0);
  if (r >= 85) return "high";
  if (r >= 70) return "medium";
  return "low";
}

function severityLabel(sev) {
  if (sev === "high") return "HIGH";
  if (sev === "medium") return "MED";
  return "LOW";
}

function severityBadgeClass(sev) {
  if (sev === "high") return "badge badgeHigh";
  if (sev === "medium") return "badge badgeMed";
  return "badge badgeLow";
}

function normalizeBackendAnalysis(a, fallbackRaw = null, meta = {}) {
  if (!a || typeof a !== "object") return null;

  const keyFieldsInput = Array.isArray(a.key_fields)
    ? a.key_fields
    : a.key_fields && typeof a.key_fields === "object"
      ? Object.entries(a.key_fields)
      : [];

  return {
    analysisSource: "backend",
    analysisLabel: "Backend Rule Engine",
    severity: String(a.severity ?? "low"),
    risk: safeInt(a.risk, 0),
    reason: String(a.reason ?? "Backend analysis generated."),
    rules: Array.isArray(a.rules)
      ? a.rules.map((x) => String(x))
      : Array.isArray(a.rules_triggered)
        ? a.rules_triggered.map((x) =>
            typeof x === "string" ? x : String(x?.id ?? x?.title ?? "RULE")
          )
        : [],
    actions: Array.isArray(a.actions)
      ? a.actions.map((x) => String(x))
      : Array.isArray(a.recommended_actions)
        ? a.recommended_actions.map((x) => String(x))
        : [],
    keyFields: keyFieldsInput.map(([k, v]) => [String(k), String(v)]),
    raw: a.raw ?? a.raw_event ?? fallbackRaw ?? a,
    detectionMeta: {
      relatedEventId:
        meta.relatedEventId ??
        a.related_event_id ??
        a.event_id ??
        fallbackRaw?.id ??
        null,
      alertId: meta.alertId ?? null,
      caseId: meta.caseId ?? null,
    },
    signals:
      a.signals && typeof a.signals === "object"
        ? Object.entries(a.signals).map(([k, v]) => [String(k), String(v)])
        : [],
  };
}

function buildAnalysisFromEvent(evt) {
  const risk = safeInt(evt?.risk, 0);
  const sev = riskToSeverity(risk);

  const source = String(evt?.source ?? "");
  const eventType = String(evt?.event_type ?? "security_event");
  const eventId = safeInt(evt?.event_id, 0);
  const provider = String(
    evt?.provider ?? evt?.ProviderName ?? evt?.provider_name ?? ""
  );

  const rules = [];
  const actions = [];

  let reason = "No specific detection rule matched; event recorded for monitoring.";

  if (
    source.toLowerCase().includes("windows.security") ||
    eventType.includes("security")
  ) {
    if (eventId === 4625) {
      reason = "Repeated or suspicious failed logon attempt observed.";
      rules.push("WIN_AUTH_FAILED_LOGON — Windows failed authentication");
      actions.push("Check the target account and source context (user, host).");
      actions.push("Look for nearby successful logons or privilege use.");
      actions.push("If suspicious, block/disable account and investigate endpoint.");
    } else if (eventId === 4624) {
      reason = "Successful logon recorded; validate if expected.";
      rules.push("WIN_AUTH_SUCCESS_LOGON — Windows successful authentication");
      actions.push("Confirm the logon is expected for the user and host.");
      actions.push("If unexpected, review preceding failures or unusual access.");
    } else if (eventId === 4672) {
      reason = "Privileged logon detected; verify if expected.";
      rules.push("WIN_PRIVILEGED_LOGON — Elevated privileges assigned");
      actions.push("Validate admin activity and change history.");
      actions.push("Correlate with process creation and remote access activity.");
    } else if (risk >= 70) {
      reason = "Security audit pattern scored as suspicious by risk heuristics.";
      rules.push("WIN_SECURITY_RISK_SCORE — Risk-based classification");
      actions.push("Validate event context and correlate with nearby events.");
      actions.push("If repeated, escalate for investigation.");
    } else {
      rules.push("GEN_base_telemetry — Baseline event telemetry");
      actions.push("Review event context if part of an ongoing investigation.");
    }
  } else {
    if (risk >= 70) {
      reason = "Event scored as suspicious based on severity and heuristics.";
      rules.push("APP_HIGH_SEVERITY — Application error/critical signal");
      actions.push("Review application/service logs and confirm impact.");
      actions.push("Correlate with security events and system changes.");
    } else {
      rules.push("GEN_base_telemetry — Baseline event telemetry");
      actions.push("Monitor for repetition or correlation with other alerts.");
    }
  }

  const keyFields = [
    ["Asset", String(evt?.asset ?? evt?.MachineName ?? "localhost")],
    ["Source", source || "-"],
    ["Event Type", eventType || "-"],
    ["Event ID", eventId ? String(eventId) : "-"],
    ["Provider", provider || "-"],
    ["Time (Local)", toLocalDisplay(evt?.timestamp ?? evt?.ingested_at)],
  ];

  return {
    analysisSource: "fallback",
    analysisLabel: "Frontend Fallback",
    severity: sev,
    risk,
    reason,
    rules,
    actions,
    keyFields,
    raw: evt,
    detectionMeta: {
      relatedEventId: evt?.id ?? null,
      alertId: null,
      caseId: null,
    },
    signals: [],
  };
}

function resolveAlertToEvent(alert, events) {
  if (!alert) return null;

  const rel = String(alert.related_event_id ?? "");
  if (rel) {
    const found = events.find((e) => String(e.id) === rel);
    if (found) return found;
  }

  const aid = String(alert.id ?? "");
  if (aid.startsWith("alrt-")) {
    const maybeEventId = aid.replace(/^alrt-/, "");
    const found = events.find((e) => String(e.id) === maybeEventId);
    if (found) return found;
  }

  const at = toEpoch(alert.timestamp);
  const title = String(alert.title ?? "");
  const risk = safeInt(alert.risk, 0);

  let best = null;
  let bestScore = Number.POSITIVE_INFINITY;

  for (const e of events) {
    const et = toEpoch(e.timestamp ?? e.ingested_at);
    const dt = Math.abs(et - at);
    const sameTitle = String(e.event_type ?? "") === title ? 0 : 1;
    const dr = Math.abs(safeInt(e.risk, 0) - risk);
    const score = dt / 1000 + sameTitle * 30 + dr;
    if (score < bestScore) {
      bestScore = score;
      best = e;
    }
  }

  return best;
}

function sortIndicator(currentKey, currentDir, colKey) {
  if (currentKey !== colKey) return "";
  return currentDir === "asc" ? " ▲" : " ▼";
}

function NavButton({ active, onClick, children }) {
  return (
    <button
      className={`tab ${active ? "active" : ""}`}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

function SummaryCard({ title, value, hint, accentClass = "" }) {
  return (
    <div className="statCard">
      <div className="statLabel">{title}</div>
      <div className={`statValue ${accentClass}`}>{value}</div>
      <div className="statHint">{hint}</div>
    </div>
  );
}

function SectionCard({ title, right, children }) {
  return (
    <div className="card">
      <div className="cardHeader">
        <h2 className="cardTitle">{title}</h2>
        <div className="cardRight muted">{right}</div>
      </div>
      <div className="cardBody">{children}</div>
    </div>
  );
}

const tableWrapStyle = {
  maxHeight: "68vh",
  overflow: "auto",
  borderRadius: 18,
};

const filterRowStyle = {
  display: "flex",
  gap: 10,
  flexWrap: "wrap",
  marginBottom: 14,
  alignItems: "center",
};

const inputStyle = {
  minWidth: 300,
  flex: "1 1 320px",
  padding: "10px 14px",
  borderRadius: 12,
  border: "1px solid rgba(255,255,255,0.10)",
  background: "rgba(255,255,255,0.04)",
  color: "inherit",
  outline: "none",
};

const selectStyle = {
  minWidth: 180,
  padding: "10px 14px",
  borderRadius: 12,
  border: "1px solid rgba(255,255,255,0.10)",
  background: "rgba(20,20,24,0.96)",
  color: "#f5f7fb",
  outline: "none",
};

const centeredCellStyle = {
  textAlign: "center",
  whiteSpace: "nowrap",
};

const stickyHeadStyle = {
  cursor: "pointer",
  position: "sticky",
  top: 0,
  zIndex: 4,
  background: "rgba(10,10,12,0.98)",
  backdropFilter: "blur(6px)",
  boxShadow: "0 1px 0 rgba(255,255,255,0.08)",
};

const TABLE_COLS = {
  cases: {
    created: 190,
    title: 520,
    sev: 110,
    status: 120,
    occur: 100,
    alerts: 90,
    events: 90,
  },
  alerts: {
    time: 190,
    title: 760,
    sev: 110,
  },
  events: {
    time: 210,
    source: 240,
    event: 260,
    id: 100,
    asset: 220,
    risk: 110,
  },
};

const CHART_COLORS = {
  cyan: "#33d1ff",
  blue: "#5b8cff",
  purple: "#9b6bff",
  amber: "#ffb547",
  red: "#ff5f6d",
  green: "#2fe38a",
  muted: "rgba(255,255,255,0.52)",
};

function formatChartHourLabel(ts) {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "-";
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function niceCompactLabel(text, max = 28) {
  const s = String(text ?? "");
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

function ChartTooltip({ active, payload, label, formatterLabel = null }) {
  if (!active || !payload || !payload.length) return null;

  return (
    <div
      style={{
        background: "rgba(12,12,16,0.96)",
        border: "1px solid rgba(255,255,255,0.12)",
        borderRadius: 12,
        padding: "10px 12px",
        boxShadow: "0 12px 30px rgba(0,0,0,0.45)",
        minWidth: 140,
      }}
    >
      {label !== undefined && (
        <div
          style={{
            fontSize: 12,
            color: "rgba(255,255,255,0.62)",
            marginBottom: 6,
          }}
        >
          {formatterLabel ? formatterLabel(label) : label}
        </div>
      )}

      <div style={{ display: "grid", gap: 4 }}>
        {payload.map((entry, idx) => (
          <div
            key={`${entry?.name ?? "val"}-${idx}`}
            style={{
              display: "flex",
              justifyContent: "space-between",
              gap: 12,
              fontSize: 13,
              color: "rgba(255,255,255,0.92)",
            }}
          >
            <span style={{ color: entry?.color ?? "#fff" }}>
              {entry?.name ?? "value"}
            </span>
            <strong>{entry?.value ?? 0}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}

function stableEventKey(e) {
  return String(
    e?.id ??
      [
        e?.timestamp ?? e?.ingested_at ?? "",
        e?.source ?? "",
        e?.event_type ?? "",
        e?.event_id ?? "",
        e?.asset ?? e?.MachineName ?? "",
        e?.risk ?? "",
      ].join("|")
  );
}

function mergeEventsStable(prev, incoming, maxItems = 3000) {
  const map = new Map();

  for (const e of incoming ?? []) {
    map.set(stableEventKey(e), e);
  }

  for (const e of prev ?? []) {
    const k = stableEventKey(e);
    if (!map.has(k)) map.set(k, e);
  }

  return Array.from(map.values())
    .sort(
      (a, b) =>
        toEpoch(b?.timestamp ?? b?.ingested_at) -
        toEpoch(a?.timestamp ?? a?.ingested_at)
    )
    .slice(0, maxItems);
}

export default function App() {
  const [backendOk, setBackendOk] = useState(false);
  const [serverUtc, setServerUtc] = useState("");

  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [cases, setCases] = useState([]);

  const [limit, setLimit] = useState(200);
  const [activeView, setActiveView] = useState("dashboard");

  const [autoRefresh, setAutoRefresh] = useState(false);
  const timerRef = useRef(null);

  const [selectedAnalysis, setSelectedAnalysis] = useState(null);

  const [tsPicker, setTsPicker] = useState({
    open: false,
    tsLabel: "",
    items: [],
  });

  const [eventSort, setEventSort] = useState({ key: "timestamp", dir: "desc" });
  const [alertSort, setAlertSort] = useState({ key: "timestamp", dir: "desc" });
  const [caseSort, setCaseSort] = useState({ key: "created_at", dir: "desc" });

  const [caseSearch, setCaseSearch] = useState("");
  const [caseSeverityFilter, setCaseSeverityFilter] = useState("all");
  const [caseStatusFilter, setCaseStatusFilter] = useState("all");

  const [alertSearch, setAlertSearch] = useState("");
  const [alertSeverityFilter, setAlertSeverityFilter] = useState("all");

  useEffect(() => {
    const shouldLock = Boolean(selectedAnalysis || tsPicker.open);
    const prevBodyOverflow = document.body.style.overflow;
    const prevHtmlOverflow = document.documentElement.style.overflow;

    if (shouldLock) {
      document.body.style.overflow = "hidden";
      document.documentElement.style.overflow = "hidden";
    }

    return () => {
      document.body.style.overflow = prevBodyOverflow;
      document.documentElement.style.overflow = prevHtmlOverflow;
    };
  }, [selectedAnalysis, tsPicker.open]);

  async function fetchHealth() {
    try {
      const j = await getHealth();
      setBackendOk(Boolean(j?.ok));
      setServerUtc(new Date().toISOString());
    } catch {
      setBackendOk(false);
      setServerUtc(new Date().toISOString());
    }
  }

  async function fetchAll() {
  await fetchHealth();

  try {
    const e = await getEvents(500);
    const incomingEvents = Array.isArray(e) ? e : [];
    setEvents((prev) => mergeEventsStable(prev, incomingEvents, 3000));
  } catch {
    setEvents((prev) => prev);
  }

  try {
    const a = await getAlerts(clamp(limit, 1, 500));
    setAlerts(Array.isArray(a) ? a : []);
  } catch {
    setAlerts([]);
  }

  try {
    const c = await getCases(clamp(limit, 1, 500));
    setCases(Array.isArray(c) ? c : []);
  } catch {
    setCases([]);
  }
}

  useEffect(() => {
    fetchAll();
  }, []);

  useEffect(() => {
    if (autoRefresh) {
      timerRef.current = setInterval(() => {
        fetchAll();
      }, 3500);
    } else if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [autoRefresh, limit]);

  const stats = useMemo(() => {
    const totalEvents = events.length;
    const totalAlerts = alerts.length;
    const totalCases = cases.length;

    let highAlerts = 0;
    let medAlerts = 0;
    let lowAlerts = 0;

    for (const a of alerts) {
      const sev = String(a?.severity ?? riskToSeverity(a?.risk));
      if (sev === "high") highAlerts++;
      else if (sev === "medium") medAlerts++;
      else lowAlerts++;
    }

    let openCases = 0;
    let totalOccurrences = 0;
    for (const c of cases) {
      if (String(c?.status ?? "").toLowerCase() === "open") openCases++;
      totalOccurrences += safeInt(c?.occurrence_count, 1);
    }

    return {
      totalEvents,
      totalAlerts,
      totalCases,
      highAlerts,
      medAlerts,
      lowAlerts,
      openCases,
      totalOccurrences,
    };
  }, [events, alerts, cases]);
  
  const dashboardTimeSeries = useMemo(() => {
  const now = Date.now();
  const bucketMinutes = 5;
  const bucketMs = bucketMinutes * 60 * 1000;
  const points = 12;

  const start = now - points * bucketMs;
  const buckets = [];

  for (let i = 0; i < points; i++) {
    const bucketStart = start + i * bucketMs;
    buckets.push({
      ts: bucketStart,
      label: formatChartHourLabel(bucketStart),
      alerts: 0,
    });
  }

  for (const alert of alerts) {
    const t = toEpoch(alert?.timestamp);
    if (!t || t < start) continue;
    const idx = Math.floor((t - start) / bucketMs);
    if (idx >= 0 && idx < buckets.length) {
      buckets[idx].alerts += 1;
    }
  }

  return buckets;
}, [alerts]);

  const dashboardSeverityData = useMemo(() => {
    const high = alerts.filter(
      (a) => String(a?.severity ?? riskToSeverity(a?.risk)) === "high"
    ).length;
    const medium = alerts.filter(
      (a) => String(a?.severity ?? riskToSeverity(a?.risk)) === "medium"
    ).length;
    const low = alerts.filter(
      (a) => String(a?.severity ?? riskToSeverity(a?.risk)) === "low"
    ).length;

    return [
      { name: "High", value: high, color: CHART_COLORS.red },
      { name: "Medium", value: medium, color: CHART_COLORS.amber },
      { name: "Low", value: low, color: CHART_COLORS.green },
    ].filter((x) => x.value > 0);
  }, [alerts]);

  const dashboardTopAlertTitles = useMemo(() => {
    const counts = new Map();

    for (const a of alerts) {
      const title = String(a?.title ?? "Unknown alert");
      counts.set(title, (counts.get(title) ?? 0) + 1);
    }

    return Array.from(counts.entries())
      .map(([title, count]) => ({
        title: niceCompactLabel(title, 34),
        fullTitle: title,
        count,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [alerts]);

  const dashboardSourceData = useMemo(() => {
    const counts = new Map();

    for (const e of events) {
      const source = String(e?.source ?? "unknown");
      counts.set(source, (counts.get(source) ?? 0) + 1);
    }

    return Array.from(counts.entries())
      .map(([source, count]) => ({ source, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 4);
  }, [events]);

      const dashboardTopSourceSummary = useMemo(() => {
    return dashboardSourceData.slice(0, 4);
  }, [dashboardSourceData]);

  const dashboardUniqueSources = useMemo(() => {
    return new Set(events.map((e) => String(e?.source ?? "unknown"))).size;
  }, [events]);

  const dashboardLatestAlertCount = useMemo(() => {
  if (!dashboardTimeSeries.length) return 0;
  return dashboardTimeSeries[dashboardTimeSeries.length - 1]?.alerts ?? 0;
}, [dashboardTimeSeries]);

  const sortedEvents = useMemo(() => {
  const arr = [...events];
  const { key, dir } = eventSort;

  const cmp = (a, b) => {
    let va, vb;

    if (key === "timestamp") {
      va = toEpoch(a.timestamp ?? a.ingested_at);
      vb = toEpoch(b.timestamp ?? b.ingested_at);
    } else if (key === "source") {
      va = String(a.source ?? "");
      vb = String(b.source ?? "");
    } else if (key === "event_type") {
      va = String(a.event_type ?? "");
      vb = String(b.event_type ?? "");
    } else if (key === "event_id") {
      va = safeInt(a.event_id, 0);
      vb = safeInt(b.event_id, 0);
    } else if (key === "asset") {
      va = String(a.asset ?? a.MachineName ?? "");
      vb = String(b.asset ?? b.MachineName ?? "");
    } else if (key === "risk") {
      va = safeInt(a.risk, 0);
      vb = safeInt(b.risk, 0);
    } else {
      va = String(a[key] ?? "");
      vb = String(b[key] ?? "");
    }

    if (typeof va === "number" && typeof vb === "number") return va - vb;
    return String(va).localeCompare(String(vb));
  };

  arr.sort((a, b) => (dir === "asc" ? cmp(a, b) : -cmp(a, b)));
  return arr;
}, [events, eventSort]);

const visibleEvents = useMemo(() => {
  return sortedEvents.slice(0, clamp(limit, 50, 500));
}, [sortedEvents, limit]);

  const groupedEvents = useMemo(() => {
    const groups = new Map();

    for (const e of sortedEvents) {
      const tsLabel = toLocalDisplay(e?.timestamp ?? e?.ingested_at);
      if (!groups.has(tsLabel)) {
        groups.set(tsLabel, {
          tsLabel,
          items: [],
          rep: e,
          maxEpoch: toEpoch(e?.timestamp ?? e?.ingested_at),
        });
      }
      const g = groups.get(tsLabel);
      g.items.push(e);
      const ep = toEpoch(e?.timestamp ?? e?.ingested_at);
      if (ep > g.maxEpoch) {
        g.maxEpoch = ep;
        g.rep = e;
      }
    }

    return Array.from(groups.values());
  }, [sortedEvents]);

  const filteredAlerts = useMemo(() => {
    const q = alertSearch.trim().toLowerCase();

    return alerts.filter((a) => {
      const sev = String(a?.severity ?? riskToSeverity(a?.risk)).toLowerCase();

      if (alertSeverityFilter !== "all" && sev !== alertSeverityFilter) {
        return false;
      }

      if (!q) return true;

      const haystack = [
        a?.title,
        a?.source,
        a?.asset,
        a?.id,
        a?.case_id,
      ]
        .map((x) => String(x ?? "").toLowerCase())
        .join(" ");

      return haystack.includes(q);
    });
  }, [alerts, alertSearch, alertSeverityFilter]);

  const sortedAlerts = useMemo(() => {
    const arr = [...filteredAlerts];
    const { key, dir } = alertSort;

    const cmp = (a, b) => {
      let va, vb;

      if (key === "timestamp") {
        va = toEpoch(a.timestamp);
        vb = toEpoch(b.timestamp);
      } else if (key === "title") {
        va = String(a.title ?? "");
        vb = String(b.title ?? "");
      } else if (key === "severity") {
        const map = { low: 0, medium: 1, high: 2 };
        va = map[String(a.severity ?? "low")] ?? 0;
        vb = map[String(b.severity ?? "low")] ?? 0;
      } else if (key === "risk") {
        va = safeInt(a.risk, 0);
        vb = safeInt(b.risk, 0);
      } else {
        va = String(a[key] ?? "");
        vb = String(b[key] ?? "");
      }

      if (typeof va === "number" && typeof vb === "number") return va - vb;
      return String(va).localeCompare(String(vb));
    };

    arr.sort((a, b) => (dir === "asc" ? cmp(a, b) : -cmp(a, b)));
    return arr;
  }, [filteredAlerts, alertSort]);

  const filteredCases = useMemo(() => {
    const q = caseSearch.trim().toLowerCase();

    return cases.filter((c) => {
      const sev = String(c?.severity ?? "low").toLowerCase();
      const status = String(c?.status ?? "").toLowerCase();

      if (caseSeverityFilter !== "all" && sev !== caseSeverityFilter) {
        return false;
      }

      if (caseStatusFilter !== "all" && status !== caseStatusFilter) {
        return false;
      }

      if (!q) return true;

      const linkedAlerts = Array.isArray(c?.linked_alert_ids)
        ? c.linked_alert_ids.join(" ")
        : "";
      const linkedEvents = Array.isArray(c?.linked_event_ids)
        ? c.linked_event_ids.join(" ")
        : "";

      const haystack = [
        c?.title,
        c?.summary,
        c?.asset,
        c?.actor,
        c?.rule_id,
        c?.case_id,
        linkedAlerts,
        linkedEvents,
      ]
        .map((x) => String(x ?? "").toLowerCase())
        .join(" ");

      return haystack.includes(q);
    });
  }, [cases, caseSearch, caseSeverityFilter, caseStatusFilter]);

  const sortedCases = useMemo(() => {
    const arr = [...filteredCases];
    const { key, dir } = caseSort;

    const cmp = (a, b) => {
      let va, vb;

      if (key === "created_at") {
        va = toEpoch(a.created_at);
        vb = toEpoch(b.created_at);
      } else if (key === "title") {
        va = String(a.title ?? "");
        vb = String(b.title ?? "");
      } else if (key === "severity") {
        const map = { low: 0, medium: 1, high: 2 };
        va = map[String(a.severity ?? "low")] ?? 0;
        vb = map[String(b.severity ?? "low")] ?? 0;
      } else if (key === "status") {
        va = String(a.status ?? "");
        vb = String(b.status ?? "");
      } else if (key === "occurrence_count") {
        va = safeInt(a.occurrence_count, 1);
        vb = safeInt(b.occurrence_count, 1);
      } else if (key === "linked_alert_ids") {
        va = Array.isArray(a.linked_alert_ids) ? a.linked_alert_ids.length : 0;
        vb = Array.isArray(b.linked_alert_ids) ? b.linked_alert_ids.length : 0;
      } else if (key === "linked_event_ids") {
        va = Array.isArray(a.linked_event_ids) ? a.linked_event_ids.length : 0;
        vb = Array.isArray(b.linked_event_ids) ? b.linked_event_ids.length : 0;
      } else {
        va = String(a[key] ?? "");
        vb = String(b[key] ?? "");
      }

      if (typeof va === "number" && typeof vb === "number") return va - vb;
      return String(va).localeCompare(String(vb));
    };

    arr.sort((a, b) => (dir === "asc" ? cmp(a, b) : -cmp(a, b)));
    return arr;
  }, [filteredCases, caseSort]);

  function toggleEventSort(key) {
    setEventSort((s) => {
      if (s.key !== key) return { key, dir: "asc" };
      return { key, dir: s.dir === "asc" ? "desc" : "asc" };
    });
  }

  function toggleAlertSort(key) {
    setAlertSort((s) => {
      if (s.key !== key) return { key, dir: "asc" };
      return { key, dir: s.dir === "asc" ? "desc" : "asc" };
    });
  }

  function toggleCaseSort(key) {
    setCaseSort((s) => {
      if (s.key !== key) return { key, dir: "asc" };
      return { key, dir: s.dir === "asc" ? "desc" : "asc" };
    });
  }

  async function onClickEventRow(evt) {
    try {
      if (evt?.id) {
        const backendAnalysis = await getEventAnalysis(evt.id);
        const normalized = normalizeBackendAnalysis(backendAnalysis, evt, {
          relatedEventId: evt.id,
        });
        if (normalized) {
          setSelectedAnalysis(normalized);
          return;
        }
      }
    } catch {}

    setSelectedAnalysis(buildAnalysisFromEvent(evt));
  }

  function onClickGroupedEventRow(group) {
    const items = group?.items ?? [];
    if (items.length <= 1) {
      onClickEventRow(items[0]);
      return;
    }

    setTsPicker({
      open: true,
      tsLabel: String(group.tsLabel ?? ""),
      items,
    });
  }

  function onPickGroupedEvent(evt) {
    setTsPicker({ open: false, tsLabel: "", items: [] });
    onClickEventRow(evt);
  }

  async function onClickAlertRow(alrt) {
    const backendAnalysis = normalizeBackendAnalysis(alrt?.analysis, alrt, {
      relatedEventId: alrt?.related_event_id ?? null,
      alertId: alrt?.id ?? null,
      caseId: alrt?.case_id ?? null,
    });

    if (backendAnalysis) {
      setSelectedAnalysis(backendAnalysis);
      return;
    }

    const evt = resolveAlertToEvent(alrt, events);
    if (evt) {
      await onClickEventRow(evt);
    } else {
      const fallback = {
        analysisSource: "fallback",
        analysisLabel: "Frontend Fallback",
        severity: String(alrt?.severity ?? "low"),
        risk: safeInt(alrt?.risk, 0),
        reason:
          "Alert generated, but related event details were not found in the current events list.",
        rules: ["ALERT_ONLY — Missing related event context"],
        actions: [
          "Refresh and try again.",
          "Increase event limit to ensure related event is loaded.",
        ],
        keyFields: [
          ["Title", String(alrt?.title ?? "-")],
          ["Time (Local)", toLocalDisplay(alrt?.timestamp)],
          ["Risk", String(safeInt(alrt?.risk, 0))],
        ],
        raw: alrt,
        detectionMeta: {
          relatedEventId: alrt?.related_event_id ?? null,
          alertId: alrt?.id ?? null,
          caseId: alrt?.case_id ?? null,
        },
        signals: [],
      };
      setSelectedAnalysis(fallback);
    }
  }

  function onClickCaseRow(cs) {
    const severity = String(cs?.severity ?? "low");
    const linkedEventIds = Array.isArray(cs?.linked_event_ids) ? cs.linked_event_ids : [];
    const linkedAlertIds = Array.isArray(cs?.linked_alert_ids) ? cs.linked_alert_ids : [];
    const relatedEventId = linkedEventIds.length ? String(linkedEventIds[0]) : null;
    const alertId = linkedAlertIds.length ? String(linkedAlertIds[0]) : null;

    const keyFields = [
      ["Case ID", String(cs?.case_id ?? "-")],
      ["Title", String(cs?.title ?? "-")],
      ["Severity", severity],
      ["Status", String(cs?.status ?? "-")],
      ["Created", toLocalDisplay(cs?.created_at)],
      ["Last Updated", toLocalDisplay(cs?.last_updated_at ?? cs?.updated_at ?? cs?.created_at)],
      ["Occurrence Count", String(safeInt(cs?.occurrence_count, 1))],
      ["Linked Alerts", String(linkedAlertIds.length)],
      ["Linked Events", String(linkedEventIds.length)],
      ["Asset", String(cs?.asset ?? "-")],
      ["Actor", String(cs?.actor ?? "-")],
      ["Rule ID", String(cs?.rule_id ?? "-")],
    ];

    const signals = [
      ["summary", String(cs?.summary ?? "-")],
      ["recommended_actions_count", String(Array.isArray(cs?.recommended_actions) ? cs.recommended_actions.length : 0)],
      ["linked_alert_ids", linkedAlertIds.join(", ") || "-"],
      ["linked_event_ids", linkedEventIds.join(", ") || "-"],
    ];

    setSelectedAnalysis({
      analysisSource: "backend",
      analysisLabel: "Backend Case Record",
      severity,
      risk: severity === "high" ? 90 : severity === "medium" ? 75 : 35,
      reason: String(cs?.summary ?? "Case record opened by backend."),
      rules: ["CASE_RECORD"],
      actions: Array.isArray(cs?.recommended_actions) ? cs.recommended_actions : [],
      keyFields,
      raw: cs,
      detectionMeta: {
        relatedEventId,
        alertId,
        caseId: String(cs?.case_id ?? ""),
      },
      signals,
    });
  }

  const recentAlerts = sortedAlerts.slice(0, 3);
  const recentCases = sortedCases.slice(0, 3);

    function renderDashboard() {
    const totalSeverityCount = dashboardSeverityData.reduce(
      (sum, item) => sum + item.value,
      0
    );

    return (
  <div style={{ display: "grid", gap: 18 }}>
    <div className="dashboardHero">
      <div className="heroPanel heroPanelWide">
        <div className="heroEyebrow">Live security overview</div>
        <div className="heroHeadline">
          Active telemetry across host, process, network, and file monitoring
        </div>
        <div className="heroSub">
          Designed to surface what matters first, without flooding the analyst view.
        </div>

        <div className="heroMiniStats">
          <div className="miniStat">
            <div className="miniStatLabel">Events loaded</div>
            <div className="miniStatValue">{stats.totalEvents}</div>
          </div>
          <div className="miniStat">
            <div className="miniStatLabel">Alerts</div>
            <div className="miniStatValue">{stats.totalAlerts}</div>
          </div>
          <div className="miniStat">
            <div className="miniStatLabel">Open cases</div>
            <div className="miniStatValue">{stats.openCases}</div>
          </div>
          <div className="miniStat">
            <div className="miniStatLabel">Unique sources</div>
            <div className="miniStatValue">{dashboardUniqueSources}</div>
          </div>
        </div>
      </div>

      <div className="heroPanel heroPanelCompact">
        <div className="heroEyebrow">Telemetry pulse</div>

        <div className="heroPulseValue">
          {dashboardLatestAlertCount}
        </div>

        <div className="heroPulseLabel">latest 5-minute alerts</div>

        <div className="heroSourceList">
          {dashboardTopSourceSummary.length ? (
            dashboardTopSourceSummary.map((item) => (
              <div key={item.source} className="heroSourceRow">
                <span className="heroSourceName">{item.source}</span>
                <span className="heroSourceCount">{item.count}</span>
              </div>
            ))
          ) : (
            <div className="muted">No source breakdown yet.</div>
          )}
        </div>
      </div>
    </div>

        <div className="gridStats">
          <SummaryCard
            title="Total Events"
            value={stats.totalEvents}
            hint="recent merged telemetry"
          />
          <SummaryCard
            title="Total Alerts"
            value={stats.totalAlerts}
            hint="current alert stream"
          />
          <SummaryCard
            title="Open Cases"
            value={stats.openCases}
            hint={`${stats.totalCases} case records`}
          />
          <SummaryCard
            title="High Alerts"
            value={stats.highAlerts}
            hint="priority triage"
            accentClass="accentRed"
          />
        </div>

        <div className="dashboardGrid">
          <div className="chartCard chartCardWide">
  <div className="chartCardHeader">
    <div>
      <div className="chartEyebrow">Alert trend</div>
      <div className="chartTitle">Alerts over recent time</div>
    </div>
    <div className="chartMeta">5-minute buckets</div>
  </div>

  <div className="chartBox chartBoxTight">
    <ResponsiveContainer width="100%" height={300}>
      <AreaChart data={dashboardTimeSeries}>
        <defs>
          <linearGradient id="alertsAreaFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={CHART_COLORS.cyan} stopOpacity={0.30} />
            <stop offset="90%" stopColor={CHART_COLORS.cyan} stopOpacity={0.03} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
        <XAxis
          dataKey="label"
          tick={{ fill: "rgba(255,255,255,0.55)", fontSize: 12 }}
          axisLine={false}
          tickLine={false}
        />
        <YAxis
          tick={{ fill: "rgba(255,255,255,0.55)", fontSize: 12 }}
          axisLine={false}
          tickLine={false}
          allowDecimals={false}
        />
        <Tooltip content={<ChartTooltip formatterLabel={(x) => `Bucket ${x}`} />} />
        <Area
          type="monotone"
          dataKey="alerts"
          name="Alerts"
          stroke={CHART_COLORS.cyan}
          strokeWidth={2.5}
          fill="url(#alertsAreaFill)"
          animationDuration={900}
          animationEasing="ease-out"
          activeDot={{ r: 5 }}
        />
      </AreaChart>
    </ResponsiveContainer>
  </div>
</div>

<div className="chartCard">
  <div className="chartCardHeader">
    <div>
      <div className="chartEyebrow">Alert mix</div>
      <div className="chartTitle">Severity distribution</div>
    </div>
    <div className="chartMeta">{totalSeverityCount} total</div>
  </div>

  <div className="severityCardBody">
    <div className="severityDonutWrap">
      {dashboardSeverityData.length ? (
        <ResponsiveContainer width="100%" height={260}>
          <PieChart>
            <Tooltip content={<ChartTooltip />} />
            <Pie
              data={dashboardSeverityData}
              dataKey="value"
              nameKey="name"
              innerRadius={62}
              outerRadius={92}
              paddingAngle={3}
              animationDuration={900}
              animationEasing="ease-out"
            >
              {dashboardSeverityData.map((entry, idx) => (
                <Cell key={`${entry.name}-${idx}`} fill={entry.color} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
      ) : (
        <div className="chartEmpty">No alert severity data yet.</div>
      )}
    </div>

    <div className="severitySideSummary">
      <div className="severitySideRow">
        <span>High</span>
        <span className="sevHigh">{stats.highAlerts}</span>
      </div>

      <div className="severitySideRow">
        <span>Medium</span>
        <span className="sevMedium">{stats.medAlerts}</span>
      </div>

      <div className="severitySideRow">
        <span>Low</span>
        <span className="sevLow">{stats.lowAlerts}</span>
      </div>
    </div>
  </div>
</div>

          <div className="chartCard chartCardFull">
            <div className="chartCardHeader">
              <div>
                <div className="chartEyebrow">Alert concentration</div>
                <div className="chartTitle">Most repeated alert titles</div>
              </div>
              <div className="chartMeta">top repeated patterns</div>
            </div>

            <div className="chartBox">
              {dashboardTopAlertTitles.length ? (
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart
                    data={dashboardTopAlertTitles}
                    layout="vertical"
                    margin={{ top: 8, right: 8, left: 8, bottom: 8 }}
                  >
                    <CartesianGrid stroke="rgba(255,255,255,0.05)" horizontal={true} vertical={false} />
                    <XAxis
                      type="number"
                      allowDecimals={false}
                      tick={{ fill: "rgba(255,255,255,0.55)", fontSize: 12 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <YAxis
                      type="category"
                      dataKey="title"
                      width={220}
                      tick={{ fill: "rgba(255,255,255,0.70)", fontSize: 12 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip
                      content={
                        <ChartTooltip
                          formatterLabel={(x) => {
                            const hit = dashboardTopAlertTitles.find((d) => d.title === x);
                            return hit?.fullTitle ?? x;
                          }}
                        />
                      }
                    />
                    <Bar
                      dataKey="count"
                      name="Count"
                      fill={CHART_COLORS.purple}
                      radius={[8, 8, 8, 8]}
                      animationDuration={950}
                      animationEasing="ease-out"
                    />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="chartEmpty">No alert title data yet.</div>
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  function renderCases() {
  return (
    <SectionCard title="Cases" right="grouped incidents • click a case for details">
      <div style={filterRowStyle}>
        <input
          value={caseSearch}
          onChange={(e) => setCaseSearch(e.target.value)}
          placeholder="Search cases by title, asset, actor, rule, case ID..."
          style={inputStyle}
        />
        <select
          value={caseSeverityFilter}
          onChange={(e) => setCaseSeverityFilter(e.target.value)}
          style={selectStyle}
        >
          <option value="all">All severities</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={caseStatusFilter}
          onChange={(e) => setCaseStatusFilter(e.target.value)}
          style={selectStyle}
        >
          <option value="all">All statuses</option>
          <option value="open">Open</option>
          <option value="in_progress">In progress</option>
          <option value="closed">Closed</option>
        </select>
        <div className="muted" style={{ fontSize: 12, whiteSpace: "nowrap" }}>
          Showing {sortedCases.length} case(s)
        </div>
      </div>

      <div className="tableWrap" style={tableWrapStyle}>
        <table className="table" style={{ minWidth: 1220 }}>
          <colgroup>
            <col style={{ width: TABLE_COLS.cases.created }} />
            <col style={{ width: TABLE_COLS.cases.title }} />
            <col style={{ width: TABLE_COLS.cases.sev }} />
            <col style={{ width: TABLE_COLS.cases.status }} />
            <col style={{ width: TABLE_COLS.cases.occur }} />
            <col style={{ width: TABLE_COLS.cases.alerts }} />
            <col style={{ width: TABLE_COLS.cases.events }} />
          </colgroup>

          <thead>
            <tr>
              <th style={stickyHeadStyle} onClick={() => toggleCaseSort("created_at")}>
                Created{sortIndicator(caseSort.key, caseSort.dir, "created_at")}
              </th>
              <th style={stickyHeadStyle} onClick={() => toggleCaseSort("title")}>
                Title{sortIndicator(caseSort.key, caseSort.dir, "title")}
              </th>
              <th style={stickyHeadStyle} onClick={() => toggleCaseSort("severity")}>
                Sev{sortIndicator(caseSort.key, caseSort.dir, "severity")}
              </th>
              <th style={stickyHeadStyle} onClick={() => toggleCaseSort("status")}>
                Status{sortIndicator(caseSort.key, caseSort.dir, "status")}
              </th>
              <th style={{ ...stickyHeadStyle, textAlign: "center" }} onClick={() => toggleCaseSort("occurrence_count")}>
                Occur.{sortIndicator(caseSort.key, caseSort.dir, "occurrence_count")}
              </th>
              <th style={{ ...stickyHeadStyle, textAlign: "center" }} onClick={() => toggleCaseSort("linked_alert_ids")}>
                Alerts{sortIndicator(caseSort.key, caseSort.dir, "linked_alert_ids")}
              </th>
              <th style={{ ...stickyHeadStyle, textAlign: "center" }} onClick={() => toggleCaseSort("linked_event_ids")}>
                Events{sortIndicator(caseSort.key, caseSort.dir, "linked_event_ids")}
              </th>
            </tr>
          </thead>

          <tbody>
            {sortedCases.map((cs) => {
              const sev = String(cs?.severity ?? "low");
              const alertCount = Array.isArray(cs?.linked_alert_ids) ? cs.linked_alert_ids.length : 0;
              const eventCount = Array.isArray(cs?.linked_event_ids) ? cs.linked_event_ids.length : 0;

              return (
                <tr
                  key={String(cs?.case_id ?? Math.random())}
                  className="row"
                  onClick={() => onClickCaseRow(cs)}
                  style={{ cursor: "pointer" }}
                >
                  <td>{toLocalDisplay(cs?.created_at)}</td>

                  <td
                    title={String(cs?.title ?? "")}
                    className="ellipsis"
                    style={{ fontWeight: 500 }}
                  >
                    {String(cs?.title ?? "-")}
                  </td>

                  <td>
                    <span className={severityBadgeClass(sev)}>
                      {severityLabel(sev)}
                    </span>
                  </td>

                  <td style={{ textTransform: "capitalize" }}>
                    {String(cs?.status ?? "-")}
                  </td>

                  <td style={centeredCellStyle}>{safeInt(cs?.occurrence_count, 1)}</td>
                  <td style={centeredCellStyle}>{alertCount}</td>
                  <td style={centeredCellStyle}>{eventCount}</td>
                </tr>
              );
            })}

            {sortedCases.length === 0 && (
              <tr>
                <td colSpan={7} className="muted" style={{ padding: 16 }}>
                  No cases match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </SectionCard>
  );
}

  function renderAlerts() {
  return (
    <SectionCard title="Alerts" right="backend generated">
      <div style={filterRowStyle}>
        <input
          value={alertSearch}
          onChange={(e) => setAlertSearch(e.target.value)}
          placeholder="Search alerts by title, source, asset, alert ID, case ID..."
          style={inputStyle}
        />
        <select
          value={alertSeverityFilter}
          onChange={(e) => setAlertSeverityFilter(e.target.value)}
          style={selectStyle}
        >
          <option value="all">All severities</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <div className="muted" style={{ fontSize: 12, whiteSpace: "nowrap" }}>
          Showing {sortedAlerts.length} alert(s)
        </div>
      </div>

      <div className="tableWrap" style={tableWrapStyle}>
        <table className="table" style={{ minWidth: 1060 }}>
          <colgroup>
            <col style={{ width: TABLE_COLS.alerts.time }} />
            <col style={{ width: TABLE_COLS.alerts.title }} />
            <col style={{ width: TABLE_COLS.alerts.sev }} />
          </colgroup>

          <thead>
            <tr>
              <th
                style={stickyHeadStyle}
                onClick={() => toggleAlertSort("timestamp")}
                title="Sort by Time"
              >
                Time{sortIndicator(alertSort.key, alertSort.dir, "timestamp")}
              </th>

              <th
                style={stickyHeadStyle}
                onClick={() => toggleAlertSort("title")}
                title="Sort by Title"
              >
                Title{sortIndicator(alertSort.key, alertSort.dir, "title")}
              </th>

              <th
                style={stickyHeadStyle}
                onClick={() => toggleAlertSort("severity")}
                title="Sort by Severity"
              >
                Sev{sortIndicator(alertSort.key, alertSort.dir, "severity")}
              </th>
            </tr>
          </thead>

          <tbody>
            {sortedAlerts.map((a) => {
              const sev = String(a?.severity ?? riskToSeverity(a?.risk));
              return (
                <tr
                  key={String(a?.id ?? Math.random())}
                  className="row"
                  onClick={() => onClickAlertRow(a)}
                  style={{ cursor: "pointer" }}
                  title="Click for full analysis"
                >
                  <td>{toLocalDisplay(a?.timestamp)}</td>

                  <td title={String(a?.title ?? "")} className="ellipsis">
                    {String(a?.title ?? "-")}
                  </td>

                  <td>
                    <span className={severityBadgeClass(sev)}>
                      {severityLabel(sev)}
                    </span>
                  </td>
                </tr>
              );
            })}

            {sortedAlerts.length === 0 && (
              <tr>
                <td colSpan={3} className="muted" style={{ padding: 16 }}>
                  No alerts match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </SectionCard>
  );
}

  function renderEvents() {
  return (
    <SectionCard
      title="Events"
      right={
        <span>
          Click a row for analysis
          <span style={{ marginLeft: 10 }}>
            <span className="muted">limit</span>{" "}
            <button
              className="btn"
              style={{ padding: "6px 10px", marginLeft: 8 }}
              onClick={() => setLimit((v) => clamp(v - 50, 50, 500))}
            >
              −
            </button>
            <span style={{ padding: "0 10px" }}>{clamp(limit, 50, 500)}</span>
            <button
              className="btn"
              style={{ padding: "6px 10px" }}
              onClick={() => setLimit((v) => clamp(v + 50, 50, 500))}
            >
              +
            </button>
          </span>
        </span>
      }
    >
      <div className="tableWrap" style={tableWrapStyle}>
        <table className="table" style={{ minWidth: 1140 }}>
          <colgroup>
            <col style={{ width: TABLE_COLS.events.time }} />
            <col style={{ width: TABLE_COLS.events.source }} />
            <col style={{ width: TABLE_COLS.events.event }} />
            <col style={{ width: TABLE_COLS.events.id }} />
            <col style={{ width: TABLE_COLS.events.asset }} />
            <col style={{ width: TABLE_COLS.events.risk }} />
          </colgroup>

          <thead>
            <tr>
              <th onClick={() => toggleEventSort("timestamp")} style={stickyHeadStyle}>
                Time{sortIndicator(eventSort.key, eventSort.dir, "timestamp")}
              </th>

              <th onClick={() => toggleEventSort("source")} style={stickyHeadStyle}>
                Source{sortIndicator(eventSort.key, eventSort.dir, "source")}
              </th>

              <th onClick={() => toggleEventSort("event_type")} style={stickyHeadStyle}>
                Event{sortIndicator(eventSort.key, eventSort.dir, "event_type")}
              </th>

              <th onClick={() => toggleEventSort("event_id")} style={stickyHeadStyle}>
                ID{sortIndicator(eventSort.key, eventSort.dir, "event_id")}
              </th>

              <th onClick={() => toggleEventSort("asset")} style={stickyHeadStyle}>
                Asset{sortIndicator(eventSort.key, eventSort.dir, "asset")}
              </th>

              <th onClick={() => toggleEventSort("risk")} style={stickyHeadStyle}>
                Risk{sortIndicator(eventSort.key, eventSort.dir, "risk")}
              </th>
            </tr>
          </thead>

          <tbody>
            {visibleEvents.map((evt) => {
              const sev = riskToSeverity(evt?.risk);
              return (
                <tr
                  key={stableEventKey(evt)}
                  className="row"
                  onClick={() => onClickEventRow(evt)}
                  style={{ cursor: "pointer" }}
                >
                  <td>{toLocalDisplay(evt?.timestamp ?? evt?.ingested_at)}</td>

                  <td title={String(evt?.source ?? "")} className="ellipsis">
                    {String(evt?.source ?? "-")}
                  </td>

                  <td title={String(evt?.event_type ?? "")} className="ellipsis">
                    {String(evt?.event_type ?? "-")}
                  </td>

                  <td style={centeredCellStyle}>
                    {String(evt?.event_id ?? "-")}
                  </td>

                  <td
                    title={String(evt?.asset ?? evt?.MachineName ?? "")}
                    className="ellipsis"
                  >
                    {String(evt?.asset ?? evt?.MachineName ?? "localhost")}
                  </td>

                  <td style={centeredCellStyle}>
                    <span className={severityBadgeClass(sev)}>
                      {severityLabel(sev)}
                    </span>
                  </td>
                </tr>
              );
            })}

            {visibleEvents.length === 0 && (
              <tr>
                <td colSpan={6} className="muted" style={{ padding: 16 }}>
                  No events loaded.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </SectionCard>
  );
}

  return (
        <div className="page">
          <div className="topbar">
            <div className="brand brandShell brandBlock">
        <div className="brandWordmark">
          <span className="brandMain">tra</span>
          <span className="brandX">X</span>
          <span className="brandMain">us</span>
        </div>

        <div className="brandTagline tagline">because sus never sleeps.</div>
      </div>

      <div className="topbarRight controlPanel">
        <div className={`pill ${backendOk ? "pillOk statusOk" : "pillBad"}`}>
          <span className="pillEmoji">{backendOk ? "🟢" : "🔴"}</span>
          <span className="pillText">
            {backendOk ? "Backend OK" : "Backend Down"}
          </span>
        </div>

        <button className="btn controlBtn" onClick={fetchAll}>
          Refresh
        </button>

        <button className="btn controlBtn" onClick={() => setAutoRefresh((v) => !v)}>
          Auto-refresh: {autoRefresh ? "ON" : "OFF"}
        </button>

        <div className="pill controlBtn">
          <span className="pillEmoji">🕒</span>
          <span className="pillText">Server UTC {serverUtc}</span>
        </div>
      </div>
    </div>

      <div
        style={{
          display: "flex",
          gap: 10,
          flexWrap: "wrap",
          marginBottom: 18,
        }}
      >
        <NavButton
          active={activeView === "dashboard"}
          onClick={() => setActiveView("dashboard")}
        >
          Dashboard
        </NavButton>

        <NavButton
          active={activeView === "cases"}
          onClick={() => setActiveView("cases")}
        >
          Cases
        </NavButton>

        <NavButton
          active={activeView === "alerts"}
          onClick={() => setActiveView("alerts")}
        >
          Alerts
        </NavButton>

        <NavButton
          active={activeView === "events"}
          onClick={() => setActiveView("events")}
        >
          Events
        </NavButton>
      </div>

      {activeView === "dashboard" && renderDashboard()}
      {activeView === "cases" && renderCases()}
      {activeView === "alerts" && renderAlerts()}
      {activeView === "events" && renderEvents()}

      {tsPicker.open && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.68)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: 18,
            zIndex: 9998,
            overscrollBehavior: "contain",
          }}
          onClick={() => setTsPicker({ open: false, tsLabel: "", items: [] })}
        >
          <div
            style={{
              width: "min(980px, 96vw)",
              maxHeight: "86vh",
              overflow: "auto",
              borderRadius: 18,
              border: "1px solid rgba(255,255,255,0.10)",
              background: "rgba(15,15,18,0.92)",
              boxShadow: "0 20px 70px rgba(0,0,0,0.75)",
              padding: 16,
              overscrollBehavior: "contain",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                gap: 12,
                alignItems: "center",
              }}
            >
              <div>
                <div style={{ fontSize: 18, fontWeight: 700 }}>
                  Multiple events at the same timestamp
                </div>
                <div className="muted" style={{ marginTop: 4 }}>
                  {tsPicker.tsLabel} • {tsPicker.items.length} events
                </div>
              </div>

              <button
                className="btn"
                onClick={() => setTsPicker({ open: false, tsLabel: "", items: [] })}
              >
                Close
              </button>
            </div>

            <div style={{ marginTop: 12 }}>
              <div className="muted" style={{ fontSize: 12 }}>
                Click one event to open the full analysis.
              </div>

              <div style={{ marginTop: 10, display: "grid", gap: 10 }}>
                {tsPicker.items.map((e, idx) => {
                  const sev = riskToSeverity(e?.risk);
                  return (
                    <div
                      key={`pick-${String(e?.id ?? idx)}`}
                      className="card"
                      style={{
                        borderRadius: 16,
                        cursor: "pointer",
                        border: "1px solid rgba(255,255,255,0.10)",
                      }}
                      onClick={() => onPickGroupedEvent(e)}
                      title="Open full analysis"
                    >
                      <div
                        className="cardBody"
                        style={{
                          paddingTop: 12,
                          display: "flex",
                          gap: 12,
                          alignItems: "center",
                          justifyContent: "space-between",
                        }}
                      >
                        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
                          <span className={severityBadgeClass(sev)}>
                            {severityLabel(sev)}
                          </span>

                          <div style={{ display: "grid", gap: 2 }}>
                            <div style={{ fontWeight: 600 }}>
                              {String(e?.source ?? "-")} • {String(e?.event_type ?? "-")}
                            </div>
                            <div className="muted" style={{ fontSize: 12 }}>
                              EventID: {String(e?.event_id ?? "-")} • Asset:{" "}
                              {String(e?.asset ?? e?.MachineName ?? "localhost")} • Risk:{" "}
                              {safeInt(e?.risk, 0)}
                            </div>
                          </div>
                        </div>

                        <div className="muted" style={{ fontSize: 12 }}>
                          {toLocalDisplay(e?.timestamp ?? e?.ingested_at)}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="muted" style={{ marginTop: 10, fontSize: 12 }}>
              Click outside to close.
            </div>
          </div>
        </div>
      )}

      {selectedAnalysis && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.68)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: 18,
            zIndex: 9999,
            overscrollBehavior: "contain",
          }}
          onClick={() => setSelectedAnalysis(null)}
        >
          <div
            style={{
              width: "min(1150px, 96vw)",
              maxHeight: "92vh",
              overflow: "auto",
              borderRadius: 18,
              border: "1px solid rgba(255,255,255,0.10)",
              background: "rgba(15,15,18,0.92)",
              boxShadow: "0 20px 70px rgba(0,0,0,0.75)",
              padding: 16,
              overscrollBehavior: "contain",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                gap: 12,
                alignItems: "center",
                flexWrap: "wrap",
              }}
            >
              <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                <span className={severityBadgeClass(selectedAnalysis.severity)}>
                  {severityLabel(selectedAnalysis.severity)}
                </span>
                <div className="muted">Risk: {safeInt(selectedAnalysis.risk, 0)}</div>

                <span
                  style={{
                    fontSize: 12,
                    padding: "6px 10px",
                    borderRadius: 999,
                    border: "1px solid rgba(255,255,255,0.12)",
                    background:
                      selectedAnalysis.analysisSource === "backend"
                        ? "rgba(80,180,255,0.14)"
                        : "rgba(255,180,80,0.14)",
                    color:
                      selectedAnalysis.analysisSource === "backend"
                        ? "#9fd3ff"
                        : "#ffd59f",
                  }}
                >
                  {selectedAnalysis.analysisLabel}
                </span>
              </div>

              <button className="btn" onClick={() => setSelectedAnalysis(null)}>
                Close
              </button>
            </div>

            <div
              style={{
                marginTop: 12,
                display: "grid",
                gridTemplateColumns: "1fr 1fr",
                gap: 12,
              }}
            >
              <div className="card" style={{ borderRadius: 16 }}>
                <div className="cardHeader">
                  <div className="cardTitle" style={{ fontSize: 18 }}>
                    Reason
                  </div>
                </div>
                <div className="cardBody" style={{ paddingTop: 0 }}>
                  <div>{selectedAnalysis.reason}</div>
                </div>
              </div>

              <div className="card" style={{ borderRadius: 16 }}>
                <div className="cardHeader">
                  <div className="cardTitle" style={{ fontSize: 18 }}>
                    Recommended actions
                  </div>
                </div>
                <div className="cardBody" style={{ paddingTop: 0 }}>
                  <ul style={{ margin: 0, paddingLeft: 18 }}>
                    {selectedAnalysis.actions.map((x, i) => (
                      <li key={i} style={{ marginBottom: 6 }}>
                        {x}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              <div className="card" style={{ borderRadius: 16 }}>
                <div className="cardHeader">
                  <div className="cardTitle" style={{ fontSize: 18 }}>
                    Rules / signals triggered
                  </div>
                </div>
                <div className="cardBody" style={{ paddingTop: 0 }}>
                  <ul style={{ margin: 0, paddingLeft: 18 }}>
                    {selectedAnalysis.rules.map((x, i) => (
                      <li key={i} style={{ marginBottom: 6 }}>
                        <span className="mono">{x}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              <div className="card" style={{ borderRadius: 16 }}>
                <div className="cardHeader">
                  <div className="cardTitle" style={{ fontSize: 18 }}>
                    Key fields
                  </div>
                </div>
                <div className="cardBody" style={{ paddingTop: 0 }}>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "140px 1fr",
                      gap: 8,
                    }}
                  >
                    {selectedAnalysis.keyFields.map(([k, v]) => (
                      <React.Fragment key={k}>
                        <div className="muted">{k}</div>
                        <div className="mono" style={{ overflowWrap: "anywhere" }}>
                          {v}
                        </div>
                      </React.Fragment>
                    ))}
                  </div>
                </div>
              </div>

              <div className="card" style={{ borderRadius: 16 }}>
                <div className="cardHeader">
                  <div className="cardTitle" style={{ fontSize: 18 }}>
                    Detection metadata
                  </div>
                </div>
                <div className="cardBody" style={{ paddingTop: 0 }}>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "140px 1fr",
                      gap: 8,
                    }}
                  >
                    <div className="muted">Analysis Source</div>
                    <div className="mono">{selectedAnalysis.analysisLabel}</div>

                    <div className="muted">Related Event ID</div>
                    <div className="mono" style={{ overflowWrap: "anywhere" }}>
                      {selectedAnalysis.detectionMeta?.relatedEventId || "-"}
                    </div>

                    <div className="muted">Alert ID</div>
                    <div className="mono" style={{ overflowWrap: "anywhere" }}>
                      {selectedAnalysis.detectionMeta?.alertId || "-"}
                    </div>

                    <div className="muted">Case ID</div>
                    <div className="mono" style={{ overflowWrap: "anywhere" }}>
                      {selectedAnalysis.detectionMeta?.caseId || "-"}
                    </div>
                  </div>
                </div>
              </div>

              <div className="card" style={{ borderRadius: 16 }}>
                <div className="cardHeader">
                  <div className="cardTitle" style={{ fontSize: 18 }}>
                    Matched signals
                  </div>
                </div>
                <div className="cardBody" style={{ paddingTop: 0 }}>
                  {selectedAnalysis.signals?.length ? (
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "140px 1fr",
                        gap: 8,
                      }}
                    >
                      {selectedAnalysis.signals.map(([k, v]) => (
                        <React.Fragment key={k}>
                          <div className="muted">{k}</div>
                          <div className="mono" style={{ overflowWrap: "anywhere" }}>
                            {v}
                          </div>
                        </React.Fragment>
                      ))}
                    </div>
                  ) : (
                    <div className="muted">
                      No backend signal map available for this analysis.
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="card" style={{ borderRadius: 16, marginTop: 12 }}>
              <div className="cardHeader">
                <div className="cardTitle" style={{ fontSize: 18 }}>
                  Raw event (JSON)
                </div>
              </div>
              <div className="cardBody">
                <pre className="debugPre">
                  {JSON.stringify(selectedAnalysis.raw, null, 2)}
                </pre>
              </div>
            </div>

            <div className="muted" style={{ marginTop: 10, fontSize: 12 }}>
              Click outside the modal to close.
            </div>
          </div>
        </div>
      )}
    </div>
  );
}