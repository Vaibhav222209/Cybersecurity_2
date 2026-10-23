import { useEffect, useMemo, useState } from "react";
import {
  Search,
  Filter,
  Download,
  ChevronRight,
  ChevronLeft,
  ArrowUpRight,
  ShieldCheck,
  Shield,
  Plus,
  Trash2,
  X,
  Check,
  CheckCircle2,
  LockKeyhole,
  Eye,
  Crosshair,
  BookOpen,
  Trophy,
  RotateCcw,
  Copy,
  Fingerprint,
  Radio,
  FileSearch,
  AlertTriangle,
  Loader2,
} from "lucide-react";
import "./security.css";

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const when = (value) =>
  value
    ? new Date(value).toLocaleString([], {
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "—";
const text = (value) => String(value ?? "");
const message = (error) =>
  error?.message || "Something went wrong. Please try again.";
function Severity({ value = "info" }) {
  return (
    <span className={`badge ${value.toLowerCase()}`}>
      <i />
      {value}
    </span>
  );
}
function Notice({ children }) {
  return (
    <div className="sec-notice">
      <LockKeyhole size={16} />
      <span>{children}</span>
    </div>
  );
}
function Loading() {
  return (
    <div className="empty-state">
      <Loader2 className="sec-spin" size={25} />
      <p>Loading workspace…</p>
    </div>
  );
}
function ExportButton({ rows, name }) {
  const download = () => {
    const href = URL.createObjectURL(
      new Blob([JSON.stringify(rows, null, 2)], { type: "application/json" }),
    );
    const link = document.createElement("a");
    link.href = href;
    link.download = `${name}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(href), 1000);
  };
  return (
    <button className="btn btn-outline" onClick={download}>
      <Download size={15} />
      Export JSON
    </button>
  );
}

function LogsView({ data }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [selected, setSelected] = useState(null);
  const logs = data.logs || [];
  const rows = useMemo(
    () =>
      logs.filter(
        (log) =>
          (severity === "all" || log.severity === severity) &&
          [log.event, log.message, log.source, log.ip].some((value) =>
            text(value).toLowerCase().includes(query.toLowerCase()),
          ),
      ),
    [logs, query, severity],
  );
  const sourceCount = new Set(logs.map((log) => log.source)).size;
  return (
    <div className="sec-view">
      <div className="sec-summary-strip">
        <div>
          <span className="sec-metric-label">Collected events</span>
          <strong>
            {logs.length.toLocaleString()}
            <small> demo events</small>
          </strong>
        </div>
        <div>
          <span className="sec-metric-label">Connected sources</span>
          <strong>
            {sourceCount}
            <small> log sources</small>
          </strong>
        </div>
        <div>
          <span className="sec-metric-label">Needs attention</span>
          <strong className="sec-red">
            {
              logs.filter((log) => ["critical", "high"].includes(log.severity))
                .length
            }
            <small> high-priority events</small>
          </strong>
        </div>
        <span className="sec-live">
          <i />
          Sample telemetry
        </span>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2 className="panel-title">Event stream</h2>
            <p className="muted">Every signal. One clear picture.</p>
          </div>
          <ExportButton rows={rows} name="archer-security-logs" />
        </div>
        <div className="sec-toolbar">
          <label className="sec-search">
            <Search size={16} />
            <input
              aria-label="Search logs"
              placeholder="Search events, sources, or IP addresses…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </label>
          <label className="sec-select">
            <Filter size={15} />
            <select
              aria-label="Filter log severity"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="all">All severities</option>
              {Object.keys(severityOrder).map((level) => (
                <option key={level} value={level}>
                  {level[0].toUpperCase() + level.slice(1)}
                </option>
              ))}
            </select>
          </label>
        </div>
        <div className="table-wrap">
          <table className="data-table sec-logs-table">
            <thead>
              <tr>
                <th>Event / source</th>
                <th>Severity</th>
                <th>IP address</th>
                <th>Timestamp</th>
                <th>
                  <span className="sec-sr">Details</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((log) => (
                <LogRow
                  key={log.id}
                  log={log}
                  selected={selected === log.id}
                  onSelect={() =>
                    setSelected(selected === log.id ? null : log.id)
                  }
                />
              ))}
            </tbody>
          </table>
        </div>
        {!rows.length && (
          <div className="empty-state">
            <Search size={26} />
            <h3>No matching events</h3>
            <p>Try another search or severity filter.</p>
          </div>
        )}
        <div className="sec-table-footer">
          <span>
            Showing {rows.length} of {logs.length} events
          </span>
          <span>All timestamps use your device’s time zone</span>
        </div>
      </section>
    </div>
  );
}
function LogRow({ log, selected, onSelect }) {
  return (
    <>
      <tr className={selected ? "sec-selected-row" : ""}>
        <td>
          <div className="sec-cell-primary">{log.event}</div>
          <div className="sec-cell-secondary">{log.source}</div>
        </td>
        <td>
          <Severity value={log.severity} />
        </td>
        <td className="sec-mono">{log.ip || "—"}</td>
        <td className="sec-nowrap">{when(log.timestamp)}</td>
        <td>
          <button
            className="sec-icon-btn"
            aria-label={`${selected ? "Hide" : "Inspect"} ${log.event}`}
            aria-expanded={selected}
            onClick={onSelect}
          >
            <ChevronRight size={17} className={selected ? "sec-rotate" : ""} />
          </button>
        </td>
      </tr>
      {selected && (
        <tr className="sec-detail-row">
          <td colSpan={5}>
            <div>
              <span className="section-label">EVENT DETAIL</span>
              <p>{log.message}</p>
              <span className="muted">
                Event ID: {log.id} {log.assetId && ` · Asset: ${log.assetId}`}
              </span>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function IntelligenceView({ data, notify }) {
  const [query, setQuery] = useState("");
  const [type, setType] = useState("all");
  const [selected, setSelected] = useState(null);
  const intel = data.intel || [];
  const rows = intel.filter(
    (item) =>
      (type === "all" || item.type === type) &&
      `${item.indicator} ${item.description} ${item.tactic} ${item.source}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  const item = intel.find((i) => i.id === selected) || rows[0];
  async function copy(value) {
    try {
      await navigator.clipboard.writeText(value);
      notify("Indicator copied to clipboard.");
    } catch {
      notify(
        "Clipboard is unavailable. Select and copy the indicator manually.",
        "error",
      );
    }
  }
  return (
    <div className="sec-view">
      <div className="sec-intel-banner">
        <div className="sec-banner-icon">
          <Fingerprint size={29} />
        </div>
        <div>
          <span className="section-label">KNOW THE SIGNAL</span>
          <h2>Context turns indicators into intelligence.</h2>
          <p>
            Explore the sample indicator feed and understand the activity behind
            each threat.
          </p>
        </div>
        <span className="sec-demo-pill">Demo intelligence feed</span>
      </div>
      <div className="sec-intel-layout">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2 className="panel-title">Indicator library</h2>
              <p className="muted">
                {intel.length} indicators across{" "}
                {new Set(intel.map((i) => i.type)).size} types
              </p>
            </div>
            <span className="sec-count-bubble">{rows.length}</span>
          </div>
          <div className="sec-toolbar">
            <label className="sec-search">
              <Search size={16} />
              <input
                aria-label="Search intelligence"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search an indicator or tactic…"
              />
            </label>
            <label className="sec-select">
              <select
                aria-label="Indicator type"
                value={type}
                onChange={(e) => setType(e.target.value)}
              >
                <option value="all">All types</option>
                {[...new Set(intel.map((i) => i.type))].map((v) => (
                  <option key={v}>{v}</option>
                ))}
              </select>
            </label>
          </div>
          <div className="sec-ioc-list">
            {rows.map((i) => (
              <button
                key={i.id}
                className={`sec-ioc-row ${item?.id === i.id ? "active" : ""}`}
                onClick={() => setSelected(i.id)}
              >
                <span className="sec-ioc-icon">
                  <Crosshair size={19} />
                </span>
                <span className="sec-ioc-main">
                  <strong className="sec-mono">{i.indicator}</strong>
                  <span>
                    {i.type} <i>·</i> {i.tactic}
                  </span>
                </span>
                <Severity value={i.severity} />
                <ChevronRight size={16} />
              </button>
            ))}
          </div>
          {!rows.length && (
            <div className="empty-state">
              <Search size={24} />
              <p>No indicators match your search.</p>
            </div>
          )}
        </section>
        <aside className="panel sec-intel-detail">
          {item ? (
            <>
              <div className="sec-detail-top">
                <span className="section-label">INDICATOR PROFILE</span>
                <Severity value={item.severity} />
              </div>
              <div className="sec-intel-symbol">
                <Fingerprint size={38} />
              </div>
              <h3 className="sec-mono">{item.indicator}</h3>
              <p className="muted">{item.description}</p>
              <dl className="sec-facts">
                <div>
                  <dt>Indicator type</dt>
                  <dd>{item.type}</dd>
                </div>
                <div>
                  <dt>Threat tactic</dt>
                  <dd>{item.tactic}</dd>
                </div>
                <div>
                  <dt>Feed source</dt>
                  <dd>{item.source}</dd>
                </div>
                <div>
                  <dt>Last observed</dt>
                  <dd>{when(item.lastSeen)}</dd>
                </div>
              </dl>
              <div className="sec-confidence">
                <div>
                  <span>Confidence score</span>
                  <strong>{item.confidence}%</strong>
                </div>
                <div className="sec-progress">
                  <span
                    style={{
                      width: `${Math.max(0, Math.min(100, item.confidence))}%`,
                    }}
                  />
                </div>
              </div>
              <button
                className="btn btn-outline sec-full-width"
                onClick={() => copy(item.indicator)}
              >
                <Copy size={15} />
                Copy indicator
              </button>
            </>
          ) : (
            <div className="empty-state">
              <Fingerprint size={25} />
              <p>Select an indicator to see its context.</p>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

function HuntingView({ api, notify, can }) {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState([]);
  async function hunt(e) {
    e?.preventDefault();
    if (!query.trim()) return;
    setBusy(true);
    try {
      const response = await api("/api/hunt", {
        method: "POST",
        body: { query: query.trim() },
      });
      setResult(response);
      setHistory((old) =>
        [query.trim(), ...old.filter((q) => q !== query.trim())].slice(0, 4),
      );
    } catch (error) {
      notify(message(error), "error");
    } finally {
      setBusy(false);
    }
  }
  const logs = result?.logs || result?.matches || result?.results || [];
  const intel = result?.intel || result?.indicators || [];
  return (
    <div className="sec-view">
      <section className="panel sec-hunt-panel">
        <div className="panel-heading">
          <div className="sec-heading-with-icon">
            <span className="sec-heading-icon">
              <Crosshair size={21} />
            </span>
            <div>
              <h2 className="panel-title">Follow your next lead</h2>
              <p className="muted">
                Search across sample logs and threat intelligence using plain
                text.
              </p>
            </div>
          </div>
          <span className="sec-demo-pill">Demo telemetry</span>
        </div>
        <form onSubmit={hunt}>
          <label className="section-label" htmlFor="hunt-query">
            HUNT QUERY
          </label>
          <div className="sec-query-editor">
            <span>01</span>
            <textarea
              id="hunt-query"
              rows={3}
              placeholder="Search a source, IP address, event, or indicator…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <div className="sec-query-actions">
            <div className="sec-example-queries">
              <span>Try:</span>
              {["powershell", "failed", "203.0.113.42"].map((q) => (
                <button type="button" key={q} onClick={() => setQuery(q)}>
                  {q}
                </button>
              ))}
            </div>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={!can("hunt") || !query.trim() || busy}
            >
              {busy ? (
                <Loader2 size={16} className="sec-spin" />
              ) : (
                <Crosshair size={16} />
              )}
              {busy ? "Hunting…" : "Run hunt"}
            </button>
          </div>
        </form>
        {!can("hunt") && (
          <Notice>
            Your current role can view data. Switch to Analyst or Administrator
            in Permissions to run a hunt.
          </Notice>
        )}
      </section>
      {history.length > 0 && (
        <div className="sec-recent-queries">
          <span className="section-label">RECENT HUNTS</span>
          {history.map((q) => (
            <button key={q} onClick={() => setQuery(q)}>
              <RotateCcw size={12} />
              {q}
            </button>
          ))}
        </div>
      )}
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2 className="panel-title">Hunt results</h2>
            <p className="muted">
              {result
                ? `${logs.length} log matches · ${intel.length} intelligence matches`
                : "A focused search can uncover a bigger story."}
            </p>
          </div>
          {result && <ExportButton rows={result} name="archer-hunt-results" />}
        </div>
        {!result ? (
          <div className="empty-state sec-hunt-empty">
            <div className="sec-empty-radar">
              <Crosshair size={35} />
            </div>
            <h3>Every investigation starts with a question.</h3>
            <p>Enter a query above to connect signals across your workspace.</p>
          </div>
        ) : (
          <>
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Matching event</th>
                    <th>Source</th>
                    <th>Severity</th>
                    <th>IP address</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((log, i) => (
                    <tr key={log.id || i}>
                      <td>
                        <div className="sec-cell-primary">
                          {log.event || log.message}
                        </div>
                        <div className="sec-cell-secondary">{log.message}</div>
                      </td>
                      <td>{log.source}</td>
                      <td>
                        <Severity value={log.severity} />
                      </td>
                      <td className="sec-mono">{log.ip || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {intel.length > 0 && (
              <div className="sec-hunt-iocs">
                <span className="section-label">MATCHED INTELLIGENCE</span>
                {intel.map((i, n) => (
                  <div key={i.id || n}>
                    <Fingerprint size={16} />
                    <strong className="sec-mono">{i.indicator}</strong>
                    <Severity value={i.severity} />
                    <span className="muted">{i.description}</span>
                  </div>
                ))}
              </div>
            )}
            {!logs.length && !intel.length && (
              <div className="empty-state">
                <Search size={27} />
                <h3>No matches for this hunt</h3>
                <p>Try a broader keyword, such as “failed” or “powershell”.</p>
              </div>
            )}
          </>
        )}
      </section>
    </div>
  );
}

const emptyRule = {
  name: "",
  source: "any",
  destination: "any",
  port: "443",
  protocol: "TCP",
  action: "deny",
  enabled: true,
};
function FirewallView({ data, api, refresh, notify, can }) {
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState(emptyRule);
  const [busy, setBusy] = useState(false);
  const [removing, setRemoving] = useState(null);
  const rules = data.firewall || [];
  async function add(e) {
    e.preventDefault();
    setBusy(true);
    try {
      await api("/api/firewall", { method: "POST", body: form });
      await refresh();
      setShowForm(false);
      setForm(emptyRule);
      notify("Demo firewall rule added.");
    } catch (error) {
      notify(message(error), "error");
    } finally {
      setBusy(false);
    }
  }
  async function remove(id) {
    setRemoving(id);
    try {
      await api(`/api/firewall/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      await refresh();
      notify("Demo firewall rule removed.");
    } catch (error) {
      notify(message(error), "error");
    } finally {
      setRemoving(null);
    }
  }
  function field(name) {
    return {
      value: form[name],
      onChange: (e) => setForm((old) => ({ ...old, [name]: e.target.value })),
    };
  }
  return (
    <div className="sec-view">
      <div className="sec-firewall-overview">
        <div className="sec-firewall-shield">
          <ShieldCheck size={36} />
        </div>
        <div>
          <span className="section-label">POLICY CONTROL</span>
          <h2>Your perimeter. Your rules.</h2>
          <p>
            {rules.filter((r) => r.enabled).length} enabled rules in this demo
            workspace. Changes are recorded in the activity log.
          </p>
        </div>
        <div className="sec-firewall-status">
          <i />
          Demo policy engine
        </div>
      </div>
      <Notice>
        Firewall rules apply to this demo workspace only. They do not change the
        operating system or filter real network traffic.
      </Notice>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2 className="panel-title">Firewall policies</h2>
            <p className="muted">
              Define which connections your demo environment allows.
            </p>
          </div>
          <button
            className="btn btn-primary"
            disabled={!can("firewall")}
            onClick={() => setShowForm(!showForm)}
          >
            {showForm ? <X size={16} /> : <Plus size={16} />}
            {showForm ? "Cancel" : "Create rule"}
          </button>
        </div>
        {!can("firewall") && (
          <div className="sec-inline-note">
            <LockKeyhole size={14} />
            Administrator permission is required to create or remove rules.
          </div>
        )}
        {showForm && (
          <form className="sec-rule-form" onSubmit={add}>
            <div className="sec-form-heading">
              <h3>New firewall rule</h3>
              <span className="muted">Applied to demo state</span>
            </div>
            <div className="sec-form-grid">
              <label className="field">
                Rule name
                <input
                  className="input"
                  required
                  maxLength={100}
                  placeholder="e.g. Block suspicious outbound traffic"
                  {...field("name")}
                />
              </label>
              <label className="field">
                Source
                <input
                  className="input"
                  required
                  placeholder="IP address, CIDR, or any"
                  {...field("source")}
                />
              </label>
              <label className="field">
                Destination
                <input
                  className="input"
                  required
                  placeholder="IP address, CIDR, or any"
                  {...field("destination")}
                />
              </label>
              <label className="field">
                Port
                <input
                  className="input"
                  required
                  placeholder="443 or any"
                  {...field("port")}
                />
              </label>
              <label className="field">
                Protocol
                <select className="input" {...field("protocol")}>
                  <option>TCP</option>
                  <option>UDP</option>
                  <option>ANY</option>
                </select>
              </label>
              <label className="field">
                Action
                <select className="input" {...field("action")}>
                  <option value="deny">Deny</option>
                  <option value="allow">Allow</option>
                </select>
              </label>
            </div>
            <div className="sec-form-actions">
              <button
                type="button"
                className="btn btn-outline"
                onClick={() => setShowForm(false)}
              >
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={busy}>
                {busy && <Loader2 className="sec-spin" size={15} />}
                {busy ? "Creating…" : "Create rule"}
              </button>
            </div>
          </form>
        )}
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Rule name</th>
                <th>Source → destination</th>
                <th>Protocol / port</th>
                <th>Action</th>
                <th>Status</th>
                <th>
                  <span className="sec-sr">Remove</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id}>
                  <td>
                    <div className="sec-cell-primary">{rule.name}</div>
                    <div className="sec-cell-secondary">{rule.id}</div>
                  </td>
                  <td className="sec-mono sec-flow-cell">
                    <span>{rule.source}</span>
                    <ChevronRight size={12} />
                    <span>{rule.destination}</span>
                  </td>
                  <td className="sec-mono">
                    {rule.protocol} / {rule.port}
                  </td>
                  <td>
                    <span
                      className={`sec-rule-action ${rule.action === "allow" ? "allow" : "deny"}`}
                    >
                      {rule.action === "allow" ? (
                        <Check size={12} />
                      ) : (
                        <X size={12} />
                      )}
                      {rule.action}
                    </span>
                  </td>
                  <td>
                    <span
                      className={`sec-rule-status ${rule.enabled ? "on" : ""}`}
                    >
                      <i />
                      {rule.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </td>
                  <td>
                    <button
                      className="sec-icon-btn sec-delete"
                      disabled={!can("firewall") || removing === rule.id}
                      aria-label={`Remove ${rule.name}`}
                      onClick={() => remove(rule.id)}
                    >
                      {removing === rule.id ? (
                        <Loader2 className="sec-spin" size={15} />
                      ) : (
                        <Trash2 size={15} />
                      )}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!rules.length && (
          <div className="empty-state">
            <Shield size={27} />
            <h3>No firewall rules</h3>
            <p>Create a rule to define a demo network policy.</p>
          </div>
        )}
      </section>
    </div>
  );
}

const roles = [
  {
    id: "viewer",
    name: "Viewer",
    icon: Eye,
    description: "Keep an eye on your security posture.",
    permissions: ["read", "quiz"],
  },
  {
    id: "analyst",
    name: "Analyst",
    icon: Crosshair,
    description: "Explore signals and investigate threats.",
    permissions: ["read", "quiz", "scan", "hunt", "analyze", "investigate"],
  },
  {
    id: "admin",
    name: "Administrator",
    icon: ShieldCheck,
    description: "Manage policies and contain demo threats.",
    permissions: [
      "read",
      "quiz",
      "scan",
      "hunt",
      "analyze",
      "investigate",
      "firewall",
      "block",
      "isolate",
    ],
  },
];
const permissionRows = [
  ["read", "View logs, intelligence & network telemetry"],
  ["quiz", "Take the security awareness quiz"],
  ["scan", "Run a demo security scan"],
  ["hunt", "Run threat hunts"],
  ["analyze", "Analyze VPN, TCP & malware samples"],
  ["investigate", "Create investigations"],
  ["firewall", "Create & remove firewall rules"],
  ["block", "Block assets in demo state"],
  ["isolate", "Isolate assets in demo state"],
];
function PermissionsView({ role, onRoleChange, notify, data }) {
  const [switching, setSwitching] = useState(null);
  async function choose(id) {
    if (role === id) return;
    setSwitching(id);
    try {
      await onRoleChange(id);
    } catch (error) {
      notify(message(error), "error");
    } finally {
      setSwitching(null);
    }
  }
  return (
    <div className="sec-view">
      <div className="sec-access-intro">
        <div className="sec-heading-icon">
          <LockKeyhole size={23} />
        </div>
        <div>
          <span className="section-label">RIGHT ACCESS. RIGHT ACTION.</span>
          <h2>A clear boundary for every role.</h2>
          <p className="muted">
            Permissions are enforced by the API on each protected action.
          </p>
        </div>
      </div>
      <div className="sec-role-grid">
        {roles.map(({ id, name, icon: Icon, description }) => (
          <button
            key={id}
            className={`sec-role-card ${role === id ? "active" : ""}`}
            onClick={() => choose(id)}
            disabled={switching !== null}
            aria-pressed={role === id}
          >
            <div>
              <span className="sec-role-icon">
                <Icon size={22} />
              </span>
              {switching === id ? (
                <Loader2 className="sec-spin" size={19} />
              ) : role === id ? (
                <span className="sec-current-role">
                  <Check size={12} />
                  Current role
                </span>
              ) : (
                <ArrowUpRight size={18} />
              )}
            </div>
            <h3>{name}</h3>
            <p>{description}</p>
            <span className="sec-role-foot">
              {role === id
                ? "Active demo session"
                : `Try ${name.toLowerCase()} role`}
              <ChevronRight size={14} />
            </span>
          </button>
        ))}
      </div>
      <Notice>
        This is a demo role switcher for exploring permissions, not production
        authentication. No passwords or real user identities are verified.
      </Notice>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2 className="panel-title">Permission matrix</h2>
            <p className="muted">
              Demo session: {data.user?.name || "Vaibhav Thakur"} ·{" "}
              {roles.find((r) => r.id === role)?.name || role}
            </p>
          </div>
          <span className="sec-demo-pill">Role-based access</span>
        </div>
        <div className="table-wrap">
          <table className="data-table sec-permissions-table">
            <thead>
              <tr>
                <th>Capability</th>
                {roles.map((r) => (
                  <th
                    key={r.id}
                    className={role === r.id ? "sec-active-col" : ""}
                  >
                    {r.name}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {permissionRows.map(([key, title]) => (
                <tr key={key}>
                  <td>{title}</td>
                  {roles.map((r) => (
                    <td
                      key={r.id}
                      className={role === r.id ? "sec-active-col" : ""}
                    >
                      {r.permissions.includes(key) ? (
                        <span className="sec-granted" aria-label="Allowed">
                          <CheckCircle2 size={17} />
                        </span>
                      ) : (
                        <span className="sec-denied" aria-label="Not allowed">
                          —
                        </span>
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function AcademyView({ api, notify }) {
  const [questions, setQuestions] = useState([]);
  const [answers, setAnswers] = useState({});
  const [active, setActive] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState(null);
  const [reload, setReload] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    api("/api/quiz")
      .then((response) => {
        if (!cancelled) setQuestions(response.questions || response);
      })
      .catch((err) => {
        if (!cancelled) setError(message(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [api, reload]);
  async function submit() {
    setSubmitting(true);
    try {
      setResult(await api("/api/quiz", { method: "POST", body: { answers } }));
    } catch (err) {
      notify(message(err), "error");
    } finally {
      setSubmitting(false);
    }
  }
  function restart() {
    setAnswers({});
    setActive(0);
    setResult(null);
  }
  const current = questions[active];
  const answered = Object.keys(answers).length;
  const correctScore = result?.score ?? result?.correct ?? 0;
  return (
    <div className="sec-view">
      <div className="sec-academy-banner">
        <div>
          <span className="section-label">THE HUMAN FIREWALL</span>
          <h2>
            A sharper mind.
            <br />A stronger defense.
          </h2>
          <p>Five questions to put your cybersecurity instincts to the test.</p>
          <div className="sec-academy-tags">
            <span>
              <BookOpen size={14} />5 questions
            </span>
            <span>
              <ShieldCheck size={14} />
              Security fundamentals
            </span>
          </div>
        </div>
        <div className="sec-academy-art">
          <div />
          <div />
          <Trophy size={74} strokeWidth={1.1} />
          <i />
          <i />
        </div>
      </div>
      <section className="panel sec-quiz-panel">
        {loading ? (
          <Loading />
        ) : error ? (
          <div className="empty-state">
            <AlertTriangle size={28} />
            <h3>Could not load the quiz</h3>
            <p>{error}</p>
            <button
              className="btn btn-outline"
              onClick={() => setReload((x) => x + 1)}
            >
              Try again
            </button>
          </div>
        ) : !questions.length ? (
          <div className="empty-state">
            <BookOpen size={28} />
            <p>No quiz questions available.</p>
          </div>
        ) : result ? (
          <>
            <div className="sec-quiz-result">
              <div
                className="sec-score-ring"
                style={{
                  "--score": `${(correctScore / (result.total || questions.length)) * 100}%`,
                }}
              >
                <div>
                  <strong>
                    {correctScore}
                    <span>/{result.total || questions.length}</span>
                  </strong>
                  <span>correct answers</span>
                </div>
              </div>
              <div>
                <span className="section-label">QUIZ COMPLETE</span>
                <h2>
                  {correctScore === questions.length
                    ? "Your instincts are on point."
                    : correctScore >= 3
                      ? "A strong foundation. Keep it sharp."
                      : "Every answer is a chance to learn."}
                </h2>
                <p className="muted">
                  Review the explanations below and keep building your security
                  awareness.
                </p>
                <button className="btn btn-primary" onClick={restart}>
                  <RotateCcw size={15} />
                  Take it again
                </button>
              </div>
            </div>
            <div className="sec-quiz-review">
              {questions.map((q, i) => {
                const feedback =
                  (result.results || []).find(
                    (r) => (r.questionId || r.id) === q.id,
                  ) || result.results?.[i];
                const correct = feedback?.correct ?? feedback?.isCorrect;
                return (
                  <div key={q.id} className="sec-review-item">
                    <span
                      className={`sec-review-icon ${correct ? "correct" : "incorrect"}`}
                    >
                      {correct ? <Check size={16} /> : <X size={16} />}
                    </span>
                    <div>
                      <h4>
                        {i + 1}. {q.question || q.prompt}
                      </h4>
                      <p>
                        {feedback?.explanation ||
                          "Review your answer and try the quiz again."}
                      </p>
                    </div>
                    <span
                      className={`sec-review-label ${correct ? "correct" : "incorrect"}`}
                    >
                      {correct ? "Correct" : "Review"}
                    </span>
                  </div>
                );
              })}
            </div>
          </>
        ) : (
          <>
            <div className="sec-quiz-top">
              <div>
                <span className="section-label">SECURITY KNOWLEDGE CHECK</span>
                <h2 className="panel-title">
                  A little practice goes a long way.
                </h2>
              </div>
              <span className="muted">
                {answered} of {questions.length} answered
              </span>
            </div>
            <div className="sec-question-progress">
              {questions.map((q, i) => (
                <button
                  key={q.id}
                  onClick={() => setActive(i)}
                  className={`${active === i ? "active" : ""} ${answers[q.id] !== undefined ? "answered" : ""}`}
                  aria-label={`Question ${i + 1}${answers[q.id] !== undefined ? ", answered" : ""}`}
                  aria-current={active === i ? "step" : undefined}
                >
                  {answers[q.id] !== undefined ? (
                    <Check size={15} />
                  ) : (
                    String(i + 1).padStart(2, "0")
                  )}
                  <span>Question {i + 1}</span>
                </button>
              ))}
            </div>
            <fieldset className="sec-question">
              <legend>
                <span>QUESTION {String(active + 1).padStart(2, "0")}</span>
                {current.question || current.prompt}
              </legend>
              <div className="sec-answer-options">
                {(current.options || []).map((option, index) => {
                  const value =
                    typeof option === "string"
                      ? String.fromCharCode(97 + index)
                      : (option.id ?? option.value);
                  const label =
                    typeof option === "string"
                      ? option
                      : option.text || option.label;
                  return (
                    <label
                      key={value}
                      className={`sec-answer-option ${answers[current.id] === value ? "selected" : ""}`}
                    >
                      <input
                        type="radio"
                        name={current.id}
                        value={value}
                        checked={answers[current.id] === value}
                        onChange={() =>
                          setAnswers((old) => ({ ...old, [current.id]: value }))
                        }
                      />
                      <span className="sec-answer-letter">
                        {String.fromCharCode(65 + index)}
                      </span>
                      <span>{label}</span>
                      <span className="sec-answer-radio">
                        {answers[current.id] === value && <span />}
                      </span>
                    </label>
                  );
                })}
              </div>
            </fieldset>
            <div className="sec-quiz-bottom">
              <button
                className="btn btn-outline"
                disabled={active === 0}
                onClick={() => setActive((i) => i - 1)}
              >
                <ChevronLeft size={15} />
                Previous
              </button>
              <span className="muted">Choose the best answer.</span>
              {active < questions.length - 1 ? (
                <button
                  className="btn btn-primary"
                  onClick={() => setActive((i) => i + 1)}
                >
                  Next question
                  <ChevronRight size={15} />
                </button>
              ) : (
                <button
                  className="btn btn-primary"
                  disabled={answered !== questions.length || submitting}
                  onClick={submit}
                >
                  {submitting ? (
                    <Loader2 className="sec-spin" size={15} />
                  ) : (
                    <CheckCircle2 size={15} />
                  )}
                  {submitting ? "Checking…" : "Check answers"}
                </button>
              )}
            </div>
          </>
        )}
      </section>
    </div>
  );
}

function InvestigationsView({ data }) {
  const [selected, setSelected] = useState(null);
  const investigations = data.investigations || [];
  return (
    <div className="sec-view">
      <div className="sec-summary-strip">
        <div>
          <span className="sec-metric-label">Case workspace</span>
          <strong>
            {investigations.length}
            <small> investigations</small>
          </strong>
        </div>
        <div>
          <span className="sec-metric-label">Open cases</span>
          <strong>
            {investigations.filter((i) => i.status !== "closed").length}
            <small> awaiting review</small>
          </strong>
        </div>
        <div className="sec-investigation-hint">
          <FileSearch size={23} />
          <span>
            Connect the evidence.
            <br />
            <strong>Understand the story.</strong>
          </span>
        </div>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2 className="panel-title">Investigation cases</h2>
            <p className="muted">
              Evidence and findings from your demo workspace.
            </p>
          </div>
          <ExportButton rows={investigations} name="archer-investigations" />
        </div>
        {!investigations.length ? (
          <div className="empty-state sec-hunt-empty">
            <FileSearch size={35} />
            <h3>Your next lead starts with an asset.</h3>
            <p>Use Investigate on an asset in the overview to create a case.</p>
          </div>
        ) : (
          <div className="sec-case-list">
            {investigations.map((item) => (
              <article
                className={`sec-case ${selected === item.id ? "open" : ""}`}
                key={item.id}
              >
                <button
                  className="sec-case-trigger"
                  onClick={() =>
                    setSelected(selected === item.id ? null : item.id)
                  }
                  aria-expanded={selected === item.id}
                >
                  <span className="sec-case-icon">
                    <FileSearch size={21} />
                  </span>
                  <span className="sec-case-main">
                    <strong>{item.title}</strong>
                    <span>
                      {item.id} · Asset {item.assetId} · Opened{" "}
                      {when(item.createdAt)}
                    </span>
                  </span>
                  <span className="sec-case-status">
                    <i />
                    {item.status}
                  </span>
                  <ChevronRight
                    size={17}
                    className={selected === item.id ? "sec-rotate" : ""}
                  />
                </button>
                {selected === item.id && (
                  <div className="sec-case-detail">
                    <span className="section-label">
                      INVESTIGATION FINDINGS
                    </span>
                    {Array.isArray(item.findings) ? (
                      <ol>
                        {item.findings.map((finding, i) => (
                          <li key={i}>
                            {typeof finding === "string"
                              ? finding
                              : finding.description ||
                                finding.message ||
                                JSON.stringify(finding)}
                          </li>
                        ))}
                      </ol>
                    ) : (
                      <p>
                        {text(item.findings) ||
                          "Evidence is being collected for this case."}
                      </p>
                    )}
                    <span className="muted">
                      Demo case data. No real endpoints have been accessed.
                    </span>
                  </div>
                )}
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

export default function SecurityViews(props) {
  switch (props.view) {
    case "logs":
      return <LogsView {...props} />;
    case "intelligence":
      return <IntelligenceView {...props} />;
    case "hunting":
      return <HuntingView {...props} />;
    case "firewall":
      return <FirewallView {...props} />;
    case "permissions":
      return <PermissionsView {...props} />;
    case "academy":
      return <AcademyView {...props} />;
    case "investigations":
      return <InvestigationsView {...props} />;
    default:
      return null;
  }
}
