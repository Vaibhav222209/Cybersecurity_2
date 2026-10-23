import { useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  ChevronRight,
  Copy,
  FileSearch,
  Fingerprint,
  Globe2,
  Network,
  Pause,
  Play,
  Radio,
  Radar,
  RefreshCw,
  ScanLine,
  Search,
  Server,
  ShieldCheck,
  Upload,
  X,
} from "lucide-react";
import "./analysis.css";

const formatTime = (value) => {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
};
const formatBytes = (value) =>
  Number(value) >= 1024
    ? `${(Number(value) / 1024).toFixed(1)} KB`
    : `${Number(value) || 0} B`;
const array = (value) => (Array.isArray(value) ? value : []);
const show = (value) =>
  typeof value === "object" && value !== null
    ? value.message ||
      value.reason ||
      value.description ||
      JSON.stringify(value)
    : value;

function DemoLabel({ children = "Demo environment" }) {
  return (
    <span className="analysis-demo">
      <span />
      {children}
    </span>
  );
}

function ToolBanner({ icon: Icon, eyebrow, title, description, children }) {
  return (
    <div className="analysis-banner">
      <div className="analysis-banner-copy">
        <div className="analysis-eyebrow">
          <Icon size={16} />
          {eyebrow}
        </div>
        <h2>{title}</h2>
        <p>{description}</p>
        {children}
      </div>
      <div className="analysis-orbit" aria-hidden="true">
        <div />
        <div />
        <div />
        <Icon size={38} strokeWidth={1.3} />
      </div>
    </div>
  );
}

function MiniStats({ items }) {
  return (
    <div className="analysis-stats">
      {items.map(({ label, value, note, icon: Icon, tone }) => (
        <div className="analysis-stat" key={label}>
          <div className={`analysis-stat-icon ${tone || ""}`}>
            <Icon size={18} />
          </div>
          <div>
            <span>{label}</span>
            <strong>{value}</strong>
            {note && <small>{note}</small>}
          </div>
        </div>
      ))}
    </div>
  );
}

function useAction(notify) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function run(action) {
    setBusy(true);
    setError("");
    try {
      return await action();
    } catch (err) {
      const message = err.message || "The operation could not be completed.";
      setError(message);
      notify(message, "error");
    } finally {
      setBusy(false);
    }
  }
  return { busy, error, run };
}

function ErrorMessage({ error }) {
  return error ? (
    <p className="analysis-error" role="alert">
      <AlertTriangle size={16} />
      {error}
    </p>
  ) : null;
}

function PermissionNote({ allowed, action }) {
  return !allowed ? (
    <p className="analysis-permission">
      <ShieldCheck size={14} />
      Your role can view this module. An analyst or administrator can {action}.
    </p>
  ) : null;
}

function Scanner({ data, api, refresh, notify, can }) {
  const [scope, setScope] = useState("all");
  const [report, setReport] = useState(null);
  const { busy, error, run } = useAction(notify);
  const assets = array(data.assets);
  const findings = array(report?.findings || report?.scan?.findings);
  const critical = findings.filter((item) =>
    ["critical", "high"].includes(item.severity),
  ).length;
  async function scan() {
    await run(async () => {
      const result = await api("/api/scan", {
        method: "POST",
        body: { scope },
      });
      setReport(result);
      await refresh();
      notify("Inventory scan complete. Review the findings below.");
    });
  }
  return (
    <div className="analysis-workspace">
      <ToolBanner
        icon={ScanLine}
        eyebrow="DISCOVER · ASSESS · PRIORITIZE"
        title="Know what needs your attention."
        description="Assess the sample asset inventory, surface exposed services, and turn potential weaknesses into your next investigation."
      >
        <DemoLabel>Simulated inventory scan</DemoLabel>
      </ToolBanner>
      <MiniStats
        items={[
          {
            label: "Assets in scope",
            value: assets.length,
            note: "Managed demo endpoints",
            icon: Server,
          },
          {
            label: "At-risk assets",
            value: assets.filter((item) => item.status === "at-risk").length,
            note: "Require a closer look",
            icon: AlertTriangle,
            tone: "amber",
          },
          {
            label: "Latest scan findings",
            value: report ? findings.length : "—",
            note: report
              ? `${critical} high priority`
              : "Run a scan to get started",
            icon: Radar,
          },
        ]}
      />
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h3 className="panel-title">Asset scanner</h3>
            <p className="muted">
              A repeatable assessment of this workspace’s demo inventory.
            </p>
          </div>
          <span className="badge info">Inventory assessment</span>
        </div>
        <div className="analysis-controls">
          <label className="field" htmlFor="scan-scope">
            Scan scope
            <select
              id="scan-scope"
              className="input"
              value={scope}
              onChange={(event) => setScope(event.target.value)}
            >
              <option value="all">All demo assets</option>
              <option value="corporate">Corporate network</option>
              <option value="cloud">Cloud services</option>
            </select>
          </label>
          <button
            className="btn btn-primary"
            onClick={scan}
            disabled={busy || !can("scan")}
          >
            <ScanLine size={16} className={busy ? "analysis-spin" : ""} />
            {busy ? "Scanning inventory…" : "Run assessment"}
          </button>
        </div>
        <PermissionNote allowed={can("scan")} action="run an assessment" />
        <ErrorMessage error={error} />
        {report ? (
          <div className="analysis-result">
            <div className="analysis-result-heading">
              <span>
                <CheckCircle2 size={17} />
                Assessment complete
              </span>
              <small>{new Date().toLocaleDateString()}</small>
            </div>
            {findings.length ? (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Finding</th>
                      <th>Asset</th>
                      <th>Severity</th>
                      <th>Recommendation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((finding, index) => (
                      <tr key={finding.id || index}>
                        <td>
                          <strong>
                            {show(
                              finding.title ||
                                finding.name ||
                                finding.issue ||
                                finding.description,
                            )}
                          </strong>
                          {finding.port && (
                            <small className="analysis-cell-note">
                              Port {finding.port} · {finding.protocol || "TCP"}
                            </small>
                          )}
                        </td>
                        <td className="analysis-mono">
                          {finding.asset ||
                            finding.assetName ||
                            assets.find((a) => a.id === finding.assetId)
                              ?.name ||
                            finding.ip ||
                            "Demo asset"}
                        </td>
                        <td>
                          <span
                            className={`badge ${finding.severity || "medium"}`}
                          >
                            {finding.severity || "medium"}
                          </span>
                        </td>
                        <td className="analysis-cell-description">
                          {show(
                            finding.recommendation ||
                              finding.remediation ||
                              finding.description ||
                              "Review this exposure and verify the asset configuration.",
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty-state">
                <ShieldCheck size={30} />
                <h3>No findings for this scope</h3>
                <p>
                  Choose a different scope to assess additional demo assets.
                </p>
              </div>
            )}
          </div>
        ) : (
          <div className="analysis-get-started">
            <div className="analysis-line-icon">
              <Radar size={25} />
            </div>
            <div>
              <strong>A clear view starts with a scan.</strong>
              <p>
                Choose a scope above. Findings will appear here, with their
                severity and a recommended next step.
              </p>
            </div>
          </div>
        )}
      </section>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h3 className="panel-title">Managed assets</h3>
            <p className="muted">
              The endpoints included in the demo workspace.
            </p>
          </div>
          <span className="analysis-count">{assets.length} assets</span>
        </div>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Asset</th>
                <th>Address</th>
                <th>Platform</th>
                <th>Risk score</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((asset) => (
                <tr key={asset.id}>
                  <td>
                    <span className="analysis-asset">
                      <span className="analysis-asset-icon">
                        <Server size={16} />
                      </span>
                      <span>
                        <strong>{asset.name}</strong>
                        <small>{asset.type}</small>
                      </span>
                    </span>
                  </td>
                  <td className="analysis-mono">{asset.ip}</td>
                  <td>{asset.os}</td>
                  <td>
                    <span className="analysis-risk">
                      <span>
                        <i
                          style={{
                            width: `${Math.min(100, asset.risk || 0)}%`,
                          }}
                        />
                      </span>
                      {asset.risk}
                    </span>
                  </td>
                  <td>
                    <span
                      className={`badge ${asset.status === "healthy" ? "low" : asset.status === "at-risk" ? "high" : "info"}`}
                    >
                      {asset.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function Vpn({ data, api, notify, can }) {
  const [csv, setCsv] = useState("");
  const [report, setReport] = useState(null);
  const [fileName, setFileName] = useState("");
  const { busy, error, run } = useAction(notify);
  const sessions = array(data.vpn);
  const anomalies = array(
    report?.alerts || report?.anomalies || report?.findings,
  );
  async function analyze() {
    await run(async () => {
      const result = await api("/api/vpn/analyze", {
        method: "POST",
        body: csv.trim() ? { csv } : {},
      });
      setReport(result);
      notify("VPN history analyzed.");
    });
  }
  async function loadFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > 500_000) {
      notify("Choose a CSV file smaller than 500 KB.", "error");
      return;
    }
    try {
      setCsv(await file.text());
      setFileName(file.name);
      setReport(null);
    } catch {
      notify(
        "The CSV file could not be read. Try selecting it again.",
        "error",
      );
    }
  }
  return (
    <div className="analysis-workspace">
      <ToolBanner
        icon={Globe2}
        eyebrow="VPN HISTORY ANALYSIS"
        title="Follow the signs of an unusual login."
        description="Spot impossible travel, failed connection bursts, and unfamiliar access patterns in VPN history. Analyze the sample sessions or bring your own CSV."
      >
        <DemoLabel>Sample history · CSV analysis</DemoLabel>
      </ToolBanner>
      <MiniStats
        items={[
          {
            label: "Sample sessions",
            value: sessions.length,
            note: "Across the demo workspace",
            icon: Network,
          },
          {
            label: "Countries seen",
            value: new Set(sessions.map((s) => s.country)).size,
            note: "Geographic access footprint",
            icon: Globe2,
          },
          {
            label: "Anomalies detected",
            value: report ? anomalies.length : "—",
            note: report ? "Review before taking action" : "Ready for analysis",
            icon: AlertTriangle,
            tone: "amber",
          },
        ]}
      />
      <div className="analysis-two-columns">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h3 className="panel-title">Analyze connection history</h3>
              <p className="muted">
                Leave blank to inspect the sample history.
              </p>
            </div>
            <Globe2 size={20} className="muted" />
          </div>
          <div className="analysis-form-body">
            <label className="field" htmlFor="vpn-csv">
              VPN history CSV
              <textarea
                id="vpn-csv"
                className="input analysis-textarea"
                value={csv}
                onChange={(event) => {
                  setCsv(event.target.value);
                  setReport(null);
                  setFileName("");
                }}
                placeholder={
                  "user,ip,country,city,timestamp,device,latitude,longitude\nvaibhav,203.0.113.10,India,Delhi,2026-10-23T09:00:00Z,Laptop,28.6,77.2"
                }
                spellCheck="false"
              />
            </label>
            <div className="analysis-inline-actions">
              <label className="btn btn-outline analysis-upload-label">
                <Upload size={15} />
                {fileName || "Import CSV"}
                <input
                  type="file"
                  accept=".csv,text/csv,text/plain"
                  onChange={loadFile}
                  aria-label="Import VPN history CSV"
                />
              </label>
              {csv && (
                <button
                  className="btn btn-ghost"
                  onClick={() => {
                    setCsv("");
                    setFileName("");
                    setReport(null);
                  }}
                >
                  <X size={15} />
                  Clear
                </button>
              )}
            </div>
            <p className="analysis-help">
              Use ISO timestamps. Optional city, device, latitude and longitude
              fields add context to travel findings.
            </p>
            <button
              className="btn btn-primary analysis-wide-button"
              onClick={analyze}
              disabled={busy || !can("analyze")}
            >
              <FileSearch size={16} />
              {busy
                ? "Analyzing history…"
                : csv.trim()
                  ? "Analyze imported history"
                  : "Analyze sample history"}
            </button>
            <PermissionNote allowed={can("analyze")} action="analyze history" />
            <ErrorMessage error={error} />
          </div>
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h3 className="panel-title">Investigation findings</h3>
              <p className="muted">
                Signals help you decide where to look next.
              </p>
            </div>
            {report && (
              <span className="badge medium">{anomalies.length} signals</span>
            )}
          </div>
          {report ? (
            <div className="analysis-findings">
              {anomalies.length ? (
                anomalies.map((item, index) => (
                  <div className="analysis-finding" key={item.id || index}>
                    <div
                      className={`analysis-finding-icon ${item.severity || "medium"}`}
                    >
                      <AlertTriangle size={17} />
                    </div>
                    <div>
                      <div className="analysis-finding-top">
                        <strong>
                          {item.title ||
                            item.type ||
                            item.reason ||
                            "Unusual access pattern"}
                        </strong>
                        <span className={`badge ${item.severity || "medium"}`}>
                          {item.severity || "medium"}
                        </span>
                      </div>
                      <p>
                        {show(
                          item.description ||
                            item.message ||
                            item.reason ||
                            item.detail,
                        )}
                      </p>
                      <small>
                        {[item.user, item.ip, item.country]
                          .filter(Boolean)
                          .join(" · ")}
                      </small>
                      {item.evidence && (
                        <p className="analysis-evidence">{item.evidence}</p>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <div className="empty-state">
                  <ShieldCheck size={32} />
                  <h3>No anomalies detected</h3>
                  <p>
                    The supplied sessions did not trigger the current analysis
                    rules.
                  </p>
                </div>
              )}
            </div>
          ) : (
            <div className="empty-state analysis-tall-empty">
              <div className="analysis-empty-orbit">
                <Globe2 size={34} />
              </div>
              <h3>Every connection tells a story.</h3>
              <p>
                Analyze a history file to reveal unusual authentication and
                travel patterns.
              </p>
            </div>
          )}
        </section>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h3 className="panel-title">Sample VPN sessions</h3>
            <p className="muted">Seeded connection history for exploration.</p>
          </div>
          <DemoLabel>Demo data</DemoLabel>
        </div>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>User</th>
                <th>Source address</th>
                <th>Location</th>
                <th>Time</th>
                <th>Device</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((session) => (
                <tr key={session.id}>
                  <td>
                    <strong>{session.user}</strong>
                  </td>
                  <td className="analysis-mono">{session.ip}</td>
                  <td>
                    {session.city ? `${session.city}, ` : ""}
                    {session.country}
                  </td>
                  <td>{formatTime(session.timestamp)}</td>
                  <td>{session.device}</td>
                  <td>
                    <span
                      className={`badge ${session.status === "success" || session.status === "connected" ? "low" : "high"}`}
                    >
                      {session.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function Connections({ data, api, notify, can }) {
  const [report, setReport] = useState(null);
  const [stateFilter, setStateFilter] = useState("all");
  const [connectionInput, setConnectionInput] = useState("");
  const { busy, error, run } = useAction(notify);
  const flows = array(report?.connections || data.connections);
  const halfOpen = array(report?.connections).filter(
    (flow) =>
      ["SYN_SENT", "SYN_RECEIVED"].includes(flow.state) &&
      flow.ageSeconds >= (report?.thresholdSeconds || 15),
  );
  const halfOpenCount =
    typeof report?.halfOpen === "number" ? report.halfOpen : halfOpen.length;
  const shown = flows.filter(
    (flow) =>
      stateFilter === "all" ||
      (stateFilter === "half-open"
        ? ["SYN_SENT", "SYN_RECEIVED"].includes(flow.state)
        : flow.state === "ESTABLISHED"),
  );
  async function analyze() {
    await run(async () => {
      let body = {};
      if (connectionInput.trim()) {
        try {
          body.connections = JSON.parse(connectionInput);
        } catch {
          throw new Error(
            "Connection data must be valid JSON. Paste an array of flow records.",
          );
        }
      }
      const result = await api("/api/tcp/analyze", { method: "POST", body });
      setReport(result);
      notify("TCP state analysis complete.");
    });
  }
  return (
    <div className="analysis-workspace">
      <ToolBanner
        icon={Network}
        eyebrow="TCP CONNECTION INTELLIGENCE"
        title="See what’s behind every handshake."
        description="Inspect established connections and detect half-open TCP sessions. Analyze the sample flows or paste your own exported connection metadata."
      >
        <DemoLabel>Sample flows · JSON analysis</DemoLabel>
      </ToolBanner>
      <MiniStats
        items={[
          {
            label: "TCP connections",
            value: flows.length,
            note: report
              ? "In the analyzed flow table"
              : "In the sample flow table",
            icon: Network,
          },
          {
            label: "Established",
            value: flows.filter((f) => f.state === "ESTABLISHED").length,
            note: "Completed three-way handshakes",
            icon: CheckCircle2,
          },
          {
            label: "Pending handshakes",
            value: flows.filter((f) =>
              ["SYN_SENT", "SYN_RECEIVED"].includes(f.state),
            ).length,
            note: "SYN sent or received",
            icon: Activity,
            tone: "amber",
          },
        ]}
      />
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h3 className="panel-title">Half-open connection detector</h3>
            <p className="muted">
              Identify incomplete handshakes that exceed the analysis threshold.
            </p>
          </div>
          <button
            className="btn btn-primary"
            onClick={analyze}
            disabled={busy || !can("analyze")}
          >
            <Radar size={16} className={busy ? "analysis-spin" : ""} />
            {busy ? "Analyzing…" : "Analyze TCP flows"}
          </button>
        </div>
        <PermissionNote allowed={can("analyze")} action="analyze connections" />
        <ErrorMessage error={error} />
        <details className="analysis-import-details">
          <summary>
            Analyze your own connection data
            <ChevronRight size={14} />
          </summary>
          <label className="field" htmlFor="tcp-json">
            Connection records (JSON)
            <textarea
              id="tcp-json"
              className="input analysis-textarea"
              value={connectionInput}
              onChange={(event) => setConnectionInput(event.target.value)}
              placeholder={
                '[{"source":"10.0.0.10","destination":"10.0.0.20","port":443,"state":"SYN_SENT","ageSeconds":45,"bytes":0}]'
              }
              spellCheck="false"
            />
          </label>
          <p className="analysis-help">
            Paste an array with source, destination, port, state and ageSeconds.
            Leave blank to use the sample flow table. Up to 1,000 records.
          </p>
          {connectionInput && (
            <button
              className="btn btn-ghost"
              onClick={() => {
                setConnectionInput("");
                setReport(null);
              }}
            >
              Use sample flows
              <X size={14} />
            </button>
          )}
        </details>
        {report ? (
          <div className="analysis-form-body">
            <div
              className={`analysis-detection-summary ${halfOpenCount ? "warning" : ""}`}
            >
              <div className="analysis-detection-icon">
                {halfOpenCount ? (
                  <AlertTriangle size={24} />
                ) : (
                  <ShieldCheck size={24} />
                )}
              </div>
              <div>
                <strong>
                  {halfOpenCount
                    ? `${halfOpenCount} half-open connections need attention`
                    : "No suspicious half-open connections detected"}
                </strong>
                <p>
                  {report.description ||
                    "A pending SYN is a signal to investigate; legitimate latency and unreachable hosts can also leave connections incomplete."}
                </p>
              </div>
              <span className={`badge ${halfOpenCount ? "high" : "low"}`}>
                {halfOpenCount ? "Review recommended" : "Clear"}
              </span>
            </div>
            {halfOpen.length > 0 && (
              <div className="analysis-halfopen-grid">
                {halfOpen.map((flow, index) => (
                  <div
                    className="analysis-halfopen-card"
                    key={flow.id || index}
                  >
                    <span className="analysis-mono">
                      {flow.source || flow.ip || "Source"}
                      <ArrowUpRight size={14} />
                      {flow.destination || flow.target || "Destination"}
                      {flow.port ? `:${flow.port}` : ""}
                    </span>
                    <p>
                      {show(
                        flow.reason ||
                          flow.description ||
                          `${flow.state || "Incomplete handshake"} · ${flow.ageSeconds || 0}s pending`,
                      )}
                    </p>
                  </div>
                ))}
              </div>
            )}
            {array(report.alerts).some(
              (alert) => alert.severity === "high",
            ) && (
              <div className="analysis-tcp-alerts">
                {array(report.alerts)
                  .filter((alert) => alert.severity === "high")
                  .map((alert) => (
                    <div key={alert.id}>
                      <AlertTriangle size={16} />
                      <p>
                        <strong>{alert.type}</strong>
                        {alert.message}
                      </p>
                    </div>
                  ))}
              </div>
            )}
          </div>
        ) : (
          <div className="analysis-get-started">
            <div className="analysis-line-icon">
              <Activity size={25} />
            </div>
            <div>
              <strong>Turn handshake states into a useful signal.</strong>
              <p>
                Run the detector to find stalled SYN sessions in the connection
                table.
              </p>
            </div>
          </div>
        )}
      </section>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h3 className="panel-title">Connection table</h3>
            <p className="muted">
              TCP flow states, destination ports and transfer sizes.
            </p>
          </div>
          <select
            className="input analysis-compact-select"
            aria-label="Filter TCP connections"
            value={stateFilter}
            onChange={(e) => setStateFilter(e.target.value)}
          >
            <option value="all">All connections</option>
            <option value="established">Established</option>
            <option value="half-open">Pending handshake</option>
          </select>
        </div>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Destination</th>
                <th>Port</th>
                <th>State</th>
                <th>Age</th>
                <th>Transferred</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((flow) => (
                <tr key={flow.id}>
                  <td className="analysis-mono">{flow.source}</td>
                  <td className="analysis-mono">{flow.destination}</td>
                  <td>
                    <span className="analysis-port">{flow.port}</span>
                  </td>
                  <td>
                    <span
                      className={`badge ${flow.state === "ESTABLISHED" ? "low" : "medium"}`}
                    >
                      {flow.state.replaceAll("_", " ")}
                    </span>
                  </td>
                  <td>{flow.ageSeconds}s</td>
                  <td>{formatBytes(flow.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {shown.length === 0 && (
            <div className="empty-state">
              <Network size={24} />
              <p>No connections match this filter.</p>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

function Malware({ api, notify, can }) {
  const [file, setFile] = useState(null);
  const [report, setReport] = useState(null);
  const { busy, error, run } = useAction(notify);
  const fileInput = useRef(null);
  const indicators = array(report?.indicators || report?.findings);
  async function loadFile(event) {
    const selected = event.target.files?.[0];
    if (!selected) return;
    if (selected.size === 0 || selected.size > 2 * 1024 * 1024) {
      notify("Select a non-empty file smaller than 2 MB.", "error");
      event.target.value = "";
      return;
    }
    const reader = new FileReader();
    reader.onerror = () => notify("This file could not be read.", "error");
    reader.onload = () => {
      setFile({
        name: selected.name,
        size: selected.size,
        contentBase64: String(reader.result).split(",")[1],
      });
      setReport(null);
    };
    reader.readAsDataURL(selected);
  }
  function loadSample() {
    const text =
      "# Archer Security analysis sample\n# Harmless text for static indicator detection\npowershell -EncodedCommand SAMPLE\nhttps://suspicious-example.invalid/payload.exe\ncmd.exe /c whoami\n";
    setFile({
      name: "archer-analysis-sample.txt",
      size: new Blob([text]).size,
      contentBase64: btoa(text),
    });
    setReport(null);
  }
  async function analyze() {
    if (!file) return;
    await run(async () => {
      const result = await api("/api/malware/analyze", {
        method: "POST",
        body: { name: file.name, contentBase64: file.contentBase64 },
      });
      setReport(result);
      notify("Static file analysis complete.");
    });
  }
  async function copyHash() {
    try {
      await navigator.clipboard.writeText(report.sha256 || report.hash);
      notify("SHA-256 copied to clipboard.");
    } catch {
      notify(
        "Clipboard access is unavailable. Select and copy the hash below.",
        "error",
      );
    }
  }
  const hash = report?.sha256 || report?.hash;
  const entropy = Number(report?.entropy || 0);
  return (
    <div className="analysis-workspace">
      <ToolBanner
        icon={Fingerprint}
        eyebrow="STATIC FILE ANALYSIS"
        title="Get a closer look. Keep the file still."
        description="Extract a SHA-256 fingerprint, inspect file entropy, and look for suspicious text indicators. Files are analyzed as bytes and are never executed."
      >
        <DemoLabel>Static analysis · 2 MB maximum</DemoLabel>
      </ToolBanner>
      <div className="analysis-two-columns">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h3 className="panel-title">Submit a file</h3>
              <p className="muted">A file’s first clues are in its contents.</p>
            </div>
            <FileSearch size={20} className="muted" />
          </div>
          <div className="analysis-form-body">
            <label className={`analysis-file-zone ${file ? "has-file" : ""}`}>
              <input
                ref={fileInput}
                type="file"
                onChange={loadFile}
                aria-label="Choose a file for static analysis"
              />
              <span className="analysis-file-icon">
                {file ? <FileSearch size={27} /> : <Upload size={27} />}
              </span>
              <strong>
                {file ? file.name : "Choose a file to investigate"}
              </strong>
              <span>
                {file
                  ? `${formatBytes(file.size)} · Click to change file`
                  : "Click to browse · Any file up to 2 MB"}
              </span>
            </label>
            <div className="analysis-sample-row">
              <span className="muted">Just exploring?</span>
              <button className="btn btn-ghost" onClick={loadSample}>
                Use a harmless sample
                <ChevronRight size={15} />
              </button>
            </div>
            <button
              className="btn btn-primary analysis-wide-button"
              disabled={!file || busy || !can("analyze")}
              onClick={analyze}
            >
              <Fingerprint size={16} />
              {busy ? "Analyzing file…" : "Analyze file"}
            </button>
            <PermissionNote allowed={can("analyze")} action="analyze files" />
            <ErrorMessage error={error} />
            <div className="analysis-static-note">
              <ShieldCheck size={18} />
              <p>
                This is a static triage tool. A clear result does not establish
                that a file is safe.
              </p>
            </div>
          </div>
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h3 className="panel-title">Analysis report</h3>
              <p className="muted">
                Hashes, characteristics and observable indicators.
              </p>
            </div>
            {report && (
              <span className={`badge ${indicators.length ? "medium" : "low"}`}>
                {indicators.length ? "Indicators found" : "No indicators"}
              </span>
            )}
          </div>
          {report ? (
            <div className="analysis-form-body">
              <div className="analysis-file-report">
                <div className="analysis-report-file-icon">
                  <Fingerprint size={25} />
                </div>
                <div>
                  <strong>{report.name || file.name}</strong>
                  <p>
                    {formatBytes(report.size || file.size)} ·{" "}
                    {report.type || report.fileType || "Static analysis"}
                  </p>
                </div>
              </div>
              <div className="analysis-hash-heading">
                <span className="section-label">SHA-256 fingerprint</span>
                <button
                  className="btn btn-ghost"
                  onClick={copyHash}
                  aria-label="Copy SHA-256 hash"
                >
                  <Copy size={15} />
                </button>
              </div>
              <code className="analysis-hash">
                {hash || "Not returned by analyzer"}
              </code>
              <div className="analysis-entropy">
                <div>
                  <span>File entropy</span>
                  <strong>
                    {entropy.toFixed(2)} <small>/ 8.00</small>
                  </strong>
                </div>
                <div className="analysis-entropy-track">
                  <span
                    style={{ width: `${Math.min(100, (entropy / 8) * 100)}%` }}
                  />
                </div>
                <p>
                  Higher values can indicate compression or encryption. Context
                  matters.
                </p>
              </div>
              <div className="analysis-verdict">
                <span className="section-label">Triage result</span>
                <p>
                  {show(
                    report.verdict?.replaceAll("-", " ") ||
                      report.summary ||
                      (indicators.length
                        ? "Review the indicators below in the context of the file’s source and purpose."
                        : "No configured text indicators matched this file."),
                  )}
                </p>
              </div>
            </div>
          ) : (
            <div className="empty-state analysis-tall-empty">
              <div className="analysis-empty-orbit">
                <Fingerprint size={36} />
              </div>
              <h3>A fingerprint is a good place to start.</h3>
              <p>
                Choose a file or use the harmless sample to inspect its static
                characteristics.
              </p>
            </div>
          )}
        </section>
      </div>
      {report && (
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h3 className="panel-title">Detected indicators</h3>
              <p className="muted">
                Text patterns provide leads for a deeper investigation.
              </p>
            </div>
            <span className="analysis-count">{indicators.length} matches</span>
          </div>
          {indicators.length ? (
            <div className="analysis-findings">
              {indicators.map((item, index) => (
                <div className="analysis-finding" key={item.id || index}>
                  <div className="analysis-finding-icon medium">
                    <FileSearch size={18} />
                  </div>
                  <div>
                    <div className="analysis-finding-top">
                      <strong>
                        {typeof item === "string"
                          ? item
                          : item.name ||
                            item.type ||
                            item.indicator ||
                            "Suspicious text pattern"}
                      </strong>
                      {item.severity && (
                        <span className={`badge ${item.severity}`}>
                          {item.severity}
                        </span>
                      )}
                    </div>
                    <p>
                      {typeof item === "string"
                        ? "Matched a configured static analysis indicator."
                        : show(
                            item.description ||
                              item.match ||
                              item.value ||
                              item.reason,
                          )}
                    </p>
                    {item.value && (
                      <code className="analysis-indicator-value">
                        {item.value}
                      </code>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="analysis-get-started">
              <ShieldCheck size={24} />
              <div>
                <strong>No configured indicators matched.</strong>
                <p>
                  Continue reviewing the file’s provenance and other analysis
                  sources before trusting it.
                </p>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
}

function Sniffer({ data, api, notify }) {
  const [capturing, setCapturing] = useState(false);
  const [packets, setPackets] = useState(array(data.packets));
  const [sourcePackets, setSourcePackets] = useState(array(data.packets));
  const [protocol, setProtocol] = useState("all");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const cursor = useRef(0);
  const started = useRef(Date.now());
  useEffect(() => {
    if (!capturing || !sourcePackets.length) return undefined;
    const timer = setInterval(() => {
      const sample = sourcePackets[cursor.current % sourcePackets.length];
      cursor.current += 1;
      const now = new Date().toISOString();
      const next = {
        ...sample,
        id: `replay-${started.current}-${cursor.current}`,
        time: now,
      };
      setPackets((current) => [next, ...current].slice(0, 150));
    }, 1100);
    return () => clearInterval(timer);
  }, [capturing, sourcePackets]);
  async function toggleCapture() {
    if (capturing) {
      setCapturing(false);
      return;
    }
    setLoading(true);
    try {
      const result = await api("/api/packets");
      const samples = array(result.packets || result);
      if (!samples.length) throw new Error("No demo packets are available.");
      setSourcePackets(samples);
      setCapturing(true);
    } catch (error) {
      notify(error.message, "error");
    } finally {
      setLoading(false);
    }
  }
  const filtered = packets.filter(
    (packet) =>
      (protocol === "all" || packet.protocol === protocol) &&
      (!query ||
        `${packet.source} ${packet.destination} ${packet.port} ${packet.info}`
          .toLowerCase()
          .includes(query.toLowerCase())),
  );
  const protocols = [...new Set(sourcePackets.map((p) => p.protocol))];
  return (
    <div className="analysis-workspace">
      <ToolBanner
        icon={Radio}
        eyebrow="PACKET EXPLORER"
        title="Make network conversations visible."
        description="Follow source and destination addresses, inspect protocols, and filter packet metadata in a replayable synthetic traffic stream."
      >
        <DemoLabel>Synthetic packets · no live capture</DemoLabel>
      </ToolBanner>
      <MiniStats
        items={[
          {
            label: "Packets in buffer",
            value: packets.length,
            note: "Latest 150 packets retained",
            icon: Radio,
          },
          {
            label: "Data observed",
            value: formatBytes(
              packets.reduce((sum, p) => sum + Number(p.size || 0), 0),
            ),
            note: "Synthetic metadata only",
            icon: Activity,
          },
          {
            label: "Protocols",
            value: protocols.length,
            note: protocols.join(" · "),
            icon: Network,
          },
        ]}
      />
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h3 className="panel-title">Traffic capture</h3>
            <p className="muted">
              Start the replay to explore a moving stream of sample traffic.
            </p>
          </div>
          <div className="analysis-inline-actions">
            <span
              className={`analysis-capture-status ${capturing ? "running" : ""}`}
            >
              <span />
              {capturing ? "Replaying demo" : "Paused"}
            </span>
            <button
              className={`btn ${capturing ? "btn-outline" : "btn-primary"}`}
              onClick={toggleCapture}
              disabled={loading}
            >
              {capturing ? <Pause size={15} /> : <Play size={15} />}
              {loading
                ? "Loading packets…"
                : capturing
                  ? "Pause capture"
                  : "Start demo capture"}
            </button>
          </div>
        </div>
        <div className="analysis-filter-bar">
          <label className="analysis-search">
            <Search size={16} />
            <input
              className="input"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search IP, port, or packet details…"
              aria-label="Search packets"
            />
          </label>
          <select
            className="input analysis-compact-select"
            aria-label="Filter packet protocol"
            value={protocol}
            onChange={(e) => setProtocol(e.target.value)}
          >
            <option value="all">All protocols</option>
            {protocols.map((p) => (
              <option value={p} key={p}>
                {p}
              </option>
            ))}
          </select>
          <button
            className="btn btn-ghost"
            onClick={() => {
              setPackets([]);
              notify("Packet buffer cleared.");
            }}
            disabled={!packets.length}
          >
            <RefreshCw size={15} />
            Clear buffer
          </button>
        </div>
        <div className="table-wrap">
          <table className="data-table analysis-packet-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Length</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((packet) => (
                <tr key={packet.id}>
                  <td className="analysis-mono">{formatTime(packet.time)}</td>
                  <td className="analysis-mono">{packet.source}</td>
                  <td className="analysis-mono">
                    {packet.destination}
                    {packet.port ? `:${packet.port}` : ""}
                  </td>
                  <td>
                    <span
                      className={`analysis-protocol ${packet.protocol?.toLowerCase()}`}
                    >
                      {packet.protocol}
                    </span>
                  </td>
                  <td>{formatBytes(packet.size)}</td>
                  <td className="analysis-packet-info">{packet.info}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length === 0 && (
            <div className="empty-state">
              <Radio size={28} />
              <h3>
                {packets.length
                  ? "No packets match these filters."
                  : "The packet buffer is empty."}
              </h3>
              <p>
                {packets.length
                  ? "Try another address or protocol."
                  : "Start the demo replay to add synthetic packets."}
              </p>
            </div>
          )}
        </div>
        <div className="analysis-table-footer">
          <span>{filtered.length} matching packets</span>
          <span>Demo stream · Metadata only · No raw network access</span>
        </div>
      </section>
    </div>
  );
}

export default function AnalysisViews(props) {
  if (props.view === "scanner") return <Scanner {...props} />;
  if (props.view === "vpn") return <Vpn {...props} />;
  if (props.view === "connections") return <Connections {...props} />;
  if (props.view === "malware") return <Malware {...props} />;
  if (props.view === "sniffer") return <Sniffer {...props} />;
  return null;
}
