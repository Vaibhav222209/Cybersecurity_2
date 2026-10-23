import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  Activity,
  ArrowDown,
  ArrowDownLeft,
  ArrowRight,
  ArrowUpRight,
  Bell,
  BookOpen,
  Check,
  CheckCheck,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Command,
  Crosshair,
  Download,
  Fingerprint,
  Globe2,
  LayoutDashboard,
  ListFilter,
  LockKeyhole,
  Menu,
  MoreHorizontal,
  Network,
  Radar,
  Radio,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Target,
  Terminal,
  Users,
  Wifi,
  X,
} from "lucide-react";
import AnalysisViews from "./components/AnalysisViews.jsx";
import SecurityViews from "./components/SecurityViews.jsx";

const NAV = [
  {
    label: "MONITOR",
    items: [
      ["overview", "Overview", LayoutDashboard],
      ["logs", "Log monitoring", Activity],
      ["intelligence", "Threat intelligence", Globe2],
      ["hunting", "Threat hunting", Crosshair],
      ["scanner", "Security scanner", Radar],
      ["vpn", "VPN history", Wifi],
    ],
  },
  {
    label: "PROTECT & INVESTIGATE",
    items: [
      ["firewall", "Firewall", Shield],
      ["connections", "TCP connections", Network],
      ["malware", "Malware analysis", Fingerprint],
      ["sniffer", "Packet sniffer", Radio],
      ["investigations", "Investigations", Search],
    ],
  },
  {
    label: "WORKSPACE",
    items: [
      ["permissions", "Permissions", Users],
      ["academy", "Security academy", BookOpen],
    ],
  },
];
const TITLES = {
  overview: [
    "Security overview",
    "The big picture. Every signal. One step ahead.",
  ],
  logs: ["Log monitoring", "Find the signal in the noise."],
  intelligence: [
    "Threat intelligence",
    "Context that turns indicators into insight.",
  ],
  hunting: ["Threat hunting", "Follow your curiosity. Uncover hidden threats."],
  scanner: [
    "Security scanner",
    "Know your attack surface before someone else does.",
  ],
  vpn: ["VPN history", "Spot unusual access, wherever it comes from."],
  firewall: ["Firewall", "Clear rules. Stronger boundaries."],
  connections: [
    "TCP connections",
    "See what connects. Detect what doesn’t belong.",
  ],
  malware: ["Malware analysis", "Inspect a file without running it."],
  sniffer: [
    "Packet sniffer",
    "A closer look at the traffic between the lines.",
  ],
  investigations: [
    "Investigations",
    "Connect the evidence. Understand the story.",
  ],
  permissions: ["Permissions", "The right access for every responsibility."],
  academy: [
    "Security academy",
    "A little knowledge. A stronger first line of defense.",
  ],
};

function relativeTime(value) {
  const date = new Date(value);
  if (Number.isNaN(+date)) return String(value || "Just now");
  const min = Math.max(0, Math.floor((Date.now() - +date) / 60000));
  return min < 1
    ? "Just now"
    : min < 60
      ? `${min}m ago`
      : min < 1440
        ? `${Math.floor(min / 60)}h ago`
        : `${Math.floor(min / 1440)}d ago`;
}

function Modal({ title, children, onClose, wide = false }) {
  const ref = useRef(null);
  useEffect(() => {
    const previous = document.activeElement;
    ref.current?.focus();
    const key = (event) => {
      if (event.key === "Escape") onClose();
      if (event.key === "Tab") {
        const elements = ref.current?.querySelectorAll(
          'button:not(:disabled), a[href], input, select, textarea, [tabindex="0"]',
        );
        if (!elements?.length) {
          event.preventDefault();
          return;
        }
        const first = elements[0],
          last = elements[elements.length - 1];
        if (
          event.shiftKey &&
          (document.activeElement === first ||
            document.activeElement === ref.current)
        ) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("keydown", key);
      previous?.focus();
    };
  }, [onClose]);
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
    >
      <section
        className={`modal ${wide ? "modal-wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        ref={ref}
      >
        <div className="modal-header">
          <h2>{title}</h2>
          <button
            className="icon-button"
            aria-label="Close dialog"
            onClick={onClose}
          >
            <X size={20} />
          </button>
        </div>
        {children}
      </section>
    </div>
  );
}

export default function App() {
  const [view, setView] = useState(() =>
    TITLES[location.hash.slice(1)] ? location.hash.slice(1) : "overview",
  );
  const [data, setData] = useState(null);
  const [token, setToken] = useState(
    () => sessionStorage.getItem("archer-token") || "",
  );
  const tokenRef = useRef(token);
  const [role, setRole] = useState("analyst");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState(null);
  const [mobileNav, setMobileNav] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showHelp, setShowHelp] = useState(false);
  const [showExport, setShowExport] = useState(false);
  const [search, setSearch] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [busy, setBusy] = useState(false);
  const [lastSync, setLastSync] = useState(new Date());
  const searchRef = useRef(null);
  const toastTimer = useRef(null);

  const notify = useCallback((message, type = "success") => {
    setToast({ message, type });
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 5000);
  }, []);

  const api = useCallback(async (path, options = {}) => {
    const response = await fetch(path, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(tokenRef.current
          ? { Authorization: `Bearer ${tokenRef.current}` }
          : {}),
        ...options.headers,
      },
      body:
        options.body === undefined ? undefined : JSON.stringify(options.body),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok)
      throw new Error(
        body.error?.message ||
          body.error ||
          body.message ||
          `Request failed (${response.status})`,
      );
    return body;
  }, []);

  const refresh = useCallback(async () => {
    const result = await api("/api/bootstrap");
    setData(result);
    setRole(result.user.role);
    setLastSync(new Date());
    return result;
  }, [api]);

  const changeRole = useCallback(
    async (nextRole) => {
      try {
        const session = await api("/api/session", {
          method: "POST",
          body: { role: nextRole },
        });
        tokenRef.current = session.token;
        setToken(session.token);
        sessionStorage.setItem("archer-token", session.token);
        await refresh();
        notify(`Demo workspace switched to ${nextRole}.`);
      } catch (e) {
        notify(e.message, "error");
      }
    },
    [api, refresh, notify],
  );

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        if (tokenRef.current) {
          try {
            await refresh();
            if (active) setLoading(false);
            return;
          } catch {
            sessionStorage.removeItem("archer-token");
            tokenRef.current = "";
          }
        }
        const session = await api("/api/session", {
          method: "POST",
          body: { role: "analyst" },
        });
        if (!active) return;
        tokenRef.current = session.token;
        setToken(session.token);
        sessionStorage.setItem("archer-token", session.token);
        await refresh();
      } catch (e) {
        if (active) setError(e.message);
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [api, refresh]);

  useEffect(() => {
    const handler = () => {
      const next = location.hash.slice(1);
      if (TITLES[next]) setView(next);
    };
    const keyboard = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        searchRef.current?.focus();
        setSearchOpen(true);
      }
      if (e.key === "Escape") {
        setSearchOpen(false);
        setMobileNav(false);
        setShowNotifications(false);
      }
    };
    window.addEventListener("hashchange", handler);
    document.addEventListener("keydown", keyboard);
    return () => {
      window.removeEventListener("hashchange", handler);
      document.removeEventListener("keydown", keyboard);
    };
  }, []);

  const navigate = (next) => {
    setView(next);
    location.hash = next;
    setMobileNav(false);
    setSearchOpen(false);
    setSearch("");
  };
  const can = useCallback(
    (permission) => Boolean(data?.permissions?.includes(permission)),
    [data],
  );
  const title = TITLES[view];
  const searchResults = useMemo(() => {
    const term = search.toLowerCase().trim();
    const pages = NAV.flatMap((section) => section.items)
      .filter(([, label]) => !term || label.toLowerCase().includes(term))
      .map(([id, label, Icon]) => ({ id, label, Icon, kind: "Workspace" }));
    if (!data || !term) return pages.slice(0, 7);
    const logs = data.logs
      .filter((log) =>
        `${log.event} ${log.message} ${log.ip}`.toLowerCase().includes(term),
      )
      .slice(0, 3)
      .map((log) => ({
        id: log.id,
        label: log.event,
        Icon: ShieldAlert,
        kind: "Event",
        log,
      }));
    const assets = data.assets
      .filter((asset) =>
        `${asset.name} ${asset.ip}`.toLowerCase().includes(term),
      )
      .slice(0, 3)
      .map((asset) => ({
        id: asset.id,
        label: `${asset.name} · ${asset.ip}`,
        Icon: Server,
        kind: "Asset",
        asset,
      }));
    return [...pages, ...logs, ...assets].slice(0, 8);
  }, [search, data]);

  const assetAction = async (assetId, action) => {
    if (!assetId) {
      notify("This event is not linked to a managed asset.", "error");
      return;
    }
    setBusy(true);
    try {
      await api(`/api/assets/${assetId}/action`, {
        method: "POST",
        body: { action },
      });
      await refresh();
      setSelectedAlert(null);
      setSelectedAsset(null);
      notify(
        action === "investigate"
          ? "Investigation opened. Review it in Investigations."
          : `Demo asset ${action === "block" ? "blocked" : "isolated"}. Activity recorded.`,
      );
    } catch (e) {
      notify(e.message, "error");
    } finally {
      setBusy(false);
    }
  };

  const downloadReport = () => {
    const report = {
      project: "Archer Security",
      author: "Vaibhav Thakur",
      mode: "demo",
      generatedAt: new Date().toISOString(),
      summary: data.summary,
      assets: data.assets,
      alerts: data.logs.filter((log) =>
        ["critical", "high"].includes(log.severity),
      ),
      investigations: data.investigations,
    };
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = `archer-security-report-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
    setShowExport(false);
    notify("Security report downloaded.");
  };

  return (
    <div className="app-shell">
      {mobileNav && (
        <button
          className="nav-scrim"
          aria-label="Close navigation"
          onClick={() => setMobileNav(false)}
        />
      )}
      <aside className={`sidebar ${mobileNav ? "sidebar-open" : ""}`}>
        <a
          href="#overview"
          className="brand"
          onClick={() => navigate("overview")}
        >
          <img src="/archer-mark.svg" alt="" />
          <div>
            archer<span>SECURITY</span>
          </div>
        </a>
        <div className="workspace-switch">
          <span className="workspace-avatar">
            <ShieldCheck size={17} />
          </span>
          <div>
            Security workspace<span>Personal organization</span>
          </div>
          <LockKeyhole size={13} className="muted" />
        </div>
        <nav aria-label="Main navigation">
          {NAV.map((group) => (
            <div className="nav-group" key={group.label}>
              <div className="nav-label">{group.label}</div>
              {group.items.map(([id, label, Icon]) => (
                <button
                  key={id}
                  onClick={() => navigate(id)}
                  className={`nav-item ${view === id ? "active" : ""}`}
                  aria-current={view === id ? "page" : undefined}
                >
                  <Icon size={17} strokeWidth={1.7} />
                  <span>{label}</span>
                  {id === "vpn" && <i className="nav-count">3</i>}
                  {view === id && <span className="active-dot" />}
                </button>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="demo-card">
            <div>
              <span className="live-dot" />
              Demo workspace
              <Sparkles size={14} />
            </div>
            <p>Explore freely. Learn by doing.</p>
            <button onClick={() => navigate("permissions")}>
              Manage your access <ArrowUpRight size={14} />
            </button>
          </div>
          <div className="made-by">
            <span className="creator-avatar">VT</span>
            <div>
              Vaibhav Thakur<span>Creator of Archer Security</span>
            </div>
          </div>
        </div>
      </aside>

      <div className="app-main">
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="icon-button mobile-menu"
              onClick={() => setMobileNav(true)}
              aria-label="Open navigation"
            >
              <Menu size={21} />
            </button>
            <ShieldCheck size={16} />
            <span>Workspace</span>
            <ChevronRight size={13} />
            <strong>{title[0]}</strong>
          </div>
          <div className="topbar-actions">
            <span className="system-status">
              <span className="live-dot" />
              Systems operational
            </span>
            <span className="topbar-divider" />
            <button
              className="icon-button"
              aria-label="Help and workspace guide"
              onClick={() => setShowHelp(true)}
            >
              <CircleHelp size={19} />
            </button>
            <div className="notifications-wrap">
              <button
                className={`icon-button notification-button ${showNotifications ? "pressed" : ""}`}
                aria-label="Notifications"
                onClick={() => setShowNotifications(!showNotifications)}
              >
                <Bell size={19} />
                <i />
              </button>
              {showNotifications && (
                <div className="notification-popover">
                  <div className="popover-heading">
                    Activity center<span className="badge info">Demo</span>
                  </div>
                  {(data?.activity || []).slice(0, 4).map((event) => (
                    <div className="notification-row" key={event.id}>
                      <span className="small-icon">
                        <Activity size={15} />
                      </span>
                      <div>
                        <strong>{event.action}</strong>
                        <p>{event.detail}</p>
                        <small>{relativeTime(event.time)}</small>
                      </div>
                    </div>
                  ))}
                  {!data?.activity?.length && (
                    <div className="notification-row muted">
                      Your workspace is ready. Actions will appear here.
                    </div>
                  )}
                  <button
                    className="popover-footer"
                    onClick={() => {
                      setShowNotifications(false);
                      navigate("investigations");
                    }}
                  >
                    Open investigations <ArrowRight size={14} />
                  </button>
                </div>
              )}
            </div>
            <button
              className="profile-button"
              onClick={() => navigate("permissions")}
              aria-label="Manage profile and permissions"
            >
              VT
            </button>
          </div>
        </header>

        <main className="page-content" id="main-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">
                ARCHER SECURITY <span>/</span>{" "}
                {view === "overview" ? "COMMAND CENTER" : "WORKSPACE"}
              </div>
              <h1>
                {title[0]}
                <span className="heading-dot">.</span>
              </h1>
              <p>{title[1]}</p>
            </div>
            <div className="page-heading-actions">
              <div className="search-box">
                <Search size={16} />
                <input
                  ref={searchRef}
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value);
                    setSearchOpen(true);
                  }}
                  onFocus={() => setSearchOpen(true)}
                  onBlur={() => setTimeout(() => setSearchOpen(false), 160)}
                  placeholder="Search workspace..."
                  aria-label="Search workspace"
                />
                <kbd>⌘ K</kbd>
                {searchOpen && (
                  <div className="search-results">
                    {searchResults.length ? (
                      searchResults.map((item) => (
                        <button
                          key={`${item.kind}-${item.id}`}
                          onMouseDown={(e) => e.preventDefault()}
                          onClick={() => {
                            if (item.log) setSelectedAlert(item.log);
                            else if (item.asset) setSelectedAsset(item.asset);
                            else navigate(item.id);
                            setSearchOpen(false);
                          }}
                        >
                          <item.Icon size={17} />
                          <span>
                            {item.label}
                            <small>{item.kind}</small>
                          </span>
                          <ArrowUpRight size={14} />
                        </button>
                      ))
                    ) : (
                      <div className="search-empty">
                        No matching pages, events, or assets.
                      </div>
                    )}
                  </div>
                )}
              </div>
              {view === "overview" && (
                <button
                  className="btn btn-outline export-button"
                  onClick={() => setShowExport(true)}
                  disabled={!data}
                >
                  <Download size={15} />
                  Export report
                </button>
              )}
            </div>
          </div>

          {loading ? (
            <div className="loading-screen">
              <div className="loading-radar">
                <Radar size={36} />
              </div>
              <h2>Getting your workspace ready</h2>
              <p>Connecting the signals…</p>
            </div>
          ) : error ? (
            <div className="panel error-panel">
              <ShieldAlert size={32} />
              <h2>We couldn’t connect to the workspace</h2>
              <p>{error}</p>
              <button
                className="btn btn-primary"
                onClick={() => location.reload()}
              >
                Try again
              </button>
            </div>
          ) : (
            data && (
              <>
                {view === "overview" ? (
                  <Overview
                    data={data}
                    navigate={navigate}
                    setSelectedAlert={setSelectedAlert}
                    setSelectedAsset={setSelectedAsset}
                    lastSync={lastSync}
                  />
                ) : [
                    "scanner",
                    "vpn",
                    "connections",
                    "malware",
                    "sniffer",
                  ].includes(view) ? (
                  <AnalysisViews
                    key={view}
                    view={view}
                    data={data}
                    api={api}
                    refresh={refresh}
                    notify={notify}
                    can={can}
                  />
                ) : (
                  <SecurityViews
                    key={view}
                    view={view}
                    data={data}
                    api={api}
                    refresh={refresh}
                    notify={notify}
                    can={can}
                    onRoleChange={changeRole}
                    role={role}
                  />
                )}
                <footer className="page-footer">
                  <span>
                    <Target size={13} /> Archer Security{" "}
                    <span className="footer-separator">·</span> Made by{" "}
                    <strong>Vaibhav Thakur</strong>
                  </span>
                  <span>
                    <span className="live-dot" />
                    Demo data <span className="footer-separator">·</span>{" "}
                    {role.charAt(0).toUpperCase() + role.slice(1)} access
                  </span>
                </footer>
              </>
            )
          )}
        </main>
      </div>

      {toast && (
        <div className={`toast ${toast.type}`} role="status">
          {toast.type === "error" ? (
            <ShieldAlert size={18} />
          ) : (
            <CheckCheck size={18} />
          )}
          <span>{toast.message}</span>
          <button aria-label="Dismiss message" onClick={() => setToast(null)}>
            <X size={15} />
          </button>
        </div>
      )}
      {showHelp && (
        <Modal
          title="Welcome to Archer Security"
          onClose={() => setShowHelp(false)}
        >
          <div className="help-hero">
            <Target size={38} />
            <h3>Your security, in focus.</h3>
            <p>
              A hands-on security operations workspace, made by Vaibhav Thakur.
            </p>
          </div>
          <div className="help-steps">
            <div>
              <span>01</span>
              <p>
                <strong>Follow the signals</strong>Review logs, explore threat
                intelligence, and hunt through workspace events.
              </p>
            </div>
            <div>
              <span>02</span>
              <p>
                <strong>Investigate and respond</strong>Analyze suspicious files
                and VPN activity. Open cases, block assets, and manage firewall
                rules.
              </p>
            </div>
            <div>
              <span>03</span>
              <p>
                <strong>Learn as you go</strong>Visit the academy for five
                cybersecurity questions and explanations.
              </p>
            </div>
          </div>
          <div className="demo-notice">
            <ShieldCheck size={18} />
            <p>
              This is a demo workspace. Network data is simulated. Firewall,
              block, and isolate actions affect the demo inventory only. File
              and pasted-history analysis run locally on this server. Switch
              demo roles in Permissions to explore access controls.
            </p>
          </div>
          <button
            className="btn btn-primary full-width"
            onClick={() => setShowHelp(false)}
          >
            Let’s explore <ArrowRight size={16} />
          </button>
        </Modal>
      )}
      {showExport && (
        <Modal
          title="Export security report"
          onClose={() => setShowExport(false)}
        >
          <div className="report-icon">
            <Download size={28} />
          </div>
          <p className="modal-description">
            A snapshot of your demo workspace, ready for review. Includes the
            security summary, asset inventory, priority alerts, and
            investigations.
          </p>
          <div className="export-file">
            <span className="file-extension">JSON</span>
            <div>
              <strong>Archer Security report</strong>
              <span>Structured data · Current workspace</span>
            </div>
            <Check size={18} />
          </div>
          <button
            className="btn btn-primary full-width"
            onClick={downloadReport}
          >
            <Download size={16} />
            Download report
          </button>
        </Modal>
      )}
      {selectedAlert && (
        <Modal
          title="Event investigation"
          onClose={() => setSelectedAlert(null)}
        >
          <div className="detail-title">
            <span className={`badge ${selectedAlert.severity}`}>
              {selectedAlert.severity}
            </span>
            <span className="muted">
              {relativeTime(selectedAlert.timestamp)}
            </span>
          </div>
          <h3 className="event-title">{selectedAlert.event}</h3>
          <p className="modal-description">{selectedAlert.message}</p>
          <dl className="detail-grid">
            <div>
              <dt>Source</dt>
              <dd>{selectedAlert.source}</dd>
            </div>
            <div>
              <dt>IP address</dt>
              <dd className="mono">{selectedAlert.ip}</dd>
            </div>
            <div>
              <dt>Asset</dt>
              <dd>
                {data.assets.find((asset) => asset.id === selectedAlert.assetId)
                  ?.name || "Unmanaged source"}
              </dd>
            </div>
            <div>
              <dt>Timestamp</dt>
              <dd>{new Date(selectedAlert.timestamp).toLocaleString()}</dd>
            </div>
          </dl>
          <div className="demo-notice">
            <ShieldAlert size={18} />
            <p>
              Review related events, validate the indicator against threat
              intelligence, and contain the affected demo asset if needed.
            </p>
          </div>
          <div className="modal-actions">
            <button
              className="btn btn-outline"
              disabled={!can("block") || busy || !selectedAlert.assetId}
              onClick={() => assetAction(selectedAlert.assetId, "block")}
            >
              <Shield size={16} />
              Block asset
            </button>
            <button
              className="btn btn-primary"
              disabled={!can("investigate") || busy || !selectedAlert.assetId}
              onClick={() => assetAction(selectedAlert.assetId, "investigate")}
            >
              <Search size={16} />
              Open investigation
            </button>
          </div>
          {!can("block") && (
            <p className="access-note">
              Blocking and isolation require the demo Administrator role.
            </p>
          )}
        </Modal>
      )}
      {selectedAsset && (
        <Modal title="Asset details" onClose={() => setSelectedAsset(null)}>
          <div className="asset-detail-icon">
            <Server size={28} />
          </div>
          <h3 className="event-title">{selectedAsset.name}</h3>
          <dl className="detail-grid">
            <div>
              <dt>IP address</dt>
              <dd className="mono">{selectedAsset.ip}</dd>
            </div>
            <div>
              <dt>Status</dt>
              <dd>
                <span
                  className={`badge ${selectedAsset.status === "healthy" ? "low" : "high"}`}
                >
                  {selectedAsset.status}
                </span>
              </dd>
            </div>
            <div>
              <dt>Operating system</dt>
              <dd>{selectedAsset.os}</dd>
            </div>
            <div>
              <dt>Risk score</dt>
              <dd>{selectedAsset.risk}/100</dd>
            </div>
          </dl>
          <div className="modal-actions asset-actions">
            <button
              className="btn btn-outline"
              disabled={!can("block") || busy}
              onClick={() => assetAction(selectedAsset.id, "block")}
            >
              <Shield size={15} />
              Block
            </button>
            <button
              className="btn btn-outline"
              disabled={!can("isolate") || busy}
              onClick={() => assetAction(selectedAsset.id, "isolate")}
            >
              <LockKeyhole size={15} />
              Isolate
            </button>
            <button
              className="btn btn-primary"
              disabled={!can("investigate") || busy}
              onClick={() => assetAction(selectedAsset.id, "investigate")}
            >
              <Search size={15} />
              Investigate
            </button>
          </div>
          <p className="access-note">
            These actions update the demo inventory and audit trail. Admin
            access is required to block or isolate.
          </p>
        </Modal>
      )}
    </div>
  );
}

function Overview({
  data,
  navigate,
  setSelectedAlert,
  setSelectedAsset,
  lastSync,
}) {
  const alerts = [...data.logs]
    .filter((log) => ["critical", "high"].includes(log.severity))
    .sort(
      (a, b) =>
        (a.severity === "critical" ? -1 : 1) -
        (b.severity === "critical" ? -1 : 1),
    );
  const total = data.summary?.totalAssets ?? data.assets.length;
  const healthy =
    data.summary?.protectedAssets ??
    data.assets.filter((asset) => asset.status === "healthy").length;
  const posture =
    data.summary?.postureScore ??
    Math.round((healthy / Math.max(total, 1)) * 100);
  const events = data.summary?.events24h ?? data.logs.length;
  const activeThreats = data.summary?.activeThreats ?? alerts.length;
  const [period, setPeriod] = useState("24h");
  const [eventType, setEventType] = useState("all");
  const [hover, setHover] = useState(null);
  const history = data.summary?.eventsTrend || [];
  const series = period === "24h" ? history : history.slice(-4);
  const chart = series.map((point) =>
    eventType === "threats" ? point.threats : point.events,
  );
  const chartMax = Math.max(3, Math.ceil(Math.max(...chart) / 3) * 3);
  const points = chart.map((n, i) => [
    42 + i * (660 / Math.max(chart.length - 1, 1)),
    170 - (n / chartMax) * 150,
  ]);
  const path = points.map(([x, y], i) => `${i ? "L" : "M"}${x},${y}`).join(" ");
  const severityCounts = ["critical", "high", "medium", "low"].map(
    (severity) => ({
      severity,
      count: data.intel.filter((item) => item.severity === severity).length,
    }),
  );
  const threatTotal =
    severityCounts.reduce((sum, row) => sum + row.count, 0) || 1;
  let offset = 0;
  const colors = ["#de7868", "#e6b467", "#8aafa0", "#d5e2cb"];
  return (
    <div className="overview-view">
      <section className="hero-banner">
        <div className="hero-copy">
          <div className="hero-label">
            <span />
            CLARITY. CONTROL. CONFIDENCE.
          </div>
          <h2>
            Stay a step ahead
            <br />
            of <span>every threat.</span>
          </h2>
          <p>
            Your signals, connected. Your defenses, stronger.
            <br />
            Security starts with seeing the whole picture.
          </p>
          <div className="hero-actions">
            <button
              className="btn btn-lime"
              onClick={() => navigate("scanner")}
            >
              <Radar size={16} />
              Run security scan
              <ArrowUpRight size={16} />
            </button>
            <button
              className="hero-link"
              onClick={() => navigate("intelligence")}
            >
              Explore intelligence <ArrowUpRight size={15} />
            </button>
          </div>
        </div>
        <div className="hero-chip">
          <span className="live-dot" />
          YOUR PERIMETER, IN PERSPECTIVE
        </div>
      </section>

      <div className="stats-grid">
        <StatCard
          label="Events monitored"
          value={events.toLocaleString()}
          icon={Activity}
          color="green"
        >
          <span className="stat-trend">
            <ArrowUpRight size={13} />
            {new Set(data.logs.map((log) => log.source)).size} connected sources
          </span>
          <span className="mini-spark">
            <i />
            <i />
            <i />
            <i />
            <i />
            <i />
            <i />
            <i />
          </span>
        </StatCard>
        <StatCard
          label="Active threats"
          value={String(activeThreats).padStart(2, "0")}
          icon={ShieldAlert}
          color="peach"
        >
          <span className="stat-description">
            <i className="tiny-dot red" />
            {data.logs.filter((log) => log.severity === "critical").length}{" "}
            require immediate attention
          </span>
        </StatCard>
        <StatCard
          label="Protected assets"
          value={
            <>
              {healthy}
              <small> / {total}</small>
            </>
          }
          icon={Server}
          color="sage"
        >
          <span className="stat-description">
            {data.assets.filter((asset) => asset.status === "at-risk").length}{" "}
            assets need your attention
          </span>
          <div className="mini-asset-dots">
            {Array.from({ length: 12 }, (_, i) => (
              <i
                key={i}
                className={
                  i < Math.round((healthy / Math.max(total, 1)) * 12)
                    ? "filled"
                    : ""
                }
              />
            ))}
          </div>
        </StatCard>
        <StatCard
          label="Security posture"
          value={
            <>
              {posture}
              <small> / 100</small>
            </>
          }
          icon={ShieldCheck}
          color="lilac"
        >
          <span className="stat-trend">
            {posture >= 80
              ? "Looking strong"
              : posture >= 50
                ? "Room to strengthen"
                : "Attention needed"}
            <ArrowUpRight size={13} />
          </span>
          <div className="posture-track">
            <span style={{ width: `${posture}%` }} />
          </div>
        </StatCard>
      </div>

      <div className="dashboard-charts">
        <section className="panel activity-chart">
          <div className="panel-heading">
            <div>
              <h2 className="panel-title">
                Event activity
                <span className="live-tag">
                  <i />
                  Demo timeline
                </span>
              </h2>
              <p className="panel-subtitle">
                A pulse on your security environment
              </p>
            </div>
            <select
              className="compact-select"
              value={period}
              onChange={(e) => {
                setPeriod(e.target.value);
                setHover(null);
              }}
              aria-label="Activity time range"
            >
              <option value="24h">Last 24 hours</option>
              <option value="12h">Last 12 hours</option>
            </select>
          </div>
          <div className="chart-toolbar">
            <div className="chart-legend">
              <span>
                <i className="legend-dot green" />
                Security events
              </span>
              <span>
                <i className="legend-dot orange" />
                Threat signals
              </span>
            </div>
            <button
              className={`chart-filter ${eventType === "threats" ? "selected" : ""}`}
              onClick={() =>
                setEventType(eventType === "all" ? "threats" : "all")
              }
            >
              <ListFilter size={13} />
              {eventType === "all" ? "All events" : "Threat signals"}
            </button>
          </div>
          <div className="chart-container">
            <svg
              className="event-chart"
              viewBox="0 0 730 206"
              role="img"
              aria-label={`Demo security ${eventType === "all" ? "events" : "threat signals"} for the last ${period === "24h" ? "24 hours" : "12 hours"}`}
            >
              <defs>
                <linearGradient id="chart-fill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#86b7a0" stopOpacity="0.26" />
                  <stop offset="100%" stopColor="#86b7a0" stopOpacity="0.015" />
                </linearGradient>
              </defs>
              {[20, 70, 120, 170].map((y, i) => (
                <g key={y}>
                  <line
                    x1="40"
                    x2="705"
                    y1={y}
                    y2={y}
                    stroke="#ebeee7"
                    strokeDasharray="3 5"
                  />
                  <text x="0" y={y + 4} className="chart-axis">
                    {Math.round((chartMax * (3 - i)) / 3)}
                  </text>
                </g>
              ))}
              <path d={`${path} L702,170 L42,170 Z`} fill="url(#chart-fill)" />
              <path
                d={path}
                fill="none"
                stroke="#4d8c70"
                strokeWidth="2.3"
                strokeLinejoin="round"
                strokeLinecap="round"
              />
              <path
                d={points
                  .map(
                    ([x], i) =>
                      `${i ? "L" : "M"}${x},${170 - (series[i].threats / chartMax) * 150}`,
                  )
                  .join(" ")}
                fill="none"
                stroke="#dbab70"
                strokeWidth="1.5"
                strokeLinejoin="round"
                opacity="0.9"
              />
              {series.map((point, i) => (
                <text
                  key={point.hour}
                  x={42 + i * (660 / Math.max(series.length - 1, 1))}
                  y="199"
                  textAnchor={i === series.length - 1 ? "end" : "middle"}
                  className="chart-axis"
                >
                  {point.hour}
                </text>
              ))}
              {points.map(([x, y], i) => (
                <g
                  key={i}
                  onMouseEnter={() => setHover(i)}
                  onMouseLeave={() => setHover(null)}
                >
                  <rect
                    x={x - 13}
                    y="0"
                    width="26"
                    height="175"
                    fill="transparent"
                  />
                  {hover === i && (
                    <>
                      <line
                        x1={x}
                        x2={x}
                        y1="8"
                        y2="170"
                        stroke="#a0b5a8"
                        strokeDasharray="3 4"
                      />
                      <circle
                        cx={x}
                        cy={y}
                        r="4.5"
                        fill="#2f6c50"
                        stroke="white"
                        strokeWidth="3"
                      />
                      <g
                        transform={`translate(${Math.min(600, Math.max(45, x - 44))},${Math.max(0, y - 40)})`}
                      >
                        <rect width="96" height="28" rx="6" fill="#1d3d30" />
                        <text
                          x="48"
                          y="18"
                          fill="white"
                          textAnchor="middle"
                          fontSize="11"
                        >
                          {chart[i]}{" "}
                          {eventType === "all" ? "events" : "signals"}
                        </text>
                      </g>
                    </>
                  )}
                </g>
              ))}
            </svg>
          </div>
        </section>

        <section className="panel threat-landscape">
          <div className="panel-heading">
            <div>
              <h2 className="panel-title">Threat landscape</h2>
              <p className="panel-subtitle">Intelligence by severity</p>
            </div>
            <button
              className="icon-button"
              onClick={() => navigate("intelligence")}
              aria-label="Open threat intelligence"
            >
              <ArrowUpRight size={18} />
            </button>
          </div>
          <div className="donut-content">
            <div className="donut-chart">
              <svg
                viewBox="0 0 160 160"
                role="img"
                aria-label={`${threatTotal} intelligence indicators by severity`}
              >
                <circle
                  cx="80"
                  cy="80"
                  r="62"
                  fill="none"
                  stroke="#f0f2eb"
                  strokeWidth="18"
                />
                {severityCounts
                  .filter((item) => item.count)
                  .map((item) => {
                    const i = ["critical", "high", "medium", "low"].indexOf(
                      item.severity,
                    );
                    const length = (item.count / threatTotal) * 389.55;
                    const start = offset;
                    offset += length;
                    return (
                      <circle
                        key={item.severity}
                        cx="80"
                        cy="80"
                        r="62"
                        fill="none"
                        stroke={colors[i]}
                        strokeWidth="18"
                        strokeDasharray={`${Math.max(0, length - 5)} ${389.55 - Math.max(0, length - 5)}`}
                        strokeDashoffset={-start}
                        transform="rotate(-90 80 80)"
                        strokeLinecap="round"
                      />
                    );
                  })}
              </svg>
              <div>
                <strong>{String(data.intel.length).padStart(2, "0")}</strong>
                <span>indicators</span>
              </div>
            </div>
            <div className="severity-legend">
              {severityCounts.map((item, i) => (
                <div key={item.severity}>
                  <span>
                    <i style={{ background: colors[i] }} />
                    {item.severity.charAt(0).toUpperCase() +
                      item.severity.slice(1)}
                  </span>
                  <strong>{String(item.count).padStart(2, "0")}</strong>
                </div>
              ))}
            </div>
          </div>
          <div className="landscape-note">
            <ShieldCheck size={14} />
            <span>Context is your strongest defense.</span>
            <ArrowUpRight size={14} />
          </div>
        </section>
      </div>

      <div className="dashboard-lower">
        <section className="panel alerts-panel">
          <div className="panel-heading">
            <div>
              <h2 className="panel-title">
                Priority alerts
                <span className="count-pill">{alerts.length}</span>
              </h2>
              <p className="panel-subtitle">
                The signals that deserve a closer look
              </p>
            </div>
            <button className="text-button" onClick={() => navigate("logs")}>
              View all logs <ArrowRight size={14} />
            </button>
          </div>
          <div className="table-wrap">
            <table className="data-table alert-table">
              <thead>
                <tr>
                  <th>EVENT</th>
                  <th>SEVERITY</th>
                  <th>SOURCE</th>
                  <th>DETECTED</th>
                  <th aria-label="Actions" />
                </tr>
              </thead>
              <tbody>
                {alerts.slice(0, 4).map((alert) => (
                  <tr key={alert.id} onClick={() => setSelectedAlert(alert)}>
                    <td>
                      <div className="event-cell">
                        <span className={`event-icon ${alert.severity}`}>
                          <ShieldAlert size={16} />
                        </span>
                        <div>
                          <strong>{alert.event}</strong>
                          <span>{alert.ip}</span>
                        </div>
                      </div>
                    </td>
                    <td>
                      <span className={`badge ${alert.severity}`}>
                        <i />
                        {alert.severity}
                      </span>
                    </td>
                    <td className="muted">{alert.source}</td>
                    <td className="muted nowrap">
                      {relativeTime(alert.timestamp)}
                    </td>
                    <td>
                      <button
                        className="icon-button"
                        aria-label={`Investigate ${alert.event}`}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedAlert(alert);
                        }}
                      >
                        <ArrowUpRight size={16} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="panel-bottom-note">
            <span className="live-dot" />
            Synced at{" "}
            {lastSync.toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
            })}
            <span>Sample security events</span>
          </div>
        </section>

        <section className="panel assets-panel">
          <div className="panel-heading">
            <div>
              <h2 className="panel-title">Your perimeter</h2>
              <p className="panel-subtitle">Every asset, accounted for</p>
            </div>
            <span className="asset-total">{data.assets.length} assets</span>
          </div>
          <div className="asset-list">
            {data.assets.slice(0, 4).map((asset) => (
              <button
                key={asset.id}
                className="asset-row"
                onClick={() => setSelectedAsset(asset)}
              >
                <span className="asset-icon">
                  <Server size={17} />
                </span>
                <span className="asset-name">
                  <strong>{asset.name}</strong>
                  <small>{asset.ip}</small>
                </span>
                <span className={`asset-status ${asset.status}`}>
                  <i />
                  {asset.status === "healthy"
                    ? "Protected"
                    : asset.status === "at-risk"
                      ? "At risk"
                      : asset.status}
                </span>
                <ChevronRight size={14} />
              </button>
            ))}
          </div>
          <button
            className="perimeter-link"
            onClick={() => navigate("scanner")}
          >
            Explore your attack surface <ArrowUpRight size={15} />
          </button>
        </section>
      </div>

      <section className="academy-strip">
        <div className="academy-strip-icon">
          <BookOpen size={24} />
        </div>
        <div>
          <span className="section-label">THE HUMAN FIREWALL</span>
          <h3>A sharper mind. A stronger defense.</h3>
          <p>Five questions. A fresh perspective on cybersecurity.</p>
        </div>
        <button className="btn btn-outline" onClick={() => navigate("academy")}>
          Test your knowledge <ArrowUpRight size={16} />
        </button>
        <span className="academy-strip-pattern" aria-hidden="true">
          ↗
        </span>
      </section>
    </div>
  );
}

function StatCard({ label, value, icon: Icon, color, children }) {
  return (
    <section className="stat-card">
      <div className="stat-header">
        <span>{label}</span>
        <span className={`stat-icon ${color}`}>
          <Icon size={16} strokeWidth={1.8} />
        </span>
      </div>
      <div className="stat-value">{value}</div>
      <div className="stat-footer">{children}</div>
    </section>
  );
}
