import express from "express";
import { randomBytes, randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { initialState, quiz } from "./data.js";
import {
  ValidationError,
  address,
  analyzeFile,
  analyzeTcp,
  analyzeVpn,
  tcpRecords,
  text,
  vpnRecords,
} from "./analysis.js";

export const ROLE_PERMISSIONS = Object.freeze({
  viewer: ["read", "quiz"],
  analyst: ["read", "quiz", "scan", "hunt", "analyze", "investigate"],
  admin: [
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
});

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const demoNotice =
  "Demonstration workspace. Network telemetry and threat feeds are synthetic. Response actions affect only this workspace, never your operating system or network.";

function loadState(file, now) {
  if (!existsSync(file)) return initialState(now());
  const state = JSON.parse(readFileSync(file, "utf8"));
  if (
    state.version !== 1 ||
    ![
      "assets",
      "logs",
      "intel",
      "vpn",
      "connections",
      "packets",
      "firewall",
      "investigations",
      "activity",
      "scans",
    ].every((key) => Array.isArray(state[key]))
  )
    throw new Error(
      "Archer state file has an unsupported structure. Preserve it and repair or move it before restarting.",
    );
  return state;
}

function summary(state) {
  const connectionAnalysis = analyzeTcp(state.connections);
  return {
    events24h: state.logs.length,
    activeThreats: state.logs.filter(
      (l) =>
        ["critical", "high"].includes(l.severity) &&
        !["blocked", "isolated"].includes(
          state.assets.find((a) => a.id === l.assetId)?.status,
        ),
    ).length,
    protectedAssets: state.assets.filter((a) => a.status === "healthy").length,
    totalAssets: state.assets.length,
    postureScore: Math.max(
      0,
      Math.round(
        100 -
          state.assets.reduce(
            (sum, a) =>
              sum + (["isolated", "blocked"].includes(a.status) ? 0 : a.risk),
            0,
          ) /
            state.assets.length,
      ),
    ),
    criticalAlerts: state.logs.filter((l) => l.severity === "critical").length,
    threatsBlocked:
      state.assets.filter((a) => a.status === "blocked").length +
      state.firewall.filter((r) => r.enabled && r.action === "deny").length,
    activeConnections: connectionAnalysis.established,
    halfOpenConnections: connectionAnalysis.halfOpen,
    openInvestigations: state.investigations.filter((i) => i.status === "open")
      .length,
    eventsTrend: [
      { hour: "00:00", events: 14, threats: 2 },
      { hour: "03:00", events: 9, threats: 1 },
      { hour: "06:00", events: 18, threats: 3 },
      { hour: "09:00", events: 31, threats: 7 },
      { hour: "12:00", events: 27, threats: 4 },
      { hour: "15:00", events: 42, threats: 9 },
      { hour: "18:00", events: 34, threats: 5 },
      { hour: "21:00", events: 23, threats: 3 },
    ],
  };
}

export function createApp(options = {}) {
  const app = express();
  const now = options.now || Date.now;
  const stateFile =
    options.stateFile ||
    process.env.ARCHER_DATA_FILE ||
    resolve(root, ".data/state.json");
  const state = loadState(stateFile, now);
  let committedState = structuredClone(state);
  const sessions = new Map();
  const save = () => {
    const temporary = `${stateFile}.${randomUUID()}.tmp`;
    try {
      const nextState = structuredClone(state);
      mkdirSync(dirname(stateFile), { recursive: true, mode: 0o700 });
      writeFileSync(temporary, JSON.stringify(nextState, null, 2), {
        mode: 0o600,
      });
      renameSync(temporary, stateFile);
      committedState = nextState;
    } catch (error) {
      for (const key of Object.keys(state)) delete state[key];
      Object.assign(state, structuredClone(committedState));
      try {
        unlinkSync(temporary);
      } catch {
        /* The write may have failed before creating a temporary file. */
      }
      throw error;
    }
  };
  const activity = (req, action, detail) => {
    state.activity.unshift({
      id: randomUUID(),
      time: new Date(now()).toISOString(),
      action,
      detail,
      user: `${req.session.user.name} (${req.session.user.role})`,
    });
    state.activity = state.activity.slice(0, 200);
  };
  const permit = (permission) => (req, res, next) => {
    if (!req.session.permissions.includes(permission))
      return res
        .status(403)
        .json({
          error: `The ${req.session.user.role} role does not have the ${permission} permission.`,
        });
    next();
  };
  app.disable("x-powered-by");
  app.use((req, res, next) => {
    res.set({
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "same-origin",
    });
    if (req.path.startsWith("/api")) res.set("Cache-Control", "no-store");
    next();
  });
  app.use(express.json({ limit: "3mb", strict: true }));
  app.use("/api", (req, res, next) => {
    if (
      req.body !== undefined &&
      (!req.body || typeof req.body !== "object" || Array.isArray(req.body))
    )
      return res
        .status(400)
        .json({ error: "Request body must be a JSON object." });
    next();
  });
  app.get("/api/health", (req, res) =>
    res.json({ status: "ok", name: "Archer Security", mode: "demo" }),
  );
  app.post("/api/session", (req, res) => {
    const role = req.body?.role ?? "analyst";
    if (typeof role !== "string" || !Object.hasOwn(ROLE_PERMISSIONS, role))
      throw new ValidationError("Choose viewer, analyst, or admin.");
    for (const [token, session] of sessions)
      if (session.expiresAt <= now()) sessions.delete(token);
    if (sessions.size >= 1000)
      return res
        .status(429)
        .json({
          error:
            "Too many active demo sessions. Restart this local demo or wait for sessions to expire.",
        });
    const token = randomBytes(32).toString("hex");
    const user = { name: "Vaibhav Thakur", role };
    const permissions = [...ROLE_PERMISSIONS[role]];
    sessions.set(token, {
      user,
      permissions,
      expiresAt: now() + 12 * 60 * 60 * 1000,
    });
    res.json({
      token,
      user,
      permissions,
      mode: "demo",
      notice:
        "Roles can be selected freely in this local demo. This is not production authentication.",
    });
  });
  app.use("/api", (req, res, next) => {
    const authorization = req.get("authorization") || "";
    const token = authorization.startsWith("Bearer ")
      ? authorization.slice(7)
      : "";
    const session = sessions.get(token);
    if (!session || session.expiresAt <= now()) {
      if (session) sessions.delete(token);
      return res
        .status(401)
        .json({
          error:
            "A valid demo session is required. Select a role to reconnect.",
        });
    }
    req.session = session;
    next();
  });
  app.delete("/api/session", (req, res) => {
    sessions.delete(req.get("authorization").slice(7));
    res.json({ signedOut: true });
  });
  app.get("/api/bootstrap", permit("read"), (req, res) =>
    res.json({
      mode: "demo",
      demoNotice,
      user: req.session.user,
      permissions: req.session.permissions,
      summary: summary(state),
      ...state,
    }),
  );
  app.get("/api/logs", permit("read"), (req, res) => {
    const q = text(req.query.q, "q", 200, true).toLowerCase();
    const severity = text(
      req.query.severity,
      "severity",
      20,
      true,
    ).toLowerCase();
    if (
      severity &&
      !["all", "critical", "high", "medium", "low", "info"].includes(severity)
    )
      throw new ValidationError("Unsupported severity filter.");
    const logs = state.logs.filter(
      (log) =>
        (!severity || severity === "all" || log.severity === severity) &&
        (!q ||
          [log.event, log.message, log.source, log.ip]
            .join(" ")
            .toLowerCase()
            .includes(q)),
    );
    res.json({ logs, count: logs.length });
  });
  app.post("/api/hunt", permit("hunt"), (req, res) => {
    const query = text(req.body?.query, "query", 200);
    const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    const matches = state.logs
      .filter((log) => {
        const content = [
          log.event,
          log.message,
          log.source,
          log.ip,
          log.severity,
        ]
          .join(" ")
          .toLowerCase();
        return terms.every((term) => content.includes(term));
      })
      .map((log) => ({
        ...log,
        matchedIndicators: state.intel
          .filter(
            (i) =>
              log.ip === i.indicator ||
              log.message.toLowerCase().includes(i.indicator.toLowerCase()),
          )
          .map((i) => i.indicator),
      }));
    const intel = state.intel.filter((i) =>
      terms.every((term) =>
        [i.indicator, i.description, i.tactic, i.type, i.severity]
          .join(" ")
          .toLowerCase()
          .includes(term),
      ),
    );
    activity(
      req,
      "Threat hunt completed",
      `Query "${query}" matched ${matches.length} events and ${intel.length} indicators.`,
    );
    save();
    res.json({
      query,
      matches,
      intel,
      count: matches.length + intel.length,
      summary: `Found ${matches.length} matching events and ${intel.length} demo indicators. Search terms are combined with AND.`,
    });
  });
  app.post("/api/scan", permit("scan"), (req, res) => {
    const scope = text(req.body?.scope ?? "all", "scope", 100).toLowerCase();
    if (!["all", "corporate", "cloud", "endpoint"].includes(scope))
      throw new ValidationError(
        "scope must be all, corporate, cloud, or endpoint.",
      );
    const selected =
      scope === "cloud"
        ? state.assets.filter((a) => a.type === "cloud")
        : scope === "corporate"
          ? state.assets.filter((a) => a.type !== "cloud")
          : scope === "endpoint"
            ? state.assets.filter((a) => a.type === "endpoint")
            : state.assets;
    const findings = selected
      .filter((a) => a.risk > 40 && !["blocked", "isolated"].includes(a.status))
      .map((asset, index) => ({
        id: randomUUID(),
        assetId: asset.id,
        asset: asset.name,
        ip: asset.ip,
        title:
          asset.type === "endpoint"
            ? "Suspicious executable and command activity"
            : "Security updates pending",
        severity: asset.risk > 80 ? "critical" : "medium",
        description:
          asset.type === "endpoint"
            ? "Demo inventory reports an unsigned executable and encoded process command on this endpoint."
            : "Demo inventory reports outdated packages on this cloud service.",
        recommendation:
          asset.type === "endpoint"
            ? "Investigate process ancestry, preserve evidence, and consider isolation."
            : "Review the package inventory and schedule supported security updates.",
      }));
    const result = {
      id: randomUUID(),
      scope,
      mode: "demo",
      completedAt: new Date(now()).toISOString(),
      assetsScanned: selected.length,
      findings,
      summary: Object.fromEntries(
        ["critical", "high", "medium", "low"].map((severity) => [
          severity,
          findings.filter((f) => f.severity === severity).length,
        ]),
      ),
    };
    state.scans.unshift(result);
    state.scans = state.scans.slice(0, 30);
    activity(
      req,
      "Inventory scan completed",
      `${scope}: ${selected.length} demo assets, ${findings.length} findings. No external hosts were scanned.`,
    );
    save();
    res.json(result);
  });
  app.post("/api/vpn/analyze", permit("analyze"), (req, res) => {
    const records = vpnRecords(req.body?.csv, state.vpn);
    const result = analyzeVpn(records, state.intel);
    activity(
      req,
      "VPN history analyzed",
      `${records.length} ${req.body?.csv ? "imported" : "demo"} sign-ins, ${result.alerts.length} signals.`,
    );
    save();
    res.json(result);
  });
  app.post("/api/tcp/analyze", permit("analyze"), (req, res) =>
    res.json(analyzeTcp(tcpRecords(req.body?.connections, state.connections))),
  );
  app.post("/api/malware/analyze", permit("analyze"), (req, res) => {
    const result = analyzeFile(req.body || {});
    activity(
      req,
      "Static file analysis completed",
      `${result.name}: ${result.size} bytes. File was not executed or retained.`,
    );
    save();
    res.json(result);
  });
  app.get("/api/packets", permit("read"), (req, res) =>
    res.json({
      packets: state.packets,
      mode: "demo",
      count: state.packets.length,
    }),
  );
  app.get("/api/firewall", permit("read"), (req, res) =>
    res.json({ firewall: state.firewall, mode: "demo" }),
  );
  app.post("/api/firewall", permit("firewall"), (req, res) => {
    const input = req.body || {};
    const name = text(input.name, "name", 100);
    const source = address(input.source, "source"),
      destination = address(input.destination, "destination");
    const port = String(input.port ?? "any").toLowerCase();
    if (
      port !== "any" &&
      (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535)
    )
      throw new ValidationError(
        'port must be "any" or a number between 1 and 65535.',
      );
    const protocol = input.protocol ?? "ANY";
    if (!["TCP", "UDP", "ANY"].includes(protocol))
      throw new ValidationError("protocol must be TCP, UDP, or ANY.");
    if (!["allow", "deny"].includes(input.action))
      throw new ValidationError("action must be allow or deny.");
    if (input.enabled !== undefined && typeof input.enabled !== "boolean")
      throw new ValidationError("enabled must be true or false.");
    if (state.firewall.length >= 500)
      throw new ValidationError(
        "The demo supports at most 500 firewall rules.",
      );
    const rule = {
      id: randomUUID(),
      name,
      source,
      destination,
      port,
      protocol,
      action: input.action,
      enabled: input.enabled ?? true,
    };
    state.firewall.unshift(rule);
    activity(
      req,
      "Demo firewall rule created",
      `${name}: ${rule.action} ${source} → ${destination}:${port}.`,
    );
    save();
    res.status(201).json({ rule, firewall: state.firewall, mode: "demo" });
  });
  app.delete("/api/firewall/:id", permit("firewall"), (req, res) => {
    const rule = state.firewall.find((r) => r.id === req.params.id);
    if (!rule)
      return res.status(404).json({ error: "Firewall rule not found." });
    state.firewall = state.firewall.filter((r) => r.id !== rule.id);
    activity(req, "Demo firewall rule removed", rule.name);
    save();
    res.json({ deleted: true, firewall: state.firewall, mode: "demo" });
  });
  app.post(
    "/api/assets/:id/action",
    (req, res, next) => {
      const action = req.body?.action;
      if (!["block", "isolate", "investigate"].includes(action))
        throw new ValidationError(
          "action must be block, isolate, or investigate.",
        );
      permit(action)(req, res, next);
    },
    (req, res) => {
      const asset = state.assets.find((a) => a.id === req.params.id);
      if (!asset) return res.status(404).json({ error: "Asset not found." });
      const action = req.body.action;
      let investigation;
      if (action === "investigate") {
        investigation = state.investigations.find(
          (i) => i.assetId === asset.id && i.status === "open",
        );
        if (!investigation) {
          const related = state.logs.filter((l) => l.assetId === asset.id);
          investigation = {
            id: randomUUID(),
            title: `Investigate ${asset.name}`,
            assetId: asset.id,
            status: "open",
            createdAt: new Date(now()).toISOString(),
            findings: related.map(
              (l) => `${l.severity.toUpperCase()}: ${l.message}`,
            ),
          };
          state.investigations.unshift(investigation);
        }
      } else {
        asset.status = action === "block" ? "blocked" : "isolated";
        state.logs.unshift({
          id: randomUUID(),
          timestamp: new Date(now()).toISOString(),
          severity: "info",
          source: "Archer Response",
          event:
            action === "block"
              ? "Demo block applied"
              : "Demo isolation applied",
          message: `${asset.name} marked ${asset.status} in the demonstration workspace. No real network controls were changed.`,
          ip: asset.ip,
          assetId: asset.id,
        });
        state.logs = state.logs.slice(0, 1000);
      }
      activity(
        req,
        action === "investigate"
          ? "Investigation opened"
          : `Demo asset ${asset.status}`,
        `${asset.name} (${asset.ip})`,
      );
      save();
      res.json({
        asset,
        ...(investigation ? { investigation } : {}),
        message:
          action === "investigate"
            ? `Investigation opened for ${asset.name}.`
            : `${asset.name} is now ${asset.status} in the demo workspace.`,
        mode: "demo",
      });
    },
  );
  app.get("/api/quiz", permit("quiz"), (req, res) =>
    res.json({
      questions: quiz.map(({ correct, explanation, ...question }) => question),
    }),
  );
  app.post("/api/quiz", permit("quiz"), (req, res) => {
    const answers = req.body?.answers;
    if (
      !answers ||
      typeof answers !== "object" ||
      Array.isArray(answers) ||
      Object.keys(answers).length !== quiz.length ||
      quiz.some(
        (question) =>
          !question.options.some(
            (option) => option.id === answers[question.id],
          ),
      )
    )
      throw new ValidationError(
        "Answer all five questions with a valid option before submitting.",
      );
    const results = quiz.map((question) => ({
      questionId: question.id,
      correct: answers[question.id] === question.correct,
      selected: answers[question.id],
      correctAnswer: question.correct,
      explanation: question.explanation,
    }));
    const score = results.filter((result) => result.correct).length;
    res.json({
      score,
      total: quiz.length,
      percentage: (score / quiz.length) * 100,
      results,
    });
  });
  app.use("/api", (req, res) =>
    res.status(404).json({ error: "API endpoint not found." }),
  );
  const dist = options.distDirectory || resolve(root, "dist");
  if (existsSync(resolve(dist, "index.html"))) {
    app.use(express.static(dist, { index: false }));
    app.get(/.*/, (req, res) => res.sendFile(resolve(dist, "index.html")));
  }
  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    if (error.type === "entity.too.large")
      return res
        .status(413)
        .json({
          error:
            "Request is too large. File analysis accepts files up to 2 MiB.",
        });
    if (error instanceof SyntaxError && error.status === 400)
      return res.status(400).json({ error: "Invalid JSON request body." });
    const status = error.status === 400 ? 400 : 500;
    if (status === 500) console.error("Archer request failed:", error.message);
    res
      .status(status)
      .json({
        error:
          status === 400
            ? error.message
            : "The operation could not be completed. Check server state and try again.",
      });
  });
  return app;
}
