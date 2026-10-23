import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { createApp } from "./app.js";
import {
  analyzeFile,
  analyzeTcp,
  analyzeVpn,
  tcpRecords,
  vpnRecords,
} from "./analysis.js";
import { initialState } from "./data.js";

async function workspace(t, options = {}) {
  const directory =
    options.directory || (await mkdtemp(join(tmpdir(), "archer-test-")));
  const stateFile = join(directory, "state.json");
  const server = createApp({ stateFile, ...options }).listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    if (!options.directory)
      await rm(directory, { recursive: true, force: true });
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = async (path, { token, method = "GET", body } = {}) => {
    const response = await fetch(base + path, {
      method,
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return { status: response.status, body: await response.json() };
  };
  const login = async (role = "analyst") =>
    (await request("/api/session", { method: "POST", body: { role } })).body
      .token;
  return { request, login, directory, stateFile, server, base };
}

test("health is public, telemetry requires a real session, and sessions expire", async (t) => {
  let clock = Date.now();
  const app = await workspace(t, { now: () => clock });
  assert.equal((await app.request("/api/health")).body.mode, "demo");
  assert.equal((await app.request("/api/bootstrap")).status, 401);
  assert.equal(
    (await app.request("/api/bootstrap", { token: "invented-token" })).status,
    401,
  );
  assert.equal(
    (
      await app.request("/api/session", {
        method: "POST",
        body: { role: "__proto__" },
      })
    ).status,
    400,
  );
  const token = await app.login("viewer");
  const bootstrap = await app.request("/api/bootstrap", { token });
  assert.equal(bootstrap.status, 200);
  assert.equal(bootstrap.body.user.role, "viewer");
  assert.deepEqual(bootstrap.body.permissions, ["read", "quiz"]);
  assert.ok(bootstrap.body.logs.length > 0);
  assert.match(bootstrap.body.demoNotice, /synthetic/);
  clock += 13 * 60 * 60 * 1000;
  assert.equal((await app.request("/api/bootstrap", { token })).status, 401);
});

test("role permissions are enforced on the server for analysis and response actions", async (t) => {
  const { request, login } = await workspace(t);
  const viewer = await login("viewer");
  const analyst = await login("analyst");
  const admin = await login("admin");
  assert.equal(
    (
      await request("/api/scan", {
        token: viewer,
        method: "POST",
        body: { scope: "all" },
      })
    ).status,
    403,
  );
  assert.equal(
    (
      await request("/api/hunt", {
        token: viewer,
        method: "POST",
        body: { query: "PowerShell" },
      })
    ).status,
    403,
  );
  assert.equal(
    (
      await request("/api/vpn/analyze", {
        token: viewer,
        method: "POST",
        body: {},
      })
    ).status,
    403,
  );
  for (const action of ["block", "isolate"])
    assert.equal(
      (
        await request("/api/assets/ast-01/action", {
          token: analyst,
          method: "POST",
          body: { action },
        })
      ).status,
      403,
    );
  assert.equal(
    (
      await request("/api/firewall", {
        token: analyst,
        method: "POST",
        body: {},
      })
    ).status,
    403,
  );
  assert.equal(
    (await request("/api/firewall/fw-01", { token: viewer, method: "DELETE" }))
      .status,
    403,
  );
  const investigation = await request("/api/assets/ast-01/action", {
    token: analyst,
    method: "POST",
    body: { action: "investigate" },
  });
  assert.equal(investigation.status, 200);
  assert.ok(investigation.body.investigation.findings.length > 0);
  assert.equal(
    (
      await request("/api/assets/ast-01/action", {
        token: admin,
        method: "POST",
        body: { action: "isolate" },
      })
    ).body.asset.status,
    "isolated",
  );
  assert.equal(
    (
      await request("/api/assets/ast-01/action", {
        token: admin,
        method: "POST",
        body: { action: "block" },
      })
    ).body.asset.status,
    "blocked",
  );
  assert.equal(
    (
      await request("/api/assets/ast-01/action", {
        token: admin,
        method: "POST",
        body: { action: "shell" },
      })
    ).status,
    400,
  );
});

test("firewall rules validate inputs, persist across app instances, and can be removed", async (t) => {
  const first = await workspace(t);
  const token = await first.login("admin");
  const rule = {
    name: "Test deny",
    source: "192.0.2.10",
    destination: "10.20.0.0/16",
    port: "443",
    protocol: "TCP",
    action: "deny",
  };
  const created = await first.request("/api/firewall", {
    token,
    method: "POST",
    body: rule,
  });
  assert.equal(created.status, 201);
  assert.equal(
    (
      await first.request("/api/firewall", {
        token,
        method: "POST",
        body: { ...rule, source: "curl example.com" },
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await first.request("/api/firewall", {
        token,
        method: "POST",
        body: { ...rule, port: "70000" },
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await first.request("/api/firewall", {
        token,
        method: "POST",
        body: { ...rule, action: "execute" },
      })
    ).status,
    400,
  );
  const second = await workspace(t, { directory: first.directory });
  const secondToken = await second.login("admin");
  const stored = (await second.request("/api/firewall", { token: secondToken }))
    .body.firewall;
  assert.ok(stored.some((item) => item.id === created.body.rule.id));
  const serialized = await readFile(first.stateFile, "utf8");
  assert.ok(
    !serialized.includes(token),
    "session tokens must not be persisted",
  );
  assert.equal(
    (
      await second.request(`/api/firewall/${created.body.rule.id}`, {
        token: secondToken,
        method: "DELETE",
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await second.request(`/api/firewall/${created.body.rule.id}`, {
        token: secondToken,
        method: "DELETE",
      })
    ).status,
    404,
  );
});

test("hunts correlate log events and IOCs, scans use only the demo inventory", async (t) => {
  const { request, login } = await workspace(t);
  const token = await login();
  const hunt = await request("/api/hunt", {
    token,
    method: "POST",
    body: { query: "198.51.100.64" },
  });
  assert.equal(hunt.status, 200);
  assert.equal(hunt.body.intel.length, 1);
  assert.equal(hunt.body.matches[0].matchedIndicators[0], "198.51.100.64");
  const none = await request("/api/hunt", {
    token,
    method: "POST",
    body: { query: "not-an-existing-indicator" },
  });
  assert.equal(none.body.count, 0);
  const scan = await request("/api/scan", {
    token,
    method: "POST",
    body: { scope: "cloud" },
  });
  assert.equal(scan.body.mode, "demo");
  assert.equal(scan.body.assetsScanned, 2);
  assert.ok(scan.body.findings.every((f) => f.asset !== "workstation-047"));
  const corporate = await request("/api/scan", {
    token,
    method: "POST",
    body: { scope: "corporate" },
  });
  assert.equal(corporate.body.assetsScanned, 4);
  assert.ok(corporate.body.findings.some((f) => f.asset === "workstation-047"));
  assert.ok(corporate.body.findings.every((f) => f.asset !== "web-server-02"));
  const endpoint = await request("/api/scan", {
    token,
    method: "POST",
    body: { scope: "endpoint" },
  });
  assert.equal(endpoint.body.assetsScanned, 2);
  const all = await request("/api/scan", { token, method: "POST", body: {} });
  assert.equal(all.body.assetsScanned, 6);
  assert.equal(
    (
      await request("/api/scan", {
        token,
        method: "POST",
        body: { scope: "unknown-cloud-scope" },
      })
    ).status,
    400,
  );
  const filtered = await request("/api/logs?q=PowerShell&severity=critical", {
    token,
  });
  assert.equal(filtered.body.count, 1);
  assert.equal(
    (await request("/api/logs?severity=invalid", { token })).status,
    400,
  );
});

test("a failed state write rolls back the inventory and audit mutation", async (t) => {
  const app = await workspace(t);
  const token = await app.login("admin");
  const before = (await app.request("/api/bootstrap", { token })).body;
  await mkdir(app.stateFile);
  const action = await app.request("/api/assets/ast-01/action", {
    token,
    method: "POST",
    body: { action: "isolate" },
  });
  assert.equal(action.status, 500);
  const after = (await app.request("/api/bootstrap", { token })).body;
  assert.deepEqual(after.assets, before.assets);
  assert.deepEqual(after.activity, before.activity);
  assert.deepEqual(after.logs, before.logs);
});

test("VPN analyzer detects impossible travel, intelligence matches and repeated failed logins", () => {
  const state = initialState();
  const result = analyzeVpn(state.vpn, state.intel);
  assert.equal(result.analyzed, state.vpn.length);
  assert.ok(result.alerts.some((a) => a.type === "Impossible travel"));
  assert.ok(
    result.alerts.some((a) => a.type === "Repeated failed authentication"),
  );
  assert.ok(result.alerts.some((a) => a.type === "Threat intelligence match"));
  const csv =
    'user,ip,timestamp,country,city,latitude,longitude\n"a,user",192.0.2.1,2026-01-01T00:00:00Z,India,Mumbai,19.076,72.8777\n"a,user",192.0.2.2,2026-01-01T00:15:00Z,Germany,Berlin,52.52,13.405';
  const records = vpnRecords(csv, []);
  assert.equal(records[0].user, "a,user");
  assert.equal(analyzeVpn(records, []).alerts[0].type, "Impossible travel");
  assert.throws(
    () => vpnRecords("user,ip,timestamp\na,not-an-ip,2026-01-01", []),
    /invalid IP/,
  );
  assert.throws(
    () =>
      vpnRecords("user,ip,timestamp,latitude\na,192.0.2.1,2026-01-01,999", []),
    /latitude/,
  );
});

test("TCP analyzer distinguishes established, recent pending and aged half-open connections", () => {
  const state = initialState();
  const result = analyzeTcp(state.connections);
  assert.equal(result.established, 3);
  assert.equal(result.pending, 5);
  assert.equal(result.halfOpen, 4);
  assert.ok(
    result.alerts.some((a) => a.type === "Repeated incomplete handshakes"),
  );
  assert.throws(() => tcpRecords([{ source: "not-ip" }], []), /IP addresses/);
  const fresh = tcpRecords(
    [
      {
        source: "192.0.2.1",
        destination: "192.0.2.2",
        state: "SYN_SENT",
        port: 443,
        ageSeconds: 2,
      },
    ],
    [],
  );
  assert.equal(analyzeTcp(fresh).halfOpen, 0);
});

test("file analyzer computes exact SHA-256 and identifies static patterns without executing content", async (t) => {
  const content = Buffer.from(
    "powershell -EncodedCommand ZGVtbw==\nhttps://sample.example/path",
  );
  const result = analyzeFile({
    name: "report.pdf.ps1",
    contentBase64: content.toString("base64"),
  });
  assert.equal(
    result.sha256,
    createHash("sha256").update(content).digest("hex"),
  );
  assert.equal(result.verdict, "suspicious");
  assert.ok(result.indicators.some((i) => i.type === "Script pattern"));
  assert.ok(result.indicators.some((i) => i.type === "Filename"));
  assert.equal(
    analyzeFile({
      name: "hello.txt",
      contentBase64: Buffer.from("hello world").toString("base64"),
    }).verdict,
    "no-obvious-indicators",
  );
  assert.throws(
    () => analyzeFile({ name: "bad.txt", contentBase64: "%%%" }),
    /Base64/,
  );
  assert.equal(
    analyzeFile({
      name: "max.txt",
      contentBase64: Buffer.alloc(2 * 1024 * 1024, 65).toString("base64"),
    }).size,
    2 * 1024 * 1024,
  );
  const app = await workspace(t);
  const token = await app.login();
  const analyzed = await app.request("/api/malware/analyze", {
    token,
    method: "POST",
    body: { name: "sample.ps1", contentBase64: content.toString("base64") },
  });
  assert.equal(analyzed.status, 200);
  assert.ok(
    !(await readFile(app.stateFile, "utf8")).includes(
      content.toString("base64"),
    ),
    "uploaded bytes are not persisted",
  );
});

test("quiz hides answers before submission, requires all five answers and grades correctly", async (t) => {
  const { request, login } = await workspace(t);
  const token = await login("viewer");
  const questions = (await request("/api/quiz", { token })).body.questions;
  assert.equal(questions.length, 5);
  assert.ok(
    questions.every(
      (q) => !Object.hasOwn(q, "correct") && !Object.hasOwn(q, "explanation"),
    ),
  );
  assert.equal(
    (
      await request("/api/quiz", {
        token,
        method: "POST",
        body: { answers: { q1: "b" } },
      })
    ).status,
    400,
  );
  const result = await request("/api/quiz", {
    token,
    method: "POST",
    body: { answers: { q1: "b", q2: "a", q3: "c", q4: "b", q5: "d" } },
  });
  assert.equal(result.body.score, 5);
  assert.equal(result.body.percentage, 100);
  assert.ok(
    result.body.results.every((item) => item.correct && item.explanation),
  );
});

test("API rejects malformed JSON and oversized bodies with useful errors", async (t) => {
  const { base, login } = await workspace(t);
  const token = await login();
  const bad = await fetch(`${base}/api/hunt`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
    },
    body: "{broken",
  });
  assert.equal(bad.status, 400);
  assert.match((await bad.json()).error, /JSON/);
  const large = await fetch(`${base}/api/malware/analyze`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      name: "large",
      contentBase64: "A".repeat(4 * 1024 * 1024),
    }),
  });
  assert.equal(large.status, 413);
});
