import { createHash } from "node:crypto";
import { isIP } from "node:net";

export class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.status = 400;
  }
}

export function text(value, name, max = 200, optional = false) {
  if (optional && (value === undefined || value === null || value === ""))
    return "";
  if (typeof value !== "string" || !value.trim() || value.length > max)
    throw new ValidationError(
      `${name} must be a non-empty string of at most ${max} characters.`,
    );
  return value.trim();
}

export function address(value, name) {
  const parsed = text(value, name, 64);
  if (parsed.toLowerCase() === "any") return "any";
  const [ip, mask, ...extra] = parsed.split("/");
  const family = isIP(ip);
  if (
    !family ||
    extra.length ||
    (mask !== undefined &&
      (!/^\d+$/.test(mask) || Number(mask) > (family === 4 ? 32 : 128)))
  )
    throw new ValidationError(
      `${name} must be an IP address, CIDR range, or "any".`,
    );
  return parsed;
}

function parseCsv(input) {
  const rows = [];
  let row = [],
    field = "",
    quoted = false;
  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    if (char === '"') {
      if (quoted && input[i + 1] === '"') {
        field += '"';
        i++;
      } else quoted = !quoted;
    } else if (char === "," && !quoted) {
      row.push(field.trim());
      field = "";
    } else if (char === "\n" && !quoted) {
      row.push(field.trim());
      if (row.some(Boolean)) rows.push(row);
      row = [];
      field = "";
    } else if (char !== "\r" || quoted) field += char;
  }
  if (quoted)
    throw new ValidationError("CSV contains an unterminated quoted field.");
  row.push(field.trim());
  if (row.some(Boolean)) rows.push(row);
  return rows;
}

export function vpnRecords(csv, fallback) {
  if (csv === undefined || csv === null || csv === "") return fallback;
  if (typeof csv !== "string" || csv.length > 500_000)
    throw new ValidationError("CSV must be text no larger than 500 KB.");
  const rows = parseCsv(csv.replace(/^\uFEFF/, ""));
  if (rows.length < 2 || rows.length > 1001)
    throw new ValidationError(
      "Provide a CSV header and between 1 and 1,000 records.",
    );
  const headers = rows.shift().map((h) => h.toLowerCase());
  if (new Set(headers).size !== headers.length)
    throw new ValidationError("CSV column names must be unique.");
  for (const required of ["user", "ip", "timestamp"])
    if (!headers.includes(required))
      throw new ValidationError(`CSV requires a ${required} column.`);
  return rows.map((values, i) => {
    if (values.length !== headers.length)
      throw new ValidationError(
        `CSV record ${i + 1} has a different number of columns than the header.`,
      );
    const record = Object.fromEntries(headers.map((h, j) => [h, values[j]]));
    if (!isIP(record.ip))
      throw new ValidationError(
        `CSV record ${i + 1} has an invalid IP address.`,
      );
    const date = Date.parse(record.timestamp);
    if (!Number.isFinite(date))
      throw new ValidationError(
        `CSV record ${i + 1} has an invalid timestamp.`,
      );
    const status = record.status || "success";
    if (!["success", "failed", "mfa_failed"].includes(status))
      throw new ValidationError(
        `CSV record ${i + 1}: status must be success, failed, or mfa_failed.`,
      );
    const output = {
      id: `import-${i + 1}`,
      user: text(record.user, "user", 100),
      ip: record.ip,
      timestamp: new Date(date).toISOString(),
      country: record.country || "Unknown",
      city: record.city || "Unknown",
      device: record.device || "Unknown",
      status,
    };
    for (const [key, limit] of [
      ["latitude", 90],
      ["longitude", 180],
    ]) {
      if (record[key] !== undefined && record[key] !== "") {
        const number = Number(record[key]);
        if (!Number.isFinite(number) || Math.abs(number) > limit)
          throw new ValidationError(`CSV record ${i + 1} has invalid ${key}.`);
        output[key] = number;
      }
    }
    return output;
  });
}

function distanceKm(a, b) {
  if (
    ![a.latitude, a.longitude, b.latitude, b.longitude].every(Number.isFinite)
  )
    return null;
  const rad = (value) => (value * Math.PI) / 180;
  const dlat = rad(b.latitude - a.latitude),
    dlon = rad(b.longitude - a.longitude);
  const chord =
    Math.sin(dlat / 2) ** 2 +
    Math.cos(rad(a.latitude)) *
      Math.cos(rad(b.latitude)) *
      Math.sin(dlon / 2) ** 2;
  return (
    6371 *
    2 *
    Math.atan2(Math.sqrt(Math.min(1, chord)), Math.sqrt(Math.max(0, 1 - chord)))
  );
}

export function analyzeVpn(records, intel) {
  const alerts = [],
    users = new Map();
  const known = new Map(
    intel.filter((i) => i.type === "IPv4").map((i) => [i.indicator, i]),
  );
  for (const record of records) {
    if (!users.has(record.user)) users.set(record.user, []);
    users.get(record.user).push(record);
    const indicator = known.get(record.ip);
    if (indicator)
      alerts.push({
        id: `vpn-alert-${alerts.length + 1}`,
        type: "Threat intelligence match",
        severity: indicator.severity,
        user: record.user,
        ip: record.ip,
        message: `${record.user} connected from an address present in the demo threat feed.`,
        evidence: `${record.ip} · ${indicator.description}`,
      });
  }
  for (const [user, events] of users) {
    const failures = events.filter((e) => e.status !== "success");
    const failureByIp = new Map();
    for (const event of failures)
      failureByIp.set(event.ip, (failureByIp.get(event.ip) || 0) + 1);
    for (const [ip, count] of failureByIp)
      if (count >= 3)
        alerts.push({
          id: `vpn-alert-${alerts.length + 1}`,
          type: "Repeated failed authentication",
          severity: "high",
          user,
          ip,
          message: `${count} failed sign-ins for ${user} from the same source.`,
          evidence: `${ip} · ${count} failures in the supplied history; review timing and account activity.`,
        });
    const success = events
      .filter((e) => e.status === "success")
      .sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
    for (let i = 1; i < success.length; i++) {
      const previous = success[i - 1],
        current = success[i];
      const km = distanceKm(previous, current),
        hours =
          (Date.parse(current.timestamp) - Date.parse(previous.timestamp)) /
          3_600_000;
      if (
        km !== null &&
        km > 500 &&
        hours >= 0 &&
        (hours === 0 || km / hours > 900)
      )
        alerts.push({
          id: `vpn-alert-${alerts.length + 1}`,
          type: "Impossible travel",
          severity: "high",
          user,
          ip: current.ip,
          message: `Sign-ins from ${previous.city} and ${current.city} imply implausible travel.`,
          evidence: `${Math.round(km).toLocaleString("en-US")} km in ${Math.round(hours * 60)} minutes. VPN routing and geolocation errors can also cause this alert.`,
        });
    }
  }
  const riskScore = Math.min(
    100,
    alerts.reduce(
      (sum, alert) =>
        sum +
        ({ critical: 35, high: 20, medium: 10, low: 5 }[alert.severity] || 5),
      0,
    ),
  );
  return {
    analyzed: records.length,
    alerts,
    riskScore,
    summary: alerts.length
      ? `${alerts.length} signals require analyst review. Alerts are indicators, not proof of compromise.`
      : "No configured anomaly rules matched. This does not establish that all sign-ins are safe.",
    records,
  };
}

export function tcpRecords(connections, fallback) {
  if (connections === undefined) return fallback;
  if (
    !Array.isArray(connections) ||
    connections.length < 1 ||
    connections.length > 1000
  )
    throw new ValidationError(
      "connections must contain between 1 and 1,000 flow records.",
    );
  return connections.map((record, index) => {
    if (
      !record ||
      typeof record !== "object" ||
      !isIP(record.source) ||
      !isIP(record.destination)
    )
      throw new ValidationError(
        `Connection ${index + 1} needs valid source and destination IP addresses.`,
      );
    if (
      ![
        "ESTABLISHED",
        "SYN_SENT",
        "SYN_RECEIVED",
        "CLOSED",
        "TIME_WAIT",
        "FIN_WAIT",
      ].includes(record.state)
    )
      throw new ValidationError(
        `Connection ${index + 1} has an unsupported state.`,
      );
    if (
      !Number.isInteger(record.port) ||
      record.port < 1 ||
      record.port > 65535 ||
      !Number.isFinite(record.ageSeconds) ||
      record.ageSeconds < 0
    )
      throw new ValidationError(
        `Connection ${index + 1} needs a valid port and non-negative ageSeconds.`,
      );
    return {
      id: `tcp-import-${index + 1}`,
      source: record.source,
      destination: record.destination,
      port: record.port,
      protocol: "TCP",
      state: record.state,
      ageSeconds: record.ageSeconds,
      bytes:
        Number.isFinite(record.bytes) && record.bytes >= 0 ? record.bytes : 0,
    };
  });
}

export function analyzeTcp(connections) {
  const thresholdSeconds = 15;
  const pending = connections.filter((c) =>
    ["SYN_SENT", "SYN_RECEIVED"].includes(c.state),
  );
  const halfOpen = pending.filter((c) => c.ageSeconds >= thresholdSeconds);
  const sources = new Map();
  const alerts = halfOpen.map((c) => {
    sources.set(c.source, (sources.get(c.source) || 0) + 1);
    return {
      id: `alert-${c.id}`,
      type: "Handshake timeout",
      severity: "medium",
      source: c.source,
      message: `${c.source} → ${c.destination}:${c.port} has remained ${c.state} for ${c.ageSeconds}s.`,
    };
  });
  for (const [source, count] of sources)
    if (count >= 3)
      alerts.push({
        id: `burst-${source}`,
        type: "Repeated incomplete handshakes",
        severity: "high",
        source,
        message: `${count} aged half-open connections from ${source}. Review for network failure or possible SYN flooding.`,
      });
  return {
    total: connections.length,
    established: connections.filter((c) => c.state === "ESTABLISHED").length,
    halfOpen: halfOpen.length,
    pending: pending.length,
    thresholdSeconds,
    alerts,
    connections,
    ratio: connections.length
      ? Math.round((halfOpen.length / connections.length) * 100)
      : 0,
  };
}

export function analyzeFile(input) {
  const name = text(input.name, "name", 255);
  if (
    typeof input.contentBase64 !== "string" ||
    !input.contentBase64 ||
    input.contentBase64.length > 2_796_204 ||
    input.contentBase64.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(input.contentBase64)
  )
    throw new ValidationError(
      "Provide a non-empty valid Base64 file up to 2 MiB.",
    );
  const buffer = Buffer.from(input.contentBase64, "base64");
  if (buffer.toString("base64") !== input.contentBase64)
    throw new ValidationError(
      "File content must use canonical Base64 encoding.",
    );
  if (!buffer.length || buffer.length > 2 * 1024 * 1024)
    throw new ValidationError("File must contain between 1 byte and 2 MiB.");
  const counts = new Uint32Array(256);
  for (const byte of buffer) counts[byte]++;
  let entropy = 0;
  for (const count of counts)
    if (count) {
      const p = count / buffer.length;
      entropy -= p * Math.log2(p);
    }
  const content = buffer.toString("latin1");
  const fileType =
    buffer[0] === 0x4d && buffer[1] === 0x5a
      ? "Windows PE executable"
      : buffer.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
        ? "ELF executable"
        : buffer[0] === 0x50 && buffer[1] === 0x4b
          ? "ZIP-compatible archive"
          : /^[\x09\x0a\x0d\x20-\x7e]*$/.test(content)
            ? "Text / script"
            : "Binary data";
  const indicators = [];
  if (/EICAR-STANDARD-ANTIVIRUS-TEST-FILE/i.test(content))
    indicators.push({
      type: "Test signature",
      value: "EICAR antivirus test marker",
      severity: "high",
      description:
        "A standard harmless antivirus test marker is present. This is not real malware.",
    });
  if (
    /powershell(?:\.exe)?[\s\S]{0,100}-(?:enc(?:odedcommand)?|e)\b/i.test(
      content,
    )
  )
    indicators.push({
      type: "Script pattern",
      value: "Encoded PowerShell invocation",
      severity: "high",
      description:
        "Encoded commands can hide intent, but can also have legitimate uses.",
    });
  if (
    /\b(?:VirtualAlloc|WriteProcessMemory|CreateRemoteThread)\b/.test(content)
  )
    indicators.push({
      type: "API string",
      value: "Process memory API reference",
      severity: "medium",
      description:
        "Memory manipulation API names require review in the context of the file.",
    });
  const urls = [
    ...new Set(content.match(/https?:\/\/[^\s"'<>\x00-\x1f]{3,200}/g) || []),
  ].slice(0, 8);
  for (const url of urls)
    indicators.push({
      type: "URL string",
      value: url,
      severity: "low",
      description:
        "Embedded URL extracted from file bytes. It has not been contacted.",
    });
  if (entropy > 7.2 && buffer.length >= 1024)
    indicators.push({
      type: "Entropy",
      value: `${entropy.toFixed(2)} bits/byte`,
      severity: "medium",
      description:
        "High entropy can indicate compression, encryption, or packing; it does not prove malicious intent.",
    });
  if (
    /\.(?:pdf|docx?|xlsx?|jpe?g|png)\.(?:exe|scr|bat|cmd|ps1|js)$/i.test(name)
  )
    indicators.push({
      type: "Filename",
      value: "Double file extension",
      severity: "high",
      description:
        "A document-like filename ends with an executable or script extension.",
    });
  return {
    name,
    size: buffer.length,
    sha256: createHash("sha256").update(buffer).digest("hex"),
    entropy: Number(entropy.toFixed(3)),
    fileType,
    verdict: indicators.some((i) => ["high", "medium"].includes(i.severity))
      ? "suspicious"
      : "no-obvious-indicators",
    indicators,
    notes: [
      "Static analysis only. The uploaded file was never executed or saved.",
      "This tool is not an antivirus engine or sandbox. A clean result does not establish safety.",
    ],
    mode: "static",
  };
}
