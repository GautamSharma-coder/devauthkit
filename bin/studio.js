const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");

const GENESIS_HASH = "0".repeat(64);

function computeCanonicalHash(prevHash, entry) {
  const normalizedPrev = prevHash || GENESIS_HASH;
  const ts = entry.timestamp || 0;
  const canonicalData = [
    normalizedPrev,
    ts,
    entry.actorId || "system",
    entry.actorType || "system",
    entry.eventType || "unknown",
    entry.targetId || "",
    entry.orgId || "",
    entry.ipAddress || "",
    entry.metadata ? JSON.stringify(entry.metadata) : "{}"
  ].join("|");

  return crypto.createHash("sha256").update(canonicalData, "utf8").digest("hex");
}

function buildInitialTelemetry(cwd, port) {
  let version = "2.0.0";
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
    if (pkg && pkg.version) version = pkg.version;
  } catch (_) {}

  const envLocalExists = fs.existsSync(path.join(cwd, ".env.local"));
  const envExists = fs.existsSync(path.join(cwd, ".env"));
  const hasSecretEnv = Boolean(
    process.env.DEVAUTHKIT_SECRET ||
    process.env.JWT_SECRET ||
    process.env.SESSION_SECRET
  );

  const now = Date.now();
  const seedEvents = [
    {
      id: "aud_0192b8f4-7c10-7a21-8b42-9a11e02f4001",
      action: "org.created",
      label: "Team created",
      eventType: "org.created",
      user: "sarah@startup.io",
      actorId: "sarah@startup.io",
      actorType: "user",
      targetId: "org_startup_io",
      orgId: "startup-io",
      ip: "192.0.2.88",
      ipAddress: "192.0.2.88",
      dpop: false,
      time: "1 hour ago",
      timestamp: now - 3600 * 1000,
      metadata: { plan: "pro", region: "us-east-1", authMethod: "email_otp", proof: "bearer_jwt" }
    },
    {
      id: "aud_0192b8f4-7c10-7a21-8b42-9a11e02f4002",
      action: "sso.saml_login",
      label: "Signed in via SSO",
      eventType: "sso.saml_login",
      user: "maya.lin@acme.com",
      actorId: "maya.lin@acme.com",
      actorType: "user",
      targetId: "ses_9f2a41c0",
      orgId: "acme-corp",
      ip: "198.51.100.14",
      ipAddress: "198.51.100.14",
      dpop: true,
      time: "38 min ago",
      timestamp: now - 38 * 60 * 1000,
      metadata: { idp: "Okta Enterprise", jkt: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", alg: "ES256" }
    },
    {
      id: "aud_0192b8f4-7c10-7a21-8b42-9a11e02f4003",
      action: "passkey.asserted",
      label: "Passkey sign-in",
      eventType: "passkey.asserted",
      user: "liam@acme.com",
      actorId: "liam@acme.com",
      actorType: "user",
      targetId: "cred_webauthn_88b1",
      orgId: "acme-corp",
      ip: "198.51.100.77",
      ipAddress: "198.51.100.77",
      dpop: true,
      time: "22 min ago",
      timestamp: now - 22 * 60 * 1000,
      metadata: { authenticator: "Platform TouchID", uv: true, jkt: "kP92mQz_4xV7sLn82rT1wYb3cDf5gHj6kLm8nPq0Rs", alg: "ES256" }
    },
    {
      id: "aud_0192b8f4-7c10-7a21-8b42-9a11e02f4004",
      action: "session.revoke",
      label: "Session signed out",
      eventType: "session.revoke",
      user: "dev@initech.org",
      actorId: "dev@initech.org",
      actorType: "user",
      targetId: "ses_3c8e12a9",
      orgId: "initech-sec",
      ip: "203.0.113.19",
      ipAddress: "203.0.113.19",
      dpop: true,
      time: "14 min ago",
      timestamp: now - 14 * 60 * 1000,
      metadata: { reason: "user_initiated_rotation", jkt: "xR4tY7uI9oP2aS5dF8gH1jK3lZ6xC9vB2nM4qW7eR0", alg: "ES256" }
    },
    {
      id: "aud_0192b8f4-7c10-7a21-8b42-9a11e02f4005",
      action: "user.login",
      label: "Email OTP sign-in",
      eventType: "user.login",
      user: "alex@acme.com",
      actorId: "alex@acme.com",
      actorType: "user",
      targetId: "ses_7a19d4e2",
      orgId: "acme-corp",
      ip: "198.51.100.42",
      ipAddress: "198.51.100.42",
      dpop: true,
      time: "2 min ago",
      timestamp: now - 2 * 60 * 1000,
      metadata: { mfa: "totp_verified", jkt: "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3", alg: "ES256" }
    }
  ];

  let prev = GENESIS_HASH;
  const chainedEvents = seedEvents.map((evt) => {
    const entryHash = computeCanonicalHash(prev, evt);
    const enriched = { ...evt, prevHash: prev, entryHash };
    prev = entryHash;
    return enriched;
  });

  const recentEvents = [...chainedEvents].reverse();

  const sessions = [
    {
      id: "ses_7a19d4e2",
      user: "alex@acme.com",
      orgId: "acme-corp",
      binding: "Key-Bound (DPoP)",
      dpop: true,
      jkt: "7f83b1657ff1fc53b92dc18148a1d65d",
      ip: "198.51.100.42",
      client: "Chrome · macOS",
      lastActive: "2m ago",
      expiresIn: "6d 23h"
    },
    {
      id: "ses_9f2a41c0",
      user: "maya.lin@acme.com",
      orgId: "acme-corp",
      binding: "Key-Bound (DPoP)",
      dpop: true,
      jkt: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAf",
      ip: "198.51.100.14",
      client: "Edge · Windows",
      lastActive: "38m ago",
      expiresIn: "6d 23h"
    },
    {
      id: "ses_5b04c81f",
      user: "liam@acme.com",
      orgId: "acme-corp",
      binding: "Key-Bound (DPoP)",
      dpop: true,
      jkt: "kP92mQz_4xV7sLn82rT1wYb3cDf5gHj6",
      ip: "198.51.100.77",
      client: "Safari · iOS",
      lastActive: "22m ago",
      expiresIn: "6d 23h"
    },
    {
      id: "ses_1e92a004",
      user: "sarah@startup.io",
      orgId: "startup-io",
      binding: "Standard JWT",
      dpop: false,
      jkt: null,
      ip: "192.0.2.88",
      client: "Node SDK Client",
      lastActive: "1h ago",
      expiresIn: "6d 22h"
    }
  ];

  const orgList = [
    { id: "org_acme", name: "Acme Corporation", slug: "acme-corp", sso: "SAML 2.0 (Okta)", scim: true, dpopPolicy: "Required", mfaPolicy: "Required", members: 64 },
    { id: "org_initech", name: "Initech Security", slug: "initech-sec", sso: "OIDC (Google)", scim: true, dpopPolicy: "Required", mfaPolicy: "Required", members: 48 },
    { id: "org_startup", name: "Startup.io", slug: "startup-io", sso: "Email OTP", scim: false, dpopPolicy: "Optional", mfaPolicy: "Optional", members: 30 }
  ];

  const nodeMajor = parseInt(process.versions.node.split(".")[0], 10);
  const webCryptoActive = typeof crypto.subtle !== "undefined";

  const securityChecks = [
    {
      name: "Node.js Version",
      status: nodeMajor >= 18 ? "pass" : "fail",
      detail: `v${process.versions.node}`,
      requirement: "Node.js 18 or newer is required."
    },
    {
      name: "Built-in Crypto Support",
      status: webCryptoActive ? "pass" : "fail",
      detail: webCryptoActive ? "Active (WebCrypto ready)" : "Unavailable",
      requirement: "Needed for token signing, passkeys, and log verification."
    },
    {
      name: "Environment File",
      status: envLocalExists || envExists ? "pass" : "warn",
      detail: envLocalExists ? "Found .env.local" : envExists ? "Found .env" : "No .env file yet",
      requirement: "Run `npx devauthkit init` to create one automatically."
    },
    {
      name: "Signing Secret",
      status: hasSecretEnv ? "pass" : "warn",
      detail: hasSecretEnv ? "Configured in environment" : "Not set in current shell",
      requirement: "Generate one with `npx devauthkit keys` before production."
    }
  ];

  return {
    activeUsers: 142,
    activeSessions: 310,
    dpopCoverage: "88%",
    dpopNumeric: 88,
    auditLedgerHead: prev,
    organizations: 14,
    recentEvents,
    sessions,
    orgList,
    securityChecks,
    runtime: {
      version,
      port,
      nodeVersion: `v${process.versions.node}`,
      webCryptoActive,
      cwd,
      mode: "Local Preview Mode",
      liveConnected: false,
      apiUrl: "",
      liveError: null
    }
  };
}

function normalizeApiUrl(url) {
  return String(url || "").trim().replace(/\/+$/, "");
}

function formatRelativeTime(ts) {
  if (!ts) return "unknown";
  const diffSec = Math.max(0, Math.floor((Date.now() - Number(ts)) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin} min ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr} hour${diffHr > 1 ? "s" : ""} ago`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}d ago`;
}

function humanizeEventType(eventType) {
  const map = {
    "user.login": "Signed in",
    "user.login_succeeded": "Signed in",
    "session.revoke": "Session signed out",
    "session.revoked": "Session signed out",
    "org.created": "Team created",
    "sso.saml_login": "Signed in via SSO",
    "passkey.asserted": "Passkey sign-in",
    "api_key.created": "API key created",
    "dpop.proof_verified": "Protected API call"
  };
  return map[eventType] || eventType || "Auth event";
}

async function fetchJsonSafe(url, options = {}) {
  try {
    const res = await fetch(url, options);
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch (_) {}
    return { ok: res.ok, status: res.status, data: json };
  } catch (err) {
    return { ok: false, status: 0, error: err.message };
  }
}

async function fetchLiveTelemetry(connection, baseTelemetry) {
  const apiUrl = normalizeApiUrl(connection?.apiUrl);
  if (!apiUrl) return baseTelemetry;

  const headers = { Accept: "application/json" };
  if (connection.token) {
    headers.Authorization = `Bearer ${connection.token}`;
  }

  const [auditRes, sessionsRes, orgsRes] = await Promise.all([
    fetchJsonSafe(`${apiUrl}/audit-logs?limit=50`, { headers }),
    fetchJsonSafe(`${apiUrl}/sessions`, { headers }),
    fetchJsonSafe(`${apiUrl}/orgs`, { headers })
  ]);

  if (!auditRes.ok && !sessionsRes.ok && !orgsRes.ok) {
    const reason = auditRes.error || sessionsRes.error || `HTTP ${auditRes.status || sessionsRes.status}`;
    return {
      ...baseTelemetry,
      runtime: {
        ...baseTelemetry.runtime,
        mode: "Live Connection Error (Showing Preview)",
        liveConnected: false,
        apiUrl,
        liveError: `Could not reach ${apiUrl} (${reason}). Check URL or Bearer token.`
      }
    };
  }

  const rawEntries = Array.isArray(auditRes.data?.entries) ? auditRes.data.entries : [];
  const mappedEvents = rawEntries.map((e) => ({
    id: e.id,
    action: e.eventType || "unknown",
    label: humanizeEventType(e.eventType),
    eventType: e.eventType || "unknown",
    user: e.actorId || "system",
    actorId: e.actorId || "system",
    actorType: e.actorType || "user",
    targetId: e.targetId || "",
    orgId: e.orgId || "default",
    ip: e.ipAddress || "—",
    ipAddress: e.ipAddress || "",
    dpop: Boolean(e.metadata?.jkt || e.metadata?.dpop || e.metadata?.alg === "ES256"),
    time: formatRelativeTime(e.timestamp || e.createdAt),
    timestamp: e.timestamp || e.createdAt || Date.now(),
    metadata: e.metadata || {},
    prevHash: e.prevHash || GENESIS_HASH,
    entryHash: e.entryHash || ""
  }));

  const rawSessions = Array.isArray(sessionsRes.data?.sessions)
    ? sessionsRes.data.sessions
    : Array.isArray(sessionsRes.data)
      ? sessionsRes.data
      : [];

  const mappedSessions = rawSessions.map((s) => ({
    id: s.id,
    user: s.email || s.userId || "authenticated-user",
    orgId: s.orgId || "default",
    binding: s.dpopJkt || s.jkt ? "Key-Bound (DPoP)" : "Standard JWT",
    dpop: Boolean(s.dpopJkt || s.jkt),
    jkt: s.dpopJkt || s.jkt || null,
    ip: s.ip || s.ipAddress || "—",
    client: s.device ? [s.device.browser, s.device.os].filter(Boolean).join(" · ") : (s.userAgent || "Browser / SDK"),
    lastActive: formatRelativeTime(s.lastActiveAt || s.createdAt),
    expiresIn: s.expiresAt ? formatRelativeTime(s.expiresAt) : "Active"
  }));

  const rawOrgs = Array.isArray(orgsRes.data?.organizations)
    ? orgsRes.data.organizations
    : Array.isArray(orgsRes.data)
      ? orgsRes.data
      : [];

  const mappedOrgs = rawOrgs.map((o) => ({
    id: o.id,
    name: o.name || o.slug || o.id,
    slug: o.slug || o.id,
    sso: "Configured / Auth",
    scim: false,
    dpopPolicy: "Optional",
    mfaPolicy: "Optional",
    members: o.memberCount || "—"
  }));

  const dpopEvents = mappedEvents.filter((e) => e.dpop).length;
  const dpopPct = mappedEvents.length ? Math.round((dpopEvents / mappedEvents.length) * 100) : 0;
  const uniqueActors = new Set([
    ...mappedEvents.map((e) => e.user),
    ...mappedSessions.map((s) => s.user)
  ].filter(Boolean));

  return {
    ...baseTelemetry,
    activeUsers: uniqueActors.size || mappedSessions.length,
    activeSessions: mappedSessions.length,
    dpopCoverage: `${dpopPct}%`,
    dpopNumeric: dpopPct,
    auditLedgerHead: mappedEvents[0]?.entryHash || GENESIS_HASH,
    organizations: mappedOrgs.length,
    recentEvents: mappedEvents,
    sessions: mappedSessions,
    orgList: mappedOrgs.length ? mappedOrgs : baseTelemetry.orgList,
    runtime: {
      ...baseTelemetry.runtime,
      mode: `Live: ${apiUrl}`,
      liveConnected: true,
      apiUrl,
      liveError: null
    }
  };
}

function readJsonBody(req, maxBytes = 65536) {
  return new Promise((resolve, reject) => {
    let body = "";
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error("Payload too large"));
        req.destroy();
        return;
      }
      body += chunk;
    });
    req.on("end", () => {
      if (!body.trim()) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

function renderStudioHtml(initialData) {
  const safePort = Number(initialData.runtime.port) || 4321;
  const serializedInitial = JSON.stringify(initialData).replace(/</g, "\\u003c");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>DevAuthKit Studio</title>
  <style>
    :root {
      --bg-base: #07090d;
      --bg-surface: #0d1017;
      --bg-elevated: #141923;
      --bg-hover: #1a2130;
      --border-subtle: rgba(255, 255, 255, 0.08);
      --border-medium: rgba(255, 255, 255, 0.15);
      --border-focus: rgba(129, 140, 248, 0.6);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --indigo: #6366f1;
      --indigo-soft: rgba(99, 102, 241, 0.14);
      --indigo-text: #a5b4fc;
      --emerald: #10b981;
      --emerald-soft: rgba(16, 185, 129, 0.14);
      --emerald-text: #34d399;
      --amber: #f59e0b;
      --amber-soft: rgba(245, 158, 11, 0.14);
      --amber-text: #fbbf24;
      --rose: #f43f5e;
      --rose-soft: rgba(244, 63, 94, 0.14);
      --rose-text: #fb7185;
      --font-sans: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      --font-mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      --radius-md: 10px;
      --radius-lg: 14px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    html, body {
      background-color: var(--bg-base);
      color: var(--text-primary);
      font-family: var(--font-sans);
      -webkit-font-smoothing: antialiased;
      min-height: 100vh;
    }

    body {
      background-image: radial-gradient(ellipse 75% 40% at 50% -10%, rgba(99, 102, 241, 0.11), transparent 70%);
    }

    .mono { font-family: var(--font-mono); font-variant-numeric: tabular-nums; }

    /* Top Bar */
    .topbar {
      position: sticky;
      top: 0;
      z-index: 40;
      background: rgba(7, 9, 13, 0.85);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      border-bottom: 1px solid var(--border-subtle);
    }

    .topbar-inner {
      max-width: 1240px;
      margin: 0 auto;
      padding: 0 24px;
      min-height: 60px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .brand-mark {
      width: 30px;
      height: 30px;
      border-radius: 8px;
      background: linear-gradient(135deg, rgba(99, 102, 241, 0.3), rgba(168, 85, 247, 0.22));
      border: 1px solid rgba(129, 140, 248, 0.35);
      display: grid;
      place-items: center;
      color: #c7d2fe;
    }

    .brand-name { font-size: 15px; font-weight: 700; letter-spacing: -0.02em; }

    .studio-pill {
      font-size: 11px;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 9999px;
      background: var(--indigo-soft);
      color: var(--indigo-text);
      border: 1px solid rgba(99, 102, 241, 0.28);
    }

    .nav-tabs {
      display: flex;
      align-items: center;
      gap: 4px;
      background: var(--bg-surface);
      padding: 4px;
      border-radius: 9px;
      border: 1px solid var(--border-subtle);
    }

    .nav-tab {
      background: transparent;
      border: none;
      color: var(--text-secondary);
      font-family: var(--font-sans);
      font-size: 13px;
      font-weight: 500;
      padding: 6px 12px;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s ease;
      white-space: nowrap;
    }

    .nav-tab:hover { color: var(--text-primary); background: rgba(255, 255, 255, 0.04); }
    .nav-tab.active { background: var(--bg-elevated); color: var(--text-primary); box-shadow: inset 0 0 0 1px var(--border-medium); }

    .topbar-actions { display: flex; align-items: center; gap: 10px; }

    .status-chip {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 5px 10px;
      border-radius: 9999px;
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      font-size: 12px;
      color: var(--text-secondary);
    }

    .pulse-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--emerald);
      animation: pulse 2.2s infinite;
    }

    @keyframes pulse {
      0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.55); }
      70% { box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
      100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      font-family: var(--font-sans);
      font-size: 12.5px;
      font-weight: 600;
      padding: 7px 12px;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.15s ease;
      border: 1px solid var(--border-medium);
      background: var(--bg-elevated);
      color: var(--text-primary);
      white-space: nowrap;
    }

    .btn:hover { background: var(--bg-hover); border-color: rgba(255, 255, 255, 0.24); }
    .btn:disabled { opacity: 0.55; cursor: not-allowed; }

    .btn-primary {
      background: var(--indigo);
      border-color: rgba(129, 140, 248, 0.4);
      color: #ffffff;
    }

    .btn-primary:hover { background: #4f46e5; }
    .btn-sm { padding: 5px 10px; font-size: 12px; border-radius: 6px; }

    /* Container */
    .container {
      max-width: 1240px;
      margin: 0 auto;
      padding: 24px 24px 48px;
    }

    .intro-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 20px;
    }

    .page-title { font-size: 20px; font-weight: 700; letter-spacing: -0.02em; }
    .page-subtitle { font-size: 13.5px; color: var(--text-secondary); margin-top: 3px; }

    .mode-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 12px;
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-subtle);
      font-size: 12px;
      color: var(--text-secondary);
    }

    /* KPI Grid */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 22px;
    }

    .kpi-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg);
      padding: 18px 20px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .kpi-label {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-secondary);
    }

    .kpi-value-row {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 8px;
    }

    .kpi-value {
      font-size: 28px;
      font-weight: 700;
      letter-spacing: -0.03em;
      font-variant-numeric: tabular-nums;
    }

    .kpi-hint {
      font-size: 12px;
      color: var(--text-muted);
    }

    .progress-track {
      height: 5px;
      width: 100%;
      background: rgba(255, 255, 255, 0.07);
      border-radius: 9999px;
      overflow: hidden;
      margin-top: 4px;
    }

    .progress-fill {
      height: 100%;
      background: linear-gradient(90deg, #6366f1, #818cf8);
      border-radius: 9999px;
    }

    /* Panels */
    .panel {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg);
      overflow: hidden;
    }

    .panel-header {
      padding: 18px 20px;
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
    }

    .panel-header h2 { font-size: 15px; font-weight: 600; }
    .panel-header p { font-size: 13px; color: var(--text-secondary); margin-top: 2px; }

    .toolbar {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
      padding: 12px 20px;
      background: rgba(255, 255, 255, 0.015);
      border-bottom: 1px solid var(--border-subtle);
    }

    .search-input {
      flex: 1;
      min-width: 220px;
      max-width: 340px;
      background: var(--bg-base);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 7px 12px;
      font-size: 13px;
      color: var(--text-primary);
      outline: none;
    }

    .search-input:focus { border-color: var(--border-focus); }
    .search-input::placeholder { color: var(--text-muted); }

    .filter-group { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }

    .filter-pill {
      background: transparent;
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
      border-radius: 9999px;
      padding: 5px 12px;
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
    }

    .filter-pill:hover { color: var(--text-primary); border-color: var(--border-medium); }
    .filter-pill.active {
      background: var(--indigo-soft);
      border-color: rgba(99, 102, 241, 0.45);
      color: var(--indigo-text);
    }

    /* Tables */
    .table-wrap { width: 100%; overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    thead th {
      text-align: left;
      padding: 11px 16px;
      font-size: 11.5px;
      font-weight: 600;
      color: var(--text-muted);
      background: rgba(255, 255, 255, 0.015);
      border-bottom: 1px solid var(--border-subtle);
      white-space: nowrap;
    }

    tbody tr { border-bottom: 1px solid var(--border-subtle); }
    tbody tr:last-child { border-bottom: none; }
    tbody tr.clickable { cursor: pointer; }
    tbody tr.clickable:hover { background: rgba(255, 255, 255, 0.03); }
    tbody tr.selected { background: rgba(99, 102, 241, 0.08); }
    td { padding: 13px 16px; vertical-align: middle; white-space: nowrap; }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 9px;
      border-radius: 9999px;
      font-size: 11.5px;
      font-weight: 600;
    }

    .badge-emerald { background: var(--emerald-soft); color: var(--emerald-text); border: 1px solid rgba(16, 185, 129, 0.25); }
    .badge-indigo { background: var(--indigo-soft); color: var(--indigo-text); border: 1px solid rgba(99, 102, 241, 0.3); }
    .badge-amber { background: var(--amber-soft); color: var(--amber-text); border: 1px solid rgba(245, 158, 11, 0.25); }
    .badge-rose { background: var(--rose-soft); color: var(--rose-text); border: 1px solid rgba(244, 63, 94, 0.25); }
    .badge-neutral { background: rgba(255, 255, 255, 0.05); color: var(--text-secondary); border: 1px solid var(--border-subtle); }

    /* Split layout */
    .split-layout { display: grid; grid-template-columns: 1fr; gap: 16px; }
    .split-layout.with-drawer { grid-template-columns: minmax(0, 1fr) 360px; }

    .drawer {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg);
      padding: 18px;
      display: flex;
      flex-direction: column;
      gap: 14px;
      align-self: start;
      position: sticky;
      top: 76px;
    }

    .drawer-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--border-subtle);
    }

    .kv-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); font-weight: 600; }
    .kv-val { font-size: 12.5px; color: var(--text-primary); word-break: break-all; margin-top: 2px; }

    .code-block {
      background: var(--bg-base);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 14px;
      font-family: var(--font-mono);
      font-size: 12px;
      line-height: 1.55;
      color: #e2e8f0;
      overflow-x: auto;
      white-space: pre;
    }

    /* Switch & Setup Builder */
    .switch-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 14px;
      padding: 20px;
      border-bottom: 1px solid var(--border-subtle);
    }

    .select-box label {
      display: block;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-secondary);
      margin-bottom: 6px;
    }

    .select-box select {
      width: 100%;
      background: var(--bg-base);
      color: var(--text-primary);
      border: 1px solid var(--border-medium);
      border-radius: 8px;
      padding: 9px 12px;
      font-size: 13px;
      outline: none;
    }

    .select-box select:focus { border-color: var(--border-focus); }

    .switch-body {
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 18px;
    }

    .mapping-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }

    .mapping-card {
      background: var(--bg-base);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 14px;
    }

    .code-section-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 8px;
    }

    .cards-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(290px, 1fr));
      gap: 14px;
      padding: 20px;
    }

    .sub-card {
      background: var(--bg-base);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .verify-banner {
      margin-bottom: 16px;
      padding: 12px 16px;
      border-radius: var(--radius-md);
      background: var(--emerald-soft);
      border: 1px solid rgba(16, 185, 129, 0.3);
      display: none;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      font-size: 13px;
      color: #d1fae5;
    }

    .verify-banner.show { display: flex; }

    .tab-view { display: none; }
    .tab-view.active { display: block; }

    .empty-state { padding: 36px 20px; text-align: center; color: var(--text-muted); font-size: 13px; }

    .toast {
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: var(--bg-elevated);
      border: 1px solid var(--border-medium);
      color: var(--text-primary);
      padding: 10px 14px;
      border-radius: 9px;
      font-size: 12.5px;
      font-weight: 500;
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.6);
      opacity: 0;
      transform: translateY(8px);
      pointer-events: none;
      transition: all 0.2s ease;
      z-index: 60;
    }

    .toast.show { opacity: 1; transform: translateY(0); }

    @media (max-width: 980px) {
      .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .split-layout.with-drawer { grid-template-columns: 1fr; }
      .switch-grid, .mapping-grid { grid-template-columns: 1fr; }
      .topbar-inner { padding: 10px 16px; flex-wrap: wrap; }
      .nav-tabs { order: 3; width: 100%; overflow-x: auto; }
    }

    @media (max-width: 600px) {
      .kpi-grid { grid-template-columns: 1fr; }
      .status-chip { display: none; }
    }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand">
        <div class="brand-mark" aria-hidden="true">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="m9 12 2 2 4-4"/>
          </svg>
        </div>
        <span class="brand-name">DevAuthKit</span>
        <span class="studio-pill">Studio</span>
      </div>

      <nav class="nav-tabs" aria-label="Studio Sections">
        <button class="nav-tab active" data-tab="overview">Overview</button>
        <button class="nav-tab" data-tab="sessions">Active Logins</button>
        <button class="nav-tab" data-tab="orgs">Teams &amp; SSO</button>
        <button class="nav-tab" data-tab="switch">Switch &amp; Setup</button>
        <button class="nav-tab" data-tab="doctor">Health Check</button>
      </nav>

      <div class="topbar-actions">
        <div class="status-chip">
          <span class="pulse-dot"></span>
          <span>Local</span>
          <span class="mono" style="color: var(--text-muted);">:${safePort}</span>
        </div>
        <button class="btn" id="refreshBtn">Refresh</button>
        <button class="btn btn-primary" id="verifyChainBtn">Verify Logs</button>
      </div>
    </div>
  </header>

  <main class="container">
    <div class="intro-bar">
      <div>
        <h1 class="page-title">Auth Dashboard</h1>
        <p class="page-subtitle">See who is signed in, check token security, verify your activity log, or switch your app in minutes.</p>
      </div>
      <div class="mode-pill">
        <span id="runtimeModeLabel">Local Preview · v${initialData.runtime.version}</span>
        <button class="btn btn-sm" id="toggleConnectBtn">Connect Live Backend</button>
        <button class="btn btn-sm" id="jumpSwitchBtn">Switch from another tool →</button>
      </div>
    </div>

    <!-- Collapsible Live Backend Connection Panel -->
    <section class="panel" id="connectPanel" style="display: none; margin-bottom: 18px; padding: 16px 20px;">
      <div style="display: flex; align-items: flex-end; flex-wrap: wrap; gap: 12px;">
        <div style="flex: 2; min-width: 240px;">
          <label class="kv-label" for="liveApiUrlInput" style="display: block; margin-bottom: 6px;">Auth Server Base URL (e.g. http://localhost:3000/auth)</label>
          <input type="text" class="search-input" id="liveApiUrlInput" style="max-width: none; width: 100%;" placeholder="http://localhost:3000/auth"/>
        </div>
        <div style="flex: 2; min-width: 220px;">
          <label class="kv-label" for="liveTokenInput" style="display: block; margin-bottom: 6px;">Bearer JWT / Admin Token (optional for local dev)</label>
          <input type="password" class="search-input" id="liveTokenInput" style="max-width: none; width: 100%;" placeholder="eyJhbGciOi..."/>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn btn-primary" id="saveConnectBtn">Connect</button>
          <button class="btn" id="disconnectLiveBtn">Use Preview Mode</button>
        </div>
      </div>
      <div id="liveErrorBanner" style="display: none; margin-top: 10px; font-size: 12.5px; color: var(--rose-text);"></div>
    </section>

    <!-- Simple 4-card KPI Summary -->
    <section class="kpi-grid">
      <article class="kpi-card">
        <span class="kpi-label">Active Users</span>
        <div class="kpi-value-row">
          <span class="kpi-value" id="statUsers">142</span>
          <span class="badge badge-emerald">+12% today</span>
        </div>
        <span class="kpi-hint" id="statOrgsMeta">Across 14 teams</span>
      </article>

      <article class="kpi-card">
        <span class="kpi-label">Active Logins</span>
        <div class="kpi-value-row">
          <span class="kpi-value" id="statSessions">310</span>
          <span class="badge badge-neutral">Live devices</span>
        </div>
        <span class="kpi-hint" id="statSessionsSplit">273 protected · 37 standard</span>
      </article>

      <article class="kpi-card">
        <span class="kpi-label">Protected Tokens (DPoP)</span>
        <div class="kpi-value-row">
          <span class="kpi-value" style="color: var(--indigo-text);" id="statDpop">88%</span>
          <span class="kpi-hint">Anti-theft binding</span>
        </div>
        <div class="progress-track">
          <div class="progress-fill" id="dpopProgress" style="width: 88%;"></div>
        </div>
      </article>

      <article class="kpi-card">
        <span class="kpi-label">Activity Log Integrity</span>
        <div class="kpi-value-row">
          <span class="kpi-value" style="color: var(--emerald-text); font-size: 23px;" id="statIntegrity">Verified</span>
          <span class="badge badge-emerald" id="statBlocksBadge">5 / 5 logs</span>
        </div>
        <span class="kpi-hint">Tamper-proof SHA-256 chain</span>
      </article>
    </section>

    <div class="verify-banner" id="verifyBanner">
      <span id="verifyBannerText">All activity logs verified — no records were modified.</span>
      <span class="mono" style="font-size: 12px;" id="verifyTiming"></span>
    </div>

    <!-- Tab 1: Overview / Activity Log -->
    <section class="tab-view active" id="tab-overview">
      <div class="split-layout" id="ledgerSplit">
        <div class="panel">
          <div class="panel-header">
            <div>
              <h2>Recent Auth Activity</h2>
              <p>Click any event to inspect full details, or verify that nothing has been tampered with.</p>
            </div>
            <button class="btn btn-sm" id="simulateEventBtn">+ Test Event</button>
          </div>

          <div class="toolbar">
            <input type="text" class="search-input" id="ledgerSearch" placeholder="Search by email, event, team, or IP..."/>
            <div class="filter-group" id="ledgerFilters">
              <button class="filter-pill active" data-filter="all">All</button>
              <button class="filter-pill" data-filter="dpop">Protected (DPoP)</button>
              <button class="filter-pill" data-filter="bearer">Standard JWT</button>
              <button class="filter-pill" data-filter="revoke">Sign-outs</button>
            </div>
          </div>

          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>What Happened</th>
                  <th>User &amp; Team</th>
                  <th>Token Protection</th>
                  <th>IP Address</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody id="ledgerBody"></tbody>
            </table>
          </div>
        </div>

        <aside class="drawer" id="inspectorDrawer" style="display: none;">
          <div class="drawer-head">
            <span style="font-size: 14px; font-weight: 600;">Event Details</span>
            <button class="btn btn-sm" id="closeDrawerBtn">Close</button>
          </div>
          <div id="drawerMeta" style="display: flex; flex-direction: column; gap: 10px;"></div>
          <div>
            <div class="kv-label" style="margin-bottom: 6px;">Extra Details (JSON)</div>
            <pre class="code-block" id="drawerJson" style="white-space: pre-wrap; word-break: break-word;"></pre>
          </div>
          <button class="btn btn-sm" id="copyEventJsonBtn" style="width: 100%;">Copy Event JSON</button>
        </aside>
      </div>
    </section>

    <!-- Tab 2: Active Logins -->
    <section class="tab-view" id="tab-sessions">
      <div class="panel">
        <div class="panel-header">
          <div>
            <h2>Active Logins</h2>
            <p>See which devices are signed in and test signing out a session immediately.</p>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Device</th>
                <th>Protection</th>
                <th>IP Address</th>
                <th>Expires In</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="sessionsBody"></tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- Tab 3: Teams & SSO -->
    <section class="tab-view" id="tab-orgs">
      <div class="panel">
        <div class="panel-header">
          <div>
            <h2>Teams &amp; Enterprise Login (SSO)</h2>
            <p>Each team can choose its own login method (Google, Okta SAML, or Email OTP) and security rules.</p>
          </div>
        </div>
        <div class="cards-grid" id="orgsGrid"></div>
      </div>
    </section>

    <!-- Tab 4: Switch & Setup -->
    <section class="tab-view" id="tab-switch">
      <div class="panel">
        <div class="panel-header">
          <div>
            <h2>Switch to DevAuthKit in 2 Minutes</h2>
            <p>Pick what you use today and copy ready-to-run code for your stack — no vendor lock-in or per-user fees.</p>
          </div>
          <button class="btn btn-sm" id="copyCliInitBtn">Copy: npx devauthkit init</button>
        </div>

        <div class="switch-grid">
          <div class="select-box">
            <label for="fromToolSelect">1. Currently Using</label>
            <select id="fromToolSelect">
              <option value="clerk">Clerk</option>
              <option value="nextauth">NextAuth / Auth.js</option>
              <option value="auth0">Auth0 / Okta</option>
              <option value="supabase">Supabase / Firebase Auth</option>
              <option value="custom">Custom Express / JWT</option>
            </select>
          </div>
          <div class="select-box">
            <label for="frameworkSelect">2. Backend Framework</label>
            <select id="frameworkSelect">
              <option value="express">Node.js + Express</option>
              <option value="hono">Hono / Cloudflare Workers</option>
            </select>
          </div>
          <div class="select-box">
            <label for="dbSelect">3. Database</label>
            <select id="dbSelect">
              <option value="prisma">Prisma</option>
              <option value="drizzle">Drizzle ORM</option>
              <option value="mongoose">MongoDB (Mongoose)</option>
              <option value="memory">In-Memory (Quick Test)</option>
            </select>
          </div>
        </div>

        <div class="switch-body">
          <div>
            <div class="kv-label" style="margin-bottom: 8px;">What Changes When You Switch</div>
            <div class="mapping-grid" id="mappingGrid"></div>
          </div>

          <div>
            <div class="code-section-head">
              <span class="kv-label">Step 1 — Backend Setup (Drop-in Auth Routes)</span>
              <button class="btn btn-sm" id="copyBackendBtn">Copy Code</button>
            </div>
            <pre class="code-block" id="backendSnippet"></pre>
          </div>

          <div>
            <div class="code-section-head">
              <span class="kv-label">Step 2 — React / Frontend UI (Optional Drop-in Components)</span>
              <button class="btn btn-sm" id="copyFrontendBtn">Copy Code</button>
            </div>
            <pre class="code-block" id="frontendSnippet"></pre>
          </div>
        </div>
      </div>
    </section>

    <!-- Tab 5: Health Check -->
    <section class="tab-view" id="tab-doctor">
      <div class="panel">
        <div class="panel-header">
          <div>
            <h2>Local Project Health Check</h2>
            <p>Live checks run on <span class="mono" id="doctorCwd"></span>.</p>
          </div>
        </div>
        <div class="cards-grid" id="doctorGrid"></div>
      </div>
    </section>
  </main>

  <div class="toast" id="toast"></div>

  <script>
    (function () {
      let state = ${serializedInitial};
      let activeFilter = "all";
      let searchQuery = "";
      let selectedEventId = null;

      function esc(str) {
        return String(str ?? "")
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#39;");
      }

      function showToast(msg) {
        const el = document.getElementById("toast");
        el.textContent = msg;
        el.classList.add("show");
        clearTimeout(showToast._t);
        showToast._t = setTimeout(() => el.classList.remove("show"), 2200);
      }

      function copyText(text, label) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(() => showToast(label || "Copied!"));
        } else {
          showToast("Clipboard unavailable");
        }
      }

      function switchTab(tabName) {
        document.querySelectorAll(".nav-tab").forEach((t) => {
          t.classList.toggle("active", t.getAttribute("data-tab") === tabName);
        });
        document.querySelectorAll(".tab-view").forEach((v) => {
          v.classList.toggle("active", v.id === "tab-" + tabName);
        });
      }

      function actionBadgeClass(action) {
        if (action.includes("revoke") || action.includes("fail")) return "badge-rose";
        if (action.includes("sso") || action.includes("passkey")) return "badge-indigo";
        if (action.includes("org")) return "badge-amber";
        return "badge-emerald";
      }

      async function sha256HexClient(input) {
        const bytes = new TextEncoder().encode(input);
        const digest = await window.crypto.subtle.digest("SHA-256", bytes);
        return Array.from(new Uint8Array(digest))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
      }

      async function computeCanonicalHashClient(prevHash, evt) {
        const canonical = [
          prevHash || "0".repeat(64),
          evt.timestamp || 0,
          evt.actorId || "system",
          evt.actorType || "system",
          evt.eventType || evt.action || "unknown",
          evt.targetId || "",
          evt.orgId || "",
          evt.ipAddress || evt.ip || "",
          evt.metadata ? JSON.stringify(evt.metadata) : "{}"
        ].join("|");
        return sha256HexClient(canonical);
      }

      function renderSummary() {
        const isLive = Boolean(state.runtime?.liveConnected);
        document.getElementById("runtimeModeLabel").textContent =
          (isLive ? "Live · " + state.runtime.apiUrl : "Local Preview") + " · v" + (state.runtime?.version || "2.0.0");
        document.getElementById("liveApiUrlInput").value = state.runtime?.apiUrl || "";
        const errBanner = document.getElementById("liveErrorBanner");
        if (state.runtime?.liveError) {
          errBanner.textContent = state.runtime.liveError;
          errBanner.style.display = "block";
          document.getElementById("connectPanel").style.display = "block";
        } else {
          errBanner.style.display = "none";
        }

        document.getElementById("statUsers").textContent = state.activeUsers;
        document.getElementById("statSessions").textContent = state.activeSessions;
        document.getElementById("statDpop").textContent = state.dpopCoverage;
        document.getElementById("dpopProgress").style.width = state.dpopCoverage;
        document.getElementById("statOrgsMeta").textContent = "Across " + state.organizations + " teams";

        const total = state.recentEvents.length;
        const estProtected = Math.round((state.activeSessions * (state.dpopNumeric || 88)) / 100);
        const estStandard = Math.max(0, state.activeSessions - estProtected);
        document.getElementById("statSessionsSplit").textContent = estProtected + " protected · " + estStandard + " standard";
        document.getElementById("statBlocksBadge").textContent = total + " / " + total + " logs";
      }

      function getFilteredEvents() {
        return state.recentEvents.filter((evt) => {
          if (activeFilter === "dpop" && !evt.dpop) return false;
          if (activeFilter === "bearer" && evt.dpop) return false;
          if (activeFilter === "revoke" && !evt.action.includes("revoke")) return false;
          if (searchQuery) {
            const hay = [evt.label, evt.action, evt.user, evt.orgId, evt.ip].join(" ").toLowerCase();
            if (!hay.includes(searchQuery)) return false;
          }
          return true;
        });
      }

      function renderLedger() {
        const tbody = document.getElementById("ledgerBody");
        const events = getFilteredEvents();
        if (events.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No matching activity yet.</td></tr>';
          return;
        }

        tbody.innerHTML = events.map((evt) => {
          const isSelected = evt.id === selectedEventId;
          const proofBadge = evt.dpop
            ? '<span class="badge badge-indigo">Key-Bound (DPoP)</span>'
            : '<span class="badge badge-amber">Standard JWT</span>';
          return '<tr class="clickable ' + (isSelected ? "selected" : "") + '" data-event-id="' + esc(evt.id) + '">' +
            '<td><span class="badge ' + actionBadgeClass(evt.action) + '">' + esc(evt.label || evt.action) + '</span>' +
              '<div class="mono" style="font-size: 11px; color: var(--text-muted); margin-top: 3px;">' + esc(evt.action) + '</div></td>' +
            '<td><div style="font-weight: 500;">' + esc(evt.user) + '</div>' +
              '<div style="font-size: 11.5px; color: var(--text-muted);">' + esc(evt.orgId || "default") + '</div></td>' +
            '<td>' + proofBadge + '</td>' +
            '<td class="mono" style="color: var(--text-secondary);">' + esc(evt.ip) + '</td>' +
            '<td style="color: var(--text-secondary);">' + esc(evt.time) + '</td>' +
          '</tr>';
        }).join("");

        tbody.querySelectorAll("tr[data-event-id]").forEach((row) => {
          row.addEventListener("click", () => openInspector(row.getAttribute("data-event-id")));
        });
      }

      function openInspector(id) {
        selectedEventId = id;
        const evt = state.recentEvents.find((e) => e.id === id);
        const split = document.getElementById("ledgerSplit");
        const drawer = document.getElementById("inspectorDrawer");
        if (!evt) {
          drawer.style.display = "none";
          split.classList.remove("with-drawer");
          renderLedger();
          return;
        }

        split.classList.add("with-drawer");
        drawer.style.display = "flex";
        document.getElementById("drawerMeta").innerHTML = [
          { label: "Event", val: (evt.label || evt.action) + " (" + evt.action + ")" },
          { label: "User & Team", val: evt.user + " · " + (evt.orgId || "default") },
          { label: "Time (UTC)", val: new Date(evt.timestamp).toISOString(), mono: true },
          { label: "SHA-256 Entry Proof", val: evt.entryHash, mono: true }
        ].map((item) => (
          '<div><div class="kv-label">' + esc(item.label) + '</div>' +
          '<div class="kv-val ' + (item.mono ? "mono" : "") + '">' + esc(item.val) + '</div></div>'
        )).join("");

        document.getElementById("drawerJson").textContent = JSON.stringify(evt.metadata || {}, null, 2);
        renderLedger();
      }

      function renderSessions() {
        const tbody = document.getElementById("sessionsBody");
        if (!state.sessions || state.sessions.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No active logins.</td></tr>';
          return;
        }
        tbody.innerHTML = state.sessions.map((s) => (
          '<tr>' +
            '<td><div style="font-weight: 500;">' + esc(s.user) + '</div><div style="font-size: 11.5px; color: var(--text-muted);">' + esc(s.orgId) + '</div></td>' +
            '<td>' + esc(s.client) + '<div class="mono" style="font-size: 11px; color: var(--text-muted);">' + esc(s.id) + '</div></td>' +
            '<td><span class="badge ' + (s.dpop ? "badge-indigo" : "badge-amber") + '">' + esc(s.binding) + '</span></td>' +
            '<td class="mono" style="color: var(--text-secondary);">' + esc(s.ip) + '</td>' +
            '<td style="color: var(--text-secondary);">' + esc(s.expiresIn) + '</td>' +
            '<td><button class="btn btn-sm" data-revoke-session="' + esc(s.id) + '">Sign Out</button></td>' +
          '</tr>'
        )).join("");

        tbody.querySelectorAll("button[data-revoke-session]").forEach((btn) => {
          btn.addEventListener("click", async () => {
            const sid = btn.getAttribute("data-revoke-session");
            const sess = state.sessions.find((x) => x.id === sid);
            if (!sess) return;
            if (state.runtime?.liveConnected) {
              const res = await fetch("/api/sessions/revoke", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ id: sid })
              });
              const data = await res.json();
              if (!res.ok) {
                showToast("Revoke failed: " + (data.error || res.status));
                return;
              }
              state = data.telemetry || state;
              renderAll();
              showToast("Revoked live session " + sid);
              return;
            }
            state.sessions = state.sessions.filter((x) => x.id !== sid);
            state.activeSessions = Math.max(0, state.activeSessions - 1);
            await appendAuditEvent({
              action: "session.revoke",
              label: "Session signed out",
              user: sess.user,
              orgId: sess.orgId,
              ip: sess.ip,
              dpop: sess.dpop,
              targetId: sess.id,
              metadata: { reason: "studio_sign_out", jkt: sess.jkt || undefined }
            });
            renderSessions();
            showToast("Signed out " + sess.user);
          });
        });
      }

      function renderOrgs() {
        const grid = document.getElementById("orgsGrid");
        grid.innerHTML = (state.orgList || []).map((org) => (
          '<div class="sub-card">' +
            '<div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 8px;">' +
              '<div><div style="font-size: 14.5px; font-weight: 600;">' + esc(org.name) + '</div>' +
              '<div class="mono" style="font-size: 11.5px; color: var(--text-muted);">' + esc(org.slug) + '</div></div>' +
              '<span class="badge ' + (org.scim ? "badge-emerald" : "badge-neutral") + '">' + (org.scim ? "Auto-Sync (SCIM)" : "Manual Users") + '</span>' +
            '</div>' +
            '<div style="display: flex; flex-wrap: wrap; gap: 6px;">' +
              '<span class="badge badge-indigo">' + esc(org.sso) + '</span>' +
              '<span class="badge ' + (org.dpopPolicy === "Required" ? "badge-emerald" : "badge-amber") + '">Token Lock: ' + esc(org.dpopPolicy) + '</span>' +
              '<span class="badge badge-neutral">MFA: ' + esc(org.mfaPolicy) + '</span>' +
            '</div>' +
            '<div style="font-size: 12px; color: var(--text-secondary); padding-top: 8px; border-top: 1px solid var(--border-subtle); display: flex; justify-content: space-between;">' +
              '<span>Team Members</span><span style="color: var(--text-primary); font-weight: 600;">' + esc(org.members) + '</span>' +
            '</div>' +
          '</div>'
        )).join("");
      }

      function renderDoctor() {
        document.getElementById("doctorCwd").textContent = state.runtime?.cwd || ".";
        const grid = document.getElementById("doctorGrid");
        grid.innerHTML = (state.securityChecks || []).map((chk) => {
          const badgeCls = chk.status === "pass" ? "badge-emerald" : chk.status === "warn" ? "badge-amber" : "badge-rose";
          const label = chk.status === "pass" ? "Ready" : chk.status === "warn" ? "Action Recommended" : "Needs Fix";
          return '<div class="sub-card">' +
            '<div style="display: flex; justify-content: space-between; align-items: center; gap: 8px;">' +
              '<span style="font-size: 14px; font-weight: 600;">' + esc(chk.name) + '</span>' +
              '<span class="badge ' + badgeCls + '">' + label + '</span>' +
            '</div>' +
            '<div class="mono" style="font-size: 12.5px;">' + esc(chk.detail) + '</div>' +
            '<div style="font-size: 12.5px; color: var(--text-secondary);">' + esc(chk.requirement) + '</div>' +
          '</div>';
        }).join("");
      }

      function renderSwitchGuide() {
        const fromTool = document.getElementById("fromToolSelect").value;
        const fw = document.getElementById("frameworkSelect").value;
        const db = document.getElementById("dbSelect").value;

        const mappings = {
          clerk: [
            { title: "React UI", from: "<ClerkProvider> / <UserButton />", to: "<AuthProvider> / <UserButton /> from devauthkit/react" },
            { title: "Route Protection", from: "clerkMiddleware() / auth()", to: "devAuthKit.requireAuth middleware" },
            { title: "User Data & Cost", from: "Hosted on Clerk ($ MAU fees)", to: "Stored in your own DB ($0 MAU fees)" }
          ],
          nextauth: [
            { title: "Config", from: "NextAuth({ providers })", to: "devAuthKit(app, { jwtSecret, userAdapter })" },
            { title: "Client Hook", from: "useSession()", to: "useAuth() from devauthkit/react" },
            { title: "Enterprise Extras", from: "DIY SAML / Audit / DPoP", to: "Built-in OTP, Passkeys, SSO, & Audit Logs" }
          ],
          auth0: [
            { title: "Login Redirects", from: "Auth0 Universal Login", to: "Drop-in <SignIn /> or /auth/* endpoints" },
            { title: "Enterprise SSO", from: "Paid SAML/SCIM tier", to: "Included self-hosted SAML, OIDC & SCIM 2.0" },
            { title: "API Protection", from: "express-oauth2-jwt-bearer", to: "requireAuth + optional DPoP token lock" }
          ],
          supabase: [
            { title: "Auth Client", from: "supabase.auth.signInWithOtp()", to: "auth.sendOTP() / <SignIn />" },
            { title: "Database", from: "Tied to Supabase Auth schema", to: "Works with Prisma, Drizzle, Mongoose, or D1" },
            { title: "Deployment", from: "Supabase hosted project", to: "Runs on Node.js, Express, or Cloudflare Workers" }
          ],
          custom: [
            { title: "Passwordless + Passkeys", from: "Hand-rolled OTP & JWT code", to: "One-line devAuthKit() setup with rotation" },
            { title: "Token Security", from: "Plain Bearer JWTs", to: "Built-in refresh rotation + DPoP support" },
            { title: "Admin Visibility", from: "Ad-hoc SQL queries", to: "Audit logs, sessions & team controls built in" }
          ]
        };

        document.getElementById("mappingGrid").innerHTML = (mappings[fromTool] || mappings.clerk).map((m) => (
          '<div class="mapping-card">' +
            '<div class="kv-label">' + esc(m.title) + '</div>' +
            '<div style="font-size: 12px; color: var(--text-muted); margin-top: 6px;">Before: <span class="mono">' + esc(m.from) + '</span></div>' +
            '<div style="font-size: 12.5px; color: var(--emerald-text); margin-top: 4px;">After: <span class="mono">' + esc(m.to) + '</span></div>' +
          '</div>'
        )).join("");

        const adapterSetup = {
          prisma: {
            imp: 'const { PrismaClient } = require("@prisma/client");\\nconst prisma = new PrismaClient();',
            opt: "userAdapter: devAuthKit.prismaAdapter(prisma)"
          },
          drizzle: {
            imp: 'const { eq } = require("drizzle-orm");\\nconst { db, users } = require("./db");',
            opt: "userAdapter: devAuthKit.drizzleAdapter(db, { table: users, eq })"
          },
          mongoose: {
            imp: 'const User = require("./models/User"); // your Mongoose model',
            opt: "userAdapter: devAuthKit.mongooseAdapter(User)"
          },
          memory: {
            imp: "// Zero-DB quick test mode (uses built-in memory store)",
            opt: "// Add prismaAdapter / drizzleAdapter / mongooseAdapter anytime"
          }
        }[db];

        let backendCode = "";
        if (fw === "express") {
          backendCode = [
            'const express = require("express");',
            'const devAuthKit = require("devauthkit");',
            adapterSetup.imp,
            "",
            "const app = express();",
            "devAuthKit(app, {",
            "  jwtSecret: process.env.JWT_SECRET,",
            "  sessionSecret: process.env.SESSION_SECRET,",
            "  " + adapterSetup.opt,
            "});",
            "",
            'app.get("/api/me", devAuthKit.requireAuth, (req, res) => {',
            "  res.json({ user: req.user });",
            "});",
            "",
            "app.listen(3000);"
          ].join("\\n");
        } else {
          backendCode = [
            'import { Hono } from "hono";',
            'import { createAuthRouter, requireAuth } from "devauthkit/hono";',
            "",
            "const app = new Hono();",
            'app.route("/auth", createAuthRouter({',
            "  jwtSecret: process.env.JWT_SECRET",
            "}));",
            "",
            'app.get("/api/me", requireAuth(), (c) => {',
            '  return c.json({ user: c.get("user") });',
            "});",
            "",
            "export default app;"
          ].join("\\n");
        }

        const frontendCode = [
          'import { AuthProvider, SignIn, UserButton, useAuth } from "devauthkit/react";',
          "",
          "export default function App() {",
          "  return (",
          "    <AuthProvider>",
          "      <header><UserButton showName /></header>",
          '      <SignIn redirectUrl="/dashboard" showPasskey showSocial />',
          "    </AuthProvider>",
          "  );",
          "}"
        ].join("\\n");

        document.getElementById("backendSnippet").textContent = backendCode;
        document.getElementById("frontendSnippet").textContent = frontendCode;
      }

      async function appendAuditEvent(partial) {
        const ts = Date.now();
        const prevHash = state.auditLedgerHead || "0".repeat(64);
        const evt = {
          id: "aud_" + Math.random().toString(16).slice(2, 10) + "-" + ts.toString(16),
          action: partial.action,
          label: partial.label || partial.action,
          eventType: partial.action,
          user: partial.user,
          actorId: partial.user,
          actorType: "user",
          targetId: partial.targetId || ("ses_" + Math.random().toString(16).slice(2, 10)),
          orgId: partial.orgId || "acme-corp",
          ip: partial.ip || "198.51.100.42",
          ipAddress: partial.ip || "198.51.100.42",
          dpop: partial.dpop !== false,
          time: "just now",
          timestamp: ts,
          metadata: partial.metadata || { alg: "ES256" },
          prevHash
        };
        evt.entryHash = await computeCanonicalHashClient(prevHash, evt);
        state.auditLedgerHead = evt.entryHash;
        state.recentEvents.unshift(evt);
        renderSummary();
        renderLedger();
      }

      async function verifyMerkleChain() {
        const btn = document.getElementById("verifyChainBtn");
        const statusEl = document.getElementById("statIntegrity");
        const banner = document.getElementById("verifyBanner");
        const bannerText = document.getElementById("verifyBannerText");
        const timingEl = document.getElementById("verifyTiming");

        btn.disabled = true;
        statusEl.textContent = "Checking…";
        const started = performance.now();

        if (state.runtime?.liveConnected) {
          try {
            const res = await fetch("/api/verify", { method: "POST" });
            const result = await res.json();
            const elapsed = (performance.now() - started).toFixed(2);
            btn.disabled = false;
            if (res.ok && result.valid) {
              statusEl.textContent = "Verified";
              statusEl.style.color = "var(--emerald-text)";
              banner.classList.add("show");
              bannerText.textContent = result.message || "Live backend SHA-256 audit chain verified.";
              timingEl.textContent = "Server · " + elapsed + " ms";
              showToast("Live audit chain verified");
            } else {
              statusEl.textContent = "Check Failed";
              statusEl.style.color = "var(--rose-text)";
              showToast(result.message || result.error || "Live verification failed");
            }
          } catch (err) {
            btn.disabled = false;
            statusEl.textContent = "Error";
            showToast("Verify request failed: " + err.message);
          }
          return;
        }

        const chronological = [...state.recentEvents].reverse();
        let expectedPrev = "0".repeat(64);
        let allValid = true;

        for (let i = 0; i < chronological.length; i++) {
          const evt = chronological[i];
          const computed = await computeCanonicalHashClient(expectedPrev, evt);
          if (evt.prevHash !== expectedPrev || evt.entryHash !== computed) {
            allValid = false;
            break;
          }
          expectedPrev = computed;
        }

        const elapsed = (performance.now() - started).toFixed(2);
        btn.disabled = false;

        if (allValid) {
          statusEl.textContent = "Verified";
          statusEl.style.color = "var(--emerald-text)";
          banner.classList.add("show");
          bannerText.textContent = "Verified " + chronological.length + " of " + chronological.length + " activity logs — SHA-256 chain is intact.";
          timingEl.textContent = elapsed + " ms";
          showToast("All " + chronological.length + " logs verified");
        } else {
          statusEl.textContent = "Mismatch";
          statusEl.style.color = "var(--rose-text)";
          showToast("Verification failed — log entry modified");
        }
      }

      document.querySelectorAll(".nav-tab").forEach((tab) => {
        tab.addEventListener("click", () => switchTab(tab.getAttribute("data-tab")));
      });
      document.getElementById("jumpSwitchBtn").addEventListener("click", () => switchTab("switch"));
      document.getElementById("toggleConnectBtn").addEventListener("click", () => {
        const p = document.getElementById("connectPanel");
        p.style.display = p.style.display === "none" ? "block" : "none";
      });

      document.getElementById("saveConnectBtn").addEventListener("click", async () => {
        const apiUrl = document.getElementById("liveApiUrlInput").value.trim();
        const token = document.getElementById("liveTokenInput").value.trim();
        if (!apiUrl) {
          showToast("Enter your auth server URL first");
          return;
        }
        try {
          const res = await fetch("/api/connect", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ apiUrl, token })
          });
          state = await res.json();
          renderAll();
          if (state.runtime?.liveConnected) {
            document.getElementById("connectPanel").style.display = "none";
            showToast("Connected to live backend");
          } else {
            showToast("Connection check failed — see banner");
          }
        } catch (err) {
          showToast("Connect failed: " + err.message);
        }
      });

      document.getElementById("disconnectLiveBtn").addEventListener("click", async () => {
        const res = await fetch("/api/connect", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ apiUrl: "", token: "" })
        });
        state = await res.json();
        document.getElementById("liveTokenInput").value = "";
        document.getElementById("connectPanel").style.display = "none";
        renderAll();
        showToast("Switched to Local Preview Mode");
      });

      document.getElementById("ledgerSearch").addEventListener("input", (e) => {
        searchQuery = e.target.value.trim().toLowerCase();
        renderLedger();
      });

      document.querySelectorAll("#ledgerFilters .filter-pill").forEach((pill) => {
        pill.addEventListener("click", () => {
          document.querySelectorAll("#ledgerFilters .filter-pill").forEach((p) => p.classList.remove("active"));
          pill.classList.add("active");
          activeFilter = pill.getAttribute("data-filter");
          renderLedger();
        });
      });

      document.getElementById("closeDrawerBtn").addEventListener("click", () => openInspector(null));
      document.getElementById("copyEventJsonBtn").addEventListener("click", () => {
        const evt = state.recentEvents.find((e) => e.id === selectedEventId);
        if (evt) copyText(JSON.stringify(evt, null, 2), "Copied event JSON");
      });

      document.getElementById("verifyChainBtn").addEventListener("click", verifyMerkleChain);
      document.getElementById("simulateEventBtn").addEventListener("click", async () => {
        const samples = [
          { action: "user.login", label: "Passkey sign-in", user: "elena@initech.org", orgId: "initech-sec", ip: "203.0.113.44", dpop: true, metadata: { method: "passkey", alg: "ES256" } },
          { action: "dpop.proof_verified", label: "Protected API call", user: "ci-runner@acme.com", orgId: "acme-corp", ip: "198.51.100.91", dpop: true, metadata: { htm: "POST", alg: "ES256" } },
          { action: "api_key.issued", label: "API key created", user: "ops@startup.io", orgId: "startup-io", ip: "192.0.2.15", dpop: false, metadata: { scope: "read:audit" } }
        ];
        const pick = samples[state.recentEvents.length % samples.length];
        await appendAuditEvent(pick);
        showToast("Added test event: " + pick.label);
      });

      document.getElementById("refreshBtn").addEventListener("click", async () => {
        try {
          const res = await fetch("/api/stats");
          if (!res.ok) throw new Error("HTTP " + res.status);
          state = await res.json();
          renderAll();
          showToast("Refreshed");
        } catch (err) {
          showToast("Refresh failed: " + err.message);
        }
      });

      ["fromToolSelect", "frameworkSelect", "dbSelect"].forEach((id) => {
        document.getElementById(id).addEventListener("change", renderSwitchGuide);
      });

      document.getElementById("copyBackendBtn").addEventListener("click", () => {
        copyText(document.getElementById("backendSnippet").textContent, "Copied backend code");
      });
      document.getElementById("copyFrontendBtn").addEventListener("click", () => {
        copyText(document.getElementById("frontendSnippet").textContent, "Copied React code");
      });
      document.getElementById("copyCliInitBtn").addEventListener("click", () => {
        copyText("npx devauthkit init", "Copied npx devauthkit init");
      });

      function renderAll() {
        renderSummary();
        renderLedger();
        renderSessions();
        renderOrgs();
        renderDoctor();
        renderSwitchGuide();
      }

      renderAll();
    })();
  </script>
</body>
</html>`;
}

function isLocalSameOriginRequest(req, port) {
  if (req.headers["sec-fetch-site"] === "cross-site") return false;
  const origin = req.headers.origin;
  if (origin) {
    try {
      const parsed = new URL(origin);
      const localHosts = new Set(["localhost", "127.0.0.1", "[::1]"]);
      if (!localHosts.has(parsed.hostname) || (parsed.port && Number(parsed.port) !== Number(port))) {
        return false;
      }
    } catch {
      return false;
    }
  }
  return true;
}

function runStudio(port = 4321, options = {}) {
  const cwd = options.cwd || process.cwd();
  const host = options.host || "127.0.0.1";
  const printBannerFn = options.printBanner;
  const connection = {
    apiUrl: normalizeApiUrl(options.apiUrl || ""),
    token: options.token || ""
  };

  if (typeof printBannerFn === "function") {
    printBannerFn();
  }
  console.log(`\x1b[36m⚡ Starting DevAuthKit Studio at \x1b[1mhttp://localhost:${port}\x1b[0m\x1b[36m...\x1b[0m`);
  if (connection.apiUrl) {
    console.log(`\x1b[32m🔗 Live Backend Target: \x1b[1m${connection.apiUrl}\x1b[0m`);
  }
  console.log();

  async function getCurrentTelemetry() {
    const base = buildInitialTelemetry(cwd, port);
    return connection.apiUrl ? fetchLiveTelemetry(connection, base) : base;
  }

  const server = http.createServer(async (req, res) => {
    try {
      const reqUrl = (req.url || "/").split("?")[0];

      if (reqUrl === "/api/stats" && req.method === "GET") {
        const telemetry = await getCurrentTelemetry();
        res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
        res.end(JSON.stringify(telemetry));
        return;
      }

      if (req.method === "POST" && !isLocalSameOriginRequest(req, port)) {
        res.writeHead(403, { "Content-Type": "application/json; charset=utf-8" });
        res.end(JSON.stringify({ error: "cross_origin_forbidden" }));
        return;
      }

      if (reqUrl === "/api/connect" && req.method === "POST") {
        const body = await readJsonBody(req);
        connection.apiUrl = normalizeApiUrl(body.apiUrl);
        connection.token = typeof body.token === "string" ? body.token.trim() : "";
        const telemetry = await getCurrentTelemetry();
        res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
        res.end(JSON.stringify(telemetry));
        return;
      }

      if (reqUrl === "/api/verify" && req.method === "POST") {
        if (!connection.apiUrl) {
          res.writeHead(400, { "Content-Type": "application/json; charset=utf-8" });
          res.end(JSON.stringify({ valid: false, error: "not_connected" }));
          return;
        }
        const headers = { Accept: "application/json" };
        if (connection.token) headers.Authorization = `Bearer ${connection.token}`;
        const result = await fetchJsonSafe(`${connection.apiUrl}/audit-logs/verify`, {
          method: "POST",
          headers
        });
        res.writeHead(result.ok ? 200 : result.status || 502, { "Content-Type": "application/json; charset=utf-8" });
        res.end(JSON.stringify(result.data || { valid: false, error: result.error || "verify_failed" }));
        return;
      }

      if (reqUrl === "/api/sessions/revoke" && req.method === "POST") {
        if (!connection.apiUrl) {
          res.writeHead(400, { "Content-Type": "application/json; charset=utf-8" });
          res.end(JSON.stringify({ error: "not_connected" }));
          return;
        }
        const body = await readJsonBody(req);
        const sid = encodeURIComponent(String(body.id || ""));
        const headers = { Accept: "application/json" };
        if (connection.token) headers.Authorization = `Bearer ${connection.token}`;
        const result = await fetchJsonSafe(`${connection.apiUrl}/sessions/${sid}`, {
          method: "DELETE",
          headers
        });
        if (!result.ok) {
          res.writeHead(result.status || 502, { "Content-Type": "application/json; charset=utf-8" });
          res.end(JSON.stringify(result.data || { error: result.error || "revoke_failed" }));
          return;
        }
        const telemetry = await getCurrentTelemetry();
        res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
        res.end(JSON.stringify({ success: true, telemetry }));
        return;
      }

      const telemetry = await getCurrentTelemetry();
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(renderStudioHtml(telemetry));
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ error: "studio_internal_error", message: err.message }));
    }
  });

  server.listen(port, host, () => {
    console.log(`\x1b[32m✔ Studio running at: \x1b[1mhttp://${host}:${port}\x1b[0m`);
    console.log("\x1b[2mPress Ctrl+C to stop.\x1b[0m\n");
  });

  return server;
}

module.exports = {
  runStudio,
  buildInitialTelemetry,
  computeCanonicalHash,
  renderStudioHtml,
  fetchLiveTelemetry
};
