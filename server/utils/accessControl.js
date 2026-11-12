// server/utils/accessControl.js
const config = require("../config");

function getActorId(user) {
  if (!user) return null;
  if (user.id !== undefined && user.id !== null) return String(user.id);
  return user.email ? String(user.email) : null;
}

function isSystemAdmin(user) {
  if (!user || user.isApiKey) return false;
  return user.role === "admin" || user.role === "superadmin";
}

function getOrgStore() {
  return config.get("organizationStore") || config.get("orgStore") || null;
}

/**
 * Verifies that req.user is either a system admin/superadmin OR an owner/admin
 * of the target orgId (when organizationStore is configured).
 */
async function authorizeOrgAdmin(req, orgId) {
  const user = req.user;
  if (!user) return { allowed: false, status: 401, error: "Unauthorized" };
  if (user.isApiKey) {
    return { allowed: false, status: 403, error: "API keys cannot manage administrative resources" };
  }
  if (isSystemAdmin(user)) {
    return { allowed: true, isSystemAdmin: true };
  }
  if (!orgId) {
    return { allowed: false, status: 403, error: "Forbidden: Administrator privileges required" };
  }
  const orgStore = getOrgStore();
  const actorId = getActorId(user);
  if (!orgStore || !actorId) {
    return { allowed: false, status: 403, error: "Forbidden: Administrator privileges required" };
  }
  const member = await orgStore.getMember(String(orgId), actorId);
  if (!member || (member.role !== "owner" && member.role !== "admin")) {
    return { allowed: false, status: 403, error: "Forbidden: Organization admin or owner privileges required" };
  }
  return { allowed: true, isSystemAdmin: false, member };
}

function isPrivateOrLocalHostname(hostname) {
  const host = String(hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
  if (!host) return true;
  if (
    host === "localhost" ||
    host === "0.0.0.0" ||
    host === "::1" ||
    host === "::" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal")
  ) {
    return true;
  }

  // IPv4 private/loopback/link-local/CGNAT ranges
  const ipv4Match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [, a, b, c, d] = ipv4Match.map(Number);
    if ([a, b, c, d].some((n) => n > 255)) return true;
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }

  // IPv6 ULA / link-local / IPv4-mapped loopback
  if (host.startsWith("fe80:") || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("::ffff:")) {
    return true;
  }

  return false;
}

function validateExternalHttpUrl(rawUrl, { allowPrivate = false } = {}) {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    return { valid: false, error: "A valid http:// or https:// URL is required" };
  }
  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return { valid: false, error: "URL is malformed" };
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    return { valid: false, error: "Only http:// and https:// URLs are supported" };
  }
  if (parsed.username || parsed.password) {
    return { valid: false, error: "URLs must not contain embedded credentials" };
  }
  if (!allowPrivate && isPrivateOrLocalHostname(parsed.hostname)) {
    return { valid: false, error: "Target URL cannot point to localhost or private network addresses" };
  }
  return { valid: true, url: parsed };
}

function getAllowedRedirectOrigins() {
  const origins = new Set();
  const corsOrigin = config.get("corsOrigin");
  const ssoAllowed = config.get("sso")?.allowedRedirectOrigins;
  const appUrl = config.get("appUrl");

  for (const source of [corsOrigin, ssoAllowed, appUrl]) {
    const list = Array.isArray(source) ? source : source ? [source] : [];
    for (const item of list) {
      if (typeof item === "string" && item !== "*") {
        try {
          origins.add(new URL(item).origin);
        } catch {
          // ignore non-URL entries
        }
      }
    }
  }
  return origins;
}

function isAllowedRedirectUrl(rawUrl) {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) return false;
  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return false;
  }
  if (!["http:", "https:"].includes(parsed.protocol)) return false;
  if (parsed.username || parsed.password) return false;
  const allowed = getAllowedRedirectOrigins();
  return allowed.has(parsed.origin);
}

module.exports = {
  getActorId,
  isSystemAdmin,
  authorizeOrgAdmin,
  isPrivateOrLocalHostname,
  validateExternalHttpUrl,
  isAllowedRedirectUrl
};

