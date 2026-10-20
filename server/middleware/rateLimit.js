const crypto = require("crypto");
const config = require("../config");
const MemoryRateLimitStore = require("../stores/memoryRateLimitStore");

const defaultStore = new MemoryRateLimitStore();

function identityHash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function getClientIp(req) {
  return req.ip || req.socket?.remoteAddress || "unknown";
}

function getIdentity(req, type) {
  if (type === "ip") return getClientIp(req);

  const candidate = req.body?.email ?? req.query?.email;
  const email = typeof candidate === "string" ? candidate.trim().toLowerCase() : "";
  if (type === "email" && email) return email;

  const refreshCookieName = `${config.get("cookieName") || "devauth_token"}_refresh`;
  const refreshCookie = req.headers?.cookie
    ?.split(";")
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith(`${refreshCookieName}=`));
  if (type === "session" && refreshCookie) return refreshCookie.slice(refreshCookieName.length + 1);

  return null;
}

function makeRateLimit(name) {
  return async (req, res, next) => {
    const allRules = config.get("rateLimit");
    if (allRules === false) return next();

    const rule = allRules?.[name];
    if (!rule || rule === false) return next();

    const identities = [];
    if (rule.perIp !== false) identities.push(["ip", getIdentity(req, "ip"), rule.perIpMax ?? rule.max]);
    if (rule.perEmail && getIdentity(req, "email")) {
      identities.push(["email", getIdentity(req, "email"), rule.perEmailMax ?? rule.max]);
    }
    if (rule.perSession && getIdentity(req, "session")) {
      identities.push(["session", getIdentity(req, "session"), rule.perSessionMax ?? rule.max]);
    }
    if (identities.length === 0) return next();

    const now = Date.now();
    const bucket = Math.floor(now / rule.windowMs);
    const resetAt = (bucket + 1) * rule.windowMs;
    const store = config.get("rateLimitStore") || defaultStore;

    try {
      const counts = await Promise.all(identities.map(([type, identity]) => {
        const key = `${name}:${type}:${identityHash(identity)}:${bucket}`;
        return store.increment(key, rule.windowMs);
      }));
      if (counts.some((count) => !Number.isSafeInteger(count) || count < 1)) {
        throw new TypeError("Rate-limit store increment must return a positive safe integer");
      }
      const limits = identities.map((identity) => identity[2]);
      const remaining = Math.min(...counts.map((count, index) => Math.max(0, limits[index] - count)));
      const effectiveLimit = Math.min(...limits);
      const retryAfterSeconds = Math.max(1, Math.ceil((resetAt - now) / 1000));

      res.set("RateLimit-Limit", String(effectiveLimit));
      res.set("RateLimit-Remaining", String(remaining));
      res.set("RateLimit-Reset", String(Math.ceil(resetAt / 1000)));

      if (counts.some((count, index) => count > limits[index])) {
        res.set("Retry-After", String(retryAfterSeconds));
        return res.status(429).json({
          error: "Too many requests. Please try again later.",
          retryAfterSeconds
        });
      }
      return next();
    } catch (error) {
      console.error(`[DevAuthKit] Rate-limit store failed for ${name}:`, error);
      return res.status(503).json({ error: "Rate-limit service unavailable" });
    }
  };
}

makeRateLimit.MemoryRateLimitStore = MemoryRateLimitStore;

module.exports = makeRateLimit;
