const { Hono } = require("hono");
const { deleteCookie, getCookie, setCookie } = require("hono/cookie");
const config = require("../config");
const authController = require("../controllers/authController");
const defaultRefreshTokenStore = require("../stores/defaultRefreshTokenStore");
const MemoryRateLimitStore = require("../stores/memoryRateLimitStore");
const { sha256Hex, signJwt, verifyJwt } = require("../utils/webCrypto");
const validateOAuthProviders = require("../utils/oauthProviderConfig");

const rateLimitStore = new MemoryRateLimitStore();
const OAUTH_SESSION_COOKIE = "devauthkit_oauth_state";
const OAUTH_SESSION_TTL_SECONDS = 10 * 60;

function cookieOptions(options = {}) {
  return {
    httpOnly: options.httpOnly !== false,
    secure: options.secure ?? true,
    sameSite: options.sameSite === "strict" ? "Strict" : "Lax",
    path: options.path || "/",
    ...(options.maxAge !== undefined ? { maxAge: Math.max(0, Math.floor(options.maxAge / 1000)) } : {})
  };
}

function createRequest(c, body, session) {
  const url = new URL(c.req.url);
  return {
    body,
    method: c.req.method,
    query: Object.fromEntries(url.searchParams.entries()),
    headers: Object.fromEntries(c.req.raw.headers.entries()),
    cookies: c.req.header("cookie") ? { [OAUTH_SESSION_COOKIE]: getCookie(c, OAUTH_SESSION_COOKIE) } : {},
    protocol: url.protocol.slice(0, -1),
    ip: c.req.header("cf-connecting-ip") || "unknown",
    session,
    params: c.req.param(),
    user: c.get("user"),
    get(name) {
      return c.req.header(name);
    }
  };
}

function createResponse(c) {
  let statusCode = 200;
  return {
    status(code) {
      statusCode = code;
      return this;
    },
    set(name, value) {
      c.header(name, value);
      return this;
    },
    cookie(name, value, options = {}) {
      setCookie(c, name, value, cookieOptions({ ...options, secure: true }));
      return this;
    },
    clearCookie(name, options = {}) {
      deleteCookie(c, name, cookieOptions(options));
      return this;
    },
    json(value) {
      return c.json(value, statusCode);
    },
    redirect(location) {
      return c.redirect(location, statusCode === 200 ? 302 : statusCode);
    }
  };
}

function createSession(c, res) {
  let state = {};
  const signedState = getCookie(c, OAUTH_SESSION_COOKIE);

  const session = new Proxy({
    async load() {
      if (!signedState) return;
      try {
        const payload = await verifyJwt(signedState, config.get("sessionSecret"));
        for (const key of ["oauthFlows", "googleOAuth", "githubOAuth"]) {
          if (payload[key] !== undefined) state[key] = payload[key];
        }
      } catch {
        deleteCookie(c, OAUTH_SESSION_COOKIE, cookieOptions({ path: config.get("apiPrefix") || "/auth" }));
      }
    },
    save(callback) {
      const oauthData = {};
      if (state.oauthFlows && Object.keys(state.oauthFlows).length > 0) {
        oauthData.oauthFlows = state.oauthFlows;
      }
      if (state.googleOAuth) oauthData.googleOAuth = state.googleOAuth;
      if (state.githubOAuth) oauthData.githubOAuth = state.githubOAuth;
      if (Object.keys(oauthData).length === 0) {
        res.clearCookie(OAUTH_SESSION_COOKIE, { path: config.get("apiPrefix") || "/auth" });
        callback?.();
        return;
      }
      signJwt(oauthData, config.get("sessionSecret"), `${OAUTH_SESSION_TTL_SECONDS}s`)
        .then((token) => {
          res.cookie(OAUTH_SESSION_COOKIE, token, {
            httpOnly: true,
            secure: true,
            sameSite: "lax",
            path: config.get("apiPrefix") || "/auth",
            maxAge: OAUTH_SESSION_TTL_SECONDS * 1000
          });
          callback?.();
        })
        .catch((error) => callback?.(error));
    },
    regenerate(callback) {
      state = {};
      callback?.();
    },
    destroy(callback) {
      state = {};
      res.clearCookie(OAUTH_SESSION_COOKIE, { path: config.get("apiPrefix") || "/auth" });
      callback?.();
    }
  }, {
    get(target, property, receiver) {
      return Reflect.has(target, property) ? Reflect.get(target, property, receiver) : state[property];
    },
    set(target, property, value) {
      if (Reflect.has(target, property)) return Reflect.set(target, property, value);
      state[property] = value;
      return true;
    },
    deleteProperty(target, property) {
      return delete state[property];
    }
  });
  return { session, load: () => session.load() };
}

function makeRateLimit(name) {
  return async (c, req) => {
    const allRules = config.get("rateLimit");
    const rule = allRules === false ? false : allRules?.[name];
    if (!rule || rule === false) return null;

    const identities = [];
    if (rule.perIp !== false) identities.push(["ip", req.ip, rule.perIpMax ?? rule.max]);
    const email = req.body?.email ?? req.query?.email;
    if (rule.perEmail && typeof email === "string" && email.trim()) {
      identities.push(["email", email.trim().toLowerCase(), rule.perEmailMax ?? rule.max]);
    }
    if (rule.perSession) {
      const refreshCookieName = `${config.get("cookieName") || "devauth_token"}_refresh`;
      const cookie = getCookie(c, refreshCookieName);
      if (cookie) identities.push(["session", cookie, rule.perSessionMax ?? rule.max]);
    }
    if (identities.length === 0) return null;

    const now = Date.now();
    const bucket = Math.floor(now / rule.windowMs);
    const resetAt = (bucket + 1) * rule.windowMs;
    const store = config.get("rateLimitStore") || rateLimitStore;
    try {
      const counts = await Promise.all(identities.map(async ([type, identity]) => {
        const key = `${name}:${type}:${await sha256Hex(identity)}:${bucket}`;
        return store.increment(key, rule.windowMs);
      }));
      if (counts.some((count) => !Number.isSafeInteger(count) || count < 1)) {
        throw new TypeError("Rate-limit store increment must return a positive safe integer");
      }

      const limits = identities.map((identity) => identity[2]);
      const remaining = Math.min(...counts.map((count, index) => Math.max(0, limits[index] - count)));
      const retryAfterSeconds = Math.max(1, Math.ceil((resetAt - now) / 1000));
      c.header("RateLimit-Limit", String(Math.min(...limits)));
      c.header("RateLimit-Remaining", String(remaining));
      c.header("RateLimit-Reset", String(Math.ceil(resetAt / 1000)));

      if (counts.some((count, index) => count > limits[index])) {
        c.header("Retry-After", String(retryAfterSeconds));
        return c.json({ error: "Too many requests. Please try again later.", retryAfterSeconds }, 429);
      }
      return null;
    } catch (error) {
      console.error(`[DevAuthKit] Rate-limit store failed for ${name}:`, error);
      return c.json({ error: "Rate-limit service unavailable" }, 503);
    }
  };
}

function requireAuth() {
  return async (c, next) => {
    const authorization = c.req.header("authorization");
    let token = authorization?.startsWith("Bearer ") ? authorization.slice(7) : null;
    const cookieName = config.get("cookieName") || "devauth_token";
    token ||= getCookie(c, cookieName);
    if (!token) return c.json({ error: "Unauthorized: No valid session, token, or auth cookie provided" }, 401);

    let user;
    try {
      user = await verifyJwt(token, config.get("jwtSecret"));
    } catch {
      return c.json({ error: `Unauthorized: Invalid or expired ${authorization ? "token" : "cookie token"}` }, 401);
    }

    if (user.sid && config.get("refreshTokens")) {
      try {
        const store = config.get("refreshTokenStore") || defaultRefreshTokenStore;
        if (!(await store.isFamilyActive(user.sid))) {
          return c.json({ error: "Unauthorized: Session has been revoked" }, 401);
        }
      } catch (error) {
        console.error("[DevAuthKit] Failed to validate refresh session:", error);
        return c.json({ error: "Authentication service unavailable" }, 503);
      }
    }
    c.set("user", user);
    await next();
  };
}

function createAuthRouter(options = {}) {
  const activeConfig = config.set({
    ...options,
    sessionSecret: options.sessionSecret || options.jwtSecret
  });
  validateOAuthProviders(activeConfig.oauthProviders);
  const oauthEnabled = Boolean(
    activeConfig.google ||
    activeConfig.github ||
    Object.keys(activeConfig.oauthProviders || {}).length
  );
  if (oauthEnabled && !activeConfig.oauthStateStore) {
    throw new TypeError("Hono OAuth requires an atomic oauthStateStore");
  }
  if (activeConfig.oauthStateStore && !["put", "consume"].every(
    (method) => typeof activeConfig.oauthStateStore[method] === "function"
  )) {
    throw new TypeError("oauthStateStore must implement put(state, expiresAt) and atomic consume(state)");
  }
  if (!activeConfig.jwtSecret || activeConfig.jwtSecret === "devAuthJwtSecretKey_change_in_production") {
    throw new TypeError("createAuthRouter requires an explicit jwtSecret");
  }
  if (activeConfig.devMode === false && typeof activeConfig.mailer !== "function" &&
      !(activeConfig.emailProvider === "resend" && activeConfig.resendApiKey)) {
    throw new TypeError("Hono requires a custom Worker-compatible mailer or Resend when devMode is false");
  }
  if (activeConfig.otpStore && !["get", "set", "delete", "recordAttempt"].every(
    (method) => typeof activeConfig.otpStore[method] === "function"
  )) {
    throw new TypeError("otpStore must implement get, set, delete, and recordAttempt methods");
  }
  if (activeConfig.devMode === false && !activeConfig.otpStore) {
    throw new TypeError("Hono production configuration requires a persistent otpStore");
  }
  if (activeConfig.userAdapter && typeof activeConfig.userAdapter.findOrCreateUser !== "function") {
    throw new TypeError("userAdapter must implement a findOrCreateUser method");
  }
  if (activeConfig.userAdapter && ["findUserByOAuthIdentity", "linkOAuthIdentity"].some(
    (method) => activeConfig.userAdapter[method] !== undefined &&
      typeof activeConfig.userAdapter[method] !== "function"
  )) {
    throw new TypeError("OAuth userAdapter identity methods must be functions when provided");
  }
  if (activeConfig.refreshTokens && activeConfig.setHttpOnlyCookie === false) {
    throw new TypeError("refreshTokens requires setHttpOnlyCookie to remain enabled");
  }
  if (activeConfig.refreshTokens && !activeConfig.refreshTokenStore) {
    throw new TypeError("Hono refreshTokens requires an explicit persistent refreshTokenStore");
  }
  if (activeConfig.refreshTokenStore && ![
    "create", "rotate", "revoke", "revokeFamily", "revokeAll", "isFamilyActive"
  ].every((method) => typeof activeConfig.refreshTokenStore[method] === "function")) {
    throw new TypeError("refreshTokenStore must implement create, rotate, revoke, revokeAll, and isFamilyActive");
  }
  if (activeConfig.rateLimitStore && typeof activeConfig.rateLimitStore.increment !== "function") {
    throw new TypeError("rateLimitStore must implement increment(key, windowMs)");
  }
  if (activeConfig.magicLinkStore && !["get", "set", "delete"].every(
    (method) => typeof activeConfig.magicLinkStore[method] === "function"
  )) {
    throw new TypeError("magicLinkStore must implement get, set, and delete");
  }
  if (activeConfig.magicLink && !activeConfig.magicLinkStore) {
    throw new TypeError("Hono magicLink requires an explicit persistent magicLinkStore");
  }

  const router = new Hono();
  const prefix = activeConfig.apiPrefix || "/auth";

  function dispatch(controller, rateRule) {
    return async (c) => {
      let body = {};
      if (
        c.req.method !== "GET" &&
        c.req.method !== "HEAD" &&
        c.req.header("content-length") !== "0" &&
        c.req.header("content-type")?.includes("application/json")
      ) {
        try {
          body = await c.req.json();
        } catch {
          return c.json({ error: "Request body must be valid JSON" }, 400);
        }
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return c.json({ error: "Request body must be a JSON object" }, 400);
      }
      if (controller === authController.requestOTP && body.magicLink && !config.get("magicLinkStore")) {
        return c.json({ error: "Magic-link authentication requires a persistent magicLinkStore" }, 503);
      }

      const res = createResponse(c);
      const sessionContext = createSession(c, res);
      await sessionContext.load();
      const req = createRequest(c, body, sessionContext.session);
      if (rateRule) {
        const limited = await makeRateLimit(rateRule)(c, req);
        if (limited) return limited;
      }
      return controller(req, res);
    };
  }

  router.post(`${prefix}/request-otp`, dispatch(authController.requestOTP, "requestOtp"));
  router.post(`${prefix}/verify-otp`, dispatch(authController.verifyOTP, "verifyOtp"));
  router.post(`${prefix}/verify-magic`, dispatch(authController.verifyMagicLink, "verifyMagicLink"));
  router.get(`${prefix}/verify-magic`, dispatch(authController.verifyMagicLink, "verifyMagicLink"));
  router.get(`${prefix}/github`, dispatch(authController.startGitHubOAuth, "githubStart"));
  router.get(`${prefix}/github/callback`, dispatch(authController.githubOAuthCallback, "githubCallback"));
  router.get(`${prefix}/google`, dispatch(authController.startGoogleOAuth, "googleStart"));
  router.get(`${prefix}/google/callback`, dispatch(authController.googleOAuthCallback, "googleCallback"));
  router.get(`${prefix}/oauth/:provider`, dispatch(authController.startOAuth, "oauthStart"));
  router.get(`${prefix}/oauth/:provider/callback`, dispatch(authController.oauthCallback, "oauthCallback"));
  router.post(`${prefix}/oauth/:provider/link`, requireAuth(), dispatch(authController.linkOAuth, "oauthLink"));
  router.post(`${prefix}/refresh`, dispatch(authController.refreshTokens, "refresh"));
  router.post(`${prefix}/logout`, dispatch(authController.logout, "logout"));
  router.get(`${prefix}/logout`, dispatch(authController.logout, "logout"));
  router.get(`${prefix}/me`, requireAuth(), (c) => c.json({ user: c.get("user") }));
  router.post(`${prefix}/sessions/revoke`, requireAuth(), dispatch(authController.revokeSession, "revokeSession"));
  router.post(`${prefix}/sessions/revoke-all`, requireAuth(), dispatch(authController.revokeAllSessions, "revokeAllSessions"));

  return router;
}

module.exports = { createAuthRouter, requireAuth };
