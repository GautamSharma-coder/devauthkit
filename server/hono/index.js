const { Hono } = require("hono");
const { deleteCookie, getCookie, setCookie } = require("hono/cookie");
const config = require("../config");
const authController = require("../controllers/authController");
const organizationController = require("../controllers/organizationController");
const webhookController = require("../controllers/webhookController");
const ssoController = require("../controllers/ssoController");
const scimController = require("../controllers/scimController");
const organizationService = require("../core/organizationService");
const ssoService = require("../core/ssoService");
const scimService = require("../core/scimService");
const { MemorySsoStore } = require("../stores/memorySsoStore");
const { CloudflareD1SsoStore } = require("../stores/cloudflareD1SsoStore");
const defaultRefreshTokenStore = require("../stores/defaultRefreshTokenStore");
const { verifyDPoPProof, DPoPError } = require("../core/dpopService");
const MemoryRateLimitStore = require("../stores/memoryRateLimitStore");
const { sha256Hex, signJwt, verifyJwt } = require("../utils/webCrypto");
const validateOAuthProviders = require("../utils/oauthProviderConfig");
const validatePasskeyConfig = require("../utils/passkeyConfig");

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
    org: c.get("org") || c.get("organization"),
    organization: c.get("organization") || c.get("org"),
    orgMember: c.get("orgMember"),
    scimDirectory: c.get("scimDirectory"),
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
    setHeader(name, value) {
      c.header(name, value);
      return this;
    },
    send(body) {
      if (typeof body === "string") {
        return c.body(body, statusCode);
      }
      return c.json(body, statusCode);
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
    let token = null;
    if (authorization) {
      if (authorization.startsWith("Bearer ")) {
        token = authorization.slice(7);
      } else if (authorization.startsWith("DPoP ")) {
        token = authorization.slice(5);
      }
    }
    const cookieName = config.get("cookieName") || "devauth_token";
    token ||= getCookie(c, cookieName);
    if (!token) return c.json({ error: "Unauthorized: No valid session, token, or auth cookie provided" }, 401);

    let user;
    try {
      user = await verifyJwt(token, config.get("jwtSecret"));
    } catch {
      return c.json({ error: `Unauthorized: Invalid or expired ${authorization ? "token" : "cookie token"}` }, 401);
    }

    if (user.cnf?.jkt) {
      const dpopHeader = c.req.header("dpop");
      if (!dpopHeader) {
        c.header("WWW-Authenticate", 'DPoP error="invalid_dpop_proof", error_description="Missing DPoP proof header"');
        return c.json({ error: "Unauthorized: DPoP proof header required for this token" }, 401);
      }

      try {
        const replayStore = config.get("dpopReplayStore");
        if (!replayStore || typeof replayStore.record !== "function") {
          return c.json({
            error: "dpop_replay_store_unavailable",
            message: "DPoP replay protection is not configured"
          }, 503);
        }
        const verification = await verifyDPoPProof({
          proofJwt: dpopHeader,
          expectedMethod: c.req.method,
          expectedUri: c.req.url,
          expectedAccessToken: token,
          expectedNonce: config.get("dpopNonce"),
          replayStore,
          maxClockSkewSeconds: config.get("dpopMaxClockSkewSeconds") || 60
        });

        if (verification.jkt !== user.cnf.jkt) {
          c.header("WWW-Authenticate", 'DPoP error="invalid_dpop_proof", error_description="Thumbprint mismatch"');
          return c.json({ error: "Unauthorized: DPoP key binding mismatch" }, 401);
        }
        c.set("dpop", { jkt: verification.jkt, payload: verification.payload });
      } catch (err) {
        const status = err instanceof DPoPError ? err.status : 401;
        const code = err instanceof DPoPError ? err.code : "invalid_dpop_proof";
        c.header("WWW-Authenticate", `DPoP error="${code}", error_description="${err.message}"`);
        return c.json({ error: code, message: err.message }, status);
      }
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

function requireDPoP() {
  return async (c, next) => {
    const dpopHeader = c.req.header("dpop");
    if (!dpopHeader) {
      c.header("WWW-Authenticate", 'DPoP error="invalid_dpop_proof", error_description="DPoP header is required"');
      return c.json({ error: "invalid_dpop_proof", message: "DPoP header is required for this endpoint" }, 401);
    }
    if (c.get("dpop")) return next();

    try {
      const replayStore = config.get("dpopReplayStore");
      if (!replayStore || typeof replayStore.record !== "function") {
        return c.json({
          error: "dpop_replay_store_unavailable",
          message: "DPoP replay protection is not configured"
        }, 503);
      }
      const authorization = c.req.header("authorization");
      let token = authorization ? authorization.replace(/^(DPoP|Bearer)\s+/i, "") : undefined;
      const verification = await verifyDPoPProof({
        proofJwt: dpopHeader,
        expectedMethod: c.req.method,
        expectedUri: c.req.url,
        expectedAccessToken: token,
        expectedNonce: config.get("dpopNonce"),
        replayStore,
        maxClockSkewSeconds: config.get("dpopMaxClockSkewSeconds") || 60
      });

      const user = c.get("user");
      if (user?.cnf?.jkt && user.cnf.jkt !== verification.jkt) {
        c.header("WWW-Authenticate", 'DPoP error="invalid_dpop_proof", error_description="Key binding mismatch"');
        return c.json({ error: "invalid_dpop_proof", message: "DPoP key binding mismatch" }, 401);
      }
      c.set("dpop", { jkt: verification.jkt, payload: verification.payload });
      await next();
    } catch (err) {
      const status = err instanceof DPoPError ? err.status : 401;
      const code = err instanceof DPoPError ? err.code : "invalid_dpop_proof";
      c.header("WWW-Authenticate", `DPoP error="${code}", error_description="${err.message}"`);
      return c.json({ error: code, message: err.message }, status);
    }
  };
}

function requireOrg() {
  return async (c, next) => {
    if (!c.get("user")) {
      const authMiddleware = requireAuth();
      let authCalled = false;
      const res = await authMiddleware(c, async () => {
        authCalled = true;
      });
      if (res) return res;
      if (!authCalled || !c.get("user")) {
        return c.json({ error: "Unauthorized: Authentication required" }, 401);
      }
    }

    const orgStore = config.get("organizationStore") || config.get("orgStore");
    if (!orgStore) {
      return c.json({ error: "Organizations feature is not configured on this server" }, 500);
    }

    const user = c.get("user");
    const orgId = user?.org_id ||
      c.req.header("x-organization-id") ||
      c.req.header("x-org-id") ||
      c.req.param("orgId") ||
      c.req.param("id");

    if (!orgId || typeof orgId !== "string") {
      return c.json({ error: "Active organization context is required (missing org_id)" }, 400);
    }

    const userId = user.id !== undefined && user.id !== null ? String(user.id) : user.email;
    const member = await orgStore.getMember(orgId, userId);
    if (!member) {
      return c.json({ error: "Forbidden: You are not an active member of this organization" }, 403);
    }

    const organization = await orgStore.getOrgById(orgId);
    if (!organization) {
      return c.json({ error: "Organization not found" }, 404);
    }

    c.set("org", organization);
    c.set("organization", organization);
    c.set("orgMember", member);
    await next();
  };
}

function requireOrgRole(allowedRoles, options = {}) {
  const roles = Array.isArray(allowedRoles)
    ? allowedRoles
    : typeof allowedRoles === "string"
      ? [allowedRoles]
      : [];

  if (roles.length === 0) {
    throw new TypeError("requireOrgRole requires at least one allowed role (string or array of strings)");
  }

  const errorMessage = options.errorMessage || "Forbidden: Insufficient organization permissions";

  return async (c, next) => {
    if (!c.get("organization") || !c.get("orgMember")) {
      const orgMw = requireOrg();
      let orgNextCalled = false;
      const res = await orgMw(c, async () => {
        orgNextCalled = true;
      });
      if (res) return res;
      if (!orgNextCalled) return;
    }

    const currentRole = c.get("orgMember")?.role;
    const hasAccess = currentRole === "owner" || roles.includes(currentRole);
    if (!hasAccess) {
      return c.json({ error: errorMessage }, 403);
    }
    await next();
  };
}

function requireOrgPermission(requiredPermission, options = {}) {
  if (!requiredPermission || typeof requiredPermission !== "string") {
    throw new TypeError("requireOrgPermission requires a permission string (e.g. 'members:invite')");
  }

  const errorMessage = options.errorMessage || `Forbidden: Missing required permission (${requiredPermission})`;

  return async (c, next) => {
    if (!c.get("organization") || !c.get("orgMember")) {
      const orgMw = requireOrg();
      let orgNextCalled = false;
      const res = await orgMw(c, async () => {
        orgNextCalled = true;
      });
      if (res) return res;
      if (!orgNextCalled) return;
    }

    const currentRole = c.get("orgMember")?.role;
    const customRoleMap = config.get("orgRoles");
    const hasAccess = organizationService.hasOrgPermission(currentRole, requiredPermission, customRoleMap);
    if (!hasAccess) {
      return c.json({ error: errorMessage }, 403);
    }
    await next();
  };
}

function createAuthRouter(options = {}) {
  if (!options.jwtSecret || options.jwtSecret === "devAuthJwtSecretKey_change_in_production") {
    throw new TypeError("createAuthRouter requires an explicit jwtSecret");
  }
  const activeConfig = config.set({
    ...options,
    sessionSecret: options.sessionSecret || options.jwtSecret
  });
  const dpopEnabled = activeConfig.dpop && activeConfig.dpop !== "disabled" &&
    activeConfig.dpop?.mode !== "disabled";
  if (dpopEnabled &&
      (!activeConfig.dpopReplayStore || typeof activeConfig.dpopReplayStore.record !== "function")) {
    throw new TypeError("Hono DPoP requires a dpopReplayStore implementing atomic record(jti, ttlSeconds)");
  }
  validateOAuthProviders(activeConfig.oauthProviders);
  validatePasskeyConfig(
    activeConfig.passkeys,
    activeConfig.passkeyStore,
    activeConfig.passkeyChallengeStore
  );
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
      const contentType = c.req.header("content-type") || "";
      if (
        c.req.method !== "GET" &&
        c.req.method !== "HEAD" &&
        c.req.header("content-length") !== "0"
      ) {
        if (contentType.includes("application/json") || contentType.includes("application/scim+json")) {
          try {
            body = await c.req.json();
          } catch {
            return c.json({ error: "Request body must be valid JSON" }, 400);
          }
        } else if (contentType.includes("application/x-www-form-urlencoded")) {
          try {
            const formData = await c.req.parseBody();
            body = { ...formData };
          } catch {
            body = {};
          }
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

  function requireScimBearer() {
    return async (c, next) => {
      const res = createResponse(c);
      const req = createRequest(c, {}, {});
      let authenticated = false;
      const maybeResponse = await scimController.authenticateScimBearer(req, res, () => {
        authenticated = true;
      });
      if (authenticated) {
        c.set("scimDirectory", req.scimDirectory);
        return next();
      }
      return maybeResponse;
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
  if (activeConfig.passkeys) {
    router.post(`${prefix}/passkeys/register/options`, requireAuth(), dispatch(authController.passkeyRegistrationOptions, "passkeyRegisterOptions"));
    router.post(`${prefix}/passkeys/register/verify`, requireAuth(), dispatch(authController.verifyPasskeyRegistration, "passkeyRegisterVerify"));
    router.post(`${prefix}/passkeys/authenticate/options`, dispatch(authController.passkeyAuthenticationOptions, "passkeyAuthenticationOptions"));
    router.post(`${prefix}/passkeys/authenticate/verify`, dispatch(authController.verifyPasskeyAuthentication, "passkeyAuthenticationVerify"));
    router.get(`${prefix}/passkeys`, requireAuth(), dispatch(authController.listPasskeys, "passkeyList"));
    router.delete(`${prefix}/passkeys/:credentialId`, requireAuth(), dispatch(authController.deletePasskey, "passkeyDelete"));
  }
  router.post(`${prefix}/refresh`, dispatch(authController.refreshTokens, "refresh"));
  router.post(`${prefix}/logout`, dispatch(authController.logout, "logout"));
  router.get(`${prefix}/logout`, dispatch(authController.logout, "logout"));
  router.get(`${prefix}/me`, requireAuth(), (c) => c.json({ user: c.get("user") }));
  router.post(`${prefix}/sessions/revoke`, requireAuth(), dispatch(authController.revokeSession, "revokeSession"));
  router.post(`${prefix}/sessions/revoke-all`, requireAuth(), dispatch(authController.revokeAllSessions, "revokeAllSessions"));

  if (activeConfig.organizations) {
    router.post(`${prefix}/orgs`, requireAuth(), dispatch(organizationController.createOrg, "orgCreate"));
    router.get(`${prefix}/orgs`, requireAuth(), dispatch(organizationController.listUserOrgs));
    router.post(`${prefix}/orgs/join`, requireAuth(), dispatch(organizationController.joinOrg, "orgJoin"));
    router.get(`${prefix}/orgs/:id`, requireAuth(), dispatch(organizationController.getOrg));
    router.patch(`${prefix}/orgs/:id`, requireAuth(), dispatch(organizationController.updateOrg));
    router.delete(`${prefix}/orgs/:id`, requireAuth(), dispatch(organizationController.deleteOrg));
    router.post(`${prefix}/orgs/:id/switch`, requireAuth(), dispatch(organizationController.switchOrg, "orgSwitch"));
    router.post(`${prefix}/orgs/:id/invites`, requireAuth(), dispatch(organizationController.inviteMember, "orgInvite"));
    router.post(`${prefix}/orgs/:id/invitations`, requireAuth(), dispatch(organizationController.inviteMember, "orgInvite"));
    router.get(`${prefix}/orgs/:id/invites`, requireAuth(), dispatch(organizationController.listInvitations));
    router.get(`${prefix}/orgs/:id/invitations`, requireAuth(), dispatch(organizationController.listInvitations));
    router.delete(`${prefix}/orgs/:id/invites/:inviteId`, requireAuth(), dispatch(organizationController.revokeInvitation));
    router.delete(`${prefix}/orgs/:id/invitations/:inviteId`, requireAuth(), dispatch(organizationController.revokeInvitation));
    router.patch(`${prefix}/orgs/:id/members/:userId`, requireAuth(), dispatch(organizationController.updateMemberRole));
    router.delete(`${prefix}/orgs/:id/members/:userId`, requireAuth(), dispatch(organizationController.removeMember));
  }

  if (activeConfig.webhooks) {
    router.post(`${prefix}/webhooks`, requireAuth(), dispatch(webhookController.createEndpoint, "webhookCreate"));
    router.get(`${prefix}/webhooks`, requireAuth(), dispatch(webhookController.listEndpoints));
    router.get(`${prefix}/webhooks/:id`, requireAuth(), dispatch(webhookController.getEndpoint));
    router.patch(`${prefix}/webhooks/:id`, requireAuth(), dispatch(webhookController.updateEndpoint));
    router.delete(`${prefix}/webhooks/:id`, requireAuth(), dispatch(webhookController.deleteEndpoint));
    router.get(`${prefix}/webhooks/:id/deliveries`, requireAuth(), dispatch(webhookController.listDeliveries));
    router.post(`${prefix}/webhooks/:id/test`, requireAuth(), dispatch(webhookController.testEndpoint, "webhookTest"));
  }

  if (activeConfig.sso || activeConfig.ssoStore) {
    router.post(`${prefix}/sso/connections`, requireAuth(), dispatch(ssoController.createConnection));
    router.get(`${prefix}/sso/connections`, requireAuth(), dispatch(ssoController.listConnections));
    router.get(`${prefix}/sso/connections/:id`, requireAuth(), dispatch(ssoController.getConnection));
    router.patch(`${prefix}/sso/connections/:id`, requireAuth(), dispatch(ssoController.updateConnection));
    router.delete(`${prefix}/sso/connections/:id`, requireAuth(), dispatch(ssoController.deleteConnection));
    router.post(`${prefix}/sso/connections/:id/verify-domain`, requireAuth(), dispatch(ssoController.verifyDomain));

    router.post(`${prefix}/sso/resolve`, dispatch(ssoController.resolveSso));
    router.get(`${prefix}/sso/resolve`, dispatch(ssoController.resolveSso));
    router.get(`${prefix}/sso/saml/:connectionId/metadata.xml`, dispatch(ssoController.getSpMetadata));
    router.get(`${prefix}/sso/saml/metadata.xml`, dispatch(ssoController.getSpMetadata));
    router.post(`${prefix}/sso/saml/:connectionId/acs`, dispatch(ssoController.handleSamlAcs));
    router.post(`${prefix}/sso/saml/acs`, dispatch(ssoController.handleSamlAcs));
  }

  if (activeConfig.scim || activeConfig.ssoStore) {
    router.post(`${prefix}/scim/directories`, requireAuth(), dispatch(scimController.createDirectory));
    router.get(`${prefix}/scim/directories`, requireAuth(), dispatch(scimController.listDirectories));
    router.get(`${prefix}/scim/directories/:id`, requireAuth(), dispatch(scimController.getDirectory));
    router.post(`${prefix}/scim/directories/:id/rotate-token`, requireAuth(), dispatch(scimController.rotateToken));
    router.delete(`${prefix}/scim/directories/:id`, requireAuth(), dispatch(scimController.deleteDirectory));

    // SCIM 2.0 Protocol Endpoints (RFC 7643 & 7644)
    for (const scimBase of [`${prefix}/scim/v2`, "/scim/v2"]) {
      router.get(`${scimBase}/ServiceProviderConfig`, dispatch(scimController.getServiceProviderConfig));
      router.get(`${scimBase}/Schemas`, dispatch(scimController.getSchemas));
      router.get(`${scimBase}/Users`, requireScimBearer(), dispatch(scimController.listUsers));
      router.get(`${scimBase}/Users/:id`, requireScimBearer(), dispatch(scimController.getUser));
      router.post(`${scimBase}/Users`, requireScimBearer(), dispatch(scimController.createUser));
      router.patch(`${scimBase}/Users/:id`, requireScimBearer(), dispatch(scimController.patchUser));
      router.put(`${scimBase}/Users/:id`, requireScimBearer(), dispatch(scimController.patchUser));
      router.delete(`${scimBase}/Users/:id`, requireScimBearer(), dispatch(scimController.deleteUser));
      router.get(`${scimBase}/Groups`, requireScimBearer(), dispatch(scimController.listGroups));
      router.get(`${scimBase}/Groups/:id`, requireScimBearer(), dispatch(scimController.getGroup));
      router.post(`${scimBase}/Groups`, requireScimBearer(), dispatch(scimController.createGroup));
      router.patch(`${scimBase}/Groups/:id`, requireScimBearer(), dispatch(scimController.patchGroup));
      router.put(`${scimBase}/Groups/:id`, requireScimBearer(), dispatch(scimController.patchGroup));
    }
  }

  return router;
}

module.exports = {
  createAuthRouter,
  requireAuth,
  requireDPoP,
  requireOrg,
  requireOrgRole,
  requireOrgPermission,
  MemorySsoStore,
  CloudflareD1SsoStore,
  sso: ssoService,
  scim: scimService
};
