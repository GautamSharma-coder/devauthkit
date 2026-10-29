// server/server.js
const express = require("express");
const session = require("express-session");
const dotenv = require("dotenv");
const cors = require("cors");

const config = require("./config");
const authRoutes = require("./routes/authRoutes");
const requireAuth = require("./middleware/requireAuth");
const requireMfa = require("./middleware/requireMfa");
const requireRole = require("./middleware/requireRole");
const RedisOtpStore = require("./stores/redisOtpStore");
const prismaAdapter = require("./adapters/prisma");
const drizzleAdapter = require("./adapters/drizzle");
const mongooseAdapter = require("./adapters/mongoose");
const MemoryRefreshTokenStore = require("./stores/memoryRefreshTokenStore");
const { RedisRefreshTokenStore } = require("./stores/redisRefreshTokenStore");
const RedisRateLimitStore = require("./stores/redisRateLimitStore");
const { RedisDpopReplayStore } = require("./stores/redisDpopReplayStore");
const MemoryRateLimitStore = require("./stores/memoryRateLimitStore");
const sendSMTPOTP = require("./utils/smtpMailer");
const validateOAuthProviders = require("./utils/oauthProviderConfig");
const validatePasskeyConfig = require("./utils/passkeyConfig");
const checkConfig = require("./utils/configDoctor");
const { MemoryMfaStore } = require("./stores/memoryMfaStore");
const { randomString } = require("./utils/webCrypto");

dotenv.config();

function devAuthKit(app, options = {}) {
  const activeConfig = config.set({
    ...options,
    smtpMailer: options.smtpMailer || sendSMTPOTP,
    smtpMailerAvailable: options.smtpMailer ? true : sendSMTPOTP.isConfigured()
  });
  const dpopEnabled = activeConfig.dpop && activeConfig.dpop !== "disabled" &&
    activeConfig.dpop?.mode !== "disabled";
  if (dpopEnabled &&
      (!activeConfig.dpopReplayStore || typeof activeConfig.dpopReplayStore.record !== "function")) {
    throw new TypeError("DPoP requires a dpopReplayStore implementing atomic record(jti, ttlSeconds)");
  }
  const jwtSecret = options.jwtSecret || process.env.JWT_SECRET ||
    options.sessionSecret || process.env.SESSION_SECRET;
  const sessionSecret = options.sessionSecret || process.env.SESSION_SECRET;
  const isProduction = process.env.NODE_ENV === "production";
  const hasStrongSecret = (secret) => typeof secret === "string" &&
    Buffer.byteLength(secret, "utf8") >= 32;
  if (
    activeConfig.jwtSecret === "devAuthJwtSecretKey_change_in_production" ||
    activeConfig.sessionSecret === "devAuthSecret"
  ) {
    throw new TypeError("Public development secrets are not allowed");
  }
  if (isProduction && (!hasStrongSecret(jwtSecret) || !hasStrongSecret(sessionSecret))) {
    throw new TypeError("Production requires explicit JWT and session secrets of at least 32 bytes");
  }
  if (!activeConfig.jwtSecret) activeConfig.jwtSecret = randomString(32, "hex");
  validateOAuthProviders(activeConfig.oauthProviders);
  validatePasskeyConfig(
    activeConfig.passkeys,
    activeConfig.passkeyStore,
    activeConfig.passkeyChallengeStore
  );
  if (activeConfig.mfaStore && ![
    "get",
    "setPending",
    "activate",
    "consumeTotpCounter",
    "consumeRecoveryCode",
    "disable"
  ].every((method) => typeof activeConfig.mfaStore[method] === "function")) {
    throw new TypeError("mfaStore must implement get, setPending, activate, consumeTotpCounter, consumeRecoveryCode, and disable");
  }
  if (typeof activeConfig.mfaIssuer !== "string" || !activeConfig.mfaIssuer.trim()) {
    throw new TypeError("mfaIssuer must be a non-empty string");
  }
  if (!Number.isSafeInteger(activeConfig.mfaStepUpExpiresInSeconds) ||
      activeConfig.mfaStepUpExpiresInSeconds < 30 ||
      activeConfig.mfaStepUpExpiresInSeconds > 3600) {
    throw new TypeError("mfaStepUpExpiresInSeconds must be an integer from 30 through 3600");
  }
  if (activeConfig.otpStore && !["get", "set", "delete", "recordAttempt"].every(
    (method) => typeof activeConfig.otpStore[method] === "function"
  )) {
    throw new TypeError("otpStore must implement get, set, delete, and recordAttempt methods");
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
  if (activeConfig.oauthStateStore && !["put", "consume"].every(
    (method) => typeof activeConfig.oauthStateStore[method] === "function"
  )) {
    throw new TypeError("oauthStateStore must implement put(state, expiresAt) and atomic consume(state)");
  }
  if (activeConfig.mapUserPayload !== undefined && typeof activeConfig.mapUserPayload !== "function") {
    throw new TypeError("mapUserPayload must be a function");
  }
  if (activeConfig.refreshTokens && activeConfig.setHttpOnlyCookie === false) {
    throw new TypeError("refreshTokens requires setHttpOnlyCookie to remain enabled");
  }
  if (activeConfig.refreshTokens && typeof activeConfig.refreshTokens === "object") {
    const days = activeConfig.refreshTokens.refreshTokenExpiresInDays ?? 30;
    const accessTokenExpiresIn = activeConfig.refreshTokens.accessTokenExpiresIn;
    if (!Number.isFinite(days) || days <= 0) {
      throw new TypeError("refreshTokens.refreshTokenExpiresInDays must be a positive number");
    }
    if (accessTokenExpiresIn !== undefined && (typeof accessTokenExpiresIn !== "string" || !accessTokenExpiresIn.trim())) {
      throw new TypeError("refreshTokens.accessTokenExpiresIn must be a non-empty duration string");
    }
  }
  if (activeConfig.refreshTokenStore && ![
    "create",
    "rotate",
    "revoke",
    "revokeFamily",
    "revokeAll",
    "isFamilyActive"
  ].every((method) => typeof activeConfig.refreshTokenStore[method] === "function")) {
    throw new TypeError("refreshTokenStore must implement create, rotate, revoke, revokeFamily, revokeAll, and isFamilyActive");
  }
  if (activeConfig.rateLimitStore && typeof activeConfig.rateLimitStore.increment !== "function") {
    throw new TypeError("rateLimitStore must implement increment(key, windowMs)");
  }
  if (activeConfig.rateLimit !== false) {
    if (!activeConfig.rateLimit || typeof activeConfig.rateLimit !== "object" || Array.isArray(activeConfig.rateLimit)) {
      throw new TypeError("rateLimit must be false or an object of route rules");
    }
    for (const [name, rule] of Object.entries(activeConfig.rateLimit)) {
      if (rule === false) continue;
      if (!rule || typeof rule !== "object" || Array.isArray(rule)) {
        throw new TypeError(`rateLimit.${name} must be false or a rule object`);
      }
      if (!Number.isInteger(rule.windowMs) || rule.windowMs <= 0) {
        throw new TypeError(`rateLimit.${name}.windowMs must be a positive integer`);
      }
      if (!Number.isInteger(rule.max) || rule.max <= 0) {
        throw new TypeError(`rateLimit.${name}.max must be a positive integer`);
      }
      for (const dimension of ["perIp", "perEmail", "perSession"]) {
        if (rule[dimension] !== undefined && typeof rule[dimension] !== "boolean") {
          throw new TypeError(`rateLimit.${name}.${dimension} must be a boolean`);
        }
      }
      for (const dimension of ["perIpMax", "perEmailMax", "perSessionMax"]) {
        if (rule[dimension] !== undefined && (!Number.isInteger(rule[dimension]) || rule[dimension] <= 0)) {
          throw new TypeError(`rateLimit.${name}.${dimension} must be a positive integer`);
        }
      }
    }
  }
  if (activeConfig.google) {
    const { clientId, clientSecret, callbackURL } = activeConfig.google;
    let callback;
    try {
      callback = new URL(callbackURL);
    } catch {
      throw new TypeError("google.callbackURL must be an absolute HTTP or HTTPS URL");
    }
    const localHost = ["localhost", "127.0.0.1", "::1"].includes(callback.hostname);
    if (
      typeof clientId !== "string" || !clientId.trim() ||
      typeof clientSecret !== "string" || !clientSecret.trim() ||
      !["https:", "http:"].includes(callback.protocol) ||
      (callback.protocol !== "https:" && !localHost) ||
      callback.hash
    ) {
      throw new TypeError("google requires clientId, clientSecret, and a valid HTTPS callbackURL (HTTP is allowed on localhost)");
    }
    if (activeConfig.google.successRedirectURL !== undefined) {
      let successRedirect;
      try {
        successRedirect = new URL(activeConfig.google.successRedirectURL);
      } catch {
        throw new TypeError("google.successRedirectURL must be an absolute HTTP or HTTPS URL");
      }
      const localSuccessHost = ["localhost", "127.0.0.1", "::1"].includes(successRedirect.hostname);
      if (
        !["https:", "http:"].includes(successRedirect.protocol) ||
        (successRedirect.protocol !== "https:" && !localSuccessHost) ||
        successRedirect.hash
      ) {
        throw new TypeError("google.successRedirectURL must use HTTPS (HTTP is allowed on localhost)");
      }
    }
  }

  if (activeConfig.github) {
    const { clientId, clientSecret, callbackURL } = activeConfig.github;
    let callback;
    try {
      callback = new URL(callbackURL);
    } catch {
      throw new TypeError("github.callbackURL must be an absolute HTTP or HTTPS URL");
    }
    const localHost = ["localhost", "127.0.0.1", "::1"].includes(callback.hostname);
    if (
      typeof clientId !== "string" || !clientId.trim() ||
      typeof clientSecret !== "string" || !clientSecret.trim() ||
      !["https:", "http:"].includes(callback.protocol) ||
      (callback.protocol !== "https:" && !localHost) ||
      callback.hash
    ) {
      throw new TypeError("github requires clientId, clientSecret, and a valid HTTPS callbackURL (HTTP is allowed on localhost)");
    }
    if (activeConfig.github.successRedirectURL !== undefined) {
      let successRedirect;
      try {
        successRedirect = new URL(activeConfig.github.successRedirectURL);
      } catch {
        throw new TypeError("github.successRedirectURL must be an absolute HTTP or HTTPS URL");
      }
      const localSuccessHost = ["localhost", "127.0.0.1", "::1"].includes(successRedirect.hostname);
      if (
        !["https:", "http:"].includes(successRedirect.protocol) ||
        (successRedirect.protocol !== "https:" && !localSuccessHost) ||
        successRedirect.hash
      ) {
        throw new TypeError("github.successRedirectURL must use HTTPS (HTTP is allowed on localhost)");
      }
    }
  }

  if (activeConfig.magicLinkSuccessURL !== undefined) {
    let magicSuccess;
    try {
      magicSuccess = new URL(activeConfig.magicLinkSuccessURL);
    } catch {
      throw new TypeError("magicLinkSuccessURL must be an absolute HTTP or HTTPS URL");
    }
    const localMagicHost = ["localhost", "127.0.0.1", "::1"].includes(magicSuccess.hostname);
    if (
      !["https:", "http:"].includes(magicSuccess.protocol) ||
      (magicSuccess.protocol !== "https:" && !localMagicHost) ||
      magicSuccess.hash
    ) {
      throw new TypeError("magicLinkSuccessURL must use HTTPS (HTTP is allowed on localhost)");
    }
  }

  if (activeConfig.webhookStore && !["createEndpoint", "getEndpoint", "listEndpoints", "updateEndpoint", "deleteEndpoint", "recordDelivery", "listDeliveries"].every(
    (method) => typeof activeConfig.webhookStore[method] === "function"
  )) {
    throw new TypeError("webhookStore must implement createEndpoint, getEndpoint, listEndpoints, updateEndpoint, deleteEndpoint, recordDelivery, and listDeliveries");
  }

  if (activeConfig.ssoStore && !["createConnection", "getConnection", "listConnections", "getConnectionByDomain", "updateConnection", "deleteConnection"].every(
    (method) => typeof activeConfig.ssoStore[method] === "function"
  )) {
    throw new TypeError("ssoStore must implement createConnection, getConnection, listConnections, getConnectionByDomain, updateConnection, and deleteConnection");
  }

  // Setup CORS
  app.use(cors({
    origin: activeConfig.corsOrigin,
    credentials: true
  }));

  // Setup body parsers
  app.use(express.json({ type: ["application/json", "application/scim+json", "*/*+json"] }));
  app.use(express.urlencoded({ extended: true }));

  // Setup session
  app.use(session({
    secret: activeConfig.sessionSecret,
    resave: false,
    saveUninitialized: false,
    ...(activeConfig.sessionStore ? { store: activeConfig.sessionStore } : {}),
    cookie: { 
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    },
  }));

  // Mount Auth Routes (default: /auth)
  const prefix = activeConfig.apiPrefix || "/auth";
  app.use(prefix, authRoutes);

  // If SCIM is enabled, also mount /scim/v2 directly at root level
  const scimController = require("./controllers/scimController");
  if (activeConfig.scim || activeConfig.ssoStore) {
    app.get("/scim/v2/ServiceProviderConfig", scimController.getServiceProviderConfig);
    app.get("/scim/v2/Schemas", scimController.getSchemas);
    app.get("/scim/v2/Users", scimController.authenticateScimBearer, scimController.listUsers);
    app.get("/scim/v2/Users/:id", scimController.authenticateScimBearer, scimController.getUser);
    app.post("/scim/v2/Users", scimController.authenticateScimBearer, scimController.createUser);
    app.patch("/scim/v2/Users/:id", scimController.authenticateScimBearer, scimController.patchUser);
    app.put("/scim/v2/Users/:id", scimController.authenticateScimBearer, scimController.patchUser);
    app.delete("/scim/v2/Users/:id", scimController.authenticateScimBearer, scimController.deleteUser);
    app.get("/scim/v2/Groups", scimController.authenticateScimBearer, scimController.listGroups);
    app.get("/scim/v2/Groups/:id", scimController.authenticateScimBearer, scimController.getGroup);
    app.post("/scim/v2/Groups", scimController.authenticateScimBearer, scimController.createGroup);
    app.patch("/scim/v2/Groups/:id", scimController.authenticateScimBearer, scimController.patchGroup);
    app.put("/scim/v2/Groups/:id", scimController.authenticateScimBearer, scimController.patchGroup);
  }

  // Optional root-level protected test route
  app.get("/profile", requireAuth, (req, res) => {
    res.json({ 
      message: `Welcome, ${req.user.email}! Authentication succeeded.`,
      user: req.user
    });
  });

  if (activeConfig.debug) {
    console.log("[DevAuthKit] Initialized with config:", {
      apiPrefix: prefix,
      corsOrigin: activeConfig.corsOrigin,
      devMode: activeConfig.devMode,
      jwtExpiresIn: activeConfig.jwtExpiresIn,
      otpExpiryMinutes: activeConfig.otpExpiryMinutes,
    });
  }

  return app;
}

const requireDPoP = require("./middleware/requireDPoP");
const { MemoryDpopReplayStore } = require("./stores/memoryDpopReplayStore");
const dpopService = require("./core/dpopService");

// Export middleware and config helpers for developers
devAuthKit.requireAuth = requireAuth;
devAuthKit.requireMfa = requireMfa;
devAuthKit.requireDPoP = requireDPoP;
devAuthKit.requireRole = requireRole;
const { requireOrg, requireOrgRole, requireOrgPermission } = require("./middleware/requireOrg");
const { MemoryOrganizationStore } = require("./stores/memoryOrganizationStore");
const { CloudflareD1OrganizationStore } = require("./stores/cloudflareD1OrganizationStore");
const organizationService = require("./core/organizationService");

devAuthKit.requireOrg = requireOrg;
devAuthKit.requireOrgRole = requireOrgRole;
devAuthKit.requireOrgPermission = requireOrgPermission;
devAuthKit.MemoryOrganizationStore = MemoryOrganizationStore;
devAuthKit.CloudflareD1OrganizationStore = CloudflareD1OrganizationStore;
devAuthKit.organizations = organizationService;

const webhookService = require("./core/webhookService");
const { WebhookDispatcher, emitWebhookEvent } = require("./core/webhookDispatcher");
const { MemoryWebhookStore } = require("./stores/memoryWebhookStore");
const { CloudflareD1WebhookStore } = require("./stores/cloudflareD1WebhookStore");

devAuthKit.webhooks = webhookService;
devAuthKit.WebhookDispatcher = WebhookDispatcher;
devAuthKit.emitWebhookEvent = emitWebhookEvent;
devAuthKit.MemoryWebhookStore = MemoryWebhookStore;
devAuthKit.CloudflareD1WebhookStore = CloudflareD1WebhookStore;

const ssoService = require("./core/ssoService");
const scimService = require("./core/scimService");
const { MemorySsoStore } = require("./stores/memorySsoStore");
const { CloudflareD1SsoStore } = require("./stores/cloudflareD1SsoStore");

devAuthKit.sso = ssoService;
devAuthKit.scim = scimService;
devAuthKit.MemorySsoStore = MemorySsoStore;
devAuthKit.CloudflareD1SsoStore = CloudflareD1SsoStore;

devAuthKit.devAuthKit = devAuthKit;
devAuthKit.config = config;
devAuthKit.checkConfig = (options) => {
  if (options !== undefined &&
      (!options || typeof options !== "object" || Array.isArray(options))) {
    return checkConfig(options);
  }
  return checkConfig({ ...config.get(), ...(options || {}) });
};
devAuthKit.RedisOtpStore = RedisOtpStore;
devAuthKit.prismaAdapter = prismaAdapter;
devAuthKit.drizzleAdapter = drizzleAdapter;
devAuthKit.mongooseAdapter = mongooseAdapter;
devAuthKit.MemoryRefreshTokenStore = MemoryRefreshTokenStore;
devAuthKit.MemoryMfaStore = MemoryMfaStore;
devAuthKit.RedisRefreshTokenStore = RedisRefreshTokenStore;
devAuthKit.MemoryRateLimitStore = MemoryRateLimitStore;
devAuthKit.RedisRateLimitStore = RedisRateLimitStore;
devAuthKit.RedisDpopReplayStore = RedisDpopReplayStore;
devAuthKit.MemoryDpopReplayStore = MemoryDpopReplayStore;
devAuthKit.dpop = dpopService;

// v2 Next-Gen Architectural Exports
const requireApiKey = require("./middleware/requireApiKey");
const { AuditLogService, emitAuditLog } = require("./core/auditLogService");
const { MemoryAuditLogStore } = require("./stores/memoryAuditLogStore");
const { CloudflareD1AuditLogStore } = require("./stores/cloudflareD1AuditLogStore");
const { ApiKeyService, matchesScopes, verifyKeyChecksum } = require("./core/apiKeyService");
const { MemoryApiKeyStore } = require("./stores/memoryApiKeyStore");
const { CloudflareD1ApiKeyStore } = require("./stores/cloudflareD1ApiKeyStore");
const { SessionService, defaultSessionService } = require("./core/sessionService");
const { blockUser, unblockUser, isUserBlocked, getUserEpoch } = require("./controllers/userManagementController");

devAuthKit.requireApiKey = requireApiKey;
devAuthKit.AuditLogService = AuditLogService;
devAuthKit.emitAuditLog = emitAuditLog;
devAuthKit.MemoryAuditLogStore = MemoryAuditLogStore;
devAuthKit.CloudflareD1AuditLogStore = CloudflareD1AuditLogStore;
devAuthKit.ApiKeyService = ApiKeyService;
devAuthKit.matchesScopes = matchesScopes;
devAuthKit.verifyKeyChecksum = verifyKeyChecksum;
devAuthKit.MemoryApiKeyStore = MemoryApiKeyStore;
devAuthKit.CloudflareD1ApiKeyStore = CloudflareD1ApiKeyStore;
devAuthKit.SessionService = SessionService;
devAuthKit.sessionService = defaultSessionService;
devAuthKit.blockUser = blockUser;
devAuthKit.unblockUser = unblockUser;
devAuthKit.isUserBlocked = isUserBlocked;
devAuthKit.getUserEpoch = getUserEpoch;

module.exports = devAuthKit;

