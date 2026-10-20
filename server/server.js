// server/server.js
const express = require("express");
const session = require("express-session");
const dotenv = require("dotenv");
const cors = require("cors");

const config = require("./config");
const authRoutes = require("./routes/authRoutes");
const requireAuth = require("./middleware/requireAuth");
const requireRole = require("./middleware/requireRole");
const RedisOtpStore = require("./stores/redisOtpStore");
const prismaAdapter = require("./adapters/prisma");
const drizzleAdapter = require("./adapters/drizzle");
const mongooseAdapter = require("./adapters/mongoose");
const MemoryRefreshTokenStore = require("./stores/memoryRefreshTokenStore");
const RedisRateLimitStore = require("./stores/redisRateLimitStore");
const MemoryRateLimitStore = require("./stores/memoryRateLimitStore");

dotenv.config();

function devAuthKit(app, options = {}) {
  const activeConfig = config.set(options);
  if (activeConfig.otpStore && !["get", "set", "delete", "recordAttempt"].every(
    (method) => typeof activeConfig.otpStore[method] === "function"
  )) {
    throw new TypeError("otpStore must implement get, set, delete, and recordAttempt methods");
  }
  if (activeConfig.userAdapter && typeof activeConfig.userAdapter.findOrCreateUser !== "function") {
    throw new TypeError("userAdapter must implement a findOrCreateUser method");
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

  // Setup CORS
  app.use(cors({
    origin: activeConfig.corsOrigin,
    credentials: true
  }));

  // Setup body parsers
  app.use(express.json());
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

// Export middleware and config helpers for developers
devAuthKit.requireAuth = requireAuth;
devAuthKit.requireRole = requireRole;
devAuthKit.devAuthKit = devAuthKit;
devAuthKit.config = config;
devAuthKit.RedisOtpStore = RedisOtpStore;
devAuthKit.prismaAdapter = prismaAdapter;
devAuthKit.drizzleAdapter = drizzleAdapter;
devAuthKit.mongooseAdapter = mongooseAdapter;
devAuthKit.MemoryRefreshTokenStore = MemoryRefreshTokenStore;
devAuthKit.MemoryRateLimitStore = MemoryRateLimitStore;
devAuthKit.RedisRateLimitStore = RedisRateLimitStore;

module.exports = devAuthKit;
