// server/server.js
const express = require("express");
const session = require("express-session");
const dotenv = require("dotenv");
const cors = require("cors");

const config = require("./config");
const authRoutes = require("./routes/authRoutes");
const requireAuth = require("./middleware/requireAuth");
const RedisOtpStore = require("./stores/redisOtpStore");
const prismaAdapter = require("./adapters/prisma");

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
devAuthKit.devAuthKit = devAuthKit;
devAuthKit.config = config;
devAuthKit.RedisOtpStore = RedisOtpStore;
devAuthKit.prismaAdapter = prismaAdapter;

module.exports = devAuthKit;
