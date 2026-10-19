// server/server.js
const express = require("express");
const session = require("express-session");
const dotenv = require("dotenv");
const cors = require("cors");

const config = require("./config");
const authRoutes = require("./routes/authRoutes");
const requireAuth = require("./middleware/requireAuth");

dotenv.config();

function devAuthKit(app, options = {}) {
  const activeConfig = config.set(options);

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

module.exports = devAuthKit;
