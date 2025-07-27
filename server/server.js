// server/server.js
const express = require("express");
const session = require("express-session");
const dotenv = require("dotenv");
const cors = require("cors");

const authRoutes = require("./routes/authRoutes");
const requireAuth = require("./middleware/requireAuth");

dotenv.config();

module.exports = function devAuthKit(app, options = {}) {
  const {
    corsOrigin = "http://localhost:3001",
    sessionSecret = process.env.SESSION_SECRET || "devAuthSecret"
  } = options;

  // Setup CORS
  app.use(cors({
    origin: corsOrigin,
    credentials: true
  }));

  app.use(express.json());

  // Setup session
  app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  }));

  // Auth Routes
  app.use("/auth", authRoutes);

  // Optional protected test route
  app.get("/profile", requireAuth, (req, res) => {
    res.json({ message: `Welcome, ${req.session.user.email}` });
  });

  if (options.debug) {
    console.log("[DevAuthKit] Initialized with options:", options);
  }
};




















