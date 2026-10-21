// example.js
const express = require("express");
const path = require("path");
const devAuthKit = require("./server/server.js");

const app = express();

// Initialize DevAuthKit
devAuthKit(app, {
  corsOrigin: ["http://localhost:3001", "http://localhost:3000"],
  sessionSecret: "my-super-secret-session-key",
  jwtSecret: "my-super-secret-jwt-key",
  jwtExpiresIn: "7d",
  devMode: true, // prints OTP in console for easy testing
  debug: true
});

// Serve client SDK, docs, and frontend demo directly for quick testing
app.use("/client", express.static(path.join(__dirname, "client")));
app.use("/demo", express.static(path.join(__dirname, "client", "frontend")));
app.use("/docs", express.static(path.join(__dirname, "docs")));

// Example custom protected route using DevAuthKit's requireAuth middleware
const { requireAuth } = devAuthKit;
app.get("/api/dashboard", requireAuth, (req, res) => {
  res.json({
    message: "Welcome to the secret dashboard!",
    user: req.user,
    timestamp: new Date().toISOString()
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 DevAuthKit example server running on http://localhost:${PORT}`);
  console.log(`📖 View Documentation & Showcase at: http://localhost:${PORT}/docs/index.html`);
  console.log(`📱 Test the interactive demo at: http://localhost:${PORT}/demo/index.html\n`);
});