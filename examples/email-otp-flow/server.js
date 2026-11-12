// examples/email-otp-flow/server.js
const express = require("express");
const path = require("path");
const devAuthKit = require("../../server/server.js");

const app = express();
const PORT = process.env.PORT || 3000;

// 1. Initialize DevAuthKit with OTP & Strict Resend Rate Limiting
devAuthKit(app, {
  corsOrigin: [`http://localhost:${PORT}`, "http://localhost:3001"],
  sessionSecret: "devauthkit-email-otp-example-session-secret",
  jwtSecret: "devauthkit-email-otp-example-jwt-secret",
  jwtExpiresIn: "7d",
  devMode: true, // Logs OTP code in terminal for frictionless testing
  debug: false,
  // Configure rate limiting for requestOtp:
  // - perEmailMax: 3 requests per 60s window (prevents OTP email spam)
  // - perIpMax: 10 requests per 60s window (prevents IP-level abuse)
  rateLimit: {
    requestOtp: {
      windowMs: 60 * 1000,
      max: 10,
      perIp: true,
      perEmail: true,
      perIpMax: 10,
      perEmailMax: 3
    },
    verifyOtp: {
      windowMs: 15 * 60 * 1000,
      max: 30,
      perIp: true,
      perEmail: true,
      perIpMax: 30,
      perEmailMax: 10
    }
  }
});

// 2. Serve static assets: client SDK, and the one-page app
app.use("/client", express.static(path.join(__dirname, "../../client")));
app.use(express.static(path.join(__dirname, "public")));

// 3. Example protected route verified by DevAuthKit's requireAuth middleware
const { requireAuth } = devAuthKit;
app.get("/api/dashboard", requireAuth, (req, res) => {
  res.json({
    status: "success",
    message: "🎉 You have reached the protected API dashboard!",
    user: req.user,
    timestamp: new Date().toISOString(),
    protectedData: {
      accountTier: "Pro Developer",
      permissions: ["read:data", "write:projects"],
      serverTime: Date.now()
    }
  });
});

app.listen(PORT, () => {
  console.log("\n=======================================================");
  console.log("  🚀 DevAuthKit One-Page Email OTP Example App");
  console.log("=======================================================");
  console.log(`  🌐 App URL:           http://localhost:${PORT}`);
  console.log(`  🛡️ Resend Limiter:    Max 3 OTP requests / minute per email`);
  console.log(`  🔑 Dev Mode:          Active (OTP will be printed below)`);
  console.log("=======================================================\n");
});

