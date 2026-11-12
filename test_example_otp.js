// test_example_otp.js
const assert = require("node:assert/strict");
const express = require("express");
const path = require("path");
const fs = require("fs");
const devAuthKit = require("./server/server.js");
const sessionStore = require("./server/sessionStore.js");
const { DevAuthClient } = require("./client/index.js");

async function testOtpAndRateLimiting() {
  console.log("🧪 Testing One-Page Email OTP & Resend Rate Limiting Example...");

  // 1. Verify example files exist
  const exampleDir = path.join(__dirname, "examples", "email-otp-flow");
  const serverPath = path.join(exampleDir, "server.js");
  const htmlPath = path.join(exampleDir, "public", "index.html");
  const readmePath = path.join(exampleDir, "README.md");

  assert(fs.existsSync(serverPath), "examples/email-otp-flow/server.js exists");
  assert(fs.existsSync(htmlPath), "examples/email-otp-flow/public/index.html exists");
  assert(fs.existsSync(readmePath), "examples/email-otp-flow/README.md exists");

  const htmlContent = fs.readFileSync(htmlPath, "utf-8");
  assert(htmlContent.includes("resend-otp-btn"), "index.html includes resend OTP button");
  assert(htmlContent.includes("startResendCooldown"), "index.html implements cooldown timer");
  assert(htmlContent.includes("retryAfterSeconds"), "index.html handles server 429 retryAfterSeconds");
  console.log("  ✅ [PASS] Static assets and UI elements verified");

  // 2. Setup isolated express app with strict rate limiting
  const app = express();
  devAuthKit(app, {
    jwtSecret: "test-jwt-secret-otp-example",
    sessionSecret: "test-session-secret-otp-example",
    devMode: true,
    debug: false,
    rateLimit: {
      requestOtp: {
        windowMs: 60_000,
        max: 5,
        perIp: true,
        perEmail: true,
        perIpMax: 5,
        perEmailMax: 3
      }
    }
  });

  const { requireAuth } = devAuthKit;
  app.get("/api/dashboard", requireAuth, (req, res) => {
    res.json({ success: true, user: req.user });
  });

  const http = require("node:http");
  const server = http.createServer(app);

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const client = new DevAuthClient({ apiUrl: baseUrl });
    const testEmail = `test-resend-${Date.now()}@example.com`;

    // 1. Initial OTP send should succeed
    const res1 = await client.sendOTP(testEmail);
    assert(Boolean(res1.message), "First OTP send returns success message");
    console.log("  ✅ [PASS] Initial OTP request succeeded");

    // 2. Immediate Resend should trigger Resend Rate Limiter (HTTP 429 with retryAfterSeconds)
    let rateLimitCaught = false;
    let retrySeconds = null;
    try {
      await client.sendOTP(testEmail);
    } catch (err) {
      rateLimitCaught = true;
      retrySeconds = err.retryAfterSeconds;
      assert.strictEqual(err.status, 429, "Error status code is 429");
      assert(typeof retrySeconds === "number" && retrySeconds > 0, "Error contains numeric retryAfterSeconds");
    }
    assert(rateLimitCaught, "Immediate resend was rate limited by server");
    console.log(`  ✅ [PASS] Resend rate limiter enforced on rapid retry (HTTP 429, Retry-After: ${retrySeconds}s)`);

    // 3. Verify OTP with the generated code
    const stored = sessionStore.get ? sessionStore.get(testEmail) : sessionStore[testEmail];
    const otp = stored?.otp;
    assert(Boolean(otp && otp.length === 6), "Valid 6-digit OTP stored in sessionStore");

    const authResult = await client.verifyOTP(testEmail, otp);
    assert(Boolean(authResult.token && authResult.user), "OTP verification succeeded with token and user");
    assert.strictEqual(client.getToken(), authResult.token, "Client stored matching JWT token");
    console.log("  ✅ [PASS] OTP verified and token acquired");

    // 4. Access protected endpoint using authenticated token
    const protectedRes = await client.fetch("/api/dashboard");
    const protectedData = await protectedRes.json();
    assert.strictEqual(protectedData.success, true, "Protected route accessible with token");
    console.log("  ✅ [PASS] Protected route accessed with DevAuthClient.fetch()");

  } finally {
    if (typeof server.closeAllConnections === "function") {
      server.closeAllConnections();
    }
    await new Promise((resolve) => server.close(resolve));
  }

  console.log("\n🎉 All One-Page Email OTP & Resend Rate Limiting tests passed successfully!\n");
}

testOtpAndRateLimiting().then(() => {
  process.exit(0);
}).catch((err) => {
  console.error("❌ Test failed:", err);
  process.exit(1);
});
