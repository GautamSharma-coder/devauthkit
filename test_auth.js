// test_auth.js
const express = require("express");
const devAuthKit = require("./server/server.js");
const sessionStore = require("./server/sessionStore.js");
const { DevAuthClient } = require("./client/index.js");

async function runTests() {
  console.log("🧪 Starting DevAuthKit Phase 1 & Client SDK Automated Verification...\n");

  const app = express();
  devAuthKit(app, {
    jwtSecret: "test-jwt-secret",
    sessionSecret: "test-session-secret",
    devMode: true,
    debug: false
  });

  const { requireAuth } = devAuthKit;
  app.get("/api/dashboard", requireAuth, (req, res) => {
    res.json({ success: true, user: req.user });
  });

  const server = app.listen(0);
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;

  let passed = 0;
  let total = 0;

  function assert(condition, testName) {
    total++;
    if (condition) {
      console.log(`  ✅ [PASS] ${testName}`);
      passed++;
    } else {
      console.error(`  ❌ [FAIL] ${testName}`);
    }
  }

  try {
    const testEmail = "testuser@example.com";

    // Test 1: Request OTP (/auth/login)
    const reqRes = await fetch(`${baseUrl}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: testEmail })
    });
    const reqData = await reqRes.json();
    assert(reqRes.ok && reqData.devMode === true, "POST /auth/login generates OTP in Dev Mode");

    // Inspect session store to retrieve generated OTP for testing
    const stored = sessionStore.get ? sessionStore.get(testEmail) : sessionStore[testEmail];
    const generatedOtp = stored?.otp;
    assert(Boolean(generatedOtp && generatedOtp.length === 6), `Generated OTP is 6 digits (${generatedOtp})`);

    // Test 2: Invalid OTP check
    const badVerifyRes = await fetch(`${baseUrl}/auth/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: testEmail, otp: "000000" })
    });
    const badVerifyData = await badVerifyRes.json();
    assert(badVerifyRes.status === 401 && badVerifyData.attemptsRemaining === 4, "Invalid OTP returns 401 and decrements attempts");

    // Test 3: Correct OTP verification & JWT issuance
    const goodVerifyRes = await fetch(`${baseUrl}/auth/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: testEmail, otp: generatedOtp })
    });
    const goodVerifyData = await goodVerifyRes.json();
    assert(goodVerifyRes.ok && Boolean(goodVerifyData.token), "Valid OTP returns 200 and issues JWT token");
    assert(goodVerifyData.user?.email === testEmail, "JWT user email matches requested email");

    const token = goodVerifyData.token;

    // Test 4: Replay protection (OTP must be cleared after verification)
    const replayRes = await fetch(`${baseUrl}/auth/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: testEmail, otp: generatedOtp })
    });
    assert(replayRes.status === 401, "Replay attack prevented: OTP cannot be reused once verified");

    // Test 5: Protected route with JWT Bearer header
    const meRes = await fetch(`${baseUrl}/auth/me`, {
      headers: { "Authorization": `Bearer ${token}` }
    });
    const meData = await meRes.json();
    assert(meRes.ok && meData.user?.email === testEmail, "GET /auth/me returns authenticated user via Bearer token");

    // Test 6: Custom route /api/dashboard with requireAuth
    const dashRes = await fetch(`${baseUrl}/api/dashboard`, {
      headers: { "Authorization": `Bearer ${token}` }
    });
    const dashData = await dashRes.json();
    assert(dashRes.ok && dashData.success === true, "Custom route /api/dashboard accessible via requireAuth");

    // Test 7: Unauthorized request without token
    const unauthRes = await fetch(`${baseUrl}/api/dashboard`);
    assert(unauthRes.status === 401, "Protected route denies request without authentication (401)");

    // Test 8: Logout endpoint
    const logoutRes = await fetch(`${baseUrl}/auth/logout`, { method: "POST" });
    const logoutData = await logoutRes.json();
    assert(logoutRes.ok && logoutData.message.includes("Logged out"), "POST /auth/logout returns 200");

    // ==========================================
    // DevAuthClient SDK Verification
    // ==========================================
    console.log("\n📦 Testing DevAuthClient SDK...");

    const client = new DevAuthClient({
      apiUrl: baseUrl,
      customFetch: fetch
    });

    const sdkEmail = "sdkuser@example.com";
    const sdkReq = await client.sendOTP(sdkEmail);
    assert(sdkReq.devMode === true, "Client SDK: client.sendOTP() works");

    const sdkStored = sessionStore.get ? sessionStore.get(sdkEmail) : sessionStore[sdkEmail];
    const sdkOtp = sdkStored?.otp;

    const verifyResult = await client.verifyOTP(sdkEmail, sdkOtp);
    assert(client.isAuthenticated() === true, "Client SDK: client.isAuthenticated() is true after verify");
    assert(Boolean(client.getToken()), "Client SDK: client.getToken() returns JWT");
    assert(client.getUser()?.email === sdkEmail, "Client SDK: client.getUser() matches signed-in user");

    // SDK authenticated fetch
    const sdkFetchRes = await client.fetch("/api/dashboard");
    const sdkFetchData = await sdkFetchRes.json();
    assert(sdkFetchRes.ok && sdkFetchData.user?.email === sdkEmail, "Client SDK: client.fetch() automatically attaches Bearer token");

    // SDK logout
    await client.logout();
    assert(client.isAuthenticated() === false, "Client SDK: client.isAuthenticated() is false after logout");
    assert(client.getToken() === null, "Client SDK: client.getToken() is null after logout");

    console.log(`\n🎉 Results: ${passed}/${total} tests passed!\n`);
  } catch (err) {
    console.error("Test runner encountered error:", err);
  } finally {
    process.exitCode = passed === total ? 0 : 1;
    server.close();
  }
}

runTests();
