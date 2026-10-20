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
    const setCookieHeader = goodVerifyRes.headers.get("set-cookie") || "";
    assert(setCookieHeader.includes("devauth_token="), "verifyOTP automatically sets httpOnly auth cookie");

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

    // Test 7: Protected route via httpOnly Cookie ONLY (no Authorization header)
    const cookieTokenMatch = setCookieHeader.match(/devauth_token=([^;]+)/);
    const cookieValue = cookieTokenMatch ? cookieTokenMatch[1] : "";
    const cookieAuthRes = await fetch(`${baseUrl}/api/dashboard`, {
      headers: { "Cookie": `devauth_token=${cookieValue}` }
    });
    const cookieAuthData = await cookieAuthRes.json();
    assert(cookieAuthRes.ok && cookieAuthData.user?.email === testEmail, "requireAuth successfully authenticates via Cookie header only");

    // Test 8: Unauthorized request without token
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

    // Configurable asynchronous OTP storage
    console.log("\n🗄️ Testing custom asynchronous OTP storage...");
    const customEntries = new Map();
    const customOtpStore = {
      async get(email) {
        return customEntries.get(email) || null;
      },
      async set(email, data) {
        customEntries.set(email, { ...data });
      },
      async delete(email) {
        customEntries.delete(email);
      },
      async recordAttempt(email) {
        const entry = customEntries.get(email);
        if (!entry) return 0;
        entry.attempts++;
        return entry.attempts;
      }
    };
    const customStoreApp = express();
    devAuthKit(customStoreApp, {
      jwtSecret: "custom-store-test-secret",
      sessionSecret: "custom-store-session-secret",
      otpStore: customOtpStore,
      devMode: true,
      setHttpOnlyCookie: false
    });
    const customStoreServer = customStoreApp.listen(0);
    try {
      const customStoreUrl = `http://localhost:${customStoreServer.address().port}`;
      const customEmail = "custom-store@example.com";
      const customRequest = await fetch(`${customStoreUrl}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: customEmail })
      });
      const customEntry = await customOtpStore.get(customEmail);
      assert(customRequest.ok && Boolean(customEntry?.otp), "Async custom OTP store saves requested OTP");

      const customInvalid = await fetch(`${customStoreUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: customEmail, otp: "000000" })
      });
      const customInvalidData = await customInvalid.json();
      assert(customInvalid.status === 401 && customInvalidData.attemptsRemaining === 4, "Async custom OTP store records failed attempts");

      const customVerify = await fetch(`${customStoreUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: customEmail, otp: customEntry.otp })
      });
      assert(customVerify.ok && !customEntries.has(customEmail), "Async custom OTP store deletes OTP after successful verification");
    } finally {
      customStoreServer.close();
    }

    const redisValues = new Map();
    let redisTtl;
    const mockRedisClient = {
      async get(key) {
        return redisValues.get(key) || null;
      },
      async set(key, value, options) {
        redisValues.set(key, value);
        redisTtl = options.EX;
      },
      async del(key) {
        const keys = Array.isArray(key) ? key : [key];
        return keys.reduce((deleted, item) => redisValues.delete(item) ? deleted + 1 : deleted, 0);
      },
      async incr(key) {
        const next = Number(redisValues.get(key) || 0) + 1;
        redisValues.set(key, String(next));
        return next;
      }
    };
    const redisOtpStore = new devAuthKit.RedisOtpStore(mockRedisClient, {
      keyPrefix: "test:otp:",
      ttlSeconds: 60
    });
    const redisOtp = { otp: "123456", attempts: 0, createdAt: Date.now() };
    await redisOtpStore.set("redis@example.com", redisOtp);
    const firstRedisEntry = await redisOtpStore.get("redis@example.com");
    assert(redisTtl === 60 && firstRedisEntry.otp === redisOtp.otp, "Redis OTP adapter stores values with its configured TTL and prefix");
    assert(await redisOtpStore.recordAttempt("redis@example.com") === 1, "Redis OTP adapter records attempts through atomic INCR");
    assert((await redisOtpStore.get("redis@example.com")).attempts === 1, "Redis OTP adapter reads the separate attempt counter");
    await redisOtpStore.set("redis@example.com", { ...redisOtp, otp: "654321" });
    assert((await redisOtpStore.get("redis@example.com")).attempts === 0, "Redis OTP adapter resets attempts for each new OTP");
    await redisOtpStore.delete("redis@example.com");
    assert(await redisOtpStore.get("redis@example.com") === null, "Redis OTP adapter deletes stored OTP values");

    const prismaCalls = [];
    const prismaUserAdapter = devAuthKit.prismaAdapter({
      account: {
        async upsert(args) {
          prismaCalls.push(args);
          return { userId: "user-42", emailAddress: args.create.emailAddress, accessLevel: "admin" };
        }
      }
    }, {
      model: "account",
      fields: { id: "userId", email: "emailAddress", role: "accessLevel" }
    });
    const mappedPrismaUser = await prismaUserAdapter.findOrCreateUser({ email: "prisma@example.com" });
    assert(
      prismaCalls[0]?.where.emailAddress === "prisma@example.com" &&
        prismaCalls[0]?.create.emailAddress === "prisma@example.com" &&
        mappedPrismaUser.id === "user-42" &&
        mappedPrismaUser.email === "prisma@example.com" &&
        mappedPrismaUser.role === "admin",
      "Prisma adapter supports custom model and field mappings"
    );

    const userAdapterApp = express();
    devAuthKit(userAdapterApp, {
      jwtSecret: "user-adapter-test-secret",
      sessionSecret: "user-adapter-session-secret",
      devMode: true,
      setHttpOnlyCookie: false,
      userAdapter: {
        async findOrCreateUser({ email }) {
          return { id: "stable-user-1", email, role: "admin", internalSecret: "not-a-claim" };
        }
      },
      mapUserPayload(user) {
        return { plan: user.role === "admin" ? "pro" : "free" };
      }
    });
    const userAdapterServer = userAdapterApp.listen(0);
    try {
      const userAdapterUrl = `http://localhost:${userAdapterServer.address().port}`;
      const userAdapterEmail = "persistent-user@example.com";
      await fetch(`${userAdapterUrl}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: userAdapterEmail })
      });
      const userAdapterOtp = sessionStore.get(userAdapterEmail)?.otp;
      const userVerifyResponse = await fetch(`${userAdapterUrl}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: userAdapterEmail, otp: userAdapterOtp })
      });
      const userVerifyData = await userVerifyResponse.json();
      assert(
        userVerifyResponse.ok &&
          userVerifyData.user.id === "stable-user-1" &&
          userVerifyData.user.role === "admin" &&
          userVerifyData.user.plan === "pro" &&
          !("internalSecret" in userVerifyData.user),
        "OTP verification returns stable identity and mapped safe claims without leaking other DB fields"
      );

      const meResponse = await fetch(`${userAdapterUrl}/auth/me`, {
        headers: { Authorization: `Bearer ${userVerifyData.token}` }
      });
      const meData = await meResponse.json();
      assert(
        meResponse.ok && meData.user.id === "stable-user-1" && meData.user.plan === "pro",
        "Protected routes expose persistent user claims from the verified JWT"
      );
    } finally {
      userAdapterServer.close();
    }

    const googleCalls = [];
    const googleApp = express();
    devAuthKit(googleApp, {
      jwtSecret: "google-oauth-test-secret",
      sessionSecret: "google-oauth-session-secret",
      setHttpOnlyCookie: true,
      google: {
        clientId: "test-google-client-id",
        clientSecret: "test-google-client-secret",
        callbackURL: "http://localhost:3000/auth/google/callback"
      },
      userAdapter: {
        async findOrCreateUser({ email }) {
          googleCalls.push({ email });
          return { id: "google-user-7", email, role: "member" };
        }
      },
      mapUserPayload(user, identity) {
        return { displayName: identity.name, authProvider: identity.provider, userRole: user.role };
      }
    });
    const googleServer = googleApp.listen(0);
    const originalFetch = global.fetch;
    let googleProfileVerified = true;
    try {
      const googleUrl = `http://localhost:${googleServer.address().port}`;
      const startOAuth = async () => {
        const response = await originalFetch(`${googleUrl}/auth/google`, { redirect: "manual" });
        const location = response.headers.get("location");
        const sessionCookie = (response.headers.get("set-cookie") || "").split(";")[0];
        return {
          response,
          authorizationURL: location ? new URL(location) : null,
          sessionCookie
        };
      };

      const invalidStateStart = await startOAuth();
      assert(
        invalidStateStart.response.status === 302 &&
          invalidStateStart.authorizationURL?.hostname === "accounts.google.com" &&
          invalidStateStart.authorizationURL.searchParams.get("code_challenge_method") === "S256" &&
          Boolean(invalidStateStart.authorizationURL.searchParams.get("code_challenge")),
        "Google sign-in redirects with OAuth state and PKCE challenge"
      );
      const invalidStateResponse = await originalFetch(
        `${googleUrl}/auth/google/callback?code=auth-code&state=invalid`,
        { headers: { Cookie: invalidStateStart.sessionCookie } }
      );
      assert(invalidStateResponse.status === 400, "Google callback rejects an invalid OAuth state");

      const validStateStart = await startOAuth();
      const authorizationURL = validStateStart.authorizationURL;
      let tokenRequestBody;
      global.fetch = async (input, init = {}) => {
        const url = input.toString();
        if (url === "https://oauth2.googleapis.com/token") {
          tokenRequestBody = new URLSearchParams(init.body);
          return new Response(JSON.stringify({ access_token: "mock-google-access-token" }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (url === "https://www.googleapis.com/oauth2/v3/userinfo") {
          assert(
            init.headers.Authorization === "Bearer mock-google-access-token",
            "Google profile request uses the exchanged access token"
          );
          return new Response(JSON.stringify({
            sub: "google-subject-7",
            email: "GoogleUser@example.com",
            email_verified: googleProfileVerified,
            name: "Google User",
            picture: "https://example.com/avatar.png"
          }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        return originalFetch(input, init);
      };

      const callbackResponse = await originalFetch(
        `${googleUrl}/auth/google/callback?code=mock-auth-code&state=${encodeURIComponent(authorizationURL.searchParams.get("state"))}`,
        { headers: { Cookie: validStateStart.sessionCookie }, redirect: "manual" }
      );
      const callbackData = await callbackResponse.json();
      assert(
        callbackResponse.ok &&
          callbackData.user.id === "google-user-7" &&
          callbackData.user.email === "googleuser@example.com" &&
          callbackData.user.displayName === "Google User" &&
          callbackData.user.authProvider === "google" &&
          callbackData.user.userRole === "member" &&
          tokenRequestBody?.get("code_verifier"),
        "Google callback exchanges PKCE code, resolves persistent user, and maps safe claims"
      );
      assert(
        googleCalls.length === 1 && googleCalls[0].email === "googleuser@example.com" &&
          (callbackResponse.headers.get("set-cookie") || "").includes("devauth_token="),
        "Google login uses normalized verified email and sets the auth cookie"
      );

      const sessionCookie = (callbackResponse.headers.get("set-cookie") || "").match(/connect\.sid=([^;,]+)/)?.[1];
      const sessionMeResponse = await originalFetch(`${googleUrl}/auth/me`, {
        headers: { Cookie: `connect.sid=${sessionCookie}` }
      });
      const sessionMeData = await sessionMeResponse.json();
      assert(
        Boolean(sessionCookie) &&
          sessionMeResponse.ok &&
          sessionMeData.user.id === "google-user-7",
        "Google login regenerates and persists the authenticated session"
      );

      const replayResponse = await originalFetch(
        `${googleUrl}/auth/google/callback?code=mock-auth-code&state=${encodeURIComponent(authorizationURL.searchParams.get("state"))}`,
        { headers: { Cookie: validStateStart.sessionCookie } }
      );
      assert(replayResponse.status === 400, "Google OAuth state cannot be replayed after successful login");

      const googleMeResponse = await originalFetch(`${googleUrl}/auth/me`, {
        headers: { Authorization: `Bearer ${callbackData.token}` }
      });
      const googleMeData = await googleMeResponse.json();
      assert(
        googleMeResponse.ok &&
          googleMeData.user.id === "google-user-7" &&
          googleMeData.user.displayName === "Google User",
        "Google user claims authenticate protected endpoints"
      );

      googleProfileVerified = false;
      const unverifiedStart = await startOAuth();
      const unverifiedResponse = await originalFetch(
        `${googleUrl}/auth/google/callback?code=mock-auth-code&state=${encodeURIComponent(unverifiedStart.authorizationURL.searchParams.get("state"))}`,
        { headers: { Cookie: unverifiedStart.sessionCookie } }
      );
      assert(
        unverifiedResponse.status === 401 && googleCalls.length === 1,
        "Google callback rejects unverified email before creating a local user"
      );
    } finally {
      global.fetch = originalFetch;
      googleServer.close();
    }

    console.log(`\n🎉 Results: ${passed}/${total} tests passed!\n`);
  } catch (err) {
    console.error("Test runner encountered error:", err);
  } finally {
    process.exitCode = passed === total ? 0 : 1;
    server.close();
  }
}

runTests();
