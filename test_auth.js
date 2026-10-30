// test_auth.js
if (typeof globalThis.SubtleCrypto === "undefined") {
  try {
    const nodeCrypto = require("node:crypto");
    globalThis.SubtleCrypto = nodeCrypto.webcrypto?.SubtleCrypto || class SubtleCrypto {};
  } catch {
    globalThis.SubtleCrypto = class SubtleCrypto {};
  }
}
const express = require("express");
const devAuthKit = require("./server/server.js");
const sessionStore = require("./server/sessionStore.js");
const { DevAuthClient } = require("./client/index.js");

async function runTests() {
  console.log("🧪 Starting DevAuthKit Phase 1 & Client SDK Automated Verification...\n");

  const passkeyCredentials = new Map();
  const passkeyChallenges = new Map();
  const passkeyStore = {
    async getUserHandle(userId) {
      return `handle-${userId}`;
    },
    async create(credential) {
      passkeyCredentials.set(credential.id, credential);
    },
    async getByCredentialId(id) {
      return passkeyCredentials.get(id) || null;
    },
    async listByUserId() {
      return [];
    },
    async updateCounter() {
      return false;
    },
    async deleteByCredentialId() {
      return false;
    },
    async put(challenge, record) {
      passkeyChallenges.set(challenge, record);
    },
    async consume(challenge, purpose) {
      const record = passkeyChallenges.get(challenge);
      if (!record || record.purpose !== purpose || record.expiresAt <= Date.now()) return null;
      passkeyChallenges.delete(challenge);
      return record;
    }
  };

  const app = express();
  devAuthKit(app, {
    jwtSecret: "test-jwt-secret",
    sessionSecret: "test-session-secret",
    devMode: true,
    debug: false,
    passkeys: {
      rpName: "DevAuthKit Test",
      rpID: "example.com",
      origins: ["https://example.com"]
    },
    passkeyStore,
    passkeyChallengeStore: passkeyStore
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
    console.log("\n📨 Testing unavailable mail delivery does not log credentials...");
    const originalMailerConfig = devAuthKit.config.get();
    devAuthKit.config.set({
      ...originalMailerConfig,
      devMode: false,
      emailProvider: "smtp",
      resendApiKey: "",
      mailer: undefined,
      smtpMailer: undefined,
      smtpMailerAvailable: false
    });
    const originalConsoleLog = console.log;
    const mailerLogs = [];
    let unavailableDeliveryRejected = false;
    try {
      console.log = (...args) => mailerLogs.push(args.join(" "));
      await require("./server/utils/mailer").sendOTP({
        email: "private@example.com",
        otp: "918273",
        magicLinkUrl: "https://example.com/auth/verify-magic?token=secret-token"
      });
    } catch (error) {
      unavailableDeliveryRejected = /OTP delivery is unavailable/.test(error.message);
    } finally {
      console.log = originalConsoleLog;
      devAuthKit.config.set(originalMailerConfig);
    }
    assert(
      unavailableDeliveryRejected &&
        !mailerLogs.join("\n").includes("918273") &&
        !mailerLogs.join("\n").includes("secret-token"),
      "Unavailable production mail delivery throws without logging OTP or magic-link credentials"
    );

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

    const passkeyOptionsResponse = await fetch(`${baseUrl}/auth/passkeys/register/options`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        Origin: "https://example.com",
        "Content-Type": "application/json"
      },
      body: "{}"
    });
    const passkeyOptions = await passkeyOptionsResponse.json();
    assert(
      passkeyOptionsResponse.ok && passkeyOptions.rp.id === "example.com",
      "Express exposes authenticated passkey registration options"
    );
    const crossOriginEnrollment = await fetch(`${baseUrl}/auth/passkeys/register/options`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        Origin: "https://attacker.example",
        "Content-Type": "application/json"
      },
      body: "{}"
    });
    assert(crossOriginEnrollment.status === 403, "Cross-origin requests cannot enroll passkeys");

    const passkeyListResponse = await fetch(`${baseUrl}/auth/passkeys`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    assert(passkeyListResponse.ok && (await passkeyListResponse.json()).passkeys.length === 0,
      "Express exposes authenticated passkey management");

    const passkeyLoginOptions = await fetch(`${baseUrl}/auth/passkeys/authenticate/options`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: testEmail })
    });
    assert(passkeyLoginOptions.ok, "Express exposes public passkey authentication options");

    const unknownPasskeyLogin = await fetch(`${baseUrl}/auth/passkeys/authenticate/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: { id: "unknown-passkey" } })
    });
    assert(unknownPasskeyLogin.status === 401, "Unknown passkey credentials cannot authenticate");

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

    const rateLimitValues = new Map();
    const redisRateLimitCalls = [];
    const mockRateLimitRedis = {
      async incr(key) {
        const count = (rateLimitValues.get(key)?.count || 0) + 1;
        rateLimitValues.set(key, { count, ttl: rateLimitValues.get(key)?.ttl ?? -1 });
        return count;
      },
      async pTTL(key) {
        return rateLimitValues.get(key)?.ttl ?? -2;
      },
      async pExpire(key, milliseconds) {
        redisRateLimitCalls.push({ key, milliseconds });
        rateLimitValues.get(key).ttl = milliseconds;
        return true;
      }
    };
    const redisRateLimitStore = new devAuthKit.RedisRateLimitStore(mockRateLimitRedis, {
      keyPrefix: "test:rate:"
    });
    assert(
      await redisRateLimitStore.increment("login:ip:abc:1", 60_000) === 1 &&
        await redisRateLimitStore.increment("login:ip:abc:1", 60_000) === 2 &&
        redisRateLimitCalls.length === 1 &&
        redisRateLimitCalls[0].key === "test:rate:login:ip:abc:1" &&
        redisRateLimitCalls[0].milliseconds === 60_000,
      "Redis rate-limit adapter increments atomically and applies expiry to new counters"
    );

    const dpopRedisValues = new Map();
    const dpopSetOptions = [];
    const mockDpopRedis = {
      async get(key) {
        return dpopRedisValues.get(key) ?? null;
      },
      async set(key, value, options) {
        dpopSetOptions.push(options);
        if (options.NX && dpopRedisValues.has(key)) return null;
        dpopRedisValues.set(key, value);
        return "OK";
      }
    };
    const redisDpopReplayStore = new devAuthKit.RedisDpopReplayStore(mockDpopRedis, {
      keyPrefix: "test:dpop:"
    });
    const concurrentJtiClaims = await Promise.all(
      Array.from({ length: 10 }, () => redisDpopReplayStore.record("same-proof-jti", 45))
    );
    assert(
      concurrentJtiClaims.filter(Boolean).length === 1 &&
        dpopSetOptions[0]?.NX === true &&
        dpopSetOptions[0]?.EX === 45 &&
        await redisDpopReplayStore.isUsed("same-proof-jti"),
      "Redis DPoP replay adapter atomically claims JTIs with an expiry"
    );
    assert(
      await redisDpopReplayStore.record("another-proof-jti") &&
        !await redisDpopReplayStore.record("same-proof-jti"),
      "Redis DPoP replay adapter accepts a fresh JTI and rejects a replay"
    );

    const rateLimitApp = express();
    devAuthKit(rateLimitApp, {
      jwtSecret: "rate-limit-test-jwt-secret",
      sessionSecret: "rate-limit-test-session-secret",
      rateLimit: {
        googleStart: { windowMs: 60_000, max: 2, perIp: true, perEmail: false },
        verifyMagicLink: {
          windowMs: 60_000,
          max: 1,
          perIp: false,
          perEmail: true,
          perEmailMax: 1
        }
      }
    });
    const rateLimitServer = rateLimitApp.listen(0);
    try {
      const rateLimitUrl = `http://localhost:${rateLimitServer.address().port}`;
      const firstLimitedRequest = await fetch(`${rateLimitUrl}/auth/google`);
      const secondLimitedRequest = await fetch(`${rateLimitUrl}/auth/google`);
      const thirdLimitedRequest = await fetch(`${rateLimitUrl}/auth/google`);
      const rateLimitBody = await thirdLimitedRequest.json();
      assert(
        firstLimitedRequest.headers.has("ratelimit-limit") &&
          secondLimitedRequest.status !== 429 &&
          thirdLimitedRequest.status === 429 &&
          thirdLimitedRequest.headers.has("retry-after") &&
          rateLimitBody.retryAfterSeconds > 0,
        "Auth route rate limits return standard headers and a 429 response after the configured limit"
      );
      const firstEmailLimitRequest = await fetch(
        `${rateLimitUrl}/auth/verify-magic?email=limit%40example.com`
      );
      const secondEmailLimitRequest = await fetch(
        `${rateLimitUrl}/auth/verify-magic?email=limit%40example.com`
      );
      assert(
        firstEmailLimitRequest.status !== 429 &&
          secondEmailLimitRequest.status === 429 &&
          secondEmailLimitRequest.headers.get("ratelimit-limit") === "1",
        "Per-email rate limits identify query-string email addresses independently of IP"
      );
    } finally {
      rateLimitServer.close();
    }

    const failedRateLimitApp = express();
    devAuthKit(failedRateLimitApp, {
      jwtSecret: "rate-limit-failure-jwt-secret",
      sessionSecret: "rate-limit-failure-session-secret",
      rateLimitStore: {
        async increment() {
          throw new Error("simulated store outage");
        }
      }
    });
    const failedRateLimitServer = failedRateLimitApp.listen(0);
    try {
      const failedRateLimitResponse = await fetch(
        `http://localhost:${failedRateLimitServer.address().port}/auth/google`
      );
      assert(
        failedRateLimitResponse.status === 503 &&
          (await failedRateLimitResponse.json()).error === "Rate-limit service unavailable",
        "Rate-limit storage failures fail explicitly with HTTP 503"
      );
    } finally {
      failedRateLimitServer.close();
    }

    let invalidRateLimitRejected = false;
    try {
      devAuthKit(express(), {
        rateLimit: { requestOtp: { windowMs: 0, max: 1 } }
      });
    } catch (error) {
      invalidRateLimitRejected = error instanceof TypeError;
    }
    assert(invalidRateLimitRejected, "Invalid rate-limit windows are rejected during initialization");

    let publicJwtSecretRejected = false;
    try {
      devAuthKit(express(), {
        jwtSecret: "devAuthJwtSecretKey_change_in_production",
        sessionSecret: "secure-test-session-secret"
      });
    } catch (error) {
      publicJwtSecretRejected = error instanceof TypeError;
    }
    assert(publicJwtSecretRejected, "Express initialization rejects the public development JWT secret");

    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    let missingProductionSecretsRejected = false;
    try {
      devAuthKit(express(), { devMode: false });
    } catch (error) {
      missingProductionSecretsRejected = error instanceof TypeError &&
        /Production requires explicit JWT and session secrets/.test(error.message);
    } finally {
      if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = originalNodeEnv;
    }
    assert(missingProductionSecretsRejected, "Production initialization requires explicit high-entropy JWT and session secrets");

    const doctorReport = devAuthKit.checkConfig({
      dpop: true,
      corsOrigin: "*"
    });
    assert(
      doctorReport.valid === false &&
        doctorReport.issues.some((issue) => issue.code === "dpop_replay_store_missing") &&
        doctorReport.issues.some((issue) => issue.code === "cors_wildcard_credentials"),
      "Configuration doctor reports actionable DPoP and credentialed CORS errors"
    );
    const previousDoctorNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    let productionDoctorReport;
    try {
      productionDoctorReport = devAuthKit.checkConfig({
        jwtSecret: "production-jwt-secret-value-that-is-long-enough",
        sessionSecret: "production-session-secret-that-is-long-enough",
        otpStore: {},
        sessionStore: {},
        rateLimit: false
      });
    } finally {
      if (previousDoctorNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previousDoctorNodeEnv;
    }
    assert(
      productionDoctorReport.issues.some((issue) => issue.code === "rate_limiting_disabled") &&
        !productionDoctorReport.issues.some((issue) => issue.code === "production_secrets"),
      "Configuration doctor reports production readiness warnings without exposing secrets"
    );

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

    console.log("\n🔄 Testing refresh-token rotation and revocation...");
    const refreshEntries = new Map();
    const refreshOtpStore = {
      async get(email) {
        return refreshEntries.get(email) || null;
      },
      async set(email, entry) {
        refreshEntries.set(email, { ...entry });
      },
      async delete(email) {
        refreshEntries.delete(email);
      },
      async recordAttempt(email) {
        const entry = refreshEntries.get(email);
        if (!entry) return 0;
        return ++entry.attempts;
      }
    };
    const refreshTokenStore = new devAuthKit.MemoryRefreshTokenStore();
    const refreshApp = express();
    devAuthKit(refreshApp, {
      jwtSecret: "refresh-test-jwt-secret",
      sessionSecret: "refresh-test-session-secret",
      otpStore: refreshOtpStore,
      refreshTokenStore,
      refreshTokens: { accessTokenExpiresIn: "15m", refreshTokenExpiresInDays: 1 },
      userAdapter: {
        async findOrCreateUser({ email }) {
          return { id: "shared-refresh-user", email, role: "user" };
        }
      },
      devMode: true
    });
    refreshApp.get("/api/private", devAuthKit.requireAuth, (req, res) => {
      res.json({ user: req.user });
    });
    const refreshServer = refreshApp.listen(0);
    try {
      const refreshUrl = `http://localhost:${refreshServer.address().port}`;
      const loginRefreshUser = async (email) => {
        const request = await originalFetch(`${refreshUrl}/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email })
        });
        if (!request.ok) throw new Error("Failed to request refresh-test OTP");
        const otp = refreshEntries.get(email)?.otp;
        const verify = await originalFetch(`${refreshUrl}/auth/verify`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, otp })
        });
        const data = await verify.json();
        const cookies = verify.headers.get("set-cookie") || "";
        const cookieHeaders = verify.headers.getSetCookie?.() || [cookies];
        const refreshCookieHeader = cookieHeaders.find((cookie) => cookie.startsWith("devauth_token_refresh=")) || "";
        const refreshCookie = refreshCookieHeader.match(/devauth_token_refresh=([^;,]+)/)?.[1];
        if (!verify.ok || !data.token || !refreshCookie) throw new Error("Refresh token login did not issue expected credentials");
        return {
          token: data.token,
          refreshCookie,
          user: data.user,
          exposesRefreshToken: Object.hasOwn(data, "refreshToken"),
          refreshCookieHttpOnly: /;\s*HttpOnly/i.test(refreshCookieHeader)
        };
      };

      const rotatedLogin = await loginRefreshUser("rotate@example.com");
      assert(
        rotatedLogin.user.id === "shared-refresh-user" &&
          !rotatedLogin.exposesRefreshToken &&
          rotatedLogin.refreshCookieHttpOnly,
        "Refresh-enabled login uses a stable user identity and keeps its token in an httpOnly cookie"
      );
      const rotateResponse = await originalFetch(`${refreshUrl}/auth/refresh`, {
        method: "POST",
        headers: { Cookie: `devauth_token_refresh=${rotatedLogin.refreshCookie}` }
      });
      const rotatedData = await rotateResponse.json();
      const rotatedCookie = (rotateResponse.headers.get("set-cookie") || "")
        .match(/devauth_token_refresh=([^;,]+)/)?.[1];
      assert(
        rotateResponse.ok &&
          rotatedData.refreshEnabled === true &&
          rotatedData.token !== rotatedLogin.token &&
          rotatedCookie &&
          rotatedCookie !== rotatedLogin.refreshCookie,
        `Refresh endpoint rotates the httpOnly refresh token and issues a new access token (status ${rotateResponse.status}; enabled ${rotatedData.refreshEnabled}; token changed ${rotatedData.token !== rotatedLogin.token}; cookie ${Boolean(rotatedCookie)}; cookie changed ${rotatedCookie !== rotatedLogin.refreshCookie})`
      );

      const reuseResponse = await originalFetch(`${refreshUrl}/auth/refresh`, {
        method: "POST",
        headers: { Cookie: `devauth_token_refresh=${rotatedLogin.refreshCookie}` }
      });
      const afterReuse = await originalFetch(`${refreshUrl}/api/private`, {
        headers: { Authorization: `Bearer ${rotatedData.token}` }
      });
      assert(
        reuseResponse.status === 401 && afterReuse.status === 401,
        "Refresh-token reuse revokes the complete family and its access tokens"
      );

      const currentLogin = await loginRefreshUser("current-revoke@example.com");
      const currentRevoke = await originalFetch(`${refreshUrl}/auth/sessions/revoke`, {
        method: "POST",
        headers: { Authorization: `Bearer ${currentLogin.token}` }
      });
      const revokedCurrentAccess = await originalFetch(`${refreshUrl}/api/private`, {
        headers: { Authorization: `Bearer ${currentLogin.token}` }
      });
      assert(
        currentRevoke.ok && revokedCurrentAccess.status === 401,
        "Current-session revocation immediately rejects that session's access token"
      );

      const allLoginA = await loginRefreshUser("all-a@example.com");
      const allLoginB = await loginRefreshUser("all-b@example.com");
      const revokeAllResponse = await originalFetch(`${refreshUrl}/auth/sessions/revoke-all`, {
        method: "POST",
        headers: { Authorization: `Bearer ${allLoginA.token}` }
      });
      const revokedAllAccess = await originalFetch(`${refreshUrl}/api/private`, {
        headers: { Authorization: `Bearer ${allLoginB.token}` }
      });
      assert(
        revokeAllResponse.ok && revokedAllAccess.status === 401,
        "Revoke-all invalidates access tokens from every session for the user"
      );

      const logoutLogin = await loginRefreshUser("logout-revoke@example.com");
      const refreshLogout = await originalFetch(`${refreshUrl}/auth/logout`, {
        method: "POST",
        headers: { Cookie: `devauth_token_refresh=${logoutLogin.refreshCookie}` }
      });
      const logoutRevokedAccess = await originalFetch(`${refreshUrl}/api/private`, {
        headers: { Authorization: `Bearer ${logoutLogin.token}` }
      });
      assert(
        refreshLogout.ok && logoutRevokedAccess.status === 401,
        "Logout revokes the refresh-token family and current access token"
      );
    } finally {
      refreshServer.close();
    }

    let sdkRefreshCalls = 0;
    let sdkProtectedCalls = 0;
    const refreshSdk = new DevAuthClient({
      apiUrl: "https://auth.example.test",
      customFetch: async (url, options = {}) => {
        if (url.endsWith("/auth/verify")) {
          return new Response(JSON.stringify({
            token: "old-access-token",
            user: { email: "sdk-refresh@example.com" },
            refreshEnabled: true
          }), { status: 200, headers: { "Content-Type": "application/json" } });
        }
        if (url.endsWith("/auth/refresh")) {
          sdkRefreshCalls++;
          return new Response(JSON.stringify({
            token: "new-access-token",
            user: { email: "sdk-refresh@example.com" },
            refreshEnabled: true,
            expiresIn: "15m"
          }), { status: 200, headers: { "Content-Type": "application/json" } });
        }
        if (url.endsWith("/api/private")) {
          sdkProtectedCalls++;
          if (options.headers.get("Authorization") === "Bearer old-access-token") {
            return new Response(JSON.stringify({ error: "expired" }), { status: 401 });
          }
          return new Response(JSON.stringify({ success: true }), { status: 200 });
        }
        return new Response(JSON.stringify({ message: "ok" }), { status: 200 });
      }
    });
    await refreshSdk.verifyOTP("sdk-refresh@example.com", "123456");
    const sdkRefreshedResponses = await Promise.all([
      refreshSdk.fetch("/api/private"),
      refreshSdk.fetch("/api/private")
    ]);
    assert(
      sdkRefreshedResponses.every((response) => response.ok) &&
        sdkRefreshCalls === 1 &&
        sdkProtectedCalls === 4 &&
        refreshSdk.getToken() === "new-access-token",
      "Client SDK shares concurrent refresh requests and retries with the rotated access token"
    );

    console.log("\n🛡️ Testing Role-Based Access Control (RBAC requireRole)...");
    const { requireRole, drizzleAdapter, mongooseAdapter } = devAuthKit;
    const rbacApp = express();
    devAuthKit(rbacApp, {
      jwtSecret: "rbac-test-jwt-secret",
      sessionSecret: "rbac-test-session-secret",
      devMode: true
    });
    rbacApp.get("/api/admin-only", requireRole("admin"), (req, res) => {
      res.json({ secret: "admin-data" });
    });
    rbacApp.get("/api/staff-only", requireRole(["admin", "moderator"]), (req, res) => {
      res.json({ secret: "staff-data" });
    });
    const rbacServer = rbacApp.listen(0);
    const rbacUrl = `http://localhost:${rbacServer.address().port}`;

    try {
      // 1. Unauthenticated request to requireRole route -> 401
      const unauthRbac = await fetch(`${rbacUrl}/api/admin-only`);
      assert(unauthRbac.status === 401, "requireRole returns 401 Unauthorized for unauthenticated requests");

      // 2. User with role 'user' -> 403 Forbidden
      const { signJwt } = require("./server/utils/webCrypto");
      const userToken = await signJwt({ email: "user@test.com", role: "user" }, "rbac-test-jwt-secret");
      const forbiddenRes = await fetch(`${rbacUrl}/api/admin-only`, {
        headers: { Authorization: `Bearer ${userToken}` }
      });
      assert(forbiddenRes.status === 403, "requireRole returns 403 Forbidden when user does not have required role");

      // 3. User with role 'admin' -> 200 OK
      const adminToken = await signJwt({ email: "admin@test.com", role: "admin" }, "rbac-test-jwt-secret");
      const adminRes = await fetch(`${rbacUrl}/api/admin-only`, {
        headers: { Authorization: `Bearer ${adminToken}` }
      });
      const adminData = await adminRes.json();
      assert(adminRes.ok && adminData.secret === "admin-data", "requireRole allows access when user role matches");

      // 4. User with role 'moderator' accessing staff route with array allowed roles -> 200 OK
      const modToken = await signJwt({ email: "mod@test.com", role: "moderator" }, "rbac-test-jwt-secret");
      const staffRes = await fetch(`${rbacUrl}/api/staff-only`, {
        headers: { Authorization: `Bearer ${modToken}` }
      });
      assert(staffRes.ok, "requireRole allows access when user role matches any allowed role in array");
    } finally {
      rbacServer.close();
    }

    console.log("\n💧 Testing Drizzle ORM and Mongoose Database Adapters...");
    // Drizzle test
    const mockDrizzleRows = [];
    const mockDrizzleTable = { id: "id", email: "email", role: "role" };
    const mockDrizzleDb = {
      select: () => ({
        from: () => ({
          where: () => Promise.resolve(mockDrizzleRows)
        })
      }),
      insert: () => ({
        values: (val) => ({
          returning: () => {
            const user = { id: "drizzle-1", email: val.email, role: "member" };
            mockDrizzleRows.push(user);
            return Promise.resolve([user]);
          }
        })
      })
    };
    const drizzle = drizzleAdapter(mockDrizzleDb, { table: mockDrizzleTable });
    const drizzleUser1 = await drizzle.findOrCreateUser({ email: "drizzle@example.com" });
    assert(
      drizzleUser1.id === "drizzle-1" && drizzleUser1.email === "drizzle@example.com" && drizzleUser1.role === "member",
      "drizzleAdapter creates and returns user record with normalized claims"
    );

    // Mongoose test
    const mockMongoDb = [];
    const mockMongooseModel = {
      findOneAndUpdate: (filter) => ({
        lean: async () => {
          let user = mockMongoDb.find((u) => u.email === filter.email);
          if (!user) {
            user = { _id: "mongo-id-1", email: filter.email, role: "guest" };
            mockMongoDb.push(user);
          }
          return user;
        }
      })
    };
    const mongoose = mongooseAdapter(mockMongooseModel);
    const mongoUser1 = await mongoose.findOrCreateUser({ email: "mongo@example.com" });
    assert(
      mongoUser1.id === "mongo-id-1" && mongoUser1.email === "mongo@example.com" && mongoUser1.role === "guest",
      "mongooseAdapter finds/creates and returns user record with mapped id and role"
    );

    console.log("\n🔗 Testing Magic Link Authentication...");
    const magicApp = express();
    devAuthKit(magicApp, {
      jwtSecret: "magic-test-jwt-secret",
      sessionSecret: "magic-test-session-secret",
      devMode: true,
      magicLink: true
    });
    const magicServer = magicApp.listen(0);
    const magicUrl = `http://localhost:${magicServer.address().port}`;

    try {
      const magicReqRes = await fetch(`${magicUrl}/auth/request-otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "magic@example.com", magicLink: true })
      });
      const magicReqData = await magicReqRes.json();
      assert(
        magicReqRes.ok && Boolean(magicReqData.magicLinkUrl),
        "requestOTP generates and returns magicLinkUrl when magicLink is enabled"
      );

      const parsedMagicUrl = new URL(magicReqData.magicLinkUrl);
      const magicToken = parsedMagicUrl.searchParams.get("token");

      // Verify valid magic link
      const magicVerifyRes = await fetch(`${magicUrl}/auth/verify-magic?token=${magicToken}&email=magic@example.com`);
      const magicVerifyData = await magicVerifyRes.json();
      assert(
        magicVerifyRes.ok && magicVerifyData.token && magicVerifyData.user.email === "magic@example.com",
        "verifyMagicLink successfully authenticates user and returns JWT token"
      );

      // Replay magic link -> 401
      const magicReplayRes = await fetch(`${magicUrl}/auth/verify-magic?token=${magicToken}`);
      assert(magicReplayRes.status === 401, "verifyMagicLink rejects already-consumed magic link tokens");

      // Client SDK verifyMagicLink
      const clientReqRes = await fetch(`${magicUrl}/auth/request-otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "magic-sdk@example.com", magicLink: true })
      });
      const clientReqData = await clientReqRes.json();
      const sdkMagicToken = new URL(clientReqData.magicLinkUrl).searchParams.get("token");
      const magicSdk = new DevAuthClient({ apiUrl: magicUrl });
      const sdkMagicVerify = await magicSdk.verifyMagicLink(sdkMagicToken, "magic-sdk@example.com");
      assert(
        magicSdk.isAuthenticated() && sdkMagicVerify.user.email === "magic-sdk@example.com",
        "DevAuthClient.verifyMagicLink stores credentials and updates auth state"
      );
    } finally {
      magicServer.close();
    }

    console.log("\n🐙 Testing GitHub OAuth 2.0 with PKCE and profile identity mapping...");
    const githubCalls = [];
    const githubApp = express();
    devAuthKit(githubApp, {
      jwtSecret: "github-oauth-test-secret",
      sessionSecret: "github-oauth-session-secret",
      github: {
        clientId: "test-gh-client-id",
        clientSecret: "test-gh-client-secret",
        callbackURL: "http://localhost:3000/auth/github/callback"
      },
      userAdapter: {
        async findOrCreateUser({ email }) {
          githubCalls.push({ email });
          return { id: "github-user-42", email, role: "developer" };
        }
      },
      mapUserPayload: (user, identity) => ({
        displayName: identity?.name,
        authProvider: identity?.provider,
        username: identity?.username
      })
    });
    const githubServer = githubApp.listen(0);
    const ghOriginalFetch = global.fetch;
    let ghEmailVerified = true;
    try {
      const ghUrl = `http://localhost:${githubServer.address().port}`;
      const startGhOAuth = async () => {
        const response = await ghOriginalFetch(`${ghUrl}/auth/github`, { redirect: "manual" });
        const location = response.headers.get("location");
        const sessionCookie = (response.headers.get("set-cookie") || "").split(";")[0];
        return {
          response,
          authorizationURL: location ? new URL(location) : null,
          sessionCookie
        };
      };

      const invalidGhStart = await startGhOAuth();
      assert(
        invalidGhStart.response.status === 302 &&
          invalidGhStart.authorizationURL?.hostname === "github.com" &&
          invalidGhStart.authorizationURL.searchParams.get("code_challenge_method") === "S256" &&
          Boolean(invalidGhStart.authorizationURL.searchParams.get("code_challenge")),
        "GitHub sign-in redirects to github.com with OAuth state and PKCE code challenge"
      );

      const invalidGhResponse = await ghOriginalFetch(
        `${ghUrl}/auth/github/callback?code=auth-code&state=invalid`,
        { headers: { Cookie: invalidGhStart.sessionCookie } }
      );
      assert(invalidGhResponse.status === 400, "GitHub callback rejects an invalid OAuth state");

      const validGhStart = await startGhOAuth();
      const authorizationURL = validGhStart.authorizationURL;

      global.fetch = async (input, init = {}) => {
        const url = input.toString();
        if (url === "https://github.com/login/oauth/access_token") {
          return new Response(JSON.stringify({ access_token: "mock-gh-access-token", token_type: "bearer" }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (url === "https://api.github.com/user") {
          return new Response(JSON.stringify({
            id: 1234567,
            login: "octocat",
            name: "Mona Lisa Octocat",
            avatar_url: "https://github.com/images/error/octocat_happy.gif",
            email: null
          }), { status: 200, headers: { "Content-Type": "application/json" } });
        }
        if (url === "https://api.github.com/user/emails") {
          return new Response(JSON.stringify([
            { email: "octocat@github.com", primary: true, verified: ghEmailVerified }
          ]), { status: 200, headers: { "Content-Type": "application/json" } });
        }
        return ghOriginalFetch(input, init);
      };

      const ghCallbackRes = await ghOriginalFetch(
        `${ghUrl}/auth/github/callback?code=mock-gh-code&state=${encodeURIComponent(authorizationURL.searchParams.get("state"))}`,
        { headers: { Cookie: validGhStart.sessionCookie } }
      );
      const ghCallbackData = await ghCallbackRes.json();
      assert(
        ghCallbackRes.ok &&
          ghCallbackData.user.id === "github-user-42" &&
          ghCallbackData.user.email === "octocat@github.com" &&
          ghCallbackData.user.authProvider === "github" &&
          ghCallbackData.user.username === "octocat",
        "GitHub callback exchanges PKCE code, fetches emails, resolves user adapter, and sets tokens"
      );

      // Replay rejection
      const ghReplay = await ghOriginalFetch(
        `${ghUrl}/auth/github/callback?code=mock-gh-code&state=${encodeURIComponent(authorizationURL.searchParams.get("state"))}`,
        { headers: { Cookie: validGhStart.sessionCookie } }
      );
      assert(ghReplay.status === 400, "GitHub OAuth state cannot be replayed after successful login");
    } finally {
      global.fetch = ghOriginalFetch;
      githubServer.close();
    }

    console.log("\n🔐 Testing custom OAuth providers and account linking...");
    const identities = new Map();
    const linkedIdentities = [];
    const oauthApp = express();
    devAuthKit(oauthApp, {
      jwtSecret: "custom-oauth-test-secret",
      sessionSecret: "custom-oauth-session-secret",
      oauthProviders: {
        acme: {
          clientId: "test-acme-client-id",
          clientSecret: "test-acme-client-secret",
          callbackURL: "http://localhost:3000/auth/oauth/acme/callback",
          authorizationURL: "https://identity.example.test/authorize",
          tokenURL: "https://identity.example.test/token",
          userInfoURL: "https://identity.example.test/userinfo",
          scope: "openid email profile",
          mapProfile: (profile) => ({
            id: profile.sub,
            email: profile.email,
            emailVerified: profile.email_verified,
            name: profile.name
          })
        }
      },
      userAdapter: {
        async findOrCreateUser({ email }) {
          return { id: "acme-user-1", email };
        },
        async findUserByOAuthIdentity({ provider, providerId }) {
          return identities.get(`${provider}:${providerId}`) || null;
        },
        async linkOAuthIdentity(identity) {
          const key = `${identity.provider}:${identity.providerId}`;
          const previous = identities.get(key);
          if (previous && String(previous.id) !== identity.userId) {
            throw new Error("OAuth identity already belongs to another user");
          }
          identities.set(key, { id: identity.userId, email: identity.email });
          linkedIdentities.push(identity);
        }
      }
    });
    const oauthServer = oauthApp.listen(0);
    const oauthOriginalFetch = global.fetch;
    try {
      const oauthUrl = `http://localhost:${oauthServer.address().port}`;
      const unauthenticatedLink = await oauthOriginalFetch(`${oauthUrl}/auth/oauth/acme/link`, {
        method: "POST",
        headers: {
          Origin: "http://localhost:3001",
          "Content-Type": "application/json"
        },
        body: "{}"
      });
      assert(unauthenticatedLink.status === 401, "OAuth account linking requires authentication");

      const linkJwt = await require("./server/utils/webCrypto").signJwt(
        { id: "existing-user-7", email: "existing@example.com" },
        "custom-oauth-test-secret",
        "1h"
      );
      const crossOriginLink = await oauthOriginalFetch(`${oauthUrl}/auth/oauth/acme/link`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${linkJwt}`,
          Origin: "https://attacker.example",
          "Content-Type": "application/json"
        },
        body: "{}"
      });
      assert(crossOriginLink.status === 403, "OAuth account linking rejects cross-origin initiation");

      const startLink = await oauthOriginalFetch(`${oauthUrl}/auth/oauth/acme/link`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${linkJwt}`,
          Origin: "http://localhost:3001",
          "Content-Type": "application/json"
        },
        body: "{}"
      });
      const startLinkData = await startLink.json();
      const linkAuthorizationURL = new URL(startLinkData.authorizationURL);
      const linkSessionCookie = (startLink.headers.get("set-cookie") || "").split(";")[0];
      assert(
        startLink.ok &&
          linkAuthorizationURL.hostname === "identity.example.test" &&
          linkAuthorizationURL.searchParams.get("code_challenge_method") === "S256" &&
          Boolean(linkAuthorizationURL.searchParams.get("code_challenge")),
        "Custom OAuth providers use authorization-code PKCE"
      );

      global.fetch = async (input, init = {}) => {
        const url = input.toString();
        if (url === "https://identity.example.test/token") {
          assert(
            new URLSearchParams(init.body).has("code_verifier"),
            "Custom OAuth token exchange includes its PKCE verifier"
          );
          return new Response(JSON.stringify({ access_token: "mock-acme-access-token" }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        if (url === "https://identity.example.test/userinfo") {
          return new Response(JSON.stringify({
            sub: "acme-subject-9",
            email: "Existing@Example.com",
            email_verified: true,
            name: "Existing User"
          }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        }
        return oauthOriginalFetch(input, init);
      };

      const linkCallback = await oauthOriginalFetch(
        `${oauthUrl}/auth/oauth/acme/callback?code=mock-acme-code&state=${encodeURIComponent(linkAuthorizationURL.searchParams.get("state"))}`,
        { headers: { Cookie: linkSessionCookie } }
      );
      const linkData = await linkCallback.json();
      assert(
        linkCallback.ok &&
          linkData.provider === "acme" &&
          linkedIdentities.length === 1 &&
          linkedIdentities[0].userId === "existing-user-7" &&
          linkedIdentities[0].email === "existing@example.com",
        "OAuth callback links verified provider identity to the authenticated account"
      );
    } finally {
      global.fetch = oauthOriginalFetch;
      oauthServer.close();
    }

    console.log("\n⚛️ Testing React Hooks export...");
    const { AuthProvider, useAuth } = require("./client/react/index.js");
    assert(
      typeof AuthProvider === "function" && typeof useAuth === "function",
      "devauthkit/react exports AuthProvider component and useAuth hook"
    );

    console.log(`\n🎉 Results: ${passed}/${total} tests passed!\n`);
  } catch (err) {
    console.error("Test runner encountered error:", err);
  } finally {
    server.close();
    process.exit(passed === total ? 0 : 1);
  }
}

runTests();
