const assert = require("node:assert/strict");
const { Miniflare } = require("miniflare");
const { Hono } = require("hono");
const {
  CloudflareKvMagicLinkStore,
  CloudflareKvOtpStore,
  CloudflareKvRateLimitStore
} = require("./server/stores/cloudflareKvStore");
const { CloudflareD1RefreshTokenStore } = require("./server/stores/cloudflareD1RefreshTokenStore");
const { CloudflareD1OAuthStateStore } = require("./server/stores/cloudflareD1OAuthStateStore");
const { CloudflareD1CounterStore } = require("./server/stores/cloudflareD1CounterStore");
const { createAuthRouter } = require("./server/hono");

async function run() {
  const miniflare = new Miniflare({
    script: 'export default { fetch() { return new Response("ok"); } }',
    modules: true,
    kvNamespaces: { AUTH_KV: "AUTH_KV" },
    d1Databases: { AUTH_DB: "AUTH_DB" }
  });

  try {
    const kv = await miniflare.getKVNamespace("AUTH_KV");
    const database = await miniflare.getD1Database("AUTH_DB");
    const counterStore = new CloudflareD1CounterStore(database);
    await counterStore.createTables();
    const otpStore = new CloudflareKvOtpStore(kv, { counterStore });
    const rateLimitStore = new CloudflareKvRateLimitStore(kv, { counterStore });
    const magicLinkStore = new CloudflareKvMagicLinkStore(kv);
    const refreshTokenStore = new CloudflareD1RefreshTokenStore(database);
    const oauthStateStore = new CloudflareD1OAuthStateStore(database);

    const createdAt = Date.now();
    await otpStore.set("store@example.com", { otp: "123456", attempts: 0, createdAt });
    assert.deepEqual(await otpStore.get("store@example.com"), {
      otp: "123456",
      createdAt,
      attempts: 0
    });
    assert.equal(await otpStore.recordAttempt("store@example.com"), 1);
    assert.equal((await otpStore.get("store@example.com")).attempts, 1);
    const otpRacingStore = await Promise.all(
      Array.from({ length: 10 }, () => otpStore.recordAttempt("store@example.com"))
    );
    assert.deepEqual(otpRacingStore.sort((left, right) => left - right), [2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    assert.equal((await otpStore.get("store@example.com")).attempts, 11);
    await otpStore.delete("store@example.com");
    assert.equal(await otpStore.get("store@example.com"), null);

    assert.equal(await rateLimitStore.increment("login:ip:test", 60_000), 1);
    assert.equal(await rateLimitStore.increment("login:ip:test", 60_000), 2);
    const concurrentRateLimitCounts = await Promise.all(
      Array.from({ length: 10 }, () => rateLimitStore.increment("login:ip:race", 60_000))
    );
    assert.deepEqual(
      concurrentRateLimitCounts.sort((left, right) => left - right),
      [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    );
    await magicLinkStore.set("magic-hash", { email: "magic@example.com", expiresAt: Date.now() + 60_000 });
    assert.equal((await magicLinkStore.get("magic-hash")).email, "magic@example.com");
    await magicLinkStore.delete("magic-hash");
    assert.equal(await magicLinkStore.get("magic-hash"), null);

    await refreshTokenStore.createTables();
    await oauthStateStore.createTables();
    await oauthStateStore.put("single-use-state", Date.now() + 60_000);
    assert.equal(await oauthStateStore.consume("single-use-state"), true);
    assert.equal(await oauthStateStore.consume("single-use-state"), false);
    await oauthStateStore.put("racing-state", Date.now() + 60_000);
    const concurrentStateConsumes = await Promise.all([
      oauthStateStore.consume("racing-state"),
      oauthStateStore.consume("racing-state")
    ]);
    assert.equal(concurrentStateConsumes.filter(Boolean).length, 1);
    await refreshTokenStore.create("refresh-one", {
      familyId: "family-one",
      userId: "user-one",
      user: { id: "user-one", email: "refresh@example.com" },
      expiresAt: Date.now() + 60_000
    });
    assert.equal(await refreshTokenStore.isFamilyActive("family-one"), true);
    const rotated = await refreshTokenStore.rotate("refresh-one", "refresh-two", {
      expiresAt: Date.now() + 120_000
    });
    assert.equal(rotated.status, "rotated");
    assert.equal(rotated.record.user.email, "refresh@example.com");
    assert.equal(await refreshTokenStore.isFamilyActive("family-one"), true);
    assert.equal((await refreshTokenStore.rotate("refresh-one", "refresh-three", {
      expiresAt: Date.now() + 120_000
    })).status, "reused");
    assert.equal(await refreshTokenStore.isFamilyActive("family-one"), false);

    await refreshTokenStore.create("race-token", {
      familyId: "race-family",
      userId: "race-user",
      user: { id: "race-user", email: "race@example.com" },
      expiresAt: Date.now() + 60_000
    });
    const concurrentRotations = await Promise.all([
      refreshTokenStore.rotate("race-token", "race-token-a", { expiresAt: Date.now() + 120_000 }),
      refreshTokenStore.rotate("race-token", "race-token-b", { expiresAt: Date.now() + 120_000 })
    ]);
    assert.equal(concurrentRotations.filter((result) => result.status === "rotated").length, 1);
    assert.equal(concurrentRotations.filter((result) => result.status === "reused").length, 1);
    assert.equal(await refreshTokenStore.isFamilyActive("race-family"), false);

    let sentOtp;
    let sentMagicLink;
    const app = new Hono();
    app.route("/", createAuthRouter({
      apiPrefix: "/auth",
      jwtSecret: "cloudflare-test-jwt-secret-at-least-32-chars",
      sessionSecret: "cloudflare-test-session-secret-at-least-32",
      otpStore,
      rateLimitStore,
      magicLinkStore,
      refreshTokenStore,
      oauthStateStore,
      refreshTokens: true,
      github: {
        clientId: "github-client-id",
        clientSecret: "github-client-secret",
        callbackURL: "https://example.com/auth/github/callback"
      },
      oauthProviders: {
        acme: {
          clientId: "acme-client-id",
          clientSecret: "acme-client-secret",
          callbackURL: "https://example.com/auth/oauth/acme/callback",
          authorizationURL: "https://identity.example.com/authorize",
          tokenURL: "https://identity.example.com/token",
          userInfoURL: "https://identity.example.com/userinfo",
          mapProfile: (profile) => ({
            id: profile.sub,
            email: profile.email,
            emailVerified: profile.email_verified === true
          })
        }
      },
      magicLink: true,
      rateLimit: false,
      devMode: true,
      mailer: async ({ otp, magicLinkUrl }) => {
        sentOtp = otp;
        sentMagicLink = magicLinkUrl;
      }
    }));

    const requestOtp = await app.request("/auth/request-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "hono@example.com" })
    });
    assert.equal(requestOtp.status, 200);
    assert.match(sentOtp, /^\d{6}$/);

    const verifyOtp = await app.request("/auth/verify-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "hono@example.com", otp: sentOtp })
    });
    assert.equal(verifyOtp.status, 200);
    const session = await verifyOtp.json();
    assert.equal(session.refreshEnabled, true);
    assert.match(verifyOtp.headers.get("set-cookie"), /devauth_token=/);
    assert.match(verifyOtp.headers.get("set-cookie"), /devauth_token_refresh=/);

    const profile = await app.request("/auth/me", {
      headers: { Authorization: `Bearer ${session.token}` }
    });
    assert.equal(profile.status, 200);
    assert.equal((await profile.json()).user.email, "hono@example.com");
    const authCookie = verifyOtp.headers.get("set-cookie").match(/(?:^|,\s*)devauth_token=([^;,]+)/)?.[1];
    assert.ok(authCookie);
    const cookieProfile = await app.request("/auth/me", {
      headers: { Cookie: `devauth_token=${authCookie}` }
    });
    assert.equal(cookieProfile.status, 200);


    const setCookie = verifyOtp.headers.get("set-cookie");
    const refreshCookie = setCookie.match(/devauth_token_refresh=([^;,]+)/)?.[1];
    assert.ok(refreshCookie);
    const refreshed = await app.request("/auth/refresh", {
      method: "POST",
      headers: { Cookie: `devauth_token_refresh=${refreshCookie}` }
    });
    assert.equal(refreshed.status, 200);
    const refreshedBody = await refreshed.json();
    assert.equal(refreshedBody.refreshEnabled, true);

    const reused = await app.request("/auth/refresh", {
      method: "POST",
      headers: { Cookie: `devauth_token_refresh=${refreshCookie}` }
    });
    assert.equal(reused.status, 401);
    const revokedProfile = await app.request("/auth/me", {
      headers: { Authorization: `Bearer ${refreshedBody.token}` }
    });
    assert.equal(revokedProfile.status, 401);

    const magicRequest = await app.request("/auth/request-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "magic@example.com", magicLink: true })
    });
    assert.equal(magicRequest.status, 200);
    assert.ok(sentMagicLink);
    const magicUrl = new URL(sentMagicLink);
    const magicResponse = await app.request(`${magicUrl.pathname}${magicUrl.search}`);
    assert.equal(magicResponse.status, 200);
    assert.equal((await magicResponse.json()).user.email, "magic@example.com");

    const oauthStart = await app.request("/auth/github");
    assert.equal(oauthStart.status, 302);
    const oauthState = new URL(oauthStart.headers.get("location")).searchParams.get("state");
    const oauthCookie = oauthStart.headers.get("set-cookie").match(/devauthkit_oauth_state=([^;,]+)/)?.[1];
    assert.ok(oauthState && oauthCookie);
    const oauthCallback = await app.request(`/auth/github/callback?state=${oauthState}`, {
      headers: { Cookie: `devauthkit_oauth_state=${oauthCookie}` }
    });
    assert.equal(oauthCallback.status, 400);
    assert.match((await oauthCallback.json()).error, /authorization code/);
    const oauthReplay = await app.request(`/auth/github/callback?state=${oauthState}`, {
      headers: { Cookie: `devauthkit_oauth_state=${oauthCookie}` }
    });
    assert.equal(oauthReplay.status, 400);
    assert.match((await oauthReplay.json()).error, /already-used/);

    const customOAuthStart = await app.request("/auth/oauth/acme");
    assert.equal(customOAuthStart.status, 302);
    assert.equal(
      new URL(customOAuthStart.headers.get("location")).hostname,
      "identity.example.com"
    );
    const customOAuthState = new URL(customOAuthStart.headers.get("location")).searchParams.get("state");
    const customOAuthCookie = customOAuthStart.headers.get("set-cookie")
      .match(/devauthkit_oauth_state=([^;,]+)/)?.[1];
    const customOAuthCallback = await app.request(
      `/auth/oauth/acme/callback?state=${customOAuthState}`,
      { headers: { Cookie: `devauthkit_oauth_state=${customOAuthCookie}` } }
    );
    assert.equal(customOAuthCallback.status, 400);
    assert.match((await customOAuthCallback.json()).error, /authorization code/);
    const customOAuthReplay = await app.request(
      `/auth/oauth/acme/callback?state=${customOAuthState}`,
      { headers: { Cookie: `devauthkit_oauth_state=${customOAuthCookie}` } }
    );
    assert.equal(customOAuthReplay.status, 400);
    assert.match((await customOAuthReplay.json()).error, /already-used/);

    console.log("Cloudflare KV, D1, and Hono integration tests passed.");
  } finally {
    await miniflare.dispose();
  }
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
