// Ensure Node 18 compatibility for Miniflare / undici which expects global File and SubtleCrypto
if (typeof globalThis.File === "undefined") {
  try {
    const { File } = require("node:buffer");
    globalThis.File = File;
  } catch {}
}
if (typeof globalThis.SubtleCrypto === "undefined") {
  try {
    const nodeCrypto = require("node:crypto");
    globalThis.SubtleCrypto = nodeCrypto.webcrypto?.SubtleCrypto || class SubtleCrypto {};
  } catch {
    globalThis.SubtleCrypto = class SubtleCrypto {};
  }
}

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
const { CloudflareD1PasskeyStore } = require("./server/stores/cloudflareD1PasskeyStore");
const { CloudflareD1DpopReplayStore } = require("./server/stores/cloudflareD1DpopReplayStore");
const { createAuthRouter } = require("./server/hono");

async function run() {
  const nodeMajor = parseInt(process.versions.node.split('.')[0], 10);
  if (nodeMajor < 20) {
    console.log('Cloudflare Miniflare integration tests skipped on Node ' + process.version + ' (Miniflare 4 requires Node >= 20.0.0).');
    return;
  }
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
    const passkeyStore = new CloudflareD1PasskeyStore(database);

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
    await passkeyStore.createTables();
    await oauthStateStore.put("single-use-state", Date.now() + 60_000);
    assert.equal(await oauthStateStore.consume("single-use-state"), true);
    assert.equal(await oauthStateStore.consume("single-use-state"), false);
    await oauthStateStore.put("racing-state", Date.now() + 60_000);
    const concurrentStateConsumes = await Promise.all([
      oauthStateStore.consume("racing-state"),
      oauthStateStore.consume("racing-state")
    ]);
    assert.equal(concurrentStateConsumes.filter(Boolean).length, 1);
    assert.equal(await passkeyStore.getUserHandle("passkey-user"), await passkeyStore.getUserHandle("passkey-user"));
    await passkeyStore.put("passkey-single-use", {
      purpose: "authentication",
      email: "passkey@example.com",
      expiresAt: Date.now() + 60_000
    });
    const challengeConsumes = await Promise.all([
      passkeyStore.consume("passkey-single-use", "authentication"),
      passkeyStore.consume("passkey-single-use", "authentication")
    ]);
    assert.equal(challengeConsumes.filter(Boolean).length, 1);
    assert.equal(await passkeyStore.consume("passkey-single-use", "authentication"), null);
    await passkeyStore.put("passkey-expired", {
      purpose: "authentication",
      expiresAt: Date.now() + 5
    });
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(await passkeyStore.consume("passkey-expired", "authentication"), null);
    const passkeyUserHandle = await passkeyStore.getUserHandle("passkey-user");
    await passkeyStore.create({
      id: "credential-one",
      userId: "passkey-user",
      userHandle: passkeyUserHandle,
      email: "passkey@example.com",
      publicKey: new Uint8Array([1, 2, 3]),
      counter: 1,
      transports: ["internal"],
      deviceType: "singleDevice",
      backedUp: false,
      createdAt: Date.now()
    });
    assert.equal((await passkeyStore.getByCredentialId("credential-one")).counter, 1);
    assert.equal((await passkeyStore.listByUserId("passkey-user"))[0].id, "credential-one");
    assert.equal(await passkeyStore.updateCounter("credential-one", 1, 2, "singleDevice", false), true);
    const counterRaces = await Promise.all([
      passkeyStore.updateCounter("credential-one", 2, 3, "singleDevice", false),
      passkeyStore.updateCounter("credential-one", 2, 3, "singleDevice", false)
    ]);
    assert.equal(counterRaces.filter(Boolean).length, 1);
    assert.equal(await passkeyStore.deleteByCredentialId("credential-one", "another-user"), false);
    assert.equal(await passkeyStore.deleteByCredentialId("credential-one", "passkey-user"), true);
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
      passkeys: {
        rpName: "DevAuthKit Test",
        rpID: "example.com",
        origins: ["https://example.com"]
      },
      passkeyStore,
      passkeyChallengeStore: passkeyStore,
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

    const registrationOptionsResponse = await app.request("/auth/passkeys/register/options", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.token}`,
        Origin: "https://example.com",
        "Content-Type": "application/json"
      },
      body: "{}"
    });
    assert.equal(registrationOptionsResponse.status, 200);
    const registrationOptions = await registrationOptionsResponse.json();
    assert.equal(registrationOptions.rp.id, "example.com");
    assert.equal(registrationOptions.authenticatorSelection.residentKey, "required");
    assert.ok(await passkeyStore.consume(registrationOptions.challenge, "registration"));

    const crossOriginPasskeyEnrollment = await app.request("/auth/passkeys/register/options", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.token}`,
        Origin: "https://attacker.example",
        "Content-Type": "application/json"
      },
      body: "{}"
    });
    assert.equal(crossOriginPasskeyEnrollment.status, 403);

    const authenticationOptionsResponse = await app.request("/auth/passkeys/authenticate/options", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "hono@example.com" })
    });
    assert.equal(authenticationOptionsResponse.status, 200);
    const authenticationOptions = await authenticationOptionsResponse.json();
    assert.ok(authenticationOptions.challenge);
    assert.equal(authenticationOptions.allowCredentials, undefined);
    assert.ok(await passkeyStore.consume(authenticationOptions.challenge, "authentication"));

    const unknownPasskey = await app.request("/auth/passkeys/authenticate/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential: { id: "not-a-credential" } })
    });
    assert.equal(unknownPasskey.status, 401);

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

    // CloudflareD1DpopReplayStore verification
    const dpopReplayStore = new CloudflareD1DpopReplayStore(database);
    await dpopReplayStore.createTables();
    assert.equal(await dpopReplayStore.record("dpop-jti-1", 60), true);
    assert.equal(await dpopReplayStore.isUsed("dpop-jti-1"), true);
    // Replay attempt must return false
    assert.equal(await dpopReplayStore.record("dpop-jti-1", 60), false);
    // Distinct JTI must succeed
    assert.equal(await dpopReplayStore.record("dpop-jti-2", 60), true);
    assert.equal(await dpopReplayStore.isUsed("dpop-jti-2"), true);
    assert.equal(await dpopReplayStore.isUsed("non-existent-jti"), false);
    const concurrentDpopClaims = await Promise.all(
      Array.from({ length: 10 }, () => dpopReplayStore.record("dpop-jti-race", 60))
    );
    assert.equal(concurrentDpopClaims.filter(Boolean).length, 1);

    console.log("Cloudflare KV, D1, and Hono integration tests passed.");
  } finally {
    await miniflare.dispose();
  }
}

run().then(() => process.exit(0)).catch((err) => { console.error(err); process.exit(1); });
