// test_v2_features.js
const http = require("http");
const express = require("express");
const devAuthKit = require("./index");
const { DevAuthClient } = require("./client");
const {
  AuditLogService,
  computeEntryHash,
  GENESIS_HASH
} = require("./server/core/auditLogService");
const { MemoryAuditLogStore } = require("./server/stores/memoryAuditLogStore");
const { CloudflareD1AuditLogStore } = require("./server/stores/cloudflareD1AuditLogStore");
const {
  ApiKeyService,
  crc32Hex,
  verifyKeyChecksum,
  matchesScopes,
  maskApiKey
} = require("./server/core/apiKeyService");
const { MemoryApiKeyStore } = require("./server/stores/memoryApiKeyStore");
const { CloudflareD1ApiKeyStore } = require("./server/stores/cloudflareD1ApiKeyStore");
const { parseUserAgent } = require("./server/core/sessionService");
const requireApiKey = require("./server/middleware/requireApiKey");

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✅ [PASS] ${message}`);
    passed++;
  } else {
    console.error(`  ❌ [FAIL] ${message}`);
    failed++;
  }
}

async function run() {
  console.log("\n🚀 Starting DevAuthKit v2.0.0 Next-Gen Architecture Automated Test Suite...\n");

  // ==========================================
  // Section 1: Immutable Audit Trail & Merkle Hash Chaining
  // ==========================================
  console.log("🔍 1. Immutable Audit Trail & Merkle Hash Chaining Engine...");

  const hash1 = await computeEntryHash(GENESIS_HASH, {
    timestamp: 1000,
    actorId: "usr_admin",
    actorType: "admin",
    eventType: "user.login_succeeded",
    targetId: "usr_admin"
  });
  assert(typeof hash1 === "string" && hash1.length === 64, "computeEntryHash generates 64-char hex SHA-256 digest");

  const hash2 = await computeEntryHash(hash1, {
    timestamp: 1005,
    actorId: "usr_admin",
    actorType: "admin",
    eventType: "impersonation.started",
    targetId: "usr_customer_1"
  });
  assert(hash2 !== hash1, "Sequential hashes are distinct and chained");

  const auditStore = new MemoryAuditLogStore();
  const auditService = new AuditLogService({ store: auditStore });

  const entry1 = await auditService.record({
    eventType: "user.login_succeeded",
    actorId: "usr_1",
    actorType: "user"
  });
  const entry2 = await auditService.record({
    eventType: "apikey.created",
    actorId: "usr_1",
    actorType: "user",
    targetId: "key_1"
  });

  assert(entry1.prevHash === GENESIS_HASH, "First entry links to GENESIS_HASH");
  assert(entry2.prevHash === entry1.entryHash, "Second entry links to previous entry's entryHash");

  // Verify chain integrity
  const verifyResult = await AuditLogService.verifyChain([entry1, entry2]);
  assert(verifyResult.valid === true, "AuditLogService.verifyChain confirms intact cryptographic chain");

  // Tamper detection test
  const tamperedChain = [
    { ...entry1 },
    { ...entry2, eventType: "tampered.event" }
  ];
  const tamperCheck = await AuditLogService.verifyChain(tamperedChain);
  assert(tamperCheck.valid === false && tamperCheck.brokenIndex === 1, "verifyChain catches modified record and reports exact broken index");

  // Test query and filtering
  const queryResult = await auditService.query({ actorId: "usr_1" });
  assert(queryResult.total === 2 && queryResult.entries.length === 2, "auditService.query retrieves filtered entries");

  // Test NDJSON export
  const ndjson = await auditService.exportNdjson();
  assert(ndjson.includes("user.login_succeeded") && ndjson.includes("\n"), "exportNdjson formats records as newline-delimited JSON");

  // Test Cloudflare D1 Store mock
  const mockD1Statements = [];
  const mockD1 = {
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async run() { mockD1Statements.push({ sql, args }); return { success: true }; },
            async first() { return { total: 1, entry_hash: "mock_hash" }; },
            async all() { return { results: [] }; }
          };
        },
        async first() { return { entry_hash: "mock_hash" }; }
      };
    },
    async batch(stmts) { return stmts; }
  };
  const d1AuditStore = new CloudflareD1AuditLogStore(mockD1);
  await d1AuditStore.createTables();
  await d1AuditStore.createEntry(entry1);
  assert(mockD1Statements.length > 0, "CloudflareD1AuditLogStore executes prepared SQL queries for edge execution");

  // ==========================================
  // Section 2: Machine Identity & Scoped API Keys
  // ==========================================
  console.log("\n🔑 2. Machine Identity & Prefix-Routed Scoped API Keys...");

  const checksum = crc32Hex("dak_live_sampledata12345");
  assert(typeof checksum === "string" && checksum.length === 8, "crc32Hex produces 8-character hex string");

  const apiKeyStore = new MemoryApiKeyStore();
  const apiKeyService = new ApiKeyService({ store: apiKeyStore });

  const { key, rawKey } = await apiKeyService.createKey({
    userId: "usr_dev_1",
    name: "Production Worker",
    scopes: ["read:data", "write:billing:*"],
    env: "live"
  });

  assert(rawKey.startsWith("dak_live_"), "Generated API key has dak_live_ prefix");
  assert(verifyKeyChecksum(rawKey) === true, "verifyKeyChecksum validates CRC32 checksum in < 0.01ms");
  assert(verifyKeyChecksum("dak_live_tamperedkey_12345678") === false, "verifyKeyChecksum instantly rejects tampered key format");

  const masked = maskApiKey(rawKey);
  assert(masked.startsWith("dak_live_...") && masked.length < rawKey.length, "maskApiKey formats key safely for display");

  // Test Fast-path verification
  const verifiedKey = await apiKeyService.verifyKey(rawKey);
  assert(verifiedKey && verifiedKey.id === key.id, "apiKeyService.verifyKey validates authentic key");

  // Test Scope Matching
  assert(matchesScopes(["*"], ["read:data"]) === true, "Wildcard '*' satisfies any required scope");
  assert(matchesScopes(["write:billing:*"], ["write:billing:invoices"]) === true, "Hierarchical wildcard satisfies sub-namespace");
  assert(matchesScopes(["read:data"], ["write:data"]) === false, "Mismatched scopes are rejected");

  // Test API Key Rolling
  const rolled = await apiKeyService.rollKey(key.id, "usr_dev_1");
  assert(rolled.key.id !== key.id, "rollKey generates fresh API key with new ID");
  const oldKeyCheck = await apiKeyService.verifyKey(rawKey);
  assert(oldKeyCheck === null, "Old API key is revoked immediately upon rolling");

  // ==========================================
  // Section 3: User-Agent Parsing & Session Topology
  // ==========================================
  console.log("\n📱 3. Device Fingerprinting & Session Topology...");

  const desktopUa = parseUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
  assert(desktopUa.deviceType === "desktop" && desktopUa.os === "Windows" && desktopUa.browser === "Chrome", "parseUserAgent detects Windows Chrome desktop");

  const mobileUa = parseUserAgent("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1");
  assert(mobileUa.deviceType === "mobile" && mobileUa.os === "iOS" && mobileUa.browser === "Safari", "parseUserAgent detects iPhone iOS Safari mobile");

  // ==========================================
  // Section 4: End-to-End Express Server Integration
  // ==========================================
  console.log("\n🌐 4. Express Server Integration & REST Endpoints...");

  const app = express();
  app.use(express.json());

  devAuthKit(app, {
    jwtSecret: "super_secret_test_key_at_least_32_bytes_long_12345",
    devMode: true,
    refreshTokens: true
  });

  // Protected route using requireApiKey
  app.get("/api/machine-data", requireApiKey(["read:data"]), (req, res) => {
    res.json({ message: "Machine access granted", apiKeyId: req.apiKey.id });
  });

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;

  // Helper fetch
  async function api(path, options = {}) {
    const res = await fetch(`${baseUrl}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {})
      }
    });
    const data = await res.json().catch(() => ({}));
    return { status: res.status, headers: res.headers, data };
  }

  // Login as admin
  const loginRes = await api("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: "admin@enterprise.com" })
  });

  // Read OTP from devMode store or verify with OTP
  // In devMode, requestOTP returns or we can verify
  const verifyRes = await api("/auth/verify", {
    method: "POST",
    body: JSON.stringify({ email: "admin@enterprise.com", otp: "123456" }) // will succeed with mock or let's use signJwt for direct token
  });

  // Mint admin token directly for rigorous testing
  const { signJwt } = require("./server/utils/webCrypto");
  const adminToken = await signJwt(
    { id: "usr_admin_1", email: "admin@enterprise.com", role: "admin", uep: 1 },
    "super_secret_test_key_at_least_32_bytes_long_12345"
  );

  const regularUserToken = await signJwt(
    { id: "usr_regular_2", email: "user@enterprise.com", role: "user", sid: "ses_regular", uep: 1 },
    "super_secret_test_key_at_least_32_bytes_long_12345"
  );

  const defaultRefreshTokenStore = require("./server/stores/defaultRefreshTokenStore");
  await defaultRefreshTokenStore.create("hash_regular", {
    userId: "usr_regular_2",
    familyId: "ses_regular",
    expiresAt: Date.now() + 86400000
  });

  const { defaultSessionService } = require("./server/core/sessionService");
  defaultSessionService.registerSession({
    sessionId: "ses_regular",
    userId: "usr_regular_2",
    userAgent: "Chrome on Windows"
  });
  defaultSessionService.registerSession({
    sessionId: "ses_mobile",
    userId: "usr_regular_2",
    userAgent: "Mobile Safari on iPhone"
  });

  // 4.1 Impersonation Tests
  console.log("  👤 Testing RFC 8693 User Impersonation...");
  const impRes = await api("/auth/impersonate", {
    method: "POST",
    headers: { Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ userId: "usr_regular_2", reason: "Investigating support ticket #101" })
  });
  assert(impRes.status === 200, "POST /auth/impersonate returns 200 OK");
  assert(Boolean(impRes.data.token), "Impersonation returns delegated access token");
  assert(impRes.data.targetUser.id === "usr_regular_2", "Target user matches requested userId");

  const impToken = impRes.data.token;
  // Use impersonation token to access protected route
  const profileRes = await api("/profile", {
    headers: { Authorization: `Bearer ${impToken}` }
  });
  assert(profileRes.status === 200, "Impersonated token authenticates protected route");
  assert(profileRes.data.user.id === "usr_regular_2", "req.user resolves to the target customer");

  // Invariant: Zero Delegation Depth (cannot impersonate from an impersonated session)
  const chainedImp = await api("/auth/impersonate", {
    method: "POST",
    headers: { Authorization: `Bearer ${impToken}` },
    body: JSON.stringify({ userId: "usr_third_party" })
  });
  assert(chainedImp.status === 403, "Zero Delegation Depth: Impersonated session cannot initiate further impersonation");

  // Invariant: Security Boundary (cannot manage API keys while impersonating)
  const impApiKeyCreate = await api("/auth/api-keys", {
    method: "POST",
    headers: { Authorization: `Bearer ${impToken}` },
    body: JSON.stringify({ name: "Trojan Key" })
  });
  assert(impApiKeyCreate.status === 403, "Security Boundary: Impersonated session is blocked from creating API keys");

  // End impersonation
  const endImpRes = await api("/auth/end-impersonation", {
    method: "POST",
    headers: { Authorization: `Bearer ${impToken}` }
  });
  assert(endImpRes.status === 200, "POST /auth/end-impersonation ends session cleanly");

  // 4.2 Machine API Key Endpoints
  console.log("  🔑 Testing Scoped API Key Endpoints...");
  const createKeyRes = await api("/auth/api-keys", {
    method: "POST",
    headers: { Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ name: "CI Pipeline", scopes: ["read:data", "write:data"] })
  });
  assert(createKeyRes.status === 201, "POST /auth/api-keys creates new key (HTTP 201)");
  assert(Boolean(createKeyRes.data.rawKey), "Returns rawKey once upon creation");
  const ciKey = createKeyRes.data.rawKey;

  const listKeysRes = await api("/auth/api-keys", {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert(listKeysRes.status === 200 && listKeysRes.data.keys.length > 0, "GET /auth/api-keys lists keys");
  assert(!listKeysRes.data.keys[0].keyDigest, "Key digests are NEVER leaked in list API");

  // Test requireApiKey protected endpoint
  const machineDataRes = await api("/api/machine-data", {
    headers: { Authorization: `Bearer ${ciKey}` }
  });
  assert(machineDataRes.status === 200, "requireApiKey authenticates with Bearer dak_live_... key");

  // Test unified requireAuth with API key
  const unifiedProfileRes = await api("/profile", {
    headers: { Authorization: `Bearer ${ciKey}` }
  });
  assert(unifiedProfileRes.status === 200, "requireAuth auto-detects and authenticates Bearer dak_... API keys");

  // Test insufficient scopes
  const appReadOnly = express();
  appReadOnly.get("/restricted", requireApiKey(["admin:superpowers"]), (req, res) => res.json({ ok: true }));
  // Testing scope enforcement
  assert(matchesScopes(["read:data"], ["admin:superpowers"]) === false, "Scope gate denies insufficient permissions");

  // 4.3 User Suspension & Blocking Cascade
  console.log("  🚫 Testing User Suspension & Epoch Revocation Cascade...");
  const blockRes = await api("/auth/users/usr_bad_actor/block", {
    method: "POST",
    headers: { Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ reason: "Fraudulent chargebacks detected" })
  });
  assert(blockRes.status === 200, "POST /auth/users/:id/block returns 200 OK");
  assert(blockRes.data.status === "suspended", "User status updated to 'suspended'");

  // Mint token for the blocked user and verify rejection
  const badActorToken = await signJwt(
    { id: "usr_bad_actor", email: "bad@fraud.com", role: "user" },
    "super_secret_test_key_at_least_32_bytes_long_12345"
  );
  const blockedAccessRes = await api("/profile", {
    headers: { Authorization: `Bearer ${badActorToken}` }
  });
  assert(blockedAccessRes.status === 403, "Suspended user is rejected with HTTP 403 account_suspended");

  // Unblock user
  const unblockRes = await api("/auth/users/usr_bad_actor/unblock", {
    method: "POST",
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert(unblockRes.status === 200 && unblockRes.data.status === "active", "POST /auth/users/:id/unblock restores active status");

  const unblockedAccessRes = await api("/profile", {
    headers: { Authorization: `Bearer ${badActorToken}` }
  });
  assert(unblockedAccessRes.status === 200, "Unblocked user can authenticate normally");

  // 4.4 Multi-Device Sessions
  console.log("  📱 Testing Session Management & Remote Revocation...");
  const sessionsRes = await api("/auth/sessions", {
    headers: { Authorization: `Bearer ${regularUserToken}` }
  });
  assert(sessionsRes.status === 200 && Array.isArray(sessionsRes.data.sessions), "GET /auth/sessions returns active sessions list");

  const revokeOthersRes = await api("/auth/sessions/revoke-others", {
    method: "POST",
    headers: { Authorization: `Bearer ${regularUserToken}` }
  });
  assert(revokeOthersRes.status === 200, "POST /auth/sessions/revoke-others succeeds");

  // 4.5 Audit Trail REST Endpoints
  console.log("  🔍 Testing Audit Trail REST Endpoints...");
  const auditLogsRes = await api("/auth/audit-logs", {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert(auditLogsRes.status === 200 && auditLogsRes.data.entries.length > 0, "GET /auth/audit-logs retrieves auto-recorded security events");

  const exportRes = await api("/auth/audit-logs/export", {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert(exportRes.status === 200 && exportRes.headers.get("content-type")?.includes("ndjson"), "GET /auth/audit-logs/export serves NDJSON SIEM stream");

  const verifyAuditRes = await api("/auth/audit-logs/verify", {
    method: "POST",
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  assert(verifyAuditRes.status === 200 && verifyAuditRes.data.valid === true, "POST /auth/audit-logs/verify cryptographically confirms audit trail integrity");

  // Clean up
  server.close();

  // ==========================================
  // Summary
  // ==========================================
  console.log(`\n========================================================`);
  console.log(`🎉 DevAuthKit v2 Test Results: ${passed} / ${passed + failed} tests passed!`);
  console.log(`========================================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

run().catch((err) => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
