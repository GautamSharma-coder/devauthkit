// test_webhooks.js
const express = require("express");
const devAuthKit = require("./server/server");
const {
  WebhookVerificationError,
  generateWebhookSecret,
  computeWebhookSignature,
  buildSignatureHeader,
  parseSignatureHeader,
  verifyWebhookSignature,
  matchesEvent,
  createWebhookHandler
} = require("./server/core/webhookService");
const { WebhookDispatcher, emitWebhookEvent } = require("./server/core/webhookDispatcher");
const { MemoryWebhookStore } = require("./server/stores/memoryWebhookStore");
const { CloudflareD1WebhookStore } = require("./server/stores/cloudflareD1WebhookStore");
const { Hono } = require("hono");
const { createAuthRouter } = require("./server/hono/index");
const { signJwt } = require("./server/utils/webCrypto");
const config = require("./server/config");

async function runWebhookTests() {
  console.log("🪝 Starting DevAuthKit Cryptographically Signed Webhooks Automated Verification...\n");

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

  // ==========================================
  // SECTION 1: Webhook Secret & Signature Primitives
  // ==========================================
  console.log("🔐 1. Webhook Secret Generation & Signature Computation...");

  const secret1 = generateWebhookSecret();
  assert(
    typeof secret1 === "string" && secret1.startsWith("whsec_") && secret1.length > 30,
    "generateWebhookSecret produces whsec_ prefixed high-entropy secret"
  );

  const customSecret = generateWebhookSecret("whsec_test_");
  assert(
    customSecret.startsWith("whsec_test_"),
    "generateWebhookSecret supports custom prefix"
  );

  const rawPayload = JSON.stringify({ id: "evt_123", event: "user.authenticated", data: { email: "alice@example.com" } });
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = await computeWebhookSignature(rawPayload, secret1, timestamp);

  assert(
    typeof signature === "string" && /^[0-9a-f]{64}$/.test(signature),
    "computeWebhookSignature outputs standard 64-char lowercase hex HMAC-SHA256"
  );

  const header = buildSignatureHeader(signature, timestamp);
  assert(
    header === `t=${timestamp},v1=${signature}`,
    "buildSignatureHeader formats Svix/Stripe compliant t=...,v1=... string"
  );

  const parsed = parseSignatureHeader(header);
  assert(
    parsed.timestamp === timestamp && parsed.signatures.length === 1 && parsed.signatures[0] === signature,
    "parseSignatureHeader accurately extracts timestamp and signature list"
  );

  // Multiple signatures in header (Secret rolling)
  const multiHeader = `t=${timestamp},v1=sig_old,v1=${signature}`;
  const parsedMulti = parseSignatureHeader(multiHeader);
  assert(
    parsedMulti.signatures.length === 2 && parsedMulti.signatures.includes(signature),
    "parseSignatureHeader supports multiple v1 signatures for zero-downtime secret rotation"
  );

  // ==========================================
  // SECTION 2: Signature Verification & Anti-Replay
  // ==========================================
  console.log("🛡️  2. Signature Verification & Replay Protection...");

  const validResult = await verifyWebhookSignature({
    rawBody: rawPayload,
    signatureHeader: header,
    secret: secret1,
    toleranceSeconds: 300
  });
  assert(Boolean(validResult) && validResult.event === "user.authenticated", "verifyWebhookSignature returns verified parsed event object");

  // Tamper detection
  const tamperedPayload = JSON.stringify({ id: "evt_123", event: "user.authenticated", data: { email: "eve@example.com" } });
  let tamperedFailed = false;
  try {
    await verifyWebhookSignature({
      rawBody: tamperedPayload,
      signatureHeader: header,
      secret: secret1
    });
  } catch (err) {
    tamperedFailed = err instanceof WebhookVerificationError && err.code === "ERR_SIGNATURE_MISMATCH";
  }
  assert(tamperedFailed, "verifyWebhookSignature throws ERR_SIGNATURE_MISMATCH when payload is modified");

  // Wrong secret detection
  let wrongSecretFailed = false;
  try {
    await verifyWebhookSignature({
      rawBody: rawPayload,
      signatureHeader: header,
      secret: "whsec_wrong_secret_1234567890"
    });
  } catch (err) {
    wrongSecretFailed = err instanceof WebhookVerificationError && err.code === "ERR_SIGNATURE_MISMATCH";
  }
  assert(wrongSecretFailed, "verifyWebhookSignature throws ERR_SIGNATURE_MISMATCH when secret does not match");

  // Expired timestamp replay attack
  const expiredTimestamp = Math.floor(Date.now() / 1000) - 600; // 10 minutes ago
  const expiredSig = await computeWebhookSignature(rawPayload, secret1, expiredTimestamp);
  const expiredHeader = buildSignatureHeader(expiredSig, expiredTimestamp);
  let expiredFailed = false;
  try {
    await verifyWebhookSignature({
      rawBody: rawPayload,
      signatureHeader: expiredHeader,
      secret: secret1,
      toleranceSeconds: 300
    });
  } catch (err) {
    expiredFailed = err instanceof WebhookVerificationError && err.code === "ERR_TIMESTAMP_OUTSIDE_TOLERANCE";
  }
  assert(expiredFailed, "verifyWebhookSignature throws ERR_TIMESTAMP_OUTSIDE_TOLERANCE for expired requests (anti-replay)");

  // Future timestamp defense
  const futureTimestamp = Math.floor(Date.now() / 1000) + 600; // 10 minutes in future
  const futureSig = await computeWebhookSignature(rawPayload, secret1, futureTimestamp);
  const futureHeader = buildSignatureHeader(futureSig, futureTimestamp);
  let futureFailed = false;
  try {
    await verifyWebhookSignature({
      rawBody: rawPayload,
      signatureHeader: futureHeader,
      secret: secret1,
      toleranceSeconds: 300
    });
  } catch (err) {
    futureFailed = err instanceof WebhookVerificationError && err.code === "ERR_TIMESTAMP_OUTSIDE_TOLERANCE";
  }
  assert(futureFailed, "verifyWebhookSignature throws ERR_TIMESTAMP_OUTSIDE_TOLERANCE for future timestamp skew");

  // Zero-downtime secret rotation verification
  const rolledMultiHeader = `t=${timestamp},v1=old_invalid_signature,v1=${signature}`;
  const rolledResult = await verifyWebhookSignature({
    rawBody: rawPayload,
    signatureHeader: rolledMultiHeader,
    secret: secret1
  });
  assert(Boolean(rolledResult), "verifyWebhookSignature validates successfully if ANY matching v1 signature is present");

  // ==========================================
  // SECTION 3: Event Pattern & Wildcard Matching
  // ==========================================
  console.log("🎯 3. Event Pattern & Wildcard Matching...");

  assert(matchesEvent("*", "user.authenticated") === true, "Wildcard '*' matches user.authenticated");
  assert(matchesEvent("*", "org.created") === true, "Wildcard '*' matches org.created");
  assert(matchesEvent("org.*", "org.created") === true, "Wildcard 'org.*' matches org.created");
  assert(matchesEvent("org.*", "org.member_added") === true, "Wildcard 'org.*' matches org.member_added");
  assert(matchesEvent("org.*", "user.authenticated") === false, "Wildcard 'org.*' does NOT match user.authenticated");
  assert(matchesEvent(["user.*", "session.*"], "session.revoked") === true, "Array of patterns ['user.*', 'session.*'] matches session.revoked");
  assert(matchesEvent(["user.*", "session.*"], "org.deleted") === false, "Array of patterns ['user.*', 'session.*'] rejects org.deleted");
  assert(matchesEvent("user.authenticated", "user.authenticated") === true, "Exact event match succeeds");
  assert(matchesEvent("user.authenticated", "user.logout") === false, "Exact event mismatch returns false");

  // ==========================================
  // SECTION 4: Webhook Receiver Middleware (createWebhookHandler)
  // ==========================================
  console.log("📥 4. Webhook Receiver Middleware (createWebhookHandler)...");

  let receivedEvent = null;
  const receiverHandler = createWebhookHandler({
    secret: secret1,
    onEvent: (evt) => {
      receivedEvent = evt;
    }
  });

  // Mock valid Express request
  const mockReq = {
    headers: {
      "devauth-signature": header
    },
    rawBody: rawPayload,
    body: JSON.parse(rawPayload)
  };
  let handlerResStatus = null;
  let handlerResJson = null;
  const mockRes = {
    status(code) {
      handlerResStatus = code;
      return this;
    },
    json(data) {
      handlerResJson = data;
      return this;
    }
  };

  await receiverHandler(mockReq, mockRes);
  assert(handlerResJson?.received === true, "createWebhookHandler returns { received: true } on authentic request");
  assert(receivedEvent?.event === "user.authenticated", "createWebhookHandler invokes onEvent callback with payload");

  // Mock invalid signature request
  const mockBadReq = {
    headers: {
      "devauth-signature": "t=123,v1=bad_signature"
    },
    rawBody: rawPayload,
    body: JSON.parse(rawPayload)
  };
  await receiverHandler(mockBadReq, mockRes);
  assert(handlerResStatus === 400 && handlerResJson?.error?.includes("Webhook verification failed"), "createWebhookHandler rejects invalid signature with HTTP 400");

  // ==========================================
  // SECTION 5: MemoryWebhookStore & Delivery Logs
  // ==========================================
  console.log("💾 5. MemoryWebhookStore Lifecycle & Delivery Tracking...");

  const memStore = new MemoryWebhookStore();
  const endpoint1 = await memStore.createEndpoint({
    url: "https://api.partner.com/webhooks",
    events: ["org.*", "user.authenticated"],
    metadata: { app: "crm-sync" }
  });

  assert(endpoint1.id && endpoint1.secret.startsWith("whsec_"), "MemoryWebhookStore auto-generates endpoint ID and secret");
  assert(endpoint1.events.includes("org.*") && endpoint1.active === true, "Endpoint stores events and active=true default");

  const fetched = await memStore.getEndpoint(endpoint1.id);
  assert(fetched.url === "https://api.partner.com/webhooks", "getEndpoint retrieves stored endpoint");

  const endpointsList = await memStore.listEndpoints();
  assert(endpointsList.length === 1 && endpointsList[0].id === endpoint1.id, "listEndpoints returns active endpoints");

  const updatedEndpoint = await memStore.updateEndpoint(endpoint1.id, {
    url: "https://api.partner.com/v2/webhooks",
    active: false
  });
  assert(updatedEndpoint.url === "https://api.partner.com/v2/webhooks" && updatedEndpoint.active === false, "updateEndpoint updates URL and active state");

  // Delivery log recording
  const deliveryRecord = await memStore.recordDelivery({
    endpointId: endpoint1.id,
    eventId: "evt_test_99",
    event: "org.created",
    payload: JSON.stringify({ orgId: "org_1" }),
    statusCode: 200,
    success: true,
    attempt: 1,
    durationMs: 42,
    timestamp: Date.now()
  });

  assert(deliveryRecord.id && deliveryRecord.success === true, "recordDelivery stores delivery attempt with ID");

  const deliveries = await memStore.listDeliveries(endpoint1.id);
  assert(deliveries.length === 1 && deliveries[0].statusCode === 200, "listDeliveries retrieves endpoint delivery history");

  const deleted = await memStore.deleteEndpoint(endpoint1.id);
  assert(deleted === true, "deleteEndpoint removes endpoint");
  const postDelete = await memStore.getEndpoint(endpoint1.id);
  assert(postDelete === null, "Endpoint is null after deletion");

  // ==========================================
  // SECTION 6: Cloudflare D1 Webhook Store Integration
  // ==========================================
  console.log("⚡ 6. Cloudflare D1 Edge SQLite Webhook Store...");

  const mockDbStatements = [];
  const mockD1Db = {
    prepare(query) {
      return {
        query,
        params: [],
        bind(...args) {
          this.params = args;
          return this;
        },
        async run() {
          mockDbStatements.push({ query: this.query, params: this.params, type: "run" });
          return { success: true, meta: { changes: 1 } };
        },
        async first() {
          mockDbStatements.push({ query: this.query, params: this.params, type: "first" });
          if (this.query.includes("webhook_endpoints WHERE id = ?")) {
            return {
              id: this.params[0],
              url: "https://edge.service.com/webhook",
              secret: "whsec_edge_secret_123",
              events: '["org.*"]',
              active: 1,
              metadata: '{"edge":true}',
              created_at: 1000,
              updated_at: 1000
            };
          }
          return null;
        },
        async all() {
          mockDbStatements.push({ query: this.query, params: this.params, type: "all" });
          if (this.query.includes("webhook_endpoints")) {
            return {
              results: [
                {
                  id: "wh_d1_1",
                  url: "https://edge.service.com/webhook",
                  secret: "whsec_edge_secret_123",
                  events: '["org.*"]',
                  active: 1,
                  metadata: '{"edge":true}',
                  created_at: 1000,
                  updated_at: 1000
                }
              ]
            };
          }
          if (this.query.includes("webhook_deliveries")) {
            return {
              results: [
                {
                  id: "del_1",
                  endpoint_id: "wh_d1_1",
                  event_id: "evt_1",
                  event: "org.created",
                  payload: "{}",
                  status_code: 200,
                  success: 1,
                  error: null,
                  attempt: 1,
                  duration_ms: 30,
                  timestamp: 1000
                }
              ]
            };
          }
          return { results: [] };
        }
      };
    },
    async batch(statements) {
      return Promise.all(statements.map((s) => s.run()));
    }
  };

  const d1Store = new CloudflareD1WebhookStore(mockD1Db);
  const d1Endpoint = await d1Store.createEndpoint({
    url: "https://edge.service.com/webhook",
    events: ["org.*"],
    metadata: { edge: true }
  });
  assert(d1Endpoint.url === "https://edge.service.com/webhook", "CloudflareD1WebhookStore creates endpoint with prepared SQL");

  const d1Fetched = await d1Store.getEndpoint("wh_d1_1");
  assert(d1Fetched.id === "wh_d1_1" && d1Fetched.events.includes("org.*"), "CloudflareD1WebhookStore deserializes SQL JSON fields");

  const d1List = await d1Store.listEndpoints();
  assert(d1List.length === 1 && d1List[0].active === true, "CloudflareD1WebhookStore lists endpoints");

  await d1Store.recordDelivery({
    endpointId: "wh_d1_1",
    eventId: "evt_1",
    event: "org.created",
    payload: "{}",
    statusCode: 200,
    success: true,
    attempt: 1,
    durationMs: 30,
    timestamp: 1000
  });
  const d1Deliveries = await d1Store.listDeliveries("wh_d1_1");
  assert(d1Deliveries.length === 1 && d1Deliveries[0].success === true, "CloudflareD1WebhookStore records and queries delivery logs");

  // ==========================================
  // SECTION 7: Dispatcher with Backoff Retries & Network Mock
  // ==========================================
  console.log("🚀 7. Webhook Dispatcher & Exponential Backoff Delivery...");

  const testStore = new MemoryWebhookStore();
  const testEndpoint = await testStore.createEndpoint({
    url: "https://api.myclient.com/webhooks",
    events: ["org.*", "user.*"]
  });

  const dispatchedRequests = [];
  const mockFetch = async (url, opts) => {
    dispatchedRequests.push({ url, opts });
    return {
      ok: true,
      status: 200,
      text: async () => "OK"
    };
  };

  const dispatcher = new WebhookDispatcher({
    store: testStore,
    fetchImpl: mockFetch,
    timeoutMs: 1000,
    retryDelays: [10, 20]
  });

  const eventId = await dispatcher.emit("org.created", {
    id: "org_alpha",
    name: "Alpha Corp"
  });

  // Give microtask queue time to deliver
  await new Promise((resolve) => setTimeout(resolve, 50));

  assert(dispatchedRequests.length === 1, "Dispatcher delivered event to matching subscribed endpoint");
  const sentReq = dispatchedRequests[0];
  assert(sentReq.opts.headers["DevAuth-Event"] === "org.created", "Dispatched HTTP request includes DevAuth-Event header");
  assert(sentReq.opts.headers["DevAuth-Event-Id"] === eventId, "Dispatched HTTP request includes matching DevAuth-Event-Id header");
  assert(sentReq.opts.headers["DevAuth-Signature"]?.startsWith("t="), "Dispatched HTTP request includes DevAuth-Signature header");

  // Verify delivery record was written to store
  const recordedDeliveries = await testStore.listDeliveries(testEndpoint.id);
  assert(recordedDeliveries.length === 1 && recordedDeliveries[0].success === true, "Dispatcher records successful delivery in store");

  // Test Retry on Failure
  let failAttempts = 0;
  const failingFetch = async (url, opts) => {
    failAttempts++;
    if (failAttempts < 3) {
      throw new Error("Temporary network timeout");
    }
    return { ok: true, status: 200, text: async () => "Recovered" };
  };

  const retryDispatcher = new WebhookDispatcher({
    store: testStore,
    fetchImpl: failingFetch,
    timeoutMs: 500,
    maxRetries: 2,
    retryDelays: [10, 20]
  });

  await retryDispatcher._deliverToEndpoint(testEndpoint, "evt_retry_1", "user.authenticated", "{}", Math.floor(Date.now() / 1000));
  assert(failAttempts === 3, "Dispatcher retried failed HTTP request up to maxRetries using backoff");

  // ==========================================
  // SECTION 8: Express Full Server & /auth/webhooks Admin Endpoints
  // ==========================================
  console.log("🌐 8. Express Server Integration & /auth/webhooks Endpoints...");

  const expressApp = express();
  const serverStore = new MemoryWebhookStore();
  devAuthKit(expressApp, {
    webhooks: true,
    webhookStore: serverStore,
    customFetch: async () => ({ ok: true, status: 200, text: async () => "OK" }),
    jwtSecret: "test-jwt-secret-at-least-32-characters-long!!",
    sessionSecret: "test-session-secret-at-least-32-characters!!",
    devMode: true
  });

  const server = expressApp.listen(0);
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;

  // Generate an auth token for admin user
  const adminToken = await signJwt(
    { id: "usr_admin_1", email: "admin@corp.com", role: "admin" },
    "test-jwt-secret-at-least-32-characters-long!!",
    "1h"
  );

  try {
    // 1. Create Webhook Endpoint via API
    const createRes = await fetch(`${baseUrl}/auth/webhooks`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        url: "https://myservice.com/events",
        events: ["org.*", "user.*"],
        metadata: { environment: "production" }
      })
    });
    const createJson = await createRes.json();
    assert(createRes.status === 201 && createJson.endpoint?.id, "POST /auth/webhooks creates new endpoint (HTTP 201)");
    const createdEpId = createJson.endpoint?.id;
    assert(createJson.endpoint.secret.startsWith("whsec_"), "Created endpoint includes generated webhook secret");

    // 2. List Webhook Endpoints
    const listRes = await fetch(`${baseUrl}/auth/webhooks`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    const listJson = await listRes.json();
    assert(listRes.status === 200 && listJson.endpoints?.length === 1, "GET /auth/webhooks lists endpoints");

    // 3. Get Webhook Endpoint by ID
    const getRes = await fetch(`${baseUrl}/auth/webhooks/${createdEpId}`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    const getJson = await getRes.json();
    assert(getRes.status === 200 && getJson.endpoint?.url === "https://myservice.com/events", "GET /auth/webhooks/:id retrieves specific endpoint");

    // 4. Update Webhook Endpoint
    const patchRes = await fetch(`${baseUrl}/auth/webhooks/${createdEpId}`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${adminToken}`
      },
      body: JSON.stringify({ events: ["*"] })
    });
    const patchJson = await patchRes.json();
    assert(patchRes.status === 200 && patchJson.endpoint?.events.includes("*"), "PATCH /auth/webhooks/:id updates endpoint events to wildcard '*'");

    // 5. Test Webhook Ping
    const testPingRes = await fetch(`${baseUrl}/auth/webhooks/${createdEpId}/test`, {
      method: "POST",
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    const testPingJson = await testPingRes.json();
    assert(testPingRes.status === 200 && testPingJson.success === true, "POST /auth/webhooks/:id/test sends webhook.test event");

    // 6. List Deliveries
    const delivRes = await fetch(`${baseUrl}/auth/webhooks/${createdEpId}/deliveries`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    const delivJson = await delivRes.json();
    assert(delivRes.status === 200 && Array.isArray(delivJson.deliveries), "GET /auth/webhooks/:id/deliveries returns delivery logs");

    // 7. Delete Webhook Endpoint
    const deleteRes = await fetch(`${baseUrl}/auth/webhooks/${createdEpId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    const deleteJson = await deleteRes.json();
    assert(deleteRes.status === 200 && deleteJson.success === true, "DELETE /auth/webhooks/:id removes endpoint");

    // Unauthenticated check
    const unauthRes = await fetch(`${baseUrl}/auth/webhooks`);
    assert(unauthRes.status === 401, "GET /auth/webhooks rejects unauthenticated access with HTTP 401");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }

  // ==========================================
  // SECTION 9: Hono Edge Worker Parity
  // ==========================================
  console.log("☁️  9. Cloudflare Workers / Hono Adapter Parity...");

  const honoStore = new MemoryWebhookStore();
  const honoRouter = createAuthRouter({
    webhooks: true,
    webhookStore: honoStore,
    jwtSecret: "test-jwt-secret-at-least-32-characters-long!!",
    sessionSecret: "test-session-secret-at-least-32-characters!!"
  });

  // Test Hono creation of webhook
  const honoCreateReq = new Request("http://localhost/auth/webhooks", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${adminToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      url: "https://worker.target.com/webhooks",
      events: ["org.*"]
    })
  });
  const honoCreateRes = await honoRouter.fetch(honoCreateReq);
  const honoCreateJson = await honoCreateRes.json();
  assert(honoCreateRes.status === 201 && honoCreateJson.endpoint?.id, "Hono worker POST /auth/webhooks creates webhook endpoint");

  // Test Hono listing of webhooks
  const honoListReq = new Request("http://localhost/auth/webhooks", {
    method: "GET",
    headers: {
      "Authorization": `Bearer ${adminToken}`
    }
  });
  const honoListRes = await honoRouter.fetch(honoListReq);
  const honoListJson = await honoListRes.json();
  assert(honoListRes.status === 200 && honoListJson.endpoints?.length === 1, "Hono worker GET /auth/webhooks lists endpoints");

  // ==========================================
  // SUMMARY
  // ==========================================
  console.log("\n========================================================");
  console.log(`🎉 Webhooks Test Results: ${passed} / ${total} tests passed!`);
  console.log("========================================================\n");

  process.exit(passed === total ? 0 : 1);
}
runWebhookTests().catch((err) => {
  console.error("Unhandled error in webhook tests:", err);
  process.exit(1);
});
