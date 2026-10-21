// test_dpop.js
const {
  DPoPError,
  calculateAccessTokenHash,
  calculateJwkThumbprint,
  createDPoPProof,
  generateDPoPKeyPair,
  normalizeTargetUri,
  verifyDPoPProof
} = require("./server/core/dpopService");
const { MemoryDpopReplayStore } = require("./server/stores/memoryDpopReplayStore");
const express = require("express");
const sessionStore = require("./server/sessionStore");
const devAuthKit = require("./server/server");
const { Hono } = require("hono");
const { createAuthRouter, requireAuth: honoRequireAuth, requireDPoP: honoRequireDPoP } = require("./server/hono");

async function runDPoPTests() {
  console.log("🛡️ Starting DevAuthKit DPoP (RFC 9449) Automated Cryptographic Verification...\n");

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

  // 1. Target URI Normalization
  console.log("📍 Testing Target URI Normalization (RFC 9449 Section 4.3)...");
  assert(
    normalizeTargetUri("https://api.example.com/api/dashboard?tab=security#hash") ===
      "https://api.example.com/api/dashboard",
    "Strips query strings and fragment from absolute URI"
  );
  assert(
    normalizeTargetUri("/api/dashboard?token=xyz") === "/api/dashboard",
    "Strips query string from relative path"
  );
  assert(
    normalizeTargetUri("https://api.example.com/api/v1/auth") ===
      "https://api.example.com/api/v1/auth",
    "Preserves clean absolute URI unchanged"
  );

  // 2. Key Generation & RFC 7638 Thumbprints
  console.log("\n🔑 Testing Key Generation & RFC 7638 JWK Thumbprints...");
  const { privateKey, jwk, keyPair } = await generateDPoPKeyPair();
  assert(
    jwk.kty === "EC" && jwk.crv === "P-256" && typeof jwk.x === "string" && typeof jwk.y === "string",
    "generateDPoPKeyPair exports valid EC P-256 public JWK"
  );
  assert(jwk.d === undefined, "Public JWK does not expose private key material ('d')");

  const thumbprint1 = await calculateJwkThumbprint(jwk);
  assert(
    typeof thumbprint1 === "string" && thumbprint1.length === 43,
    `Calculates 43-character Base64URL SHA-256 JWK thumbprint (${thumbprint1})`
  );

  // Ensure lexicographical order invariance in calculation
  const shuffledJwk = { y: jwk.y, kty: jwk.kty, x: jwk.x, crv: jwk.crv };
  const thumbprint2 = await calculateJwkThumbprint(shuffledJwk);
  assert(
    thumbprint1 === thumbprint2,
    "JWK thumbprint calculation is invariant to JSON property order (RFC 7638 canonical form)"
  );

  // 3. Access Token Hash (ath)
  console.log("\n🔒 Testing Access Token Hash (ath)...");
  const sampleToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sample_token_payload";
  const ath = await calculateAccessTokenHash(sampleToken);
  assert(
    typeof ath === "string" && ath.length === 43,
    `Calculates RFC 9449 compliant Base64URL SHA-256 access token hash (${ath})`
  );

  // 4. Valid Proof Creation & Verification (Phase A: Login without access token)
  console.log("\n⚡ Testing DPoP Proof Verification (Login / Token Endpoint)...");
  const loginProof = await createDPoPProof({
    privateKey,
    jwk,
    method: "POST",
    uri: "https://api.example.com/auth/verify-otp"
  });

  const loginVerification = await verifyDPoPProof({
    proofJwt: loginProof,
    expectedMethod: "POST",
    expectedUri: "https://api.example.com/auth/verify-otp"
  });

  assert(
    loginVerification.valid === true && loginVerification.jkt === thumbprint1,
    "Successfully verifies valid login DPoP proof and extracts matching jkt thumbprint"
  );

  // 5. Valid Proof with Access Token Binding (Phase B: Resource Request with ath)
  console.log("\n🛡️ Testing Resource Access with DPoP-Bound Access Token (ath)...");
  const resourceProof = await createDPoPProof({
    privateKey,
    jwk,
    method: "GET",
    uri: "https://api.example.com/api/dashboard",
    accessToken: sampleToken
  });

  const resourceVerification = await verifyDPoPProof({
    proofJwt: resourceProof,
    expectedMethod: "GET",
    expectedUri: "https://api.example.com/api/dashboard",
    expectedAccessToken: sampleToken
  });

  assert(
    resourceVerification.valid === true && resourceVerification.jkt === thumbprint1,
    "Successfully validates DPoP proof with matching access token hash (ath)"
  );

  // Relative URI matching tolerance
  const relativeVerification = await verifyDPoPProof({
    proofJwt: resourceProof,
    expectedMethod: "GET",
    expectedUri: "/api/dashboard",
    expectedAccessToken: sampleToken
  });
  assert(
    relativeVerification.valid === true,
    "Tolerates relative expectedUri pathname matching against absolute proof target URI"
  );

  // 6. Security Violations & Negative Assertions
  console.log("\n🚫 Testing Security Attack Mitigations & Error Handling...");

  // 6.1 Tampered payload
  const proofParts = resourceProof.split(".");
  const tamperedPayload = JSON.parse(Buffer.from(proofParts[1], "base64url").toString());
  tamperedPayload.htm = "DELETE"; // attacker changes GET to DELETE
  const tamperedProof = `${proofParts[0]}.${Buffer.from(JSON.stringify(tamperedPayload)).toString("base64url")}.${proofParts[2]}`;

  let tamperedCaught = false;
  try {
    await verifyDPoPProof({
      proofJwt: tamperedProof,
      expectedMethod: "DELETE",
      expectedUri: "https://api.example.com/api/dashboard"
    });
  } catch (err) {
    tamperedCaught = err instanceof DPoPError && err.code === "invalid_dpop_proof";
  }
  assert(tamperedCaught, "Rejects tampered DPoP proof with invalid signature");

  // 6.2 Signed by wrong key (different private key than claimed JWK)
  const anotherKey = await generateDPoPKeyPair();
  const spoofedProof = await createDPoPProof({
    privateKey: anotherKey.privateKey,
    jwk, // Claims to be key 1, but signed by key 2!
    method: "GET",
    uri: "https://api.example.com/api/dashboard"
  });

  let spoofCaught = false;
  try {
    await verifyDPoPProof({
      proofJwt: spoofedProof,
      expectedMethod: "GET",
      expectedUri: "https://api.example.com/api/dashboard"
    });
  } catch (err) {
    spoofCaught = err instanceof DPoPError && err.code === "invalid_dpop_proof";
  }
  assert(spoofCaught, "Rejects proof where signature does not match embedded header JWK");

  // 6.3 HTTP Method mismatch
  let methodMismatchCaught = false;
  try {
    await verifyDPoPProof({
      proofJwt: resourceProof,
      expectedMethod: "POST", // Proof was created for GET
      expectedUri: "https://api.example.com/api/dashboard",
      expectedAccessToken: sampleToken
    });
  } catch (err) {
    methodMismatchCaught = err instanceof DPoPError && err.message.includes("DPoP method mismatch");
  }
  assert(methodMismatchCaught, "Rejects DPoP proof when HTTP method (htm) mismatches");

  // 6.4 Target URI mismatch
  let uriMismatchCaught = false;
  try {
    await verifyDPoPProof({
      proofJwt: resourceProof,
      expectedMethod: "GET",
      expectedUri: "https://api.example.com/api/admin/settings",
      expectedAccessToken: sampleToken
    });
  } catch (err) {
    uriMismatchCaught = err instanceof DPoPError && err.message.includes("DPoP target URI mismatch");
  }
  assert(uriMismatchCaught, "Rejects DPoP proof when HTTP target URI (htu) mismatches");

  // 6.5 Access Token Hash (ath) mismatch
  let athMismatchCaught = false;
  try {
    await verifyDPoPProof({
      proofJwt: resourceProof,
      expectedMethod: "GET",
      expectedUri: "https://api.example.com/api/dashboard",
      expectedAccessToken: "stolen_or_different_access_token"
    });
  } catch (err) {
    athMismatchCaught = err instanceof DPoPError && err.message.includes("ath");
  }
  assert(athMismatchCaught, "Rejects request when access token hash (ath) does not match token presented");

  // 6.6 Clock Skew / Expired Proof
  const oldIat = Math.floor(Date.now() / 1000) - 120; // 2 minutes ago
  const expiredProof = await createDPoPProof({
    privateKey,
    jwk,
    method: "GET",
    uri: "https://api.example.com/api/dashboard",
    iat: oldIat
  });

  let expiredCaught = false;
  try {
    await verifyDPoPProof({
      proofJwt: expiredProof,
      expectedMethod: "GET",
      expectedUri: "https://api.example.com/api/dashboard",
      maxClockSkewSeconds: 60
    });
  } catch (err) {
    expiredCaught = err instanceof DPoPError && err.message.includes("clock skew");
  }
  assert(expiredCaught, "Rejects expired DPoP proof exceeding maximum clock skew (60s)");

  // 6.7 Header contains private key material (d)
  const maliciousHeader = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: { ...jwk, d: "malicious_private_key_material" }
  };
  const malformedProof = `${Buffer.from(JSON.stringify(maliciousHeader)).toString("base64url")}.${proofParts[1]}.${proofParts[2]}`;

  let privateKeyLeakedCaught = false;
  try {
    await verifyDPoPProof({
      proofJwt: malformedProof,
      expectedMethod: "GET",
      expectedUri: "https://api.example.com/api/dashboard"
    });
  } catch (err) {
    privateKeyLeakedCaught = err instanceof DPoPError && err.message.includes("private key material");
  }
  assert(privateKeyLeakedCaught, "Rejects proof header if JWK contains private key component 'd'");

  // 6.8 Invalid header typ (must be dpop+jwt)
  const wrongTypHeader = { typ: "JWT", alg: "ES256", jwk };
  const wrongTypProof = `${Buffer.from(JSON.stringify(wrongTypHeader)).toString("base64url")}.${proofParts[1]}.${proofParts[2]}`;

  let wrongTypCaught = false;
  try {
    await verifyDPoPProof({
      proofJwt: wrongTypProof,
      expectedMethod: "GET",
      expectedUri: "https://api.example.com/api/dashboard"
    });
  } catch (err) {
    wrongTypCaught = err instanceof DPoPError && err.message.includes("typ: expected 'dpop+jwt'");
  }
  assert(wrongTypCaught, "Rejects proof header if typ is not 'dpop+jwt'");

  // 7. Replay Protection with MemoryDpopReplayStore
  console.log("\n🛡️ Testing Replay Protection Shield (MemoryDpopReplayStore)...");
  const replayStore = new MemoryDpopReplayStore();
  const freshProof = await createDPoPProof({
    privateKey,
    jwk,
    method: "POST",
    uri: "https://api.example.com/api/transfer"
  });

  const firstAttempt = await verifyDPoPProof({
    proofJwt: freshProof,
    expectedMethod: "POST",
    expectedUri: "https://api.example.com/api/transfer",
    replayStore
  });
  assert(firstAttempt.valid === true, "First request with unique jti succeeds");

  let replayCaught = false;
  try {
    await verifyDPoPProof({
      proofJwt: freshProof, // Replaying exact same proof!
      expectedMethod: "POST",
      expectedUri: "https://api.example.com/api/transfer",
      replayStore
    });
  } catch (err) {
    replayCaught = err instanceof DPoPError && err.message.includes("replay detected");
  }
  assert(replayCaught, "Second request with identical jti is rejected by Replay Store");

  // 8. Server Nonce Enforcement
  console.log("\n🎲 Testing Server Nonce Challenges (use_dpop_nonce)...");
  const requiredNonce = "srv_nonce_random_987654";
  const proofWithNonce = await createDPoPProof({
    privateKey,
    jwk,
    method: "POST",
    uri: "https://api.example.com/api/sensitive",
    nonce: requiredNonce
  });

  const nonceVerified = await verifyDPoPProof({
    proofJwt: proofWithNonce,
    expectedMethod: "POST",
    expectedUri: "https://api.example.com/api/sensitive",
    expectedNonce: requiredNonce
  });
  assert(nonceVerified.valid === true, "Accepts proof matching expected server nonce");

  let missingNonceCaught = false;
  try {
    await verifyDPoPProof({
      proofJwt: loginProof, // Created without nonce
      expectedMethod: "POST",
      expectedUri: "https://api.example.com/auth/verify-otp",
      expectedNonce: requiredNonce
    });
  } catch (err) {
    missingNonceCaught = err instanceof DPoPError && err.code === "use_dpop_nonce";
  }
  // 9. Express End-to-End DPoP Verification
  console.log("\n🚀 Testing Express End-to-End DPoP Integration...");
  const app = express();
  app.use(express.json());
  let missingReplayStoreRejected = false;
  try {
    devAuthKit(express(), {
      jwtSecret: "test-jwt-secret-for-dpop-at-least-32-bytes-long",
      sessionSecret: "test-session-secret-for-dpop-at-least-32-bytes",
      dpop: true
    });
  } catch (err) {
    missingReplayStoreRejected = err instanceof TypeError && err.message.includes("dpopReplayStore");
  }
  assert(missingReplayStoreRejected, "Rejects DPoP setup without a replay store");

  devAuthKit(app, {
    jwtSecret: "test-jwt-secret-for-dpop-at-least-32-bytes-long",
    sessionSecret: "test-session-secret-for-dpop-at-least-32-bytes",
    devMode: true,
    debug: false,
    dpop: true,
    dpopReplayStore: new MemoryDpopReplayStore()
  });

  const { requireAuth, requireDPoP } = devAuthKit;

  app.get("/api/protected", requireAuth, (req, res) => {
    res.json({ success: true, user: req.user, dpop: req.dpop });
  });

  app.post("/api/sensitive-transfer", requireDPoP, (req, res) => {
    res.json({ success: true, transferred: true, dpop: req.dpop });
  });

  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 9.1 Login and request OTP
    const email = "dpop-client@example.com";
    const loginReq = await fetch(`${baseUrl}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email })
    });
    assert(loginReq.ok, "POST /auth/login generates OTP for DPoP client");

    const storedOtp = (sessionStore.get ? sessionStore.get(email) : sessionStore[email])?.otp;
    assert(Boolean(storedOtp), "OTP is stored in memory store");

    // 9.2 Verify OTP with DPoP proof
    const verifyProof = await createDPoPProof({
      privateKey,
      jwk,
      method: "POST",
      uri: `${baseUrl}/auth/verify-otp`
    });

    const verifyRes = await fetch(`${baseUrl}/auth/verify-otp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        DPoP: verifyProof
      },
      body: JSON.stringify({ email, otp: storedOtp })
    });
    const verifyData = await verifyRes.json();
    assert(
      verifyRes.ok && verifyData.tokenType === "DPoP",
      "POST /auth/verify-otp with DPoP proof issues DPoP-bound token (tokenType: DPoP)"
    );

    const clientToken = verifyData.token;
    // Decode token to verify cnf.jkt
    const tokenPayload = JSON.parse(Buffer.from(clientToken.split(".")[1], "base64url").toString());
    assert(
      tokenPayload.cnf?.jkt === thumbprint1,
      `Access token has embedded cnf.jkt matching client public key (${tokenPayload.cnf?.jkt})`
    );

    // 9.3 Access protected route with legitimate DPoP token and proof
    const resourceReqProof = await createDPoPProof({
      privateKey,
      jwk,
      method: "GET",
      uri: `${baseUrl}/api/protected`,
      accessToken: clientToken
    });

    const protectedRes = await fetch(`${baseUrl}/api/protected`, {
      headers: {
        Authorization: `DPoP ${clientToken}`,
        DPoP: resourceReqProof
      }
    });
    const protectedData = await protectedRes.json();
    assert(
      protectedRes.ok && protectedData.success === true && protectedData.dpop.jkt === thumbprint1,
      "GET /api/protected with valid DPoP proof and token succeeds (200 OK)"
    );

    // 9.4 Attacker Scenario 1: Token theft without DPoP header
    const stolenWithoutDpop = await fetch(`${baseUrl}/api/protected`, {
      headers: {
        Authorization: `DPoP ${clientToken}`
        // Attacker stole token, but has no DPoP proof
      }
    });
    assert(
      stolenWithoutDpop.status === 401,
      "Rejects stolen DPoP-bound token when presented without DPoP proof (401 Unauthorized)"
    );

    // 9.5 Attacker Scenario 2: Attacker generates their own keypair and signs a DPoP proof
    const attackerKey = await generateDPoPKeyPair();
    const attackerProof = await createDPoPProof({
      privateKey: attackerKey.privateKey,
      jwk: attackerKey.jwk,
      method: "GET",
      uri: `${baseUrl}/api/protected`,
      accessToken: clientToken
    });

    const stolenWithAttackerProof = await fetch(`${baseUrl}/api/protected`, {
      headers: {
        Authorization: `DPoP ${clientToken}`,
        DPoP: attackerProof
      }
    });
    const attackerData = await stolenWithAttackerProof.json();
    assert(
      stolenWithAttackerProof.status === 401 && attackerData.error.includes("binding mismatch"),
      "Rejects stolen token when proof is signed by attacker's keypair (Key binding mismatch)"
    );

    // 9.6 Attacker Scenario 3: Attacker replays victim's previous DPoP proof
    const replayAttempt = await fetch(`${baseUrl}/api/protected`, {
      headers: {
        Authorization: `DPoP ${clientToken}`,
        DPoP: resourceReqProof // Replaying the exact same proof!
      }
    });
    const replayData = await replayAttempt.json();
    assert(
      replayAttempt.status === 401 && replayData.message.includes("replay detected"),
      "Rejects replayed DPoP proof on protected endpoint (Replay detected)"
    );

    // 9.7 Test dedicated requireDPoP middleware
    const transferProof = await createDPoPProof({
      privateKey,
      jwk,
      method: "POST",
      uri: `${baseUrl}/api/sensitive-transfer`
    });
    const transferRes = await fetch(`${baseUrl}/api/sensitive-transfer`, {
      method: "POST",
      headers: {
        DPoP: transferProof
      }
    });
    assert(
      transferRes.ok && (await transferRes.json()).transferred === true,
      "POST /api/sensitive-transfer with requireDPoP succeeds when valid proof provided"
    );

    // 9.8 Client SDK End-to-End Integration: DevAuthClient({ dpop: true })
    console.log("\n📱 Testing DevAuthClient SDK Automated DPoP Handshake...");
    const { DevAuthClient } = require("./client/index");
    const client = new DevAuthClient({
      apiUrl: baseUrl,
      dpop: true
    });

    assert(client.dpop === true, "DevAuthClient initialized with dpop: true");
    assert(client.isDPoPBound() === true, "client.isDPoPBound() returns true");

    const clientKeyPair = await client.getDPoPKeyPair();
    assert(
      Boolean(clientKeyPair.publicKey && clientKeyPair.privateKey && clientKeyPair.jwk?.kty === "EC"),
      "client.getDPoPKeyPair generates valid ECDSA P-256 key pair"
    );

    // Perform login with client
    const clientEmail = "alice-client-sdk@example.com";
    await client.sendOTP(clientEmail);
    const clientOtp = (sessionStore.get ? sessionStore.get(clientEmail) : sessionStore[clientEmail])?.otp;
    assert(Boolean(clientOtp), "client.sendOTP sent OTP to session store");

    // Perform verifyOTP with client - should automatically generate DPoP proof
    const verifySdkRes = await client.verifyOTP(clientEmail, clientOtp);
    assert(
      verifySdkRes.tokenType === "DPoP" && Boolean(client.getToken()),
      "client.verifyOTP automatically signs DPoP proof, binds token, and stores tokenType DPoP"
    );

    // Call protected endpoint using client.fetch - should automatically sign and inject DPoP headers
    const sdkFetchRes = await client.fetch("/api/protected");
    const sdkFetchData = await sdkFetchRes.json();
    assert(
      sdkFetchRes.ok && sdkFetchData.success === true && sdkFetchData.user.email === clientEmail,
      "client.fetch automatically computes DPoP proof + ath hash and accesses protected endpoint"
    );

    // Call sensitive transfer using client.fetch with POST
    const sdkTransferRes = await client.fetch("/api/sensitive-transfer", { method: "POST" });
    const sdkTransferData = await sdkTransferRes.json();
    assert(
      sdkTransferRes.ok && sdkTransferData.transferred === true,
      "client.fetch seamlessly accesses requireDPoP POST endpoint"
    );

  } finally {
    await new Promise((resolve) => server.close(resolve));
  }

  // 10. Hono DPoP Integration
  console.log("\n⚡ Testing Hono DPoP Middleware Integration...");
  const honoApp = new Hono();
  honoApp.use("/api/*", honoRequireAuth());
  honoApp.get("/api/data", (c) => c.json({ success: true, user: c.get("user"), dpop: c.get("dpop") }));

  // Issue token for Hono test
  const { signJwt } = require("./server/utils/webCrypto");
  const honoToken = await signJwt(
    { email: "hono-dpop@example.com", cnf: { jkt: thumbprint1 } },
    "test-jwt-secret-for-dpop-at-least-32-bytes-long",
    "15m"
  );

  const honoProof = await createDPoPProof({
    privateKey,
    jwk,
    method: "GET",
    uri: "http://localhost/api/data",
    accessToken: honoToken
  });

  const honoRes = await honoApp.request("http://localhost/api/data", {
    headers: {
      Authorization: `DPoP ${honoToken}`,
      DPoP: honoProof
    }
  });

  assert(
    honoRes.status === 200 && (await honoRes.json()).dpop.jkt === thumbprint1,
    "Hono requireAuth middleware verifies DPoP bound token and sets c.get('dpop')"
  );

  console.log(`\n🎉 DPoP Results: ${passed}/${total} tests passed!\n`);
  if (passed !== total) {
    process.exit(1);
  }
}

runDPoPTests().catch((err) => {
  console.error("❌ Test suite encountered unhandled error:", err);
  process.exit(1);
});
