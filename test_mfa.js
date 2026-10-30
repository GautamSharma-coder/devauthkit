const assert = require("node:assert/strict");
const express = require("express");
const devAuthKit = require("./server/server");
const { MemoryMfaStore } = require("./server/stores/memoryMfaStore");
const { totpAtCounter } = require("./server/core/mfaService");
const { signJwt } = require("./server/utils/webCrypto");

async function run() {
  const secretKey = "mfa-test-jwt-secret-that-is-at-least-32-characters";
  const app = express();
  devAuthKit(app, {
    jwtSecret: secretKey,
    sessionSecret: "mfa-test-session-secret-that-is-long-enough",
    corsOrigin: "http://localhost:3001",
    mfaIssuer: "DevAuthKit Test",
    mfaStore: new MemoryMfaStore()
  });
  app.get("/api/step-up", devAuthKit.requireMfa, (req, res) =>
    res.json({ verifiedAt: req.mfa.verifiedAt })
  );

  const token = await signJwt({ id: "mfa-user", email: "mfa@example.com" }, secretKey, "15m");
  const authorization = { Authorization: `Bearer ${token}` };
  const origin = { Origin: "http://localhost:3001" };
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, () => resolve(instance));
  });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const post = (path, body = {}, headers = {}) => fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { ...authorization, ...headers, "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });

  try {
    const initialStatus = await fetch(`${baseUrl}/auth/mfa`, { headers: authorization });
    assert.deepEqual(await initialStatus.json(), { enabled: false, recoveryCodesRemaining: 0 });

    const enrollmentResponse = await post("/auth/mfa/enroll", {}, origin);
    assert.equal(enrollmentResponse.status, 200);
    const enrollment = await enrollmentResponse.json();
    assert.match(enrollment.otpauthUrl, /^otpauth:\/\/totp\//);

    const counter = Math.floor(Date.now() / 1000 / 30);
    const enableResponse = await post("/auth/mfa/enable", {
      code: totpAtCounter(enrollment.secret, counter)
    }, origin);
    assert.equal(enableResponse.status, 200);
    const enabled = await enableResponse.json();
    assert.equal(enabled.enabled, true);
    assert.equal(enabled.recoveryCodes.length, 10);

    const invalidCodeResponse = await post("/auth/mfa/verify", { code: "invalid" });
    assert.equal(invalidCodeResponse.status, 401);
    const protectedWithoutStepUp = await fetch(`${baseUrl}/api/step-up`, { headers: authorization });
    assert.equal(protectedWithoutStepUp.status, 403);

    const nextCounter = Math.floor(Date.now() / 1000 / 30) + 1;
    const totpCode = totpAtCounter(enrollment.secret, nextCounter);
    const verificationResponse = await post("/auth/mfa/verify", { code: totpCode });
    assert.equal(verificationResponse.status, 200);
    const verification = await verificationResponse.json();
    const protectedWithStepUp = await fetch(`${baseUrl}/api/step-up`, {
      headers: { ...authorization, "X-MFA-Token": verification.mfaToken }
    });
    assert.equal(protectedWithStepUp.status, 200);

    const repeatedTotp = await post("/auth/mfa/verify", { code: totpCode });
    assert.equal(repeatedTotp.status, 401);

    const recoveryCode = enabled.recoveryCodes[0];
    const recoveryResponse = await post("/auth/mfa/verify", { code: recoveryCode });
    assert.equal(recoveryResponse.status, 200);
    const recoveryVerification = await recoveryResponse.json();
    assert.equal((await post("/auth/mfa/verify", { code: recoveryCode })).status, 401);

    const disableResponse = await post("/auth/mfa/disable", {}, {
      ...origin,
      "X-MFA-Token": recoveryVerification.mfaToken
    });
    assert.equal(disableResponse.status, 200);
    assert.deepEqual(await disableResponse.json(), { enabled: false });
    console.log("MFA enrollment, TOTP, recovery-code and step-up tests passed.");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

run().then(() => process.exit(0)).catch((err) => { console.error(err); process.exit(1); });
