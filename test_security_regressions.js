// test_security_regressions.js
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const express = require("express");
const { Hono } = require("hono");

const devAuthKit = require("./server/server");
const config = require("./server/config");
const { signJwt, verifyJwt } = require("./server/utils/webCrypto");
const {
  verifySamlResponse,
  canonicalizeXml,
  computeXmlDigest
} = require("./server/core/ssoService");
const { MemorySsoStore } = require("./server/stores/memorySsoStore");
const { MemoryOrganizationStore } = require("./server/stores/memoryOrganizationStore");
const { MemoryWebhookStore } = require("./server/stores/memoryWebhookStore");
const MemoryRefreshTokenStore = require("./server/stores/memoryRefreshTokenStore");
const { MemoryDpopReplayStore } = require("./server/stores/memoryDpopReplayStore");
const { MemoryAuditLogStore } = require("./server/stores/memoryAuditLogStore");
const { AuditLogService } = require("./server/core/auditLogService");
const { CloudflareD1WebhookStore } = require("./server/stores/cloudflareD1WebhookStore");
const { CloudflareD1ApiKeyStore } = require("./server/stores/cloudflareD1ApiKeyStore");
const { createAuthRouter, requireAuth: honoRequireAuth } = require("./server/hono/index");
const {
  generateDPoPKeyPair,
  createDPoPProof,
  calculateJwkThumbprint
} = require("./server/core/dpopService");
const { defaultSessionService } = require("./server/core/sessionService");
const { DevAuthClient } = require("./client/index");
const ssoController = require("./server/controllers/ssoController");
const scimController = require("./server/controllers/scimController");
const webhookController = require("./server/controllers/webhookController");
const auditLogController = require("./server/controllers/auditLogController");
const apiKeyController = require("./server/controllers/apiKeyController");
const userManagementController = require("./server/controllers/userManagementController");
const sessionController = require("./server/controllers/sessionController");
const impersonationController = require("./server/controllers/impersonationController");
const organizationController = require("./server/controllers/organizationController");
const authController = require("./server/controllers/authController");
const requireAuth = require("./server/middleware/requireAuth");
const requireApiKey = require("./server/middleware/requireApiKey");

function mockRes() {
  return {
    statusCode: 200,
    headers: {},
    cookies: {},
    body: null,
    redirectedTo: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    set(k, v) {
      this.headers[k.toLowerCase()] = v;
      return this;
    },
    setHeader(k, v) {
      this.headers[k.toLowerCase()] = v;
      return this;
    },
    cookie(k, v, opts) {
      this.cookies[k] = { v, opts };
      return this;
    },
    clearCookie(k) {
      delete this.cookies[k];
      return this;
    },
    json(data) {
      this.body = data;
      return this;
    },
    send(data) {
      this.body = data;
      return this;
    },
    redirect(url) {
      this.redirectedTo = url;
      return this;
    }
  };
}

async function runSecurityRegressionTests() {
  console.log("🔐 Starting DevAuthKit Security & Bug Regression Suite...\n");

  let passed = 0;
  let total = 0;

  function check(condition, label) {
    total++;
    if (condition) {
      console.log(`  ✅ [PASS] ${label}`);
      passed++;
    } else {
      console.error(`  ❌ [FAIL] ${label}`);
    }
  }

  const secret = "security_regression_secret_at_least_32_bytes_long!";
  const ssoStore = new MemorySsoStore();
  const orgStore = new MemoryOrganizationStore();
  const webhookStore = new MemoryWebhookStore();
  const refreshStore = new MemoryRefreshTokenStore();
  const dpopReplayStore = new MemoryDpopReplayStore();

  const app = express();
  devAuthKit(app, {
    jwtSecret: secret,
    sessionSecret: secret,
    corsOrigin: ["https://app.example.com"],
    sso: true,
    ssoStore,
    scim: true,
    organizations: true,
    organizationStore: orgStore,
    webhooks: true,
    webhookStore,
    refreshTokens: true,
    refreshTokenStore: refreshStore,
    dpop: true,
    dpopReplayStore,
    magicLink: false,
    devMode: false
  });

  const { organization: orgA } = await orgStore.createOrg({
    name: "Acme Org",
    ownerUserId: "owner_a",
    ownerEmail: "owner@a.com"
  });
  const regularUser = { id: "user_1", email: "user1@example.com", role: "user" };
  const adminUser = { id: "admin_1", email: "admin@example.com", role: "admin" };
  const orgOwnerUser = { id: "owner_a", email: "owner@a.com", role: "user" };

  // ==========================================
  // 1. Authorization & SSRF on SSO, SCIM, Webhooks, Audit Logs
  // ==========================================
  {
    const resCreate = mockRes();
    await ssoController.createConnection(
      { user: regularUser, body: { orgId: orgA.id, name: "Evil" }, headers: {}, get: () => "app.example.com", protocol: "https" },
      resCreate
    );
    check(resCreate.statusCode === 403, "Non-admin/non-org-owner cannot create SSO connection");

    const resList = mockRes();
    await ssoController.listConnections({ user: regularUser, query: { orgId: orgA.id }, params: {} }, resList);
    check(resList.statusCode === 403, "Non-admin/non-org-owner cannot list another org's SSO connections");

    const resOwnerCreate = mockRes();
    await ssoController.createConnection(
      {
        user: orgOwnerUser,
        body: { orgId: orgA.id, name: "Okta", domains: ["a.com"], oidcClientSecret: "super_secret_client", domainVerified: true },
        headers: {},
        get: () => "app.example.com",
        protocol: "https"
      },
      resOwnerCreate
    );
    check(resOwnerCreate.statusCode === 201, "Org owner can create SSO connection for their own org");
    check(resOwnerCreate.body?.connection?.oidcClientSecret === "***", "SSO oidcClientSecret is redacted in API responses");

    const connId = resOwnerCreate.body?.connection?.id;
    const resOtherPatch = mockRes();
    await ssoController.updateConnection(
      { user: regularUser, params: { id: connId }, body: { idpCertificates: ["fake"] } },
      resOtherPatch
    );
    check(resOtherPatch.statusCode === 403, "Regular user cannot tamper with another org's SSO connection");

    const resOwnerPatch = mockRes();
    await ssoController.updateConnection(
      { user: orgOwnerUser, params: { id: connId }, body: { domainVerified: true } },
      resOwnerPatch
    );
    check(resOwnerPatch.body?.connection?.domainVerified === false, "SSO update cannot self-assert domainVerified=true");
  }

  {
    const resScim = mockRes();
    await scimController.createDirectory({ user: regularUser, body: { orgId: orgA.id } }, resScim);
    check(resScim.statusCode === 403, "Non-admin/non-org-owner cannot create SCIM directory for another org");
  }

  {
    const resWhList = mockRes();
    await webhookController.listEndpoints({ user: regularUser, query: {} }, resWhList);
    check(resWhList.statusCode === 403, "Regular user cannot list webhook endpoints or steal signing secrets");

    const resSsrfMeta = mockRes();
    await webhookController.createEndpoint({ user: adminUser, body: { url: "http://169.254.169.254/latest/meta-data/" } }, resSsrfMeta);
    check(resSsrfMeta.statusCode === 400, "Webhook SSRF to link-local metadata IP is blocked");

    const resSsrfLocal = mockRes();
    await webhookController.createEndpoint({ user: adminUser, body: { url: "http://127.0.0.1:8080/internal" } }, resSsrfLocal);
    check(resSsrfLocal.statusCode === 400, "Webhook SSRF to loopback IP is blocked");

    const resSsrfPrivate = mockRes();
    await webhookController.createEndpoint({ user: adminUser, body: { url: "http://10.0.0.5/hook" } }, resSsrfPrivate);
    check(resSsrfPrivate.statusCode === 400, "Webhook SSRF to RFC1918 private IP is blocked");
  }

  {
    const resAudit = mockRes();
    await auditLogController.queryAuditLogs({ user: regularUser, query: {} }, resAudit);
    check(resAudit.statusCode === 403, "Regular user without org_id cannot query cross-tenant audit logs");

    const resAuditVerify = mockRes();
    await auditLogController.verifyAuditTrail({ user: regularUser }, resAuditVerify);
    check(resAuditVerify.statusCode === 403, "Regular user cannot invoke audit chain verify endpoint");
  }

  // ==========================================
  // 2. SAML 2.0 XML Hardening & RelayState Open Redirect
  // ==========================================
  {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" }
    });
    const assertionId = "_assert_sec_1";
    const spEntityId = "https://app.example.com/auth/sso/saml/c1/metadata.xml";
    const rawAssertion = [
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" Version="2.0">`,
      `<saml:Issuer>https://idp.example.com</saml:Issuer>`,
      `<saml:Subject><saml:NameID>bob@a.com</saml:NameID></saml:Subject>`,
      `<saml:Conditions NotBefore="${new Date(Date.now() - 60000).toISOString()}" NotOnOrAfter="${new Date(Date.now() + 60000).toISOString()}"><saml:AudienceRestriction><saml:Audience>${spEntityId}</saml:Audience></saml:AudienceRestriction></saml:Conditions>`,
      `<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>bob@a.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`,
      `</saml:Assertion>`
    ].join("");
    const digest = computeXmlDigest(canonicalizeXml(rawAssertion), "RSA-SHA256");
    const signedInfo = `<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#${assertionId}"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>${digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>`;
    const signer = crypto.createSign("RSA-SHA256");
    signer.update(canonicalizeXml(signedInfo));
    const sigVal = signer.sign(privateKey, "base64");
    const sigXml = `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${signedInfo}<ds:SignatureValue>${sigVal}</ds:SignatureValue></ds:Signature>`;

    const commentInjectedXml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_resp1">${rawAssertion.replace("<saml:Subject>", `${sigXml}<!--<saml:NameID>admin@a.com</saml:NameID>--><saml:Subject>`)}</samlp:Response>`;
    const verified = await verifySamlResponse({ samlResponse: commentInjectedXml, idpCertificates: [publicKey], spEntityId });
    check(verified.nameId === "bob@a.com" && verified.email === "bob@a.com", "SAML XML comment injection cannot spoof NameID/email");

    let cdataRejected = false;
    try {
      await verifySamlResponse({ samlResponse: commentInjectedXml.replace("bob@a.com", "<![CDATA[bob@a.com]]>"), idpCertificates: [publicKey], spEntityId });
    } catch (err) {
      cdataRejected = err.code === "ERR_XXE_DETECTED";
    }
    check(cdataRejected, "SAML CDATA sections are rejected");

    let badRefRejected = false;
    try {
      const badRefXml = commentInjectedXml.replace(`URI="#${assertionId}"`, `URI="#_other_id"`);
      await verifySamlResponse({ samlResponse: badRefXml, idpCertificates: [publicKey], spEntityId });
    } catch (err) {
      badRefRejected = err.code === "ERR_SAML_REFERENCE_MISMATCH";
    }
    check(badRefRejected, "SAML Reference URI mismatch is rejected");

    const conn = await ssoStore.createConnection({
      orgId: orgA.id,
      name: "Test SAML",
      domains: ["a.com"],
      idpCertificates: [publicKey],
      spEntityId,
      spAcsUrl: "https://app.example.com/auth/sso/saml/acs"
    });
    const acsRes = mockRes();
    await ssoController.handleSamlAcs(
      { params: { connectionId: conn.id }, body: { SAMLResponse: commentInjectedXml, RelayState: "https://evil.attacker.com/steal" }, query: {} },
      acsRes
    );
    check(acsRes.redirectedTo === null && acsRes.body?.success === true, "SAML ACS blocks open redirect to untrusted RelayState origin");
  }

  // ==========================================
  // 3. Production devMode, Magic Link, Host Header, OTP & Logout CSRF
  // ==========================================
  {
    const prevEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    const prodCfg = config.set({ jwtSecret: secret, sessionSecret: secret });
    check(prodCfg.devMode === false, "Production never silently auto-enables devMode");
    process.env.NODE_ENV = prevEnv || "test";

    const magicStore = new Map();
    config.set({
      jwtSecret: secret,
      sessionSecret: secret,
      magicLink: false,
      magicLinkStore: magicStore,
      devMode: true,
      refreshTokenStore: refreshStore,
      organizationStore: orgStore,
      apiKeyService: devAuthKit.config.get("apiKeyService")
    });

    const reqMagicDisabled = mockRes();
    await authController.requestOTP(
      { body: { email: "victim@example.com", magicLink: true }, headers: { host: "evil.com" }, protocol: "https", get: () => "evil.com" },
      reqMagicDisabled
    );
    check(reqMagicDisabled.body?.magicLinkUrl === undefined, "Client cannot force magicLink when config.magicLink is false");

    config.set({
      jwtSecret: secret,
      sessionSecret: secret,
      magicLink: true,
      magicLinkStore: magicStore,
      devMode: true,
      refreshTokenStore: refreshStore,
      organizationStore: orgStore,
      apiKeyService: devAuthKit.config.get("apiKeyService")
    });

    const badHostRes = mockRes();
    await authController.requestOTP(
      { body: { email: "host@example.com" }, headers: { host: "evil.com/phish@good.com" }, protocol: "https", get: () => "evil.com/phish@good.com" },
      badHostRes
    );
    check(badHostRes.statusCode === 500 || badHostRes.statusCode === 400, "Spoofed Host header with path/@ is rejected");

    const missingBodyRes = mockRes();
    await authController.requestOTP({ headers: {}, get: () => "localhost" }, missingBodyRes);
    check(missingBodyRes.statusCode === 400, "requestOTP handles missing req.body with 400 instead of 500");

    const logoutCsrfRes = mockRes();
    await authController.logout({ method: "GET", headers: { "sec-fetch-site": "cross-site" } }, logoutCsrfRes);
    check(logoutCsrfRes.statusCode === 403, "Cross-site GET /auth/logout CSRF is rejected with 403");

    // Concurrent verifyOTP lock prevents double redemption under async store delays
    const backingOtpMap = new Map();
    const delay = () => new Promise((r) => setTimeout(r, 15));
    const asyncOtpStore = {
      async set(email, val) { await delay(); backingOtpMap.set(email, val); },
      async get(email) { await delay(); return backingOtpMap.get(email) || null; },
      async recordAttempt(email) {
        await delay();
        const entry = backingOtpMap.get(email);
        if (!entry) return 0;
        entry.attempts += 1;
        return entry.attempts;
      },
      async delete(email) { await delay(); backingOtpMap.delete(email); }
    };
    const prevOtpStore = config.get("otpStore");
    config.set({
      jwtSecret: secret,
      sessionSecret: secret,
      otpStore: asyncOtpStore,
      devMode: false,
      refreshTokenStore: refreshStore,
      organizationStore: orgStore,
      apiKeyService: devAuthKit.config.get("apiKeyService")
    });
    await asyncOtpStore.set("race@example.com", { otp: "654321", createdAt: Date.now(), attempts: 0 });
    const [r1, r2] = [mockRes(), mockRes()];
    await Promise.all([
      authController.verifyOTP({ body: { email: "race@example.com", otp: "654321" }, headers: {}, ip: "127.0.0.1" }, r1),
      authController.verifyOTP({ body: { email: "race@example.com", otp: "654321" }, headers: {}, ip: "127.0.0.1" }, r2)
    ]);
    const raceStatuses = [r1.statusCode, r2.statusCode].sort();
    check(raceStatuses[0] === 200 && raceStatuses[1] === 401, "Concurrent verifyOTP lock prevents double redemption of single-use OTP");
    config.set({
      jwtSecret: secret,
      sessionSecret: secret,
      otpStore: prevOtpStore,
      devMode: true,
      refreshTokenStore: refreshStore,
      organizationStore: orgStore,
      apiKeyService: devAuthKit.config.get("apiKeyService")
    });
  }

  // ==========================================
  // 4. API Keys, User Blocking, Epoch (uep), Sessions, Impersonation & Orgs
  // ==========================================
  {
    const apiKeyService = config.get("apiKeyService");
    const { rawKey: readOnlyKey } = await apiKeyService.createKey({
      userId: "user_1",
      name: "Read Only",
      scopes: ["read:data"]
    });

    const reqApiEsc = { headers: { authorization: `Bearer ${readOnlyKey}` }, originalUrl: "/auth/api-keys", method: "POST" };
    const resApiEsc = mockRes();
    let escNext = false;
    await requireAuth(reqApiEsc, resApiEsc, () => { escNext = true; });
    check(!escNext && resApiEsc.statusCode === 403, "API key cannot create/escalate API keys through requireAuth");

    const resBadOrgKey = mockRes();
    await apiKeyController.createApiKey({ user: regularUser, body: { name: "CrossOrg", orgId: orgA.id }, headers: {}, ip: "127.0.0.1" }, resBadOrgKey);
    check(resBadOrgKey.statusCode === 403, "User cannot create API key scoped to an organization they do not belong to");

    // Numeric vs string userId blocking, epoch bump, and refresh token revocation
    const { createAuthService } = require("./server/core/authService");
    const authSvc = createAuthService({ config, getRefreshTokenStore: () => refreshStore });
    const preBlockJwt = await authSvc.createAccessToken({ id: 42, email: "num@example.com", role: "user" }, null, null);
    const decodedPre = await verifyJwt(preBlockJwt, secret);
    check(typeof decodedPre.uep === "number", "Access tokens include numeric uep revocation epoch");

    await refreshStore.create("hash_num_42", {
      familyId: "fam_num_42",
      userId: "42",
      user: { id: 42, email: "num@example.com" },
      expiresAt: Date.now() + 60000
    });
    defaultSessionService.registerSession({ sessionId: "fam_num_42", userId: 42, userAgent: "Chrome" });
    check(defaultSessionService.listUserSessions("42").length === 1, "SessionService normalizes numeric userId 42 to '42'");

    const blockRes = mockRes();
    await userManagementController.blockUser({ user: adminUser, params: { userId: "42" }, body: { reason: "Abuse" }, headers: {}, ip: "127.0.0.1" }, blockRes);
    check(blockRes.statusCode === 200, "Admin blocks numeric user '42'");
    check(userManagementController.isUserBlocked(42) === true, "isUserBlocked(42) matches blocked '42'");
    check((await refreshStore.isFamilyActive("fam_num_42")) === false, "blockUser revokes refresh token families via revokeAll");
    check(defaultSessionService.listUserSessions("42").length === 0, "blockUser purges SessionService sessions");

    // Unblock user: old pre-block JWT must still be rejected due to uep bump!
    await userManagementController.unblockUser({ user: adminUser, params: { userId: "42" }, headers: {}, ip: "127.0.0.1" }, mockRes());
    const resOldJwt = mockRes();
    let oldJwtNext = false;
    await requireAuth({ headers: { authorization: `Bearer ${preBlockJwt}` }, originalUrl: "/profile", method: "GET" }, resOldJwt, () => { oldJwtNext = true; });
    check(!oldJwtNext && resOldJwt.statusCode === 401, "Pre-suspension JWT remains revoked after unblock due to uep epoch bump");

    // Blocked user's API key is suspended on blockUser AND active keys for blocked users are rejected by requireApiKey
    const { rawKey: blockedUserKey } = await apiKeyService.createKey({ userId: "blocked_api_user", name: "K", scopes: ["*"] });
    await userManagementController.blockUser({ user: adminUser, params: { userId: "blocked_api_user" }, body: {}, headers: {}, ip: "127.0.0.1" }, mockRes());
    const resSuspendedApiKey = mockRes();
    let suspendedKeyNext = false;
    await requireApiKey(["*"])({ headers: { authorization: `Bearer ${blockedUserKey}` } }, resSuspendedApiKey, () => { suspendedKeyNext = true; });
    check(!suspendedKeyNext && (resSuspendedApiKey.statusCode === 401 || resSuspendedApiKey.statusCode === 403), "blockUser suspends existing API keys for suspended users");

    const { rawKey: activeKeyForBlockedUser } = await apiKeyService.createKey({ userId: "blocked_api_user", name: "K2", scopes: ["*"] });
    const resBlockedApiKey = mockRes();
    let blockedKeyNext = false;
    await requireApiKey(["*"])({ headers: { authorization: `Bearer ${activeKeyForBlockedUser}` } }, resBlockedApiKey, () => { blockedKeyNext = true; });
    check(!blockedKeyNext && resBlockedApiKey.statusCode === 403, "requireApiKey explicitly rejects active API keys owned by suspended users");

    // Session IDOR & revokeOtherSessions refresh purge
    defaultSessionService.registerSession({ sessionId: "victim_sid", userId: "victim_u", userAgent: "Chrome" });
    await refreshStore.create("victim_rt", { familyId: "victim_sid", userId: "victim_u", user: { id: "victim_u", email: "v@example.com" }, expiresAt: Date.now() + 60000 });
    const idorRes = mockRes();
    await sessionController.revokeSession({ user: { id: "attacker_u", sid: "att_sid" }, params: { id: "victim_sid" }, headers: {} }, idorRes);
    check(idorRes.statusCode === 404 && (await refreshStore.isFamilyActive("victim_sid")) === true, "Session IDOR cannot revoke another user's refresh family");

    defaultSessionService.registerSession({ sessionId: "cur_sid", userId: "multi_u", userAgent: "Chrome" });
    defaultSessionService.registerSession({ sessionId: "old_sid", userId: "multi_u", userAgent: "Safari" });
    await refreshStore.create("rt_old", { familyId: "old_sid", userId: "multi_u", user: { id: "multi_u", email: "m@example.com" }, expiresAt: Date.now() + 60000 });
    await sessionController.revokeOtherSessions({ user: { id: "multi_u", sid: "cur_sid" }, headers: {}, ip: "127.0.0.1" }, mockRes());
    check((await refreshStore.isFamilyActive("old_sid")) === false, "revokeOtherSessions also revokes other refresh token families");

    // Impersonation end revokes token & blocks admin->admin
    const prevUserAdapter = config.get("userAdapter");
    config.set({
      ...config.get(),
      jwtSecret: secret,
      sessionSecret: secret,
      userAdapter: {
        findUserById: async (id) => {
          if (id === "other_admin") return { id: "other_admin", email: "a2@example.com", role: "admin" };
          return { id, email: `${id}@example.com`, role: "user" };
        },
        findOrCreateUser: async (email) => ({ id: "user_1", email, role: "user" })
      }
    });
    const adminImpAdmin = mockRes();
    await impersonationController.startImpersonation(
      { user: adminUser, body: { userId: "other_admin" }, headers: {}, ip: "127.0.0.1" },
      adminImpAdmin
    );
    check(adminImpAdmin.statusCode === 403, "Admin cannot impersonate another admin account");
    const impRes = mockRes();
    await impersonationController.startImpersonation({ user: adminUser, body: { userId: "user_1" }, headers: {}, ip: "127.0.0.1" }, impRes);
    config.set({
      ...config.get(),
      jwtSecret: secret,
      sessionSecret: secret,
      userAdapter: prevUserAdapter
    });
    const impToken = impRes.body.token;

    const reqImpMfa = { headers: { authorization: `Bearer ${impToken}` }, originalUrl: "/auth/mfa/disable", method: "POST" };
    const resImpMfa = mockRes();
    await requireAuth(reqImpMfa, resImpMfa, () => {});
    check(resImpMfa.statusCode === 403, "Impersonated session cannot access /mfa routes");

    const reqImpProfile = { headers: { authorization: `Bearer ${impToken}` }, originalUrl: "/profile", method: "GET" };
    await requireAuth(reqImpProfile, mockRes(), () => {});
    await impersonationController.endImpersonation({ user: reqImpProfile.user, headers: {}, ip: "127.0.0.1" }, mockRes());
    const resImpAfter = mockRes();
    await requireAuth(reqImpProfile, resImpAfter, () => {});
    check(resImpAfter.statusCode === 401, "Ended impersonation token is rejected immediately");

    // Organization invite email check
    const invToken = "inv_secret_token_123456";
    const { hashInvitationToken } = require("./server/core/organizationService");
    await orgStore.createInvitation({
      orgId: orgA.id,
      email: "intended@example.com",
      role: "member",
      inviterId: "owner_a",
      tokenHash: await hashInvitationToken(invToken),
      expiresAt: Date.now() + 60000
    });
    const wrongJoinRes = mockRes();
    await organizationController.joinOrg({ user: { id: "intruder", email: "intruder@example.com", role: "user" }, body: { token: invToken } }, wrongJoinRes);
    check(wrongJoinRes.statusCode === 403, "Organization joinOrg rejects user whose email does not match invitation");
  }

  // ==========================================
  // 5. Concurrent Audit Chain, D1 Row Counts, Hono Parity & DevAuthClient
  // ==========================================
  {
    const auditStore = new MemoryAuditLogStore();
    const auditSvc = new AuditLogService({ store: auditStore });
    const entries = await Promise.all(
      Array.from({ length: 12 }, (_, i) => auditSvc.record({ eventType: "sec.test", actorId: `u_${i}` }))
    );
    const chainCheck = await AuditLogService.verifyChain(entries);
    check(chainCheck.valid === true, "Concurrent AuditLogService.record calls maintain intact Merkle chain");

    const zeroChangesDb = {
      prepare() {
        return {
          bind() { return this; },
          async run() { return { success: true, meta: { changes: 0 } }; }
        };
      },
      async batch() { return []; }
    };
    const d1Wh = new CloudflareD1WebhookStore(zeroChangesDb);
    const d1Key = new CloudflareD1ApiKeyStore(zeroChangesDb);
    check((await d1Wh.deleteEndpoint("missing")) === false, "CloudflareD1WebhookStore.deleteEndpoint returns false when 0 rows deleted");
    check((await d1Key.revokeKey("missing")) === false, "CloudflareD1ApiKeyStore.revokeKey returns false when 0 rows updated");

    // Hono parity: dpop required, blocked user, no Host header requestOTP
    const kv = new Map();
    const otpStore = {
      async get(k) { return kv.get(k) || null; },
      async set(k, v) { kv.set(k, v); },
      async delete(k) { kv.delete(k); },
      async recordAttempt(k) { const e = kv.get(k); e.attempts++; return e.attempts; }
    };
    const ml = new Map();
    const mlStore = {
      async get(k) { return ml.get(k) || null; },
      async set(k, v) { ml.set(k, v); },
      async delete(k) { ml.delete(k); }
    };

    const honoApp = new Hono();
    const router = createAuthRouter({
      jwtSecret: secret,
      otpStore,
      magicLink: true,
      magicLinkStore: mlStore,
      dpop: "required",
      dpopReplayStore,
      rateLimit: false,
      devMode: true,
      mailer: async () => {}
    });
    honoApp.route("/", router);
    honoApp.get("/protected", honoRequireAuth(), (c) => c.json({ ok: true }));

    const honoOtpRes = await honoApp.request("/auth/request-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "hono@example.com" })
    });
    check(honoOtpRes.status === 200, "Hono request-otp succeeds when Host header is omitted");

    const unboundJwt = await signJwt({ id: "u_hono", email: "hono@example.com" }, secret, "1h");
    const honoUnboundRes = await honoApp.request("http://localhost/protected", {
      headers: { Authorization: `Bearer ${unboundJwt}` }
    });
    check(honoUnboundRes.status === 400, "Hono requireAuth enforces dpop: 'required' on unbound Bearer tokens");

    const { privateKey: dPriv, jwk: dJwk } = await generateDPoPKeyPair();
    const jkt = await calculateJwkThumbprint(dJwk);
    const blockedBoundJwt = await signJwt({ id: "blocked_api_user", email: "b@example.com", cnf: { jkt } }, secret, "1h");
    const dProof = await createDPoPProof({
      privateKey: dPriv,
      jwk: dJwk,
      method: "GET",
      uri: "http://localhost/protected",
      accessToken: blockedBoundJwt
    });
    const honoBlockedRes = await honoApp.request("http://localhost/protected", {
      headers: { Authorization: `DPoP ${blockedBoundJwt}`, DPoP: dProof }
    });
    check(honoBlockedRes.status === 403, "Hono requireAuth rejects blocked users");

    const client = new DevAuthClient();
    check(client.storagePrefix === "devauth_token_", "DevAuthClient initializes storagePrefix cleanly");
  }

  console.log(`\n========================================`);
  console.log(`Security Regression Results: ${passed}/${total} passed`);
  console.log(`========================================\n`);

  process.exitCode = passed === total ? 0 : 1;
}

runSecurityRegressionTests().then(() => {
  process.exit(process.exitCode || 0);
}).catch((err) => {
  console.error("Security regression suite failed:", err);
  process.exit(1);
});
