// test_sso_scim.js
const crypto = require("crypto");
const express = require("express");
const { Hono } = require("hono");
const devAuthKit = require("./server/server");
const {
  SsoError,
  formatX509Cert,
  canonicalizeXml,
  computeXmlDigest,
  verifyRsaSignature,
  verifySamlResponse,
  generateSamlAuthnRequest,
  generateSpMetadataXml,
  generateDomainVerificationToken,
  verifyDomainTxt,
  deflateRaw,
  inflateRaw
} = require("./server/core/ssoService");
const {
  SCIM_USER_SCHEMA,
  SCIM_GROUP_SCHEMA,
  generateScimBearerToken,
  hashScimBearerToken,
  verifyScimBearerToken,
  getServiceProviderConfig,
  getSchemas,
  formatScimUser,
  formatScimGroup,
  formatScimList,
  formatScimError,
  parseScimFilter,
  parseScimPatchOperations
} = require("./server/core/scimService");
const { MemorySsoStore } = require("./server/stores/memorySsoStore");
const { CloudflareD1SsoStore } = require("./server/stores/cloudflareD1SsoStore");
const { MemoryOrganizationStore } = require("./server/stores/memoryOrganizationStore");
const MemoryRefreshTokenStore = require("./server/stores/memoryRefreshTokenStore");
const { createAuthRouter } = require("./server/hono/index");
const { signJwt } = require("./server/utils/webCrypto");
const config = require("./server/config");

async function runSsoScimTests() {
  console.log("🛡️ Starting DevAuthKit Enterprise SSO (SAML 2.0 & OIDC) and SCIM 2.0 Automated Verification...\n");

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
  // Generate Test RSA Key Pair & Self-Signed Cert
  // ==========================================
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });

  // Second key pair for dual rolling certificate rollover tests
  const { privateKey: secondaryPrivateKey, publicKey: secondaryPublicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });

  // Helper to build a signed SAML 2.0 Response XML
  function createSignedSamlResponse({
    assertionId = `_assert_${Date.now()}`,
    issuer = "https://idp.enterprise.com",
    audience = "https://app.devauthkit.com/auth/sso/saml/conn_123/metadata.xml",
    recipient = "https://app.devauthkit.com/auth/sso/saml/conn_123/acs",
    nameId = "alice@enterprise.com",
    notBefore = new Date(Date.now() - 60000).toISOString(),
    notOnOrAfter = new Date(Date.now() + 300000).toISOString(),
    signingKey = privateKey,
    extraAssertions = false,
    xxePayload = false
  } = {}) {
    if (xxePayload) {
      return `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&xxe;</samlp:Response>`;
    }

    const rawAssertionXml = [
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" IssueInstant="${new Date().toISOString()}" Version="2.0">`,
      `  <saml:Issuer>${issuer}</saml:Issuer>`,
      `  <saml:Subject>`,
      `    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameId}</saml:NameID>`,
      `    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`,
      `      <saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" Recipient="${recipient}"/>`,
      `    </saml:SubjectConfirmationData>`,
      `  </saml:Subject>`,
      `  <saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">`,
      `    <saml:AudienceRestriction>`,
      `      <saml:Audience>${audience}</saml:Audience>`,
      `    </saml:AudienceRestriction>`,
      `  </saml:Conditions>`,
      `  <saml:AttributeStatement>`,
      `    <saml:Attribute Name="email"><saml:AttributeValue>${nameId}</saml:AttributeValue></saml:Attribute>`,
      `    <saml:Attribute Name="name"><saml:AttributeValue>Alice Enterprise</saml:AttributeValue></saml:Attribute>`,
      `  </saml:AttributeStatement>`,
      `</saml:Assertion>`
    ].join("\n");

    const canonicalAssertion = canonicalizeXml(rawAssertionXml);
    const digestValue = computeXmlDigest(canonicalAssertion, "RSA-SHA256");

    const rawSignedInfo = [
      `<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`,
      `  <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`,
      `  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>`,
      `  <ds:Reference URI="#${assertionId}">`,
      `    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`,
      `    <ds:DigestValue>${digestValue}</ds:DigestValue>`,
      `  </ds:Reference>`,
      `</ds:SignedInfo>`
    ].join("\n");

    const canonicalSignedInfo = canonicalizeXml(rawSignedInfo);
    const signer = crypto.createSign("RSA-SHA256");
    signer.update(canonicalSignedInfo);
    const signatureValue = signer.sign(signingKey, "base64");

    const signatureXml = [
      `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`,
      rawSignedInfo,
      `  <ds:SignatureValue>${signatureValue}</ds:SignatureValue>`,
      `</ds:Signature>`
    ].join("\n");

    // Envelop signature into assertion
    const signedAssertionXml = rawAssertionXml.replace(`</saml:Issuer>`, `</saml:Issuer>\n${signatureXml}`);

    let responseXml = [
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_resp_${Date.now()}" Version="2.0" IssueInstant="${new Date().toISOString()}">`,
      `  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${issuer}</saml:Issuer>`,
      `  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`,
      signedAssertionXml,
      extraAssertions ? signedAssertionXml : "", // XSW attack simulation
      `</samlp:Response>`
    ].join("\n");

    return responseXml;
  }

  // ==========================================
  // SECTION 1: SAML 2.0 Cryptographic Primitives & Canonicalization
  // ==========================================
  console.log("🔐 1. SAML XML C14N Canonicalization & Signature Verification...");

  const rawBase64 = publicKey.replace(/-----[^\n]+-----|\n|\r/g, "");
  const formattedCert = formatX509Cert(rawBase64);
  assert(
    formattedCert.startsWith("-----BEGIN CERTIFICATE-----") && formattedCert.endsWith("-----END CERTIFICATE-----"),
    "formatX509Cert formats public key into valid PEM certificate block"
  );

  const dirtyXml = `  <saml:Issuer   xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"  >https://idp.com</saml:Issuer>\r\n<!-- comment -->`;
  const cleanXml = canonicalizeXml(dirtyXml);
  assert(
    !cleanXml.includes("comment") && !cleanXml.includes("\r") && cleanXml.includes("<saml:Issuer"),
    "canonicalizeXml strips XML comments and normalizes line endings and attributes"
  );

  const digest = computeXmlDigest("<foo>bar</foo>", "RSA-SHA256");
  assert(
    typeof digest === "string" && digest.length > 20,
    "computeXmlDigest produces base64 SHA-256 digest"
  );

  // Generate valid SAML response
  const validSamlXml = createSignedSamlResponse();
  const verified = await verifySamlResponse({
    samlResponse: validSamlXml,
    idpCertificates: [publicKey],
    spEntityId: "https://app.devauthkit.com/auth/sso/saml/conn_123/metadata.xml"
  });

  assert(
    verified.nameId === "alice@enterprise.com" && verified.email === "alice@enterprise.com",
    "verifySamlResponse successfully validates RSA-SHA256 digital signature and extracts identity"
  );

  // Dual rolling certificate verification
  const secondarySignedXml = createSignedSamlResponse({ signingKey: secondaryPrivateKey });
  const rolloverVerified = await verifySamlResponse({
    samlResponse: secondarySignedXml,
    idpCertificates: [publicKey, secondaryPublicKey], // primary is old, secondary is active
    spEntityId: "https://app.devauthkit.com/auth/sso/saml/conn_123/metadata.xml"
  });

  assert(
    rolloverVerified.promotedCert === secondaryPublicKey,
    "verifySamlResponse supports dual rolling certificates and signals promotion of secondary cert"
  );

  // ==========================================
  // SECTION 2: SAML Security Defenses (XXE, XSW, Anti-Replay, Clock Skew)
  // ==========================================
  console.log("\n🛡️ 2. SAML Security Hardening (XXE, XSW, Replay, Audience, Clock Skew)...");

  // XXE Defense
  try {
    await verifySamlResponse({
      samlResponse: createSignedSamlResponse({ xxePayload: true }),
      idpCertificates: [publicKey]
    });
    assert(false, "XXE payload should have been rejected");
  } catch (err) {
    assert(err.code === "ERR_XXE_DETECTED", "XXE Defense: blocks <!DOCTYPE and <!ENTITY injection");
  }

  // XML Signature Wrapping (XSW) Defense
  try {
    await verifySamlResponse({
      samlResponse: createSignedSamlResponse({ extraAssertions: true }),
      idpCertificates: [publicKey]
    });
    assert(false, "XSW duplicate assertions should have been rejected");
  } catch (err) {
    assert(err.code === "ERR_XSW_DETECTED", "XSW Defense: blocks multiple <Assertion> elements");
  }

  // Anti-Replay Protection
  const replayStore = new MemorySsoStore();
  const replaySamlXml = createSignedSamlResponse({ assertionId: "assert_replay_test_1" });
  await verifySamlResponse({
    samlResponse: replaySamlXml,
    idpCertificates: [publicKey],
    spEntityId: "https://app.devauthkit.com/auth/sso/saml/conn_123/metadata.xml",
    replayStore
  });

  try {
    await verifySamlResponse({
      samlResponse: replaySamlXml,
      idpCertificates: [publicKey],
      spEntityId: "https://app.devauthkit.com/auth/sso/saml/conn_123/metadata.xml",
      replayStore
    });
    assert(false, "Replayed assertion ID should have been rejected");
  } catch (err) {
    assert(err.code === "ERR_SAML_ASSERTION_REPLAYED", "Anti-Replay Defense: rejects re-submitted assertion ID");
  }

  // Clock Skew Defense (expired assertion)
  try {
    await verifySamlResponse({
      samlResponse: createSignedSamlResponse({
        notOnOrAfter: new Date(Date.now() - 3600000).toISOString() // expired 1 hr ago
      }),
      idpCertificates: [publicKey],
      clockSkewSeconds: 60
    });
    assert(false, "Expired assertion should have been rejected");
  } catch (err) {
    assert(err.code === "ERR_SAML_TIMESTAMP_OUTSIDE_TOLERANCE", "Clock Skew Defense: rejects expired assertions");
  }

  // Audience Restriction Defense
  try {
    await verifySamlResponse({
      samlResponse: validSamlXml,
      idpCertificates: [publicKey],
      spEntityId: "https://different-audience.com/metadata.xml"
    });
    assert(false, "Audience mismatch should have been rejected");
  } catch (err) {
    assert(err.code === "ERR_SAML_AUDIENCE_MISMATCH", "Audience Restriction Defense: rejects audience mismatch");
  }

  // ==========================================
  // SECTION 3: AuthnRequest & SP Metadata Generation
  // ==========================================
  console.log("\n📦 3. AuthnRequest & SP Metadata Generation...");

  const authn = generateSamlAuthnRequest({
    spEntityId: "https://app.devauthkit.com/auth/sso/saml/conn_123/metadata.xml",
    acsUrl: "https://app.devauthkit.com/auth/sso/saml/conn_123/acs",
    idpSsoUrl: "https://idp.enterprise.com/sso",
    relayState: "state_xyz123"
  });

  assert(
    authn.xml.includes("<samlp:AuthnRequest") && authn.xml.includes("AssertionConsumerServiceURL="),
    "generateSamlAuthnRequest constructs standard SAML 2.0 AuthnRequest XML"
  );
  assert(
    authn.redirectUrl.includes("SAMLRequest=") && authn.redirectUrl.includes("RelayState=state_xyz123"),
    "generateSamlAuthnRequest generates Deflate/Base64 HTTP-Redirect URL"
  );

  const spMetadataXml = generateSpMetadataXml({
    spEntityId: "https://app.devauthkit.com/auth/sso/saml/conn_123/metadata.xml",
    acsUrl: "https://app.devauthkit.com/auth/sso/saml/conn_123/acs",
    signingCert: publicKey
  });

  assert(
    spMetadataXml.includes("<md:EntityDescriptor") &&
    spMetadataXml.includes("<md:SPSSODescriptor") &&
    spMetadataXml.includes("<md:AssertionConsumerService"),
    "generateSpMetadataXml generates valid SAML 2.0 SP Metadata XML"
  );

  // ==========================================
  // SECTION 4: DNS TXT Domain Verification Primitives
  // ==========================================
  console.log("\n🌐 4. DNS TXT Domain Verification...");

  const token = generateDomainVerificationToken();
  assert(token.startsWith("devauth-domain-verification="), "generateDomainVerificationToken generates formatted verification token");

  // Mock DoH fetch returning verification record
  const mockFetchSuccess = async () => ({
    ok: true,
    json: async () => ({
      Answer: [{ data: `"${token}"` }]
    })
  });
  const domainVerified = await verifyDomainTxt("acme.com", token, mockFetchSuccess);
  assert(domainVerified === true, "verifyDomainTxt returns true when DNS TXT matches token");

  const mockFetchFail = async () => ({
    ok: true,
    json: async () => ({
      Answer: [{ data: `"devauth-domain-verification=different_token"` }]
    })
  });
  const domainFailed = await verifyDomainTxt("acme.com", token, mockFetchFail);
  assert(domainFailed === false, "verifyDomainTxt returns false when DNS TXT token does not match");

  // ==========================================
  // SECTION 5: SCIM 2.0 Protocol Engine
  // ==========================================
  console.log("\n👥 5. SCIM 2.0 Protocol Engine & Instant Deprovisioning Parsing...");

  const scimToken = generateScimBearerToken();
  assert(scimToken.startsWith("scim_live_"), "generateScimBearerToken produces scim_live_ token");

  const scimTokenHash = await hashScimBearerToken(scimToken);
  assert(typeof scimTokenHash === "string" && scimTokenHash.length === 64, "hashScimBearerToken computes SHA-256 hex");

  const scimTokenValid = await verifyScimBearerToken(scimToken, scimTokenHash);
  assert(scimTokenValid === true, "verifyScimBearerToken validates matching token with constant-time check");

  const scimTokenTampered = await verifyScimBearerToken(scimToken + "tamper", scimTokenHash);
  assert(scimTokenTampered === false, "verifyScimBearerToken rejects tampered token");

  // Filter parsing
  const filterParsed = parseScimFilter('userName eq "alice@enterprise.com"');
  assert(
    filterParsed.attribute === "userName" && filterParsed.operator === "eq" && filterParsed.value === "alice@enterprise.com",
    "parseScimFilter parses userName eq 'value'"
  );

  // Patch parsing for deprovisioning
  const patchDeprovision = parseScimPatchOperations([
    { op: "replace", path: "active", value: false }
  ]);
  assert(patchDeprovision.active === false, "parseScimPatchOperations detects active: false deactivation");

  const patchDeprovisionObj = parseScimPatchOperations([
    { op: "replace", value: { active: false } }
  ]);
  assert(patchDeprovisionObj.active === false, "parseScimPatchOperations detects { active: false } object replace");

  // RFC 7643 & 7644 schemas
  const spConfig = getServiceProviderConfig("https://api.devauthkit.com/scim/v2");
  assert(spConfig.schemas[0].includes("ServiceProviderConfig") && spConfig.patch.supported === true, "getServiceProviderConfig conforms to RFC 7643");

  const formattedScimUser = formatScimUser(
    { id: "usr_1", email: "alice@enterprise.com", name: "Alice Enterprise" },
    { userId: "usr_1", active: true },
    "https://api.devauthkit.com/scim/v2"
  );
  assert(formattedScimUser.schemas.includes(SCIM_USER_SCHEMA) && formattedScimUser.userName === "alice@enterprise.com", "formatScimUser formats RFC 7644 user");

  // ==========================================
  // SECTION 6: Multi-Tenant Stores (MemorySsoStore & CloudflareD1SsoStore)
  // ==========================================
  console.log("\n🗄️ 6. Storage Adapters: MemorySsoStore & CloudflareD1SsoStore Parity...");

  const memStore = new MemorySsoStore();
  const conn1 = await memStore.createConnection({
    orgId: "org_acme",
    name: "Acme Okta SAML",
    type: "SAML",
    domains: ["acme.com", "@acme-corp.com"],
    idpSsoUrl: "https://idp.acme.com/sso",
    idpCertificates: [publicKey]
  });

  assert(conn1.id && conn1.domains.includes("acme.com") && conn1.domains.includes("acme-corp.com"), "MemorySsoStore creates connection with normalized domains");

  const connByDomain = await memStore.getConnectionByDomain("acme.com");
  assert(connByDomain && connByDomain.id === conn1.id, "MemorySsoStore resolves connection by domain");

  // Mock D1 Database for CloudflareD1SsoStore
  const d1Tables = {
    sso_connections: new Map(),
    saml_replays: new Map(),
    scim_directories: new Map(),
    scim_user_mappings: new Map(),
    scim_group_mappings: new Map()
  };

  const mockD1Database = {
    prepare(query) {
      let bound = [];
      return {
        bind(...args) {
          bound = args;
          return this;
        },
        async first() {
          if (query.includes("SELECT * FROM devauthkit_sso_connections WHERE id = ?")) {
            return d1Tables.sso_connections.get(bound[0]) || null;
          }
          if (query.includes("SELECT * FROM devauthkit_scim_directories WHERE bearer_token_hash = ?")) {
            for (const dir of d1Tables.scim_directories.values()) {
              if (dir.bearer_token_hash === bound[0] && dir.active === 1) return dir;
            }
            return null;
          }
          if (query.includes("SELECT expires_at FROM devauthkit_saml_assertion_replays WHERE assertion_id = ?")) {
            const exp = d1Tables.saml_replays.get(bound[0]);
            return exp ? { expires_at: exp } : null;
          }
          return null;
        },
        async all() {
          if (query.includes("devauthkit_sso_connections")) {
            return { results: Array.from(d1Tables.sso_connections.values()) };
          }
          if (query.includes("devauthkit_scim_user_mappings")) {
            return { results: Array.from(d1Tables.scim_user_mappings.values()) };
          }
          return { results: [] };
        },
        async run() {
          if (query.includes("INSERT INTO devauthkit_sso_connections")) {
            const row = {
              id: bound[0],
              org_id: bound[1],
              name: bound[2],
              type: bound[3],
              domains: bound[4],
              domain_verified: bound[5],
              domain_verification_token: bound[6],
              idp_entity_id: bound[7],
              idp_sso_url: bound[8],
              idp_slo_url: bound[9],
              idp_certificates: bound[10],
              sp_entity_id: bound[11],
              sp_acs_url: bound[12],
              oidc_issuer: bound[13],
              oidc_client_id: bound[14],
              oidc_client_secret: bound[15],
              oidc_discovery_url: bound[16],
              default_role: bound[17],
              attribute_mapping: bound[18],
              active: bound[19],
              created_at: bound[20],
              updated_at: bound[21]
            };
            d1Tables.sso_connections.set(bound[0], row);
            return { success: true, meta: { changes: 1 } };
          }
          if (query.includes("INSERT OR REPLACE INTO devauthkit_saml_assertion_replays")) {
            d1Tables.saml_replays.set(bound[0], bound[1]);
            return { success: true, meta: { changes: 1 } };
          }
          if (query.includes("INSERT INTO devauthkit_scim_directories")) {
            const row = {
              id: bound[0],
              org_id: bound[1],
              bearer_token_hash: bound[2],
              scim_base_url: bound[3],
              active: bound[4],
              created_at: bound[5],
              updated_at: bound[6]
            };
            d1Tables.scim_directories.set(bound[0], row);
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 1 } };
        }
      };
    },
    async batch() {
      return [];
    }
  };

  const d1Store = new CloudflareD1SsoStore(mockD1Database);
  await d1Store.createTables();

  const d1Conn = await d1Store.createConnection({
    orgId: "org_d1_corp",
    name: "D1 SAML Azure AD",
    domains: ["d1corp.com"],
    idpSsoUrl: "https://login.microsoftonline.com/sso",
    idpCertificates: [publicKey]
  });

  assert(d1Conn && d1Conn.name === "D1 SAML Azure AD", "CloudflareD1SsoStore creates and maps SSO connection");

  const d1ConnByDomain = await d1Store.getConnectionByDomain("d1corp.com");
  assert(d1ConnByDomain && d1ConnByDomain.id === d1Conn.id, "CloudflareD1SsoStore resolves connection by domain");

  await d1Store.recordAssertion("assert_d1_test", 600);
  const d1Replayed = await d1Store.isAssertionReplayed("assert_d1_test");
  assert(d1Replayed === true, "CloudflareD1SsoStore records and detects assertion replays");

  // ==========================================
  // SECTION 7: End-to-End Express Integration
  // ==========================================
  console.log("\n🚀 7. End-to-End Express Server Integration (SSO & SCIM)...");

  const expressApp = express();
  const testSsoStore = new MemorySsoStore();
  const testOrgStore = new MemoryOrganizationStore();
  const testRefreshStore = new MemoryRefreshTokenStore();

  devAuthKit(expressApp, {
    jwtSecret: "devAuthSuperSecretKeyForSSOTesting123!",
    sessionSecret: "devAuthSessionSecretForSSOTesting123!",
    sso: true,
    ssoStore: testSsoStore,
    organizations: true,
    organizationStore: testOrgStore,
    refreshTokens: true,
    refreshTokenStore: testRefreshStore,
    webhooks: true
  });

  const server = await new Promise((resolve) => {
    const s = expressApp.listen(0, () => resolve(s));
  });
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  // Admin creates an Organization
  const orgResult = await testOrgStore.createOrg({
    name: "Acme Corporation",
    slug: "acme",
    ownerUserId: "admin_1",
    ownerEmail: "admin@acme.com"
  });
  const orgId = orgResult.organization.id;

  // Create admin JWT for API calls
  const adminToken = await signJwt(
    { id: "admin_1", email: "admin@acme.com" },
    "devAuthSuperSecretKeyForSSOTesting123!",
    "1h"
  );

  // 1. Admin creates SSO Connection
  const createConnRes = await fetch(`${baseUrl}/auth/sso/connections`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${adminToken}`
    },
    body: JSON.stringify({
      orgId,
      name: "Acme Okta SAML",
      type: "SAML",
      domains: ["acme.com"],
      idpSsoUrl: "https://idp.acme.com/app/sso",
      idpCertificates: [publicKey],
      defaultRole: "member"
    })
  });
  const createConnData = await createConnRes.json();
  assert(createConnRes.status === 201 && createConnData.connection.id, "POST /auth/sso/connections creates SSO connection");
  const connectionId = createConnData.connection.id;

  // 2. Resolve SSO by domain
  const resolveRes = await fetch(`${baseUrl}/auth/sso/resolve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "bob@acme.com" })
  });
  const resolveData = await resolveRes.json();
  assert(
    resolveRes.status === 200 && resolveData.type === "SAML" && resolveData.redirectUrl.includes("SAMLRequest="),
    "POST /auth/sso/resolve resolves connection and returns AuthnRequest redirectUrl"
  );

  // 3. Download SP Metadata XML
  const metaRes = await fetch(`${baseUrl}/auth/sso/saml/${connectionId}/metadata.xml`);
  const metaXml = await metaRes.text();
  assert(
    metaRes.status === 200 &&
    metaRes.headers.get("content-type").includes("xml") &&
    metaXml.includes("<md:EntityDescriptor"),
    "GET /auth/sso/saml/:id/metadata.xml serves standard XML SP Metadata"
  );

  // 4. SAML ACS Callback Authentication & JIT Provisioning
  const samlResponseXml = createSignedSamlResponse({
    nameId: "bob@acme.com",
    audience: createConnData.connection.spEntityId,
    recipient: createConnData.connection.spAcsUrl
  });

  const acsRes = await fetch(`${baseUrl}/auth/sso/saml/${connectionId}/acs`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json"
    },
    body: new URLSearchParams({
      SAMLResponse: Buffer.from(samlResponseXml, "utf8").toString("base64")
    }).toString()
  });

  const acsData = await acsRes.json();
  assert(
    acsRes.status === 200 && acsData.success === true && acsData.token && acsData.user.email === "bob@acme.com",
    "POST /auth/sso/saml/:id/acs verifies SAMLResponse and issues tenant-scoped JWT"
  );

  // Verify JIT organization membership was created for Bob
  const bobMember = await testOrgStore.getMember(orgId, acsData.user.id);
  assert(
    bobMember && bobMember.role === "member",
    "SAML ACS automatically JIT provisions user into organization with defaultRole"
  );

  // 5. Admin creates SCIM 2.0 Directory
  const createScimDirRes = await fetch(`${baseUrl}/auth/scim/directories`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${adminToken}`
    },
    body: JSON.stringify({ orgId })
  });
  const createScimDirData = await createScimDirRes.json();
  assert(
    createScimDirRes.status === 201 && createScimDirData.bearerToken.startsWith("scim_live_"),
    "POST /auth/scim/directories generates SCIM directory and high-entropy bearer token"
  );
  const scimBearer = createScimDirData.bearerToken;

  // 6. SCIM 2.0 Provision User (RFC 7644 POST /scim/v2/Users)
  const scimCreateUserRes = await fetch(`${baseUrl}/scim/v2/Users`, {
    method: "POST",
    headers: {
      "Content-Type": "application/scim+json",
      Authorization: `Bearer ${scimBearer}`
    },
    body: JSON.stringify({
      schemas: [SCIM_USER_SCHEMA],
      userName: "charlie@acme.com",
      externalId: "ext_okta_charlie_123",
      name: { givenName: "Charlie", familyName: "Acme" },
      emails: [{ value: "charlie@acme.com", primary: true }],
      active: true
    })
  });
  const scimCreateUserData = await scimCreateUserRes.json();
  assert(
    scimCreateUserRes.status === 201 && scimCreateUserData.userName === "charlie@acme.com",
    "POST /scim/v2/Users provisions user and membership over SCIM 2.0 protocol"
  );
  const charlieUserId = scimCreateUserData.id;

  // Create an active session for Charlie in refreshTokenStore to test cascade purge
  await testRefreshStore.create("token_hash_charlie", {
    familyId: "fam_charlie",
    userId: charlieUserId,
    user: { id: charlieUserId, email: "charlie@acme.com" },
    expiresAt: Date.now() + 86400000
  });

  // 7. SCIM 2.0 Instant Deprovisioning Cascade (PATCH /scim/v2/Users/:id with active: false)
  const scimPatchRes = await fetch(`${baseUrl}/scim/v2/Users/${charlieUserId}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/scim+json",
      Authorization: `Bearer ${scimBearer}`
    },
    body: JSON.stringify({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [
        { op: "replace", path: "active", value: false }
      ]
    })
  });
  const scimPatchData = await scimPatchRes.json();
  assert(
    scimPatchRes.status === 200 && scimPatchData.active === false,
    "PATCH /scim/v2/Users/:id deactivates user"
  );

  // Check that Charlie's org membership was removed
  const charlieMember = await testOrgStore.getMember(orgId, charlieUserId);
  assert(charlieMember === null, "Instant Deprovisioning Cascade: removes organization membership");

  // Check that Charlie's active refresh session family was purged
  const isFamilyActive = await testRefreshStore.isFamilyActive("fam_charlie");
  assert(isFamilyActive === false, "Instant Deprovisioning Cascade: revokes all active user sessions across clusters");

  // Close server cleanly
  await new Promise((resolve) => server.close(resolve));

  // ==========================================
  // SECTION 8: Hono & Cloudflare Workers Dual-Runtime Parity
  // ==========================================
  console.log("\n⚡ 8. Hono on Cloudflare Workers Runtime Parity...");

  const honoApp = new Hono();
  const honoSsoStore = new MemorySsoStore();
  const honoConn = await honoSsoStore.createConnection({
    orgId: "org_hono",
    name: "Hono SAML",
    domains: ["hono-cloud.com"],
    idpSsoUrl: "https://idp.hono.com/sso",
    idpCertificates: [publicKey]
  });

  const honoDir = await honoSsoStore.createDirectory({
    orgId: "org_hono",
    bearerTokenHash: await hashScimBearerToken("scim_hono_token_123")
  });

  config.set({
    jwtSecret: "honoSuperSecretKeyForSSOTesting123!",
    sessionSecret: "honoSessionSecretForSSOTesting123!",
    sso: true,
    ssoStore: honoSsoStore,
    scim: true
  });

  const authRouter = createAuthRouter({
    jwtSecret: "honoSuperSecretKeyForSSOTesting123!",
    sessionSecret: "honoSessionSecretForSSOTesting123!",
    sso: true,
    ssoStore: honoSsoStore,
    scim: true
  });
  honoApp.route("/", authRouter);

  // 1. Resolve SSO on Hono
  const honoResolveRes = await honoApp.request("http://localhost/auth/sso/resolve", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "worker@hono-cloud.com" })
  });
  const honoResolveData = await honoResolveRes.json();
  assert(
    honoResolveRes.status === 200 && honoResolveData.type === "SAML",
    "Hono: POST /auth/sso/resolve domain routing works on Workers"
  );

  // 2. SP Metadata on Hono
  const honoMetaRes = await honoApp.request(`http://localhost/auth/sso/saml/${honoConn.id}/metadata.xml`);
  const honoMetaText = await honoMetaRes.text();
  assert(
    honoMetaRes.status === 200 && honoMetaText.includes("<md:EntityDescriptor"),
    "Hono: GET /auth/sso/saml/:id/metadata.xml generates SP metadata XML"
  );

  // 3. SCIM ServiceProviderConfig on Hono
  const honoScimConfigRes = await honoApp.request("http://localhost/scim/v2/ServiceProviderConfig");
  const honoScimConfigData = await honoScimConfigRes.json();
  assert(
    honoScimConfigRes.status === 200 && honoScimConfigData.schemas[0].includes("ServiceProviderConfig"),
    "Hono: GET /scim/v2/ServiceProviderConfig returns RFC 7643 config"
  );

  // 4. SCIM Bearer Authentication on Hono
  const honoScimUnauthorized = await honoApp.request("http://localhost/scim/v2/Users");
  assert(honoScimUnauthorized.status === 401, "Hono: SCIM rejects unauthorized requests without bearer token");

  const honoScimAuthorized = await honoApp.request("http://localhost/scim/v2/Users", {
    headers: { Authorization: "Bearer scim_hono_token_123" }
  });
  assert(honoScimAuthorized.status === 200, "Hono: SCIM accepts valid bearer token");

  // Summary
  console.log(`\n========================================`);
  console.log(`Enterprise SSO & SCIM Verification Complete: ${passed}/${total} assertions passed.`);
  console.log(`========================================\n`);

  if (passed !== total) {
    throw new Error(`SSO/SCIM Tests Failed: ${total - passed} assertions failed`);
  }
}

if (require.main === module) {
  runSsoScimTests().then(() => process.exit(0)).catch((err) => {
    console.error("Test failure:", err);
    process.exit(1);
  });
}

module.exports = { runSsoScimTests };
