// test_organizations.js
const express = require("express");
const devAuthKit = require("./server/server");
const {
  DEFAULT_ORG_ROLES,
  slugify,
  hasOrgPermission,
  getRolePermissions,
  canManageRole,
  generateInvitationToken,
  hashInvitationToken
} = require("./server/core/organizationService");
const { MemoryOrganizationStore } = require("./server/stores/memoryOrganizationStore");
const { DevAuthClient } = require("./client/index");
const { Hono } = require("hono");
const {
  createAuthRouter,
  requireAuth: honoRequireAuth,
  requireOrg: honoRequireOrg,
  requireOrgRole: honoRequireOrgRole,
  requireOrgPermission: honoRequireOrgPermission
} = require("./server/hono/index");
const { generateDPoPKeyPair, calculateJwkThumbprint, createDPoPProof } = require("./server/core/dpopService");
const { MemoryDpopReplayStore } = require("./server/stores/memoryDpopReplayStore");
const { signJwt } = require("./server/utils/webCrypto");

async function runOrganizationTests() {
  console.log("🏢 Starting DevAuthKit Multi-Tenancy & Organizations Automated Verification...\n");

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
  // SECTION 1: Core Domain Service Logic
  // ==========================================
  console.log("📐 1. Core Domain Service & Permission Matrix...");

  assert(
    slugify("Acme Rocket Corporation!") === "acme-rocket-corporation",
    "slugify creates clean, URL-safe workspace slug"
  );
  assert(
    slugify("  Spaces & Special @ Characters #123 ") === "spaces-special-characters-123",
    "slugify strips special characters and collapses dashes"
  );

  // Role hierarchies & Privilege Escalation protection
  assert(canManageRole("owner", "admin") === true, "Owner can manage Admin");
  assert(canManageRole("owner", "member") === true, "Owner can manage Member");
  assert(canManageRole("owner", "viewer") === true, "Owner can manage Viewer");
  assert(canManageRole("admin", "member") === true, "Admin can manage Member");
  assert(canManageRole("admin", "viewer") === true, "Admin can manage Viewer");
  assert(canManageRole("admin", "admin") === true, "Admin can manage Admin");
  assert(canManageRole("admin", "owner") === false, "Admin CANNOT grant Owner role (anti-privilege-escalation)");
  assert(canManageRole("member", "viewer") === false, "Member cannot manage roles");
  assert(canManageRole("viewer", "viewer") === false, "Viewer cannot manage roles");

  // Permission matching with wildcards
  assert(hasOrgPermission("owner", "any:random:permission") === true, "Owner has wildcard (*) access to everything");
  assert(hasOrgPermission("admin", "org:update") === true, "Admin has org:update permission");
  assert(hasOrgPermission("admin", "org:delete") === false, "Admin lacks org:delete (restricted to owner)");
  assert(hasOrgPermission("admin", "members:invite") === true, "Admin has members:invite (via members:* wildcard)");
  assert(hasOrgPermission("admin", "members:remove") === true, "Admin has members:remove (via members:* wildcard)");
  assert(hasOrgPermission("member", "projects:create") === true, "Member has projects:create (via projects:* wildcard)");
  assert(hasOrgPermission("member", "members:invite") === false, "Member lacks members:invite");
  assert(hasOrgPermission("viewer", "projects:read") === true, "Viewer has projects:read");
  assert(hasOrgPermission("viewer", "projects:create") === false, "Viewer lacks projects:create");

  // Invitation token cryptography
  const rawToken = generateInvitationToken();
  assert(typeof rawToken === "string" && rawToken.length === 64, "generateInvitationToken generates 256-bit hex token");
  const tokenHash1 = await hashInvitationToken(rawToken);
  const tokenHash2 = await hashInvitationToken(rawToken);
  assert(tokenHash1 === tokenHash2, "hashInvitationToken produces deterministic SHA-256 hash");
  assert(tokenHash1 !== rawToken, "Token hash is cryptographically distinct from raw secret");

  // ==========================================
  // SECTION 2: MemoryOrganizationStore Unit
  // ==========================================
  console.log("\n💾 2. MemoryOrganizationStore Unit Verification...");
  const memStore = new MemoryOrganizationStore();

  const { organization: org1, member: mem1 } = await memStore.createOrg({
    name: "Nebula Systems",
    ownerUserId: "user_owner_1",
    ownerEmail: "owner@nebula.com"
  });
  assert(org1.id && org1.slug === "nebula-systems", "createOrg provisions org with auto-slug");
  assert(mem1.role === "owner" && mem1.userId === "user_owner_1", "createOrg auto-provisions owner member");

  const orgBySlug = await memStore.getOrgBySlug("nebula-systems");
  assert(orgBySlug && orgBySlug.id === org1.id, "getOrgBySlug retrieves organization");

  const userOrgs = await memStore.listUserOrgs("user_owner_1");
  assert(userOrgs.length === 1 && userOrgs[0].name === "Nebula Systems", "listUserOrgs returns user memberships");

  // Member management
  const mem2 = await memStore.addMember(org1.id, "user_dev_2", "member", "dev@nebula.com");
  assert(mem2.role === "member", "addMember adds new member");
  const memberList = await memStore.listMembers(org1.id);
  assert(memberList.length === 2, "listMembers returns all members");

  const updatedMem = await memStore.updateMemberRole(org1.id, "user_dev_2", "admin");
  assert(updatedMem.role === "admin", "updateMemberRole promotes member to admin");

  // Invitation flow in store
  const inviteTokenRaw = generateInvitationToken();
  const inviteTokenHash = await hashInvitationToken(inviteTokenRaw);
  const invitation = await memStore.createInvitation({
    orgId: org1.id,
    email: "contractor@nebula.com",
    role: "viewer",
    inviterId: "user_owner_1",
    tokenHash: inviteTokenHash,
    expiresAt: Date.now() + 86400000
  });
  assert(invitation.id && invitation.email === "contractor@nebula.com", "createInvitation records invitation");

  const fetchedInvite = await memStore.getInvitationByTokenHash(inviteTokenHash);
  assert(fetchedInvite && fetchedInvite.id === invitation.id, "getInvitationByTokenHash resolves invitation");

  const inviteList = await memStore.listInvitations(org1.id);
  assert(inviteList.length === 1 && inviteList[0].tokenHash === undefined, "listInvitations excludes sensitive tokenHash");

  await memStore.deleteInvitation(invitation.id);
  const afterDeleteInvite = await memStore.getInvitationByTokenHash(inviteTokenHash);
  assert(afterDeleteInvite === null, "deleteInvitation deletes invitation");

  // Cascade delete
  await memStore.deleteOrg(org1.id);
  const orgAfterDelete = await memStore.getOrgById(org1.id);
  const membersAfterDelete = await memStore.listMembers(org1.id);
  assert(orgAfterDelete === null && membersAfterDelete.length === 0, "deleteOrg cascades and removes members");

  // ==========================================
  // SECTION 3: Express Endpoints & Middlewares
  // ==========================================
  console.log("\n🚀 3. Express Integration & Lifecycle Endpoints...");
  const app = express();
  const dpopReplayStore = new MemoryDpopReplayStore();
  devAuthKit(app, {
    jwtSecret: "org-test-jwt-secret-key-1234567890",
    sessionSecret: "org-test-session-secret-key-1234567890",
    devMode: true,
    organizations: true,
    dpop: true,
    dpopReplayStore
  });

  const { requireAuth, requireOrg, requireOrgRole, requireOrgPermission } = devAuthKit;

  // Protected workspace routes for testing
  app.get("/api/workspace/info", requireOrg, (req, res) => {
    res.json({ success: true, org: req.org, member: req.orgMember });
  });

  app.get("/api/workspace/billing", requireOrgRole("owner"), (req, res) => {
    res.json({ success: true, billing: "active" });
  });

  app.post("/api/workspace/projects", requireOrgPermission("projects:create"), (req, res) => {
    res.json({ success: true, project: "created" });
  });

  const server = app.listen(0);
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;

  try {
    // Generate auth tokens for Alice (user 1) and Bob (user 2)
    const aliceToken = await signJwt(
      { id: "usr_alice", email: "alice@example.com", role: "user" },
      "org-test-jwt-secret-key-1234567890"
    );
    const bobToken = await signJwt(
      { id: "usr_bob", email: "bob@example.com", role: "user" },
      "org-test-jwt-secret-key-1234567890"
    );

    // Test 3.1: Alice creates an organization "Starlight Labs"
    const createRes = await fetch(`${baseUrl}/auth/orgs`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${aliceToken}`
      },
      body: JSON.stringify({ name: "Starlight Labs" })
    });
    const createData = await createRes.json();
    assert(createRes.status === 201 && createData.organization.name === "Starlight Labs", "POST /auth/orgs creates organization");
    assert(createData.member.role === "owner", "Creator is granted owner role");
    const starlightOrgId = createData.organization.id;

    // Test 3.2: Alice lists user orgs
    const listRes = await fetch(`${baseUrl}/auth/orgs`, {
      headers: { Authorization: `Bearer ${aliceToken}` }
    });
    const listData = await listRes.json();
    assert(listData.organizations.length === 1 && listData.organizations[0].id === starlightOrgId, "GET /auth/orgs returns Starlight Labs for Alice");

    // Test 3.3: Switch workspace to Starlight Labs (mint tenant-scoped token)
    const switchRes = await fetch(`${baseUrl}/auth/orgs/${starlightOrgId}/switch`, {
      method: "POST",
      headers: { Authorization: `Bearer ${aliceToken}` }
    });
    const switchData = await switchRes.json();
    assert(switchRes.status === 200 && switchData.token, "POST /auth/orgs/:id/switch returns tenant-scoped token");
    const starlightAliceToken = switchData.token;

    // Test 3.4: Alice accesses requireOrg endpoint with tenant token
    const wsInfoRes = await fetch(`${baseUrl}/api/workspace/info`, {
      headers: { Authorization: `Bearer ${starlightAliceToken}` }
    });
    const wsInfoData = await wsInfoRes.json();
    assert(wsInfoRes.status === 200 && wsInfoData.org.name === "Starlight Labs", "requireOrg authenticates with tenant-scoped token");

    // Test 3.5: Alice accesses owner-only endpoint
    const billingRes = await fetch(`${baseUrl}/api/workspace/billing`, {
      headers: { Authorization: `Bearer ${starlightAliceToken}` }
    });
    assert(billingRes.status === 200, "requireOrgRole('owner') allows owner");

    // Test 3.6: Alice invites Bob as "member"
    const inviteRes = await fetch(`${baseUrl}/auth/orgs/${starlightOrgId}/invites`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${starlightAliceToken}`
      },
      body: JSON.stringify({ email: "bob@example.com", role: "member" })
    });
    const inviteData = await inviteRes.json();
    assert(inviteRes.status === 201 && inviteData.devModeInviteToken, "POST /auth/orgs/:id/invites returns devModeInviteToken in devMode");
    const bobInviteToken = inviteData.devModeInviteToken;

    // Test 3.7: Bob joins the organization
    const joinRes = await fetch(`${baseUrl}/auth/orgs/join`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${bobToken}`
      },
      body: JSON.stringify({ token: bobInviteToken })
    });
    const joinData = await joinRes.json();
    assert(joinRes.status === 200 && joinData.member.role === "member", "POST /auth/orgs/join accepts invite and adds Bob as member");
    const bobStarlightToken = joinData.token;

    // Test 3.8: Replaying the used invite token must fail
    const replayJoinRes = await fetch(`${baseUrl}/auth/orgs/join`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${bobToken}`
      },
      body: JSON.stringify({ token: bobInviteToken })
    });
    assert(replayJoinRes.status === 400, "Invitation token is single-use (replay rejected)");

    // Test 3.9: Bob (member) cannot access owner-only billing
    const bobBillingRes = await fetch(`${baseUrl}/api/workspace/billing`, {
      headers: { Authorization: `Bearer ${bobStarlightToken}` }
    });
    assert(bobBillingRes.status === 403, "requireOrgRole('owner') rejects member with 403");

    // Test 3.10: Bob (member) CAN access projects:create (via projects:* wildcard)
    const bobProjectRes = await fetch(`${baseUrl}/api/workspace/projects`, {
      method: "POST",
      headers: { Authorization: `Bearer ${bobStarlightToken}` }
    });
    assert(bobProjectRes.status === 200, "requireOrgPermission('projects:create') permits member");

    // Test 3.11: Header-based workspace switching (x-organization-id)
    const headerWsRes = await fetch(`${baseUrl}/api/workspace/info`, {
      headers: {
        Authorization: `Bearer ${bobToken}`, // base user token without org_id
        "x-organization-id": starlightOrgId
      }
    });
    const headerWsData = await headerWsRes.json();
    assert(headerWsRes.status === 200 && headerWsData.member.userId === "usr_bob", "x-organization-id header dynamically resolves organization context");

    // Test 3.12: Privilege escalation prevention via API:
    // Promote Bob to admin
    await fetch(`${baseUrl}/auth/orgs/${starlightOrgId}/members/usr_bob`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${starlightAliceToken}`
      },
      body: JSON.stringify({ role: "admin" })
    });

    // Bob switches to admin token
    const bobAdminSwitch = await fetch(`${baseUrl}/auth/orgs/${starlightOrgId}/switch`, {
      method: "POST",
      headers: { Authorization: `Bearer ${bobToken}` }
    });
    const bobAdminToken = (await bobAdminSwitch.json()).token;

    // Bob (admin) attempts to invite someone as "owner" -> must be rejected
    const escalateRes = await fetch(`${baseUrl}/auth/orgs/${starlightOrgId}/invites`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${bobAdminToken}`
      },
      body: JSON.stringify({ email: "mallory@example.com", role: "owner" })
    });
    assert(escalateRes.status === 403, "Admin cannot invite an owner (privilege escalation blocked)");

    // ==========================================
    // SECTION 4: DPoP Token Binding Continuity
    // ==========================================
    console.log("\n🔒 4. DPoP Cryptographic Binding Continuity on Org Switch...");
    const { keyPair: dpopKeyPair, jwk: dpopJwk } = await generateDPoPKeyPair();
    const dpopJkt = await calculateJwkThumbprint(dpopJwk);

    const dpopUserToken = await signJwt(
      { id: "usr_dpop", email: "dpop_user@example.com", role: "user", cnf: { jkt: dpopJkt } },
      "org-test-jwt-secret-key-1234567890"
    );

    // DPoP user creates an org
    const orgProof = await createDPoPProof({
      privateKey: dpopKeyPair.privateKey,
      jwk: dpopJwk,
      method: "POST",
      uri: `${baseUrl}/auth/orgs`,
      accessToken: dpopUserToken
    });

    const dpopOrgRes = await fetch(`${baseUrl}/auth/orgs`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `DPoP ${dpopUserToken}`,
        DPoP: orgProof
      },
      body: JSON.stringify({ name: "Cryptographic Labs" })
    });
    const dpopOrgData = await dpopOrgRes.json();
    const cryptoOrgId = dpopOrgData.organization.id;

    // DPoP user switches org
    const switchProof = await createDPoPProof({
      privateKey: dpopKeyPair.privateKey,
      jwk: dpopJwk,
      method: "POST",
      uri: `${baseUrl}/auth/orgs/${cryptoOrgId}/switch`,
      accessToken: dpopUserToken
    });

    const dpopSwitchRes = await fetch(`${baseUrl}/auth/orgs/${cryptoOrgId}/switch`, {
      method: "POST",
      headers: {
        Authorization: `DPoP ${dpopUserToken}`,
        DPoP: switchProof
      }
    });
    const dpopSwitchData = await dpopSwitchRes.json();
    assert(
      dpopSwitchData.tokenType === "DPoP",
      "Switching org preserves DPoP tokenType"
    );
    // Verify decoded JWT preserves cnf claim
    const { verifyJwt } = require("./server/utils/webCrypto");
    const verifiedTenantToken = await verifyJwt(dpopSwitchData.token, "org-test-jwt-secret-key-1234567890");
    assert(
      verifiedTenantToken.cnf?.jkt === dpopJkt,
      "DPoP thumbprint (cnf.jkt) is preserved in newly minted tenant-scoped token"
    );

    // ==========================================
    // SECTION 5: Hono Multi-Tenancy Parity
    // ==========================================
    console.log("\n⚡ 5. Hono Multi-Tenancy & Middleware Parity...");
    const honoApp = new Hono();
    const honoAuth = createAuthRouter({
      jwtSecret: "org-test-jwt-secret-key-1234567890",
      devMode: true,
      organizations: true
    });
    honoApp.route("/", honoAuth);

    // Protected Hono workspace route
    honoApp.get("/api/hono/workspace", honoRequireOrg(), (c) => {
      return c.json({ success: true, org: c.get("org"), member: c.get("orgMember") });
    });

    honoApp.get("/api/hono/admin-only", honoRequireOrgRole("admin"), (c) => {
      return c.json({ success: true, role: "admin_approved" });
    });

    honoApp.get("/api/hono/projects", honoRequireOrgPermission("projects:read"), (c) => {
      return c.json({ success: true, permission: "granted" });
    });

    // Hono create org
    const honoCreateReq = new Request("http://localhost/auth/orgs", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${aliceToken}`
      },
      body: JSON.stringify({ name: "Hono Cloud Inc" })
    });
    const honoCreateRes = await honoApp.fetch(honoCreateReq);
    const honoCreateData = await honoCreateRes.json();
    assert(honoCreateRes.status === 201 && honoCreateData.organization.name === "Hono Cloud Inc", "Hono: POST /auth/orgs creates organization");
    const honoOrgId = honoCreateData.organization.id;

    // Hono switch org
    const honoSwitchReq = new Request(`http://localhost/auth/orgs/${honoOrgId}/switch`, {
      method: "POST",
      headers: { Authorization: `Bearer ${aliceToken}` }
    });
    const honoSwitchRes = await honoApp.fetch(honoSwitchReq);
    const honoSwitchData = await honoSwitchRes.json();
    assert(honoSwitchRes.status === 200 && honoSwitchData.token, "Hono: POST /auth/orgs/:id/switch mints tenant-scoped token");
    const honoAliceToken = honoSwitchData.token;

    // Hono requireOrg middleware
    const honoWsReq = new Request("http://localhost/api/hono/workspace", {
      headers: { Authorization: `Bearer ${honoAliceToken}` }
    });
    const honoWsRes = await honoApp.fetch(honoWsReq);
    const honoWsData = await honoWsRes.json();
    assert(honoWsRes.status === 200 && honoWsData.org.name === "Hono Cloud Inc", "Hono: requireOrg middleware verifies tenant context");

    // Hono requireOrgRole middleware (Alice is owner, which satisfies admin requirement)
    const honoRoleReq = new Request("http://localhost/api/hono/admin-only", {
      headers: { Authorization: `Bearer ${honoAliceToken}` }
    });
    const honoRoleRes = await honoApp.fetch(honoRoleReq);
    assert(honoRoleRes.status === 200, "Hono: requireOrgRole allows owner");

    // Hono requireOrgPermission middleware
    const honoPermReq = new Request("http://localhost/api/hono/projects", {
      headers: { Authorization: `Bearer ${honoAliceToken}` }
    });
    const honoPermRes = await honoApp.fetch(honoPermReq);
    assert(honoPermRes.status === 200, "Hono: requireOrgPermission grants access");

    // ==========================================
    // SECTION 6: Client SDK Integration
    // ==========================================
    console.log("\n💻 6. Client SDK (DevAuthClient) Org Helpers...");
    const client = new DevAuthClient({
      apiUrl: baseUrl,
      customFetch: fetch
    });
    client.storage.setItem(client.tokenKey, aliceToken);

    const clientOrgs = await client.listOrgs();
    assert(Array.isArray(clientOrgs) && clientOrgs.length >= 1, "client.listOrgs() retrieves user organizations");

    const createdOrg = await client.createOrg({ name: "Quantum Software" });
    assert(createdOrg.success && createdOrg.organization.name === "Quantum Software", "client.createOrg() creates org");

    const switchResult = await client.switchOrg(createdOrg.organization.id);
    assert(switchResult.success && switchResult.token, "client.switchOrg() switches context");
    assert(client.getActiveOrg().id === createdOrg.organization.id, "client.getActiveOrg() stores active organization");

    // Verify client.fetch automatically attaches x-organization-id header
    const interceptedHeaders = [];
    const customFetchClient = new DevAuthClient({
      apiUrl: baseUrl,
      customFetch: async (url, opts) => {
        interceptedHeaders.push(opts.headers);
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
    });
    customFetchClient.storage.setItem(customFetchClient.tokenKey, aliceToken);
    customFetchClient.storage.setItem(customFetchClient.orgKey, JSON.stringify(createdOrg.organization));

    await customFetchClient.fetch("/api/custom");
    const sentHeaders = interceptedHeaders[0];
    const sentOrgId = sentHeaders.get ? sentHeaders.get("x-organization-id") : sentHeaders["x-organization-id"];
    assert(sentOrgId === createdOrg.organization.id, "client.fetch automatically injects x-organization-id header");

  } finally {
    server.close();
  }

  console.log(`\n==============================================`);
  console.log(`📊 Organization Test Summary: ${passed}/${total} assertions passed`);
  console.log(`==============================================\n`);

  if (passed !== total) {
    process.exit(1);
  }
}

runOrganizationTests().catch((err) => {
  console.error("❌ Test crashed:", err);
  process.exit(1);
});
