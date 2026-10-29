// server/routes/authRoutes.js
const express = require("express");
const router = express.Router();
const {
  requestOTP,
  verifyOTP,
  verifyMagicLink,
  refreshTokens,
  revokeSession,
  revokeAllSessions,
  startGoogleOAuth,
  googleOAuthCallback,
  startGitHubOAuth,
  githubOAuthCallback,
  startOAuth,
  oauthCallback,
  linkOAuth,
  passkeyRegistrationOptions,
  verifyPasskeyRegistration,
  passkeyAuthenticationOptions,
  verifyPasskeyAuthentication,
  listPasskeys,
  deletePasskey,
  getMe,
  logout
} = require("../controllers/authController");
const requireAuth = require("../middleware/requireAuth");
const rateLimit = require("../middleware/rateLimit");
const mfaController = require("../controllers/mfaController");
const requireMfa = require("../middleware/requireMfa");

// Request OTP / Login routes (aliases supported)
router.post("/request-otp", rateLimit("requestOtp"), requestOTP);
router.post("/login", rateLimit("requestOtp"), requestOTP);

// Verify OTP routes (aliases supported)
router.post("/verify-otp", rateLimit("verifyOtp"), verifyOTP);
router.post("/verify", rateLimit("verifyOtp"), verifyOTP);

// Magic Link verification routes (GET for browser click, POST for client API)
router.get("/verify-magic", rateLimit("verifyMagicLink"), verifyMagicLink);
router.post("/verify-magic", rateLimit("verifyMagicLink"), verifyMagicLink);

router.post("/refresh", rateLimit("refresh"), refreshTokens);
router.post("/sessions/revoke", rateLimit("revokeSession"), requireAuth, revokeSession);
router.post("/sessions/revoke-all", rateLimit("revokeAllSessions"), requireAuth, revokeAllSessions);

router.get("/mfa", requireAuth, mfaController.status);
router.post("/mfa/enroll", rateLimit("mfaEnroll"), requireAuth, mfaController.sameOrigin, mfaController.enroll);
router.post("/mfa/enable", rateLimit("mfaEnable"), requireAuth, mfaController.sameOrigin, mfaController.enable);
router.post("/mfa/verify", rateLimit("mfaVerify"), requireAuth, mfaController.verify);
router.post("/mfa/disable", rateLimit("mfaDisable"), requireAuth, mfaController.sameOrigin, requireMfa, mfaController.disable);

// Optional Google OAuth flow (enabled when google credentials are configured)
router.get("/google", rateLimit("googleStart"), startGoogleOAuth);
router.get("/google/callback", rateLimit("googleCallback"), googleOAuthCallback);

// Optional GitHub OAuth flow (enabled when github credentials are configured)
router.get("/github", rateLimit("githubStart"), startGitHubOAuth);
router.get("/github/callback", rateLimit("githubCallback"), githubOAuthCallback);

router.get("/oauth/:provider", rateLimit("oauthStart"), startOAuth);
router.get("/oauth/:provider/callback", rateLimit("oauthCallback"), oauthCallback);
router.post("/oauth/:provider/link", rateLimit("oauthLink"), requireAuth, linkOAuth);

router.post("/passkeys/register/options", rateLimit("passkeyRegisterOptions"), requireAuth, passkeyRegistrationOptions);
router.post("/passkeys/register/verify", rateLimit("passkeyRegisterVerify"), requireAuth, verifyPasskeyRegistration);
router.post("/passkeys/authenticate/options", rateLimit("passkeyAuthenticationOptions"), passkeyAuthenticationOptions);
router.post("/passkeys/authenticate/verify", rateLimit("passkeyAuthenticationVerify"), verifyPasskeyAuthentication);
router.get("/passkeys", rateLimit("passkeyList"), requireAuth, listPasskeys);
router.delete("/passkeys/:credentialId", rateLimit("passkeyDelete"), requireAuth, deletePasskey);

// Multi-Tenancy & Organizations routes
const orgController = require("../controllers/organizationController");
router.post("/orgs", requireAuth, orgController.createOrg);
router.get("/orgs", requireAuth, orgController.listUserOrgs);
router.post("/orgs/join", requireAuth, orgController.joinOrg);
router.get("/orgs/:id", requireAuth, orgController.getOrg);
router.patch("/orgs/:id", requireAuth, orgController.updateOrg);
router.delete("/orgs/:id", requireAuth, orgController.deleteOrg);
router.post("/orgs/:id/switch", requireAuth, orgController.switchOrg);
router.post("/orgs/:id/invites", requireAuth, orgController.inviteMember);
router.get("/orgs/:id/invites", requireAuth, orgController.listInvitations);
router.delete("/orgs/:id/invites/:inviteId", requireAuth, orgController.revokeInvitation);
router.patch("/orgs/:id/members/:userId", requireAuth, orgController.updateMemberRole);
router.delete("/orgs/:id/members/:userId", requireAuth, orgController.removeMember);

// Cryptographically Signed Webhooks management routes
const webhookController = require("../controllers/webhookController");
router.post("/webhooks", requireAuth, webhookController.createEndpoint);
router.get("/webhooks", requireAuth, webhookController.listEndpoints);
router.get("/webhooks/:id", requireAuth, webhookController.getEndpoint);
router.patch("/webhooks/:id", requireAuth, webhookController.updateEndpoint);
router.delete("/webhooks/:id", requireAuth, webhookController.deleteEndpoint);
router.get("/webhooks/:id/deliveries", requireAuth, webhookController.listDeliveries);
router.post("/webhooks/:id/test", requireAuth, webhookController.testEndpoint);

// Enterprise SSO (SAML 2.0 & OIDC) routes
const ssoController = require("../controllers/ssoController");
router.post("/sso/connections", requireAuth, ssoController.createConnection);
router.get("/sso/connections", requireAuth, ssoController.listConnections);
router.get("/sso/connections/:id", requireAuth, ssoController.getConnection);
router.patch("/sso/connections/:id", requireAuth, ssoController.updateConnection);
router.delete("/sso/connections/:id", requireAuth, ssoController.deleteConnection);
router.post("/sso/connections/:id/verify-domain", requireAuth, ssoController.verifyDomain);

// Public SSO Discovery and IdP Handlers
router.post("/sso/resolve", ssoController.resolveSso);
router.get("/sso/resolve", ssoController.resolveSso);
router.get("/sso/saml/:connectionId/metadata.xml", ssoController.getSpMetadata);
router.get("/sso/saml/metadata.xml", ssoController.getSpMetadata);
router.post("/sso/saml/:connectionId/acs", ssoController.handleSamlAcs);
router.post("/sso/saml/acs", ssoController.handleSamlAcs);

// SCIM 2.0 Directory Management & Protocol routes
const scimController = require("../controllers/scimController");
router.post("/scim/directories", requireAuth, scimController.createDirectory);
router.get("/scim/directories", requireAuth, scimController.listDirectories);
router.get("/scim/directories/:id", requireAuth, scimController.getDirectory);
router.post("/scim/directories/:id/rotate-token", requireAuth, scimController.rotateToken);
router.delete("/scim/directories/:id", requireAuth, scimController.deleteDirectory);

// SCIM 2.0 Protocol Endpoints (RFC 7643 & 7644)
router.get("/scim/v2/ServiceProviderConfig", scimController.getServiceProviderConfig);
router.get("/scim/v2/Schemas", scimController.getSchemas);
router.get("/scim/v2/Users", scimController.authenticateScimBearer, scimController.listUsers);
router.get("/scim/v2/Users/:id", scimController.authenticateScimBearer, scimController.getUser);
router.post("/scim/v2/Users", scimController.authenticateScimBearer, scimController.createUser);
router.patch("/scim/v2/Users/:id", scimController.authenticateScimBearer, scimController.patchUser);
router.put("/scim/v2/Users/:id", scimController.authenticateScimBearer, scimController.patchUser);
router.delete("/scim/v2/Users/:id", scimController.authenticateScimBearer, scimController.deleteUser);
router.get("/scim/v2/Groups", scimController.authenticateScimBearer, scimController.listGroups);
router.get("/scim/v2/Groups/:id", scimController.authenticateScimBearer, scimController.getGroup);
router.post("/scim/v2/Groups", scimController.authenticateScimBearer, scimController.createGroup);
router.patch("/scim/v2/Groups/:id", scimController.authenticateScimBearer, scimController.patchGroup);
router.put("/scim/v2/Groups/:id", scimController.authenticateScimBearer, scimController.patchGroup);

// Profile / Current user
router.get("/me", requireAuth, getMe);

// Logout
router.post("/logout", rateLimit("logout"), logout);
router.get("/logout", rateLimit("logout"), logout); // also support GET for quick link clicks

// ==========================================
// DevAuthKit v2 Next-Gen Feature Routes
// ==========================================

// 1. Immutable Audit Logs & Merkle Verification
const auditLogController = require("../controllers/auditLogController");
router.get("/audit-logs", requireAuth, auditLogController.queryAuditLogs);
router.get("/audit-logs/export", requireAuth, auditLogController.exportAuditLogs);
router.get("/audit-logs/:id", requireAuth, auditLogController.getAuditLog);
router.post("/audit-logs/verify", requireAuth, auditLogController.verifyAuditTrail);

// 2. Machine Identity & Scoped API Keys
const apiKeyController = require("../controllers/apiKeyController");
router.post("/api-keys", requireAuth, rateLimit("createApiKey"), apiKeyController.createApiKey);
router.get("/api-keys", requireAuth, rateLimit("listApiKeys"), apiKeyController.listApiKeys);
router.get("/api-keys/:id", requireAuth, apiKeyController.getApiKey);
router.patch("/api-keys/:id", requireAuth, apiKeyController.updateApiKey);
router.delete("/api-keys/:id", requireAuth, apiKeyController.revokeApiKey);
router.post("/api-keys/:id/roll", requireAuth, apiKeyController.rollApiKey);

// 3. RFC 8693 User Impersonation ("Act As")
const impersonationController = require("../controllers/impersonationController");
router.post("/impersonate", requireAuth, rateLimit("impersonate"), impersonationController.startImpersonation);
router.post("/end-impersonation", requireAuth, impersonationController.endImpersonation);

// 4. User Status, Blocking & Suspension Cascade
const userManagementController = require("../controllers/userManagementController");
router.post("/users/:userId/block", requireAuth, rateLimit("blockUser"), userManagementController.blockUser);
router.post("/users/:userId/unblock", requireAuth, rateLimit("blockUser"), userManagementController.unblockUser);
router.get("/users/:userId/status", requireAuth, userManagementController.getUserStatus);

// 5. Multi-Device Sessions & Remote Revocation
const sessionController = require("../controllers/sessionController");
router.get("/sessions", requireAuth, rateLimit("listSessions"), sessionController.listSessions);
router.delete("/sessions/:id", requireAuth, sessionController.revokeSession);
router.post("/sessions/revoke-others", requireAuth, sessionController.revokeOtherSessions);

module.exports = router;