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

// Profile / Current user
router.get("/me", requireAuth, getMe);

// Logout
router.post("/logout", rateLimit("logout"), logout);
router.get("/logout", rateLimit("logout"), logout); // also support GET for quick link clicks

module.exports = router;