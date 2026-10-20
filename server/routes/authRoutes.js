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
  getMe,
  logout
} = require("../controllers/authController");
const requireAuth = require("../middleware/requireAuth");
const rateLimit = require("../middleware/rateLimit");

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

// Optional Google OAuth flow (enabled when google credentials are configured)
router.get("/google", rateLimit("googleStart"), startGoogleOAuth);
router.get("/google/callback", rateLimit("googleCallback"), googleOAuthCallback);

// Optional GitHub OAuth flow (enabled when github credentials are configured)
router.get("/github", rateLimit("githubStart"), startGitHubOAuth);
router.get("/github/callback", rateLimit("githubCallback"), githubOAuthCallback);

// Profile / Current user
router.get("/me", requireAuth, getMe);

// Logout
router.post("/logout", rateLimit("logout"), logout);
router.get("/logout", rateLimit("logout"), logout); // also support GET for quick link clicks

module.exports = router;