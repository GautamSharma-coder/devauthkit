// server/routes/authRoutes.js
const express = require("express");
const router = express.Router();
const {
  requestOTP,
  verifyOTP,
  startGoogleOAuth,
  googleOAuthCallback,
  getMe,
  logout
} = require("../controllers/authController");
const requireAuth = require("../middleware/requireAuth");

// Request OTP / Login routes (aliases supported)
router.post("/request-otp", requestOTP);
router.post("/login", requestOTP);

// Verify OTP routes (aliases supported)
router.post("/verify-otp", verifyOTP);
router.post("/verify", verifyOTP);

// Optional Google OAuth flow (enabled when google credentials are configured)
router.get("/google", startGoogleOAuth);
router.get("/google/callback", googleOAuthCallback);

// Profile / Current user
router.get("/me", requireAuth, getMe);

// Logout
router.post("/logout", logout);
router.get("/logout", logout); // also support GET for quick link clicks

module.exports = router;