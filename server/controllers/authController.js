// server/controllers/authController.js
const jwt = require("jsonwebtoken");
const { sendOTP } = require("../utils/mailer");
const generateOTP = require("../utils/generateOTP");
const sessionStore = require("../sessionStore");
const config = require("../config");

// Simple email regex for basic validation
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Request an OTP for email login/verification
 */
exports.requestOTP = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !EMAIL_REGEX.test(email.trim())) {
      return res.status(400).json({ error: "A valid email address is required" });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const existing = sessionStore.get ? sessionStore.get(normalizedEmail) : sessionStore[normalizedEmail];

    // Throttle: enforce minimum 30 seconds between OTP requests per email
    if (existing && Date.now() - existing.createdAt < 30 * 1000) {
      const waitSeconds = Math.ceil((30 * 1000 - (Date.now() - existing.createdAt)) / 1000);
      return res.status(429).json({ 
        error: `Please wait ${waitSeconds}s before requesting a new code` 
      });
    }

    const otp = generateOTP();
    const otpData = { otp, attempts: 0, createdAt: Date.now() };

    if (sessionStore.set) {
      sessionStore.set(normalizedEmail, otpData);
    } else {
      sessionStore[normalizedEmail] = otpData;
    }

    const result = await sendOTP({ email: normalizedEmail, otp });

    return res.json({
      message: "OTP sent successfully",
      expiresInMinutes: config.get("otpExpiryMinutes"),
      devMode: result.devMode || undefined
    });
  } catch (error) {
    console.error("[DevAuthKit] Error requesting OTP:", error);
    return res.status(500).json({ 
      error: "Failed to send OTP",
      details: config.get("debug") ? error.message : undefined
    });
  }
};

/**
 * Verify OTP and authenticate user (generates JWT + creates session)
 */
exports.verifyOTP = (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ error: "Email and OTP are required" });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const entry = sessionStore.get ? sessionStore.get(normalizedEmail) : sessionStore[normalizedEmail];

    if (!entry) {
      return res.status(401).json({ 
        error: "No pending OTP found for this email. Please request a new code." 
      });
    }

    const maxAttempts = config.get("maxAttempts");
    if (entry.attempts >= maxAttempts) {
      if (sessionStore.delete) sessionStore.delete(normalizedEmail);
      else delete sessionStore[normalizedEmail];
      return res.status(429).json({ 
        error: "Too many failed attempts. This OTP has been invalidated for security. Please request a new code." 
      });
    }

    const expiryMs = config.get("otpExpiryMinutes") * 60 * 1000;
    if (Date.now() - entry.createdAt > expiryMs) {
      if (sessionStore.delete) sessionStore.delete(normalizedEmail);
      else delete sessionStore[normalizedEmail];
      return res.status(401).json({ error: "OTP has expired. Please request a new one." });
    }

    if (entry.otp !== otp.toString().trim()) {
      let attempts = 0;
      if (sessionStore.recordAttempt) {
        attempts = sessionStore.recordAttempt(normalizedEmail);
      } else {
        entry.attempts = (entry.attempts || 0) + 1;
        attempts = entry.attempts;
      }
      const attemptsRemaining = Math.max(0, maxAttempts - attempts);
      return res.status(401).json({ 
        error: "Invalid OTP",
        attemptsRemaining
      });
    }

    // OTP is valid - clear from store to prevent replay attacks
    if (sessionStore.delete) sessionStore.delete(normalizedEmail);
    else delete sessionStore[normalizedEmail];

    const userPayload = { email: normalizedEmail };

    // 1. Generate JWT Token
    const token = jwt.sign(
      userPayload,
      config.get("jwtSecret"),
      { expiresIn: config.get("jwtExpiresIn") }
    );

    // 2. Set Session (if session is available on req)
    if (req.session) {
      req.session.user = userPayload;
    }

    // 3. Set secure httpOnly cookie (if res.cookie is available and setHttpOnlyCookie is enabled)
    if (config.get("setHttpOnlyCookie") && typeof res.cookie === "function") {
      const isProduction = process.env.NODE_ENV === "production";
      const cookieName = config.get("cookieName") || "devauth_token";
      res.cookie(cookieName, token, {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? "strict" : "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });
    }

    return res.json({
      message: "Logged in successfully",
      token,
      user: userPayload
    });
  } catch (error) {
    console.error("[DevAuthKit] Error verifying OTP:", error);
    return res.status(500).json({ 
      error: "Verification failed",
      details: config.get("debug") ? error.message : undefined
    });
  }
};

/**
 * Get current authenticated user profile
 */
exports.getMe = (req, res) => {
  return res.json({
    user: req.user
  });
};

/**
 * Logout user - destroy session and clear session & auth cookies
 */
exports.logout = (req, res) => {
  const cookieName = config.get("cookieName") || "devauth_token";
  if (typeof res.clearCookie === "function") {
    res.clearCookie(cookieName);
    res.clearCookie("connect.sid");
  }

  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: "Failed to log out" });
      }
      return res.json({ message: "Logged out successfully" });
    });
  } else {
    return res.json({ message: "Logged out successfully" });
  }
};