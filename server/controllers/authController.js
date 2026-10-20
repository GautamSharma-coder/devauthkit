// server/controllers/authController.js
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { sendOTP } = require("../utils/mailer");
const generateOTP = require("../utils/generateOTP");
const sessionStore = require("../sessionStore");
const config = require("../config");

// Simple email regex for basic validation
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

async function resolveUserPayload(email, identity = {}) {
  const userAdapter = config.get("userAdapter");
  if (!userAdapter) {
    return {
      email,
      ...(identity.name ? { name: identity.name } : {}),
      ...(identity.picture ? { picture: identity.picture } : {})
    };
  }

  const dbUser = await userAdapter.findOrCreateUser({ email });
  if (!dbUser || typeof dbUser !== "object" || dbUser.id === undefined || !dbUser.email) {
    throw new TypeError("userAdapter.findOrCreateUser must return a user with id and email");
  }

  const mappedClaims = config.get("mapUserPayload")
    ? config.get("mapUserPayload")(dbUser, identity)
    : {};
  if (!mappedClaims || typeof mappedClaims !== "object" || Array.isArray(mappedClaims)) {
    throw new TypeError("mapUserPayload must return an object");
  }

  return {
    ...mappedClaims,
    id: dbUser.id,
    email: dbUser.email,
    ...(dbUser.role !== undefined ? { role: dbUser.role } : {})
  };
}

function createToken(userPayload) {
  return jwt.sign(
    userPayload,
    config.get("jwtSecret"),
    { expiresIn: config.get("jwtExpiresIn") }
  );
}

function setAuthCookie(res, token) {
  if (!config.get("setHttpOnlyCookie") || typeof res.cookie !== "function") return;

  const isProduction = process.env.NODE_ENV === "production";
  const cookieName = config.get("cookieName") || "devauth_token";
  res.cookie(cookieName, token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "strict" : "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save((error) => error ? reject(error) : resolve());
  });
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => error ? reject(error) : resolve());
  });
}

function sendOAuthError(res, status, error, cause) {
  console.error(`[DevAuthKit] Google OAuth error: ${error}`, cause || "");
  return res.status(status).json({
    error,
    details: config.get("debug") && cause ? cause.message : undefined
  });
}

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
    const otpStore = config.get("otpStore") || sessionStore;
    const existing = await otpStore.get(normalizedEmail);

    // Throttle: enforce minimum 30 seconds between OTP requests per email
    if (existing && Date.now() - existing.createdAt < 30 * 1000) {
      const waitSeconds = Math.ceil((30 * 1000 - (Date.now() - existing.createdAt)) / 1000);
      return res.status(429).json({ 
        error: `Please wait ${waitSeconds}s before requesting a new code` 
      });
    }

    const otp = generateOTP();
    const otpData = { otp, attempts: 0, createdAt: Date.now() };

    await otpStore.set(normalizedEmail, otpData);

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
exports.verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ error: "Email and OTP are required" });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const otpStore = config.get("otpStore") || sessionStore;
    const entry = await otpStore.get(normalizedEmail);

    if (!entry) {
      return res.status(401).json({ 
        error: "No pending OTP found for this email. Please request a new code." 
      });
    }

    const maxAttempts = config.get("maxAttempts");
    if (entry.attempts >= maxAttempts) {
      await otpStore.delete(normalizedEmail);
      return res.status(429).json({ 
        error: "Too many failed attempts. This OTP has been invalidated for security. Please request a new code." 
      });
    }

    const expiryMs = config.get("otpExpiryMinutes") * 60 * 1000;
    if (Date.now() - entry.createdAt > expiryMs) {
      await otpStore.delete(normalizedEmail);
      return res.status(401).json({ error: "OTP has expired. Please request a new one." });
    }

    if (entry.otp !== otp.toString().trim()) {
      const attempts = await otpStore.recordAttempt(normalizedEmail);
      const attemptsRemaining = Math.max(0, maxAttempts - attempts);
      return res.status(401).json({ 
        error: "Invalid OTP",
        attemptsRemaining
      });
    }

    const userPayload = await resolveUserPayload(normalizedEmail);

    // OTP is valid - clear from store to prevent replay attacks
    await otpStore.delete(normalizedEmail);

    // 1. Generate JWT Token
    const token = createToken(userPayload);

    // 2. Set Session (if session is available on req)
    if (req.session) {
      req.session.user = userPayload;
    }

    // 3. Set secure httpOnly cookie (if res.cookie is available and setHttpOnlyCookie is enabled)
    setAuthCookie(res, token);

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

exports.startGoogleOAuth = async (req, res) => {
  const google = config.get("google");
  if (!google) return res.status(404).json({ error: "Google sign-in is not configured" });
  if (!req.session || typeof req.session.save !== "function") {
    return res.status(500).json({ error: "Google sign-in requires Express session middleware" });
  }

  const state = crypto.randomBytes(32).toString("hex");
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  req.session.googleOAuth = { state, codeVerifier, createdAt: Date.now() };

  try {
    await saveSession(req);
    const authorizationURL = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    authorizationURL.search = new URLSearchParams({
      client_id: google.clientId,
      redirect_uri: google.callbackURL,
      response_type: "code",
      scope: "openid email profile",
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256"
    }).toString();
    return res.redirect(authorizationURL.toString());
  } catch (error) {
    return sendOAuthError(res, 500, "Failed to start Google sign-in", error);
  }
};

exports.googleOAuthCallback = async (req, res) => {
  const google = config.get("google");
  if (!google) return res.status(404).json({ error: "Google sign-in is not configured" });

  const pending = req.session?.googleOAuth;
  const pendingState = typeof pending?.state === "string" ? Buffer.from(pending.state) : null;
  const queryState = typeof req.query.state === "string" ? Buffer.from(req.query.state) : null;
  if (
    !pending ||
    typeof pending.codeVerifier !== "string" ||
    !Number.isFinite(pending.createdAt) ||
    Date.now() - pending.createdAt > 10 * 60 * 1000 ||
    !pendingState ||
    !queryState ||
    pendingState.length !== queryState.length ||
    !crypto.timingSafeEqual(pendingState, queryState)
  ) {
    return res.status(400).json({ error: "Invalid or expired Google OAuth state" });
  }
  delete req.session.googleOAuth;

  if (typeof req.query.code !== "string" || !req.query.code) {
    return res.status(400).json({ error: "Google did not return an authorization code" });
  }

  try {
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      signal: AbortSignal.timeout(10_000),
      body: new URLSearchParams({
        code: req.query.code,
        client_id: google.clientId,
        client_secret: google.clientSecret,
        redirect_uri: google.callbackURL,
        grant_type: "authorization_code",
        code_verifier: pending.codeVerifier
      })
    });
    if (!tokenResponse.ok) {
      throw new Error(`Google token exchange returned HTTP ${tokenResponse.status}`);
    }
    const tokenData = await tokenResponse.json();
    if (!tokenData.access_token) {
      throw new Error("Google token exchange did not return an access token");
    }

    const profileResponse = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
      signal: AbortSignal.timeout(10_000)
    });
    if (!profileResponse.ok) {
      throw new Error(`Google user profile request returned HTTP ${profileResponse.status}`);
    }
    const profile = await profileResponse.json();
    if (
      typeof profile.sub !== "string" ||
      !profile.sub ||
      typeof profile.email !== "string" ||
      !EMAIL_REGEX.test(profile.email.trim()) ||
      profile.email_verified !== true
    ) {
      return res.status(401).json({ error: "Google did not provide a verified email address" });
    }

    const email = profile.email.trim().toLowerCase();
    const userPayload = await resolveUserPayload(email, {
      provider: "google",
      providerId: profile.sub,
      name: typeof profile.name === "string" ? profile.name : undefined,
      picture: typeof profile.picture === "string" ? profile.picture : undefined
    });
    const token = createToken(userPayload);

    if (req.session && typeof req.session.regenerate === "function") {
      await regenerateSession(req);
      req.session.user = userPayload;
      await saveSession(req);
    }

    setAuthCookie(res, token);

    if (google.successRedirectURL && config.get("setHttpOnlyCookie")) {
      return res.redirect(google.successRedirectURL);
    }
    return res.json({ message: "Logged in successfully", token, user: userPayload });
  } catch (error) {
    return sendOAuthError(res, 502, "Google sign-in failed", error);
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