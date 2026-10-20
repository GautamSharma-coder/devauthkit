// server/controllers/authController.js
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { sendOTP } = require("../utils/mailer");
const generateOTP = require("../utils/generateOTP");
const sessionStore = require("../sessionStore");
const config = require("../config");
const defaultRefreshTokenStore = require("../stores/defaultRefreshTokenStore");

// Magic link in-memory store
const magicLinkStore = new Map();
exports.magicLinkStore = magicLinkStore;
exports.clearMagicLinks = () => magicLinkStore.clear();

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

function refreshOptions() {
  const value = config.get("refreshTokens");
  if (!value) return null;
  const options = typeof value === "object" ? value : {};
  return {
    accessTokenExpiresIn: options.accessTokenExpiresIn || "15m",
    refreshTokenExpiresInDays: options.refreshTokenExpiresInDays ?? 30
  };
}

function getRefreshTokenStore() {
  return config.get("refreshTokenStore") || defaultRefreshTokenStore;
}

function hashRefreshToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function getCookie(req, name) {
  if (req.cookies && req.cookies[name]) return req.cookies[name];
  const match = req.headers?.cookie?.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

function refreshCookieOptions(maxAge) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
    path: config.get("apiPrefix") || "/auth",
    maxAge
  };
}

function setRefreshCookie(res, token, maxAge) {
  const cookieName = `${config.get("cookieName") || "devauth_token"}_refresh`;
  res.cookie(cookieName, token, refreshCookieOptions(maxAge));
}

function clearRefreshCookie(res) {
  const cookieName = `${config.get("cookieName") || "devauth_token"}_refresh`;
  res.clearCookie(cookieName, refreshCookieOptions(0));
}

async function issueTokens(userPayload, res) {
  const refreshConfig = refreshOptions();
  if (!refreshConfig) {
    const token = createToken(userPayload);
    setAuthCookie(res, token);
    return { token, user: userPayload };
  }

  const familyId = crypto.randomUUID();
  const refreshToken = crypto.randomBytes(48).toString("base64url");
  const expiresAt = Date.now() + refreshConfig.refreshTokenExpiresInDays * 24 * 60 * 60 * 1000;
  await getRefreshTokenStore().create(hashRefreshToken(refreshToken), {
    familyId,
    userId: String(userPayload.id ?? userPayload.email),
    user: userPayload,
    expiresAt
  });

  const token = jwt.sign(
    { ...userPayload, sid: familyId, jti: crypto.randomUUID() },
    config.get("jwtSecret"),
    { expiresIn: refreshConfig.accessTokenExpiresIn }
  );
  setAuthCookie(res, token);
  setRefreshCookie(
    res,
    refreshToken,
    refreshConfig.refreshTokenExpiresInDays * 24 * 60 * 60 * 1000
  );
  const tokens = {
    token,
    user: userPayload,
    refreshEnabled: true,
    expiresIn: refreshConfig.accessTokenExpiresIn
  };
  Object.defineProperty(tokens, "sessionId", { value: familyId });
  return tokens;
}

function setAuthCookie(res, token) {
  if (!config.get("setHttpOnlyCookie") || typeof res.cookie !== "function") return;

  const isProduction = process.env.NODE_ENV === "production";
  const cookieName = config.get("cookieName") || "devauth_token";
  const refreshConfig = refreshOptions();
  const accessDuration = refreshConfig?.accessTokenExpiresIn.match(/^(\d+)(ms|s|m|h|d)$/);
  const accessMaxAge = accessDuration
    ? Number(accessDuration[1]) * ({ ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[accessDuration[2]])
    : 15 * 60 * 1000;
  res.cookie(cookieName, token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "strict" : "lax",
    maxAge: refreshConfig ? accessMaxAge : 7 * 24 * 60 * 60 * 1000
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

    let magicLinkUrl = null;
    const magicLinkEnabled = Boolean(config.get("magicLink") || req.body?.magicLink);
    if (magicLinkEnabled) {
      const magicToken = crypto.randomBytes(32).toString("hex");
      const tokenHash = crypto.createHash("sha256").update(magicToken).digest("hex");
      const expiryMinutes = config.get("magicLinkExpiryMinutes") || 15;
      magicLinkStore.set(tokenHash, {
        email: normalizedEmail,
        expiresAt: Date.now() + expiryMinutes * 60 * 1000
      });
      const baseUrl = config.get("magicLinkBaseURL") || `${req.protocol}://${req.get("host")}${config.get("apiPrefix") || "/auth"}`;
      const verifyUrl = new URL(baseUrl.includes("/verify-magic") ? baseUrl : `${baseUrl.replace(/\/+$/, "")}/verify-magic`);
      verifyUrl.searchParams.set("token", magicToken);
      verifyUrl.searchParams.set("email", normalizedEmail);
      magicLinkUrl = verifyUrl.toString();
    }

    const result = await sendOTP({ email: normalizedEmail, otp, magicLinkUrl });

    return res.json({
      message: "OTP sent successfully",
      expiresInMinutes: config.get("otpExpiryMinutes"),
      devMode: result.devMode || undefined,
      ...(magicLinkUrl && (config.get("devMode") || result.devMode) ? { magicLinkUrl } : {})
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

    const tokens = await issueTokens(userPayload, res);
    if (req.session) {
      req.session.user = tokens.sessionId
        ? { ...userPayload, sid: tokens.sessionId }
        : userPayload;
    }

    return res.json({
      message: "Logged in successfully",
      ...tokens
    });
  } catch (error) {
    console.error("[DevAuthKit] Error verifying OTP:", error);
    return res.status(500).json({ 
      error: "Verification failed",
      details: config.get("debug") ? error.message : undefined
    });
  }
};

exports.refreshTokens = async (req, res) => {
  const refreshConfig = refreshOptions();
  if (!refreshConfig) {
    return res.status(404).json({ error: "Refresh tokens are not enabled" });
  }

  const refreshCookieName = `${config.get("cookieName") || "devauth_token"}_refresh`;
  const presentedToken = getCookie(req, refreshCookieName);
  if (!presentedToken) return res.status(401).json({ error: "Refresh token is required" });

  try {
    const replacementToken = crypto.randomBytes(48).toString("base64url");
    const expiresAt = Date.now() + refreshConfig.refreshTokenExpiresInDays * 24 * 60 * 60 * 1000;
    const result = await getRefreshTokenStore().rotate(
      hashRefreshToken(presentedToken),
      hashRefreshToken(replacementToken),
      { expiresAt }
    );

    if (result.status !== "rotated") {
      clearRefreshCookie(res);
      return res.status(401).json({
        error: result.status === "reused"
          ? "Refresh token reuse detected. This session has been revoked."
          : "Refresh token is invalid or expired"
      });
    }
    if (!result.record?.user || !result.record.familyId) {
      throw new TypeError("refreshTokenStore.rotate must return its record when rotation succeeds");
    }

    const userPayload = result.record.user;
    const token = jwt.sign(
      { ...userPayload, sid: result.record.familyId, jti: crypto.randomUUID() },
      config.get("jwtSecret"),
      { expiresIn: refreshConfig.accessTokenExpiresIn }
    );
    setAuthCookie(res, token);
    setRefreshCookie(
      res,
      replacementToken,
      refreshConfig.refreshTokenExpiresInDays * 24 * 60 * 60 * 1000
    );

    return res.json({
      message: "Token refreshed successfully",
      token,
      user: userPayload,
      refreshEnabled: true,
      expiresIn: refreshConfig.accessTokenExpiresIn
    });
  } catch (error) {
    console.error("[DevAuthKit] Error refreshing tokens:", error);
    return res.status(500).json({
      error: "Failed to refresh token",
      details: config.get("debug") ? error.message : undefined
    });
  }
};

exports.revokeSession = async (req, res) => {
  const familyId = req.user?.sid;
  if (!familyId) return res.status(400).json({ error: "No revocable token session is active" });
  try {
    await getRefreshTokenStore().revokeFamily(familyId);
    res.clearCookie(config.get("cookieName") || "devauth_token");
    clearRefreshCookie(res);
    return res.json({ message: "Current session revoked" });
  } catch (error) {
    console.error("[DevAuthKit] Failed to revoke current session:", error);
    return res.status(500).json({ error: "Failed to revoke current session" });
  }
};

exports.revokeAllSessions = async (req, res) => {
  const userId = req.user?.id ?? req.user?.email;
  if (!userId) return res.status(400).json({ error: "Authenticated user identity is unavailable" });
  try {
    await getRefreshTokenStore().revokeAll(String(userId));
    res.clearCookie(config.get("cookieName") || "devauth_token");
    clearRefreshCookie(res);
    return res.json({ message: "All sessions revoked" });
  } catch (error) {
    console.error("[DevAuthKit] Failed to revoke all user sessions:", error);
    return res.status(500).json({ error: "Failed to revoke all sessions" });
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
    if (req.session && typeof req.session.regenerate === "function") {
      await regenerateSession(req);
    }

    const tokens = await issueTokens(userPayload, res);
    if (req.session) {
      req.session.user = tokens.sessionId
        ? { ...userPayload, sid: tokens.sessionId }
        : userPayload;
      await saveSession(req);
    }

    if (google.successRedirectURL && config.get("setHttpOnlyCookie")) {
      return res.redirect(google.successRedirectURL);
    }
    return res.json({ message: "Logged in successfully", ...tokens });
  } catch (error) {
    return sendOAuthError(res, 502, "Google sign-in failed", error);
  }
};

/**
 * Verify Magic Link token and authenticate user
 */
exports.verifyMagicLink = async (req, res) => {
  try {
    const token = req.query.token || req.body?.token;
    const email = req.query.email || req.body?.email;

    if (!token) {
      return res.status(400).json({ error: "Magic link token is required" });
    }

    const tokenHash = crypto.createHash("sha256").update(String(token).trim()).digest("hex");
    const entry = magicLinkStore.get(tokenHash);

    if (!entry) {
      return res.status(401).json({ error: "Invalid or already used magic link" });
    }

    magicLinkStore.delete(tokenHash);

    if (Date.now() > entry.expiresAt) {
      return res.status(401).json({ error: "Magic link has expired. Please request a new one." });
    }

    if (email && entry.email.toLowerCase() !== String(email).trim().toLowerCase()) {
      return res.status(401).json({ error: "Magic link does not match the provided email" });
    }

    const userPayload = await resolveUserPayload(entry.email);

    if (req.session && typeof req.session.regenerate === "function") {
      await regenerateSession(req);
    }

    const tokens = await issueTokens(userPayload, res);
    if (req.session) {
      req.session.user = tokens.sessionId
        ? { ...userPayload, sid: tokens.sessionId }
        : userPayload;
      await saveSession(req);
    }

    const successUrl = config.get("magicLinkSuccessURL");
    if (req.method === "GET" && successUrl && config.get("setHttpOnlyCookie")) {
      return res.redirect(successUrl);
    }

    return res.json({
      message: "Magic link verified successfully",
      ...tokens
    });
  } catch (error) {
    console.error("[DevAuthKit] Error verifying magic link:", error);
    return res.status(500).json({ error: "Failed to verify magic link" });
  }
};

/**
 * Start GitHub OAuth flow with PKCE
 */
exports.startGitHubOAuth = async (req, res) => {
  const github = config.get("github");
  if (!github) return res.status(404).json({ error: "GitHub sign-in is not configured" });
  if (!req.session || typeof req.session.save !== "function") {
    return res.status(500).json({ error: "GitHub sign-in requires Express session middleware" });
  }

  const state = crypto.randomBytes(32).toString("hex");
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  req.session.githubOAuth = { state, codeVerifier, createdAt: Date.now() };

  try {
    await saveSession(req);
    const authorizationURL = new URL("https://github.com/login/oauth/authorize");
    authorizationURL.search = new URLSearchParams({
      client_id: github.clientId,
      redirect_uri: github.callbackURL,
      scope: github.scope || "read:user user:email",
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256"
    }).toString();
    return res.redirect(authorizationURL.toString());
  } catch (error) {
    return sendOAuthError(res, 500, "Failed to start GitHub sign-in", error);
  }
};

/**
 * Handle GitHub OAuth callback
 */
exports.githubOAuthCallback = async (req, res) => {
  const github = config.get("github");
  if (!github) return res.status(404).json({ error: "GitHub sign-in is not configured" });

  const pending = req.session?.githubOAuth;
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
    return res.status(400).json({ error: "Invalid or expired GitHub OAuth state" });
  }
  delete req.session.githubOAuth;

  if (typeof req.query.code !== "string" || !req.query.code) {
    return res.status(400).json({ error: "GitHub did not return an authorization code" });
  }

  try {
    const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
      },
      signal: AbortSignal.timeout(10_000),
      body: new URLSearchParams({
        code: req.query.code,
        client_id: github.clientId,
        client_secret: github.clientSecret,
        redirect_uri: github.callbackURL,
        code_verifier: pending.codeVerifier
      })
    });
    if (!tokenResponse.ok) {
      throw new Error(`GitHub token exchange returned HTTP ${tokenResponse.status}`);
    }
    const tokenData = await tokenResponse.json();
    if (!tokenData.access_token) {
      throw new Error(tokenData.error_description || "GitHub token exchange did not return an access token");
    }

    const profileResponse = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        "User-Agent": "devauthkit",
        Accept: "application/vnd.github+json"
      },
      signal: AbortSignal.timeout(10_000)
    });
    if (!profileResponse.ok) {
      throw new Error(`GitHub user profile request returned HTTP ${profileResponse.status}`);
    }
    const profile = await profileResponse.json();

    let verifiedEmail = null;
    if (typeof profile.email === "string" && EMAIL_REGEX.test(profile.email.trim())) {
      verifiedEmail = profile.email.trim().toLowerCase();
    }

    if (!verifiedEmail) {
      const emailsResponse = await fetch("https://api.github.com/user/emails", {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
          "User-Agent": "devauthkit",
          Accept: "application/vnd.github+json"
        },
        signal: AbortSignal.timeout(10_000)
      });
      if (emailsResponse.ok) {
        const emails = await emailsResponse.json();
        if (Array.isArray(emails)) {
          const primaryVerified = emails.find((e) => e.verified && e.primary);
          const anyVerified = emails.find((e) => e.verified);
          const chosen = primaryVerified || anyVerified;
          if (chosen && typeof chosen.email === "string" && EMAIL_REGEX.test(chosen.email.trim())) {
            verifiedEmail = chosen.email.trim().toLowerCase();
          }
        }
      }
    }

    if (!verifiedEmail) {
      return res.status(401).json({ error: "GitHub did not provide a verified email address" });
    }

    const userPayload = await resolveUserPayload(verifiedEmail, {
      provider: "github",
      providerId: String(profile.id),
      name: typeof profile.name === "string" ? profile.name : profile.login,
      picture: typeof profile.avatar_url === "string" ? profile.avatar_url : undefined,
      username: profile.login
    });

    if (req.session && typeof req.session.regenerate === "function") {
      await regenerateSession(req);
    }

    const tokens = await issueTokens(userPayload, res);
    if (req.session) {
      req.session.user = tokens.sessionId
        ? { ...userPayload, sid: tokens.sessionId }
        : userPayload;
      await saveSession(req);
    }

    if (github.successRedirectURL && config.get("setHttpOnlyCookie")) {
      return res.redirect(github.successRedirectURL);
    }
    return res.json({ message: "Logged in successfully", ...tokens });
  } catch (error) {
    return sendOAuthError(res, 502, "GitHub sign-in failed", error);
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
exports.logout = async (req, res) => {
  const cookieName = config.get("cookieName") || "devauth_token";
  if (typeof res.clearCookie === "function") {
    res.clearCookie(cookieName);
    res.clearCookie("connect.sid");
    clearRefreshCookie(res);
  }

  const refreshToken = getCookie(req, `${cookieName}_refresh`);
  if (refreshToken) {
    try {
      await getRefreshTokenStore().revoke(hashRefreshToken(refreshToken));
    } catch (error) {
      console.error("[DevAuthKit] Failed to revoke refresh token on logout:", error);
      return res.status(500).json({ error: "Failed to log out" });
    }
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