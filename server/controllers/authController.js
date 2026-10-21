// server/controllers/authController.js
const {
  constantTimeEqual,
  randomString,
  sha256Base64Url,
  sha256Hex
} = require("../utils/webCrypto");
const { createAuthService } = require("../core/authService");
const { createPasskeyService, PasskeyServiceError } = require("../core/passkeyService");
const { sendOTP } = require("../utils/mailer");
const generateOTP = require("../utils/generateOTP");
const config = require("../config");
const defaultRefreshTokenStore = require("../stores/defaultRefreshTokenStore");
const { verifyDPoPProof, DPoPError } = require("../core/dpopService");

// Magic link in-memory store
const magicLinkStore = new Map();
exports.magicLinkStore = magicLinkStore;
exports.clearMagicLinks = () => magicLinkStore.clear();

// Simple email regex for basic validation
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const isProduction = () => typeof process !== "undefined" && process.env.NODE_ENV === "production";

function getMagicLinkStore() {
  return config.get("magicLinkStore") || magicLinkStore;
}

function getOtpStore() {
  return config.get("otpStore") || require("../sessionStore");
}

function getRefreshTokenStore() {
  return config.get("refreshTokenStore") || defaultRefreshTokenStore;
}

const authService = createAuthService({ config, getRefreshTokenStore });
const passkeyService = createPasskeyService({ config, authService });

function handlePasskeyError(res, error, action) {
  if (error instanceof PasskeyServiceError) {
    return res.status(error.status).json({ error: error.message });
  }
  console.error(`[DevAuthKit] Error ${action}:`, error);
  return res.status(500).json({
    error: `Failed to ${action}`,
    details: config.get("debug") ? error.message : undefined
  });
}

function requirePasskeySameOrigin(req, res) {
  const origins = config.get("passkeys")?.origins || [];
  if (
    !origins.includes(req.headers?.origin) ||
    req.headers?.["sec-fetch-site"] === "cross-site"
  ) {
    return res.status(403).json({ error: "Passkey management requires a same-origin request" });
  }
  return null;
}

async function completePasskeyLogin(req, res, userPayload) {
  if (req.session && typeof req.session.regenerate === "function") {
    await regenerateSession(req);
  }
  const tokens = await issueTokens(userPayload, res);
  if (req.session) {
    req.session.user = tokens.sessionId
      ? { ...userPayload, sid: tokens.sessionId }
      : userPayload;
    if (typeof req.session.save === "function") await saveSession(req);
  }
  return res.json({ message: "Logged in successfully", ...tokens });
}

function getCookie(req, name) {
  if (req.cookies && req.cookies[name]) return req.cookies[name];
  const match = req.headers?.cookie?.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

function refreshCookieOptions(maxAge) {
  return {
    httpOnly: true,
    secure: isProduction(),
    sameSite: isProduction() ? "strict" : "lax",
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

async function resolveDPoPJkt(req) {
  const dpopHeader = req.headers?.dpop || req.headers?.DPoP;
  if (!dpopHeader) return null;
  const replayStore = config.get("dpopReplayStore");
  if (!replayStore || typeof replayStore.record !== "function") {
    throw new DPoPError(503, "dpop_replay_store_unavailable", "DPoP replay protection is not configured");
  }
  const verification = await verifyDPoPProof({
    proofJwt: dpopHeader,
    expectedMethod: req.method,
    expectedUri: req.originalUrl || req.url,
    expectedNonce: config.get("dpopNonce"),
    replayStore,
    maxClockSkewSeconds: config.get("dpopMaxClockSkewSeconds") || 60
  });
  return verification.jkt;
}

function handleDPoPError(res, error) {
  if (!(error instanceof DPoPError)) return null;
  res.set("WWW-Authenticate", `DPoP error="${error.code}", error_description="${error.message}"`);
  return res.status(error.status).json({ error: error.code, message: error.message });
}

function issueTokens(userPayload, res, dpopJkt = null) {
  return authService.issueTokens(
    userPayload,
    {
      setAuthCookie: (token) => setAuthCookie(res, token),
      setRefreshCookie: (token, maxAge) => setRefreshCookie(res, token, maxAge)
    },
    dpopJkt
  );
}

function setAuthCookie(res, token) {
  if (!config.get("setHttpOnlyCookie") || typeof res.cookie !== "function") return;

  const production = isProduction();
  const cookieName = config.get("cookieName") || "devauth_token";
  const refreshConfig = authService.refreshOptions();
  const accessDuration = refreshConfig?.accessTokenExpiresIn.match(/^(\d+)(ms|s|m|h|d)$/);
  const accessMaxAge = accessDuration
    ? Number(accessDuration[1]) * ({ ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[accessDuration[2]])
    : 15 * 60 * 1000;
  res.cookie(cookieName, token, {
    httpOnly: true,
    secure: production,
    sameSite: production ? "strict" : "lax",
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
    const otpStore = getOtpStore();
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
      const magicToken = randomString(32, "hex");
      const tokenHash = await sha256Hex(magicToken);
      const expiryMinutes = config.get("magicLinkExpiryMinutes") || 15;
      await getMagicLinkStore().set(tokenHash, {
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
    const otpStore = getOtpStore();
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

    const userPayload = await authService.resolveUserPayload(normalizedEmail);

    // OTP is valid - clear from store to prevent replay attacks
    await otpStore.delete(normalizedEmail);

    const dpopJkt = await resolveDPoPJkt(req);
    const tokens = await issueTokens(userPayload, res, dpopJkt);
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
    const dpopErrorResponse = handleDPoPError(res, error);
    if (dpopErrorResponse) return dpopErrorResponse;
    console.error("[DevAuthKit] Error verifying OTP:", error);
    return res.status(500).json({ 
      error: "Verification failed",
      details: config.get("debug") ? error.message : undefined
    });
  }
};

exports.refreshTokens = async (req, res) => {
  const refreshConfig = authService.refreshOptions();
  if (!refreshConfig) {
    return res.status(404).json({ error: "Refresh tokens are not enabled" });
  }

  const refreshCookieName = `${config.get("cookieName") || "devauth_token"}_refresh`;
  const presentedToken = getCookie(req, refreshCookieName);
  if (!presentedToken) return res.status(401).json({ error: "Refresh token is required" });

  try {
    const replacementToken = randomString(48);
    const expiresAt = Date.now() + refreshConfig.refreshTokenExpiresInDays * 24 * 60 * 60 * 1000;
    const result = await getRefreshTokenStore().rotate(
      await authService.hashRefreshToken(presentedToken),
      await authService.hashRefreshToken(replacementToken),
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
    const dpopJkt = await resolveDPoPJkt(req);
    const token = await authService.createAccessToken(userPayload, result.record.familyId, dpopJkt);
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
      tokenType: dpopJkt ? "DPoP" : "Bearer",
      refreshEnabled: true,
      expiresIn: refreshConfig.accessTokenExpiresIn
    });
  } catch (error) {
    const dpopErrorResponse = handleDPoPError(res, error);
    if (dpopErrorResponse) return dpopErrorResponse;
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

    const tokenHash = await sha256Hex(String(token).trim());
    const entry = await getMagicLinkStore().get(tokenHash);

    if (!entry) {
      return res.status(401).json({ error: "Invalid or already used magic link" });
    }

    await getMagicLinkStore().delete(tokenHash);

    if (Date.now() > entry.expiresAt) {
      return res.status(401).json({ error: "Magic link has expired. Please request a new one." });
    }

    if (email && entry.email.toLowerCase() !== String(email).trim().toLowerCase()) {
      return res.status(401).json({ error: "Magic link does not match the provided email" });
    }

    const userPayload = await authService.resolveUserPayload(entry.email);

    if (req.session && typeof req.session.regenerate === "function") {
      await regenerateSession(req);
    }

    const dpopJkt = await resolveDPoPJkt(req);
    const tokens = await issueTokens(userPayload, res, dpopJkt);
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
    const dpopErrorResponse = handleDPoPError(res, error);
    if (dpopErrorResponse) return dpopErrorResponse;
    console.error("[DevAuthKit] Error verifying magic link:", error);
    return res.status(500).json({ error: "Failed to verify magic link" });
  }
};

function getOAuthProvider(provider) {
  const providers = config.get("oauthProviders");
  const custom = providers && Object.prototype.hasOwnProperty.call(providers, provider)
    ? providers[provider]
    : null;
  if (custom) return { ...custom, provider };
  if (provider === "google" && config.get("google")) {
    return {
      ...config.get("google"),
      provider,
      authorizationURL: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenURL: "https://oauth2.googleapis.com/token",
      userInfoURL: "https://www.googleapis.com/oauth2/v3/userinfo",
      scope: "openid email profile"
    };
  }
  if (provider === "github" && config.get("github")) {
    return {
      ...config.get("github"),
      provider,
      authorizationURL: "https://github.com/login/oauth/authorize",
      tokenURL: "https://github.com/login/oauth/access_token",
      userInfoURL: "https://api.github.com/user",
      scope: config.get("github").scope || "read:user user:email"
    };
  }
  return null;
}

function createOAuthHandler(provider, link = false) {
  return async (req, res) => {
    const oauth = getOAuthProvider(provider);
    if (!oauth) return res.status(404).json({ error: `${provider} sign-in is not configured` });
    if (!req.session || typeof req.session.save !== "function") {
      return res.status(500).json({ error: `${provider} sign-in requires session middleware` });
    }
    if (link) {
      const allowedOrigins = config.get("corsOrigin");
      const origins = Array.isArray(allowedOrigins) ? allowedOrigins : [allowedOrigins];
      if (
        req.method !== "POST" ||
        typeof req.headers?.origin !== "string" ||
        !origins.includes(req.headers.origin) ||
        req.headers["sec-fetch-site"] === "cross-site"
      ) {
        return res.status(403).json({ error: "OAuth linking requires a same-origin POST request" });
      }
    }
    if (link && (!req.user || req.user.id === undefined)) {
      return res.status(401).json({ error: "An authenticated user is required to link an identity" });
    }
    if (link && typeof config.get("userAdapter")?.linkOAuthIdentity !== "function") {
      return res.status(501).json({
        error: "Account linking requires userAdapter.linkOAuthIdentity with provider identity uniqueness"
      });
    }

    const state = randomString(32, "hex");
    const codeVerifier = randomString(32);
    const codeChallenge = await sha256Base64Url(codeVerifier);
    req.session.oauthFlows ||= {};
    req.session.oauthFlows[provider] = {
      state,
      codeVerifier,
      createdAt: Date.now(),
      ...(link ? { linkUserId: String(req.user.id) } : {})
    };

    try {
      const oauthStateStore = config.get("oauthStateStore");
      if (oauthStateStore) await oauthStateStore.put(state, Date.now() + 10 * 60 * 1000);
      await saveSession(req);
      const authorizationURL = new URL(oauth.authorizationURL);
      authorizationURL.search = new URLSearchParams({
        client_id: oauth.clientId,
        redirect_uri: oauth.callbackURL,
        response_type: "code",
        scope: oauth.scope || "",
        state,
        code_challenge: codeChallenge,
        code_challenge_method: "S256"
      }).toString();
      if (link && req.headers["content-type"]?.includes("application/json")) {
        return res.json({ authorizationURL: authorizationURL.toString() });
      }
      return res.redirect(authorizationURL.toString());
    } catch (error) {
      return sendOAuthError(res, 500, `Failed to start ${provider} sign-in`, error);
    }
  };
}

async function fetchOAuthIdentity(provider, oauth, accessToken) {
  const response = await fetch(oauth.userInfoURL, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: provider === "github" ? "application/vnd.github+json" : "application/json",
      ...(provider === "github" ? { "User-Agent": "devauthkit" } : {})
    },
    signal: AbortSignal.timeout(10_000)
  });
  if (!response.ok) throw new Error(`${provider} profile request returned HTTP ${response.status}`);
  const profile = await response.json();

  if (typeof oauth.mapProfile === "function") {
    const mapped = await oauth.mapProfile(profile, { accessToken, fetch });
    if (!mapped || typeof mapped !== "object") {
      throw new TypeError("OAuth mapProfile must return a profile object");
    }
    return mapped;
  }
  if (provider === "google") {
    return {
      id: profile.sub,
      email: profile.email,
      emailVerified: profile.email_verified === true,
      name: profile.name,
      picture: profile.picture
    };
  }
  if (provider === "github") {
    let email = typeof profile.email === "string" ? profile.email : null;
    if (!email) {
      const emailResponse = await fetch("https://api.github.com/user/emails", {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "User-Agent": "devauthkit",
          Accept: "application/vnd.github+json"
        },
        signal: AbortSignal.timeout(10_000)
      });
      if (emailResponse.ok) {
        const emails = await emailResponse.json();
        if (Array.isArray(emails)) {
          const chosen = emails.find((entry) => entry.verified && entry.primary) ||
            emails.find((entry) => entry.verified);
          if (chosen?.verified) email = chosen.email;
        }
      }
    }
    return {
      id: profile.id === undefined ? undefined : String(profile.id),
      email,
      emailVerified: Boolean(email),
      name: typeof profile.name === "string" ? profile.name : profile.login,
      picture: profile.avatar_url,
      username: profile.login
    };
  }
  throw new TypeError("OAuth provider must define mapProfile");
}

function createOAuthCallback(provider) {
  return async (req, res) => {
    const oauth = getOAuthProvider(provider);
    if (!oauth) return res.status(404).json({ error: `${provider} sign-in is not configured` });
    const pending = req.session?.oauthFlows?.[provider] ||
      (provider === "google" ? req.session?.googleOAuth : req.session?.githubOAuth);
    const pendingState = typeof pending?.state === "string" ? pending.state : null;
    const queryState = typeof req.query.state === "string" ? req.query.state : null;
    if (
      !pending ||
      typeof pending.codeVerifier !== "string" ||
      !Number.isFinite(pending.createdAt) ||
      Date.now() - pending.createdAt > 10 * 60 * 1000 ||
      !pendingState ||
      !queryState ||
      !constantTimeEqual(pendingState, queryState)
    ) {
      return res.status(400).json({ error: `Invalid or expired ${provider} OAuth state` });
    }
    const oauthStateStore = config.get("oauthStateStore");
    if (oauthStateStore) {
      let consumed;
      try {
        consumed = await oauthStateStore.consume(pending.state);
      } catch (error) {
        return sendOAuthError(res, 503, `${provider} OAuth state store is unavailable`, error);
      }
      if (!consumed) {
        return res.status(400).json({ error: `Invalid, expired, or already-used ${provider} OAuth state` });
      }
    }
    delete req.session.oauthFlows?.[provider];
    if (provider === "google") delete req.session.googleOAuth;
    if (provider === "github") delete req.session.githubOAuth;
    try {
      await saveSession(req);
    } catch (error) {
      return sendOAuthError(res, 500, `Failed to consume ${provider} OAuth state`, error);
    }
    if (typeof req.query.code !== "string" || !req.query.code) {
      return res.status(400).json({ error: `${provider} did not return an authorization code` });
    }

    try {
      const tokenResponse = await fetch(oauth.tokenURL, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          ...(provider === "github" ? { Accept: "application/json" } : {})
        },
        signal: AbortSignal.timeout(10_000),
        body: new URLSearchParams({
          code: req.query.code,
          client_id: oauth.clientId,
          client_secret: oauth.clientSecret,
          redirect_uri: oauth.callbackURL,
          grant_type: "authorization_code",
          code_verifier: pending.codeVerifier
        })
      });
      if (!tokenResponse.ok) throw new Error(`${provider} token exchange returned HTTP ${tokenResponse.status}`);
      const tokenData = await tokenResponse.json();
      if (typeof tokenData.access_token !== "string" || !tokenData.access_token) {
        throw new Error(tokenData.error_description || `${provider} token exchange did not return an access token`);
      }

      const profile = await fetchOAuthIdentity(provider, oauth, tokenData.access_token);
      if (
        (typeof profile.id !== "string" && typeof profile.id !== "number") ||
        !String(profile.id) ||
        typeof profile.email !== "string" ||
        !EMAIL_REGEX.test(profile.email.trim()) ||
        profile.emailVerified !== true
      ) {
        return res.status(401).json({
          error: `${provider} did not provide a verified email and stable identity`
        });
      }

      const email = profile.email.trim().toLowerCase();
      const identity = {
        provider,
        providerId: String(profile.id),
        name: typeof profile.name === "string" ? profile.name : undefined,
        picture: typeof profile.picture === "string" ? profile.picture : undefined,
        username: typeof profile.username === "string" ? profile.username : undefined
      };
      if (pending.linkUserId !== undefined) {
        const adapter = config.get("userAdapter");
        if (typeof adapter?.linkOAuthIdentity !== "function") {
          return res.status(501).json({ error: "Account linking is not supported by the configured userAdapter" });
        }
        await adapter.linkOAuthIdentity({
          userId: pending.linkUserId,
          ...identity,
          email
        });
        await saveSession(req);
        return res.json({ message: "OAuth identity linked successfully", provider });
      }

      const userPayload = await authService.resolveUserPayload(email, identity);
      if (req.session && typeof req.session.regenerate === "function") await regenerateSession(req);
      const tokens = await issueTokens(userPayload, res);
      if (req.session) {
        req.session.user = tokens.sessionId
          ? { ...userPayload, sid: tokens.sessionId }
          : userPayload;
        await saveSession(req);
      }
      if (oauth.successRedirectURL && config.get("setHttpOnlyCookie")) {
        return res.redirect(oauth.successRedirectURL);
      }
      return res.json({ message: "Logged in successfully", ...tokens });
    } catch (error) {
      return sendOAuthError(res, 502, `${provider} sign-in failed`, error);
    }
  };
}

exports.startOAuth = (req, res) => createOAuthHandler(req.params.provider)(req, res);
exports.oauthCallback = (req, res) => createOAuthCallback(req.params.provider)(req, res);
exports.linkOAuth = (req, res) => createOAuthHandler(req.params.provider, true)(req, res);
exports.startGoogleOAuth = (req, res) => createOAuthHandler("google")(req, res);
exports.googleOAuthCallback = (req, res) => createOAuthCallback("google")(req, res);
exports.startGitHubOAuth = (req, res) => createOAuthHandler("github")(req, res);
exports.githubOAuthCallback = (req, res) => createOAuthCallback("github")(req, res);

exports.passkeyRegistrationOptions = async (req, res) => {
  const forbidden = requirePasskeySameOrigin(req, res);
  if (forbidden) return forbidden;
  try {
    const options = await passkeyService.registrationOptions(req.user);
    return res.json(options);
  } catch (error) {
    return handlePasskeyError(res, error, "create passkey registration options");
  }
};

exports.verifyPasskeyRegistration = async (req, res) => {
  const forbidden = requirePasskeySameOrigin(req, res);
  if (forbidden) return forbidden;
  try {
    const result = await passkeyService.verifyRegistration(req.user, req.body?.credential);
    return res.json({ message: "Passkey registered successfully", ...result });
  } catch (error) {
    return handlePasskeyError(res, error, "verify passkey registration");
  }
};

exports.passkeyAuthenticationOptions = async (req, res) => {
  try {
    const options = await passkeyService.authenticationOptions(req.body?.email);
    return res.json(options);
  } catch (error) {
    return handlePasskeyError(res, error, "create passkey authentication options");
  }
};

exports.verifyPasskeyAuthentication = async (req, res) => {
  try {
    const userPayload = await passkeyService.verifyAuthentication(req.body?.credential);
    return await completePasskeyLogin(req, res, userPayload);
  } catch (error) {
    return handlePasskeyError(res, error, "verify passkey authentication");
  }
};

exports.listPasskeys = async (req, res) => {
  try {
    const passkeys = await passkeyService.list(req.user);
    return res.json({ passkeys });
  } catch (error) {
    return handlePasskeyError(res, error, "list passkeys");
  }
};

exports.deletePasskey = async (req, res) => {
  const forbidden = requirePasskeySameOrigin(req, res);
  if (forbidden) return forbidden;
  try {
    await passkeyService.remove(req.user, req.params?.credentialId);
    return res.json({ message: "Passkey deleted successfully" });
  } catch (error) {
    return handlePasskeyError(res, error, "delete passkey");
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
      await getRefreshTokenStore().revoke(await authService.hashRefreshToken(refreshToken));
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