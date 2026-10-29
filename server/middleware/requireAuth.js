const { verifyJwt } = require("../utils/webCrypto");
const config = require("../config");
const defaultRefreshTokenStore = require("../stores/defaultRefreshTokenStore");
const { verifyDPoPProof, DPoPError } = require("../core/dpopService");
const { isUserBlocked, getUserEpoch } = require("../controllers/userManagementController");

function getRefreshTokenStore() {
  return config.get("refreshTokenStore") || defaultRefreshTokenStore;
}

function unauthorized(res, message, wwwAuthHeader) {
  if (wwwAuthHeader) {
    res.set("WWW-Authenticate", wwwAuthHeader);
  }
  return res.status(401).json({ error: message });
}

async function validateFamily(user) {
  if (!user.sid || !config.get("refreshTokens")) return true;
  return getRefreshTokenStore().isFamilyActive(user.sid);
}

async function attachVerifiedToken(token, req, res, next, source) {
  let decoded;
  try {
    decoded = await verifyJwt(token, config.get("jwtSecret"));
  } catch {
    return unauthorized(res, `Unauthorized: Invalid or expired ${source}`);
  }

  const userId = decoded.id || decoded.sub;

  // Check account suspension status
  if (userId && isUserBlocked(userId)) {
    return res.status(403).json({
      error: "account_suspended",
      message: "Account has been suspended by an administrator"
    });
  }

  // Check revocation epoch
  if (decoded.uep !== undefined && userId) {
    const currentEpoch = getUserEpoch(userId);
    if (currentEpoch > decoded.uep) {
      return unauthorized(res, "Unauthorized: Session has been revoked");
    }
  }

  // DPoP Verification
  const dpopConfig = config.get("dpop");
  const isDPoPRequired = dpopConfig === "required" || dpopConfig?.mode === "required";

  if (decoded.cnf?.jkt) {
    const dpopHeader = req.headers.dpop || req.headers.DPoP;
    if (!dpopHeader) {
      return unauthorized(
        res,
        "Unauthorized: DPoP proof header required for this token",
        'DPoP error="invalid_dpop_proof", error_description="Missing DPoP proof header"'
      );
    }

    try {
      const replayStore = config.get("dpopReplayStore");
      if (!replayStore || typeof replayStore.record !== "function") {
        return res.status(503).json({
          error: "dpop_replay_store_unavailable",
          message: "DPoP replay protection is not configured"
        });
      }
      const verification = await verifyDPoPProof({
        proofJwt: dpopHeader,
        expectedMethod: req.method,
        expectedUri: req.originalUrl || req.url,
        expectedAccessToken: token,
        expectedNonce: config.get("dpopNonce"),
        replayStore,
        maxClockSkewSeconds: config.get("dpopMaxClockSkewSeconds") || 60
      });

      if (verification.jkt !== decoded.cnf.jkt) {
        return unauthorized(
          res,
          "Unauthorized: DPoP key binding mismatch",
          'DPoP error="invalid_dpop_proof", error_description="Thumbprint mismatch"'
        );
      }

      req.dpop = { jkt: verification.jkt, payload: verification.payload };
    } catch (err) {
      const status = err instanceof DPoPError ? err.status : 401;
      const code = err instanceof DPoPError ? err.code : "invalid_dpop_proof";
      res.set("WWW-Authenticate", `DPoP error="${code}", error_description="${err.message}"`);
      return res.status(status).json({ error: code, message: err.message });
    }
  } else if (isDPoPRequired) {
    return res.status(400).set(
      "WWW-Authenticate",
      'DPoP error="invalid_dpop_proof", error_description="DPoP bound access token is required"'
    ).json({ error: "invalid_dpop_proof", message: "A DPoP-bound access token is required" });
  }

  try {
    if (!(await validateFamily(decoded))) {
      return unauthorized(res, "Unauthorized: Session has been revoked");
    }
  } catch (error) {
    console.error("[DevAuthKit] Failed to validate refresh session:", error);
    return res.status(503).json({ error: "Authentication service unavailable" });
  }

  // Multi-Device Session Heartbeat Registration
  const sessionService = config.get("sessionService");
  if (sessionService && decoded.sid && typeof sessionService.registerSession === "function") {
    sessionService.registerSession({
      sessionId: decoded.sid,
      userId,
      ipAddress: req.ip || req.connection?.remoteAddress,
      userAgent: req.headers["user-agent"]
    });
  }

  // Handle RFC 8693 Impersonation Dual Attribution
  if (decoded.act) {
    req.actor = decoded.act;

    // Security Boundary: Impersonated sessions cannot access credential management or admin routes
    const path = (req.originalUrl || req.url || "").toLowerCase();
    if (
      path.includes("/api-keys") ||
      path.includes("/impersonate") ||
      path.includes("/block") ||
      path.includes("/unblock")
    ) {
      return res.status(403).json({
        error: "impersonation_restricted",
        message: "Impersonated sessions cannot perform administrative or credential management actions"
      });
    }
  }

  req.user = decoded;
  return next();
}

module.exports = async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (authHeader) {
    // Check for API Key (Bearer dak_...)
    if (authHeader.startsWith("Bearer dak_")) {
      const rawKey = authHeader.slice(7);
      const apiKeyService = config.get("apiKeyService");
      if (apiKeyService) {
        const keyRecord = await apiKeyService.verifyKey(rawKey);
        if (keyRecord) {
          req.apiKey = keyRecord;
          req.user = {
            id: keyRecord.userId,
            org_id: keyRecord.orgId || null,
            role: "apiKey",
            isApiKey: true,
            scopes: keyRecord.scopes,
            apiKeyId: keyRecord.id
          };
          return next();
        }
      }
      return unauthorized(res, "Unauthorized: Invalid or revoked API key");
    }

    let token = null;
    if (authHeader.startsWith("Bearer ")) {
      token = authHeader.slice(7);
    } else if (authHeader.startsWith("DPoP ")) {
      token = authHeader.slice(5);
    } else {
      return unauthorized(res, "Unauthorized: Malformed token header");
    }

    if (!token) return unauthorized(res, "Unauthorized: Malformed token header");
    return attachVerifiedToken(token, req, res, next, "token");
  }

  // Check for x-api-key header
  if (req.headers["x-api-key"] && req.headers["x-api-key"].startsWith("dak_")) {
    const rawKey = req.headers["x-api-key"];
    const apiKeyService = config.get("apiKeyService");
    if (apiKeyService) {
      const keyRecord = await apiKeyService.verifyKey(rawKey);
      if (keyRecord) {
        req.apiKey = keyRecord;
        req.user = {
          id: keyRecord.userId,
          org_id: keyRecord.orgId || null,
          role: "apiKey",
          isApiKey: true,
          scopes: keyRecord.scopes,
          apiKeyId: keyRecord.id
        };
        return next();
      }
    }
    return unauthorized(res, "Unauthorized: Invalid or revoked API key");
  }

  const cookieName = config.get("cookieName") || "devauth_token";
  let cookieToken = req.cookies?.[cookieName] || null;
  if (!cookieToken && req.headers?.cookie) {
    const match = req.headers.cookie.match(new RegExp(`(?:^|;\\s*)${cookieName}=([^;]*)`));
    if (match) cookieToken = decodeURIComponent(match[1]);
  }
  if (cookieToken) return attachVerifiedToken(cookieToken, req, res, next, "cookie token");

  if (req.session?.user) {
    const userId = req.session.user.id || req.session.user.sub;
    if (userId && isUserBlocked(userId)) {
      return res.status(403).json({
        error: "account_suspended",
        message: "Account has been suspended by an administrator"
      });
    }

    try {
      if (!(await validateFamily(req.session.user))) {
        return unauthorized(res, "Unauthorized: Session has been revoked");
      }
    } catch (error) {
      console.error("[DevAuthKit] Failed to validate refresh session:", error);
      return res.status(503).json({ error: "Authentication service unavailable" });
    }
    req.user = req.session.user;
    return next();
  }

  return unauthorized(res, "Unauthorized: No valid session, token, or auth cookie provided");
};
