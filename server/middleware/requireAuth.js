const { verifyJwt } = require("../utils/webCrypto");
const config = require("../config");
const defaultRefreshTokenStore = require("../stores/defaultRefreshTokenStore");

function getRefreshTokenStore() {
  return config.get("refreshTokenStore") || defaultRefreshTokenStore;
}

function unauthorized(res, message) {
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

  try {
    if (!(await validateFamily(decoded))) {
      return unauthorized(res, "Unauthorized: Session has been revoked");
    }
  } catch (error) {
    console.error("[DevAuthKit] Failed to validate refresh session:", error);
    return res.status(503).json({ error: "Authentication service unavailable" });
  }

  req.user = decoded;
  return next();
}

module.exports = async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];
    if (!token) return unauthorized(res, "Unauthorized: Malformed token header");
    return attachVerifiedToken(token, req, res, next, "token");
  }

  const cookieName = config.get("cookieName") || "devauth_token";
  let cookieToken = req.cookies?.[cookieName] || null;
  if (!cookieToken && req.headers?.cookie) {
    const match = req.headers.cookie.match(new RegExp(`(?:^|;\\s*)${cookieName}=([^;]*)`));
    if (match) cookieToken = decodeURIComponent(match[1]);
  }
  if (cookieToken) return attachVerifiedToken(cookieToken, req, res, next, "cookie token");

  if (req.session?.user) {
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
