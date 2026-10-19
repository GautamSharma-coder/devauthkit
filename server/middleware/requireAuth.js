// server/middleware/requireAuth.js
const jwt = require("jsonwebtoken");
const config = require("../config");

/**
 * Dual-Strategy Authentication Middleware:
 * Verifies either a JWT Bearer token from headers OR an active session cookie.
 * Attaches the authenticated user info to `req.user`.
 */
module.exports = function requireAuth(req, res, next) {
  // 1. Check Bearer Token in Authorization header
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ error: "Unauthorized: Malformed token header" });
    }

    try {
      const decoded = jwt.verify(token, config.get("jwtSecret"));
      req.user = decoded;
      return next();
    } catch (err) {
      return res.status(401).json({ 
        error: "Unauthorized: Invalid or expired token",
        details: err.message
      });
    }
  }

  // 2. Check Cookie for devauth_token
  const cookieName = config.get("cookieName") || "devauth_token";
  let cookieToken = null;
  if (req.cookies && req.cookies[cookieName]) {
    cookieToken = req.cookies[cookieName];
  } else if (req.headers && req.headers.cookie) {
    const match = req.headers.cookie.match(new RegExp(`(?:^|;\\s*)${cookieName}=([^;]*)`));
    if (match) {
      cookieToken = decodeURIComponent(match[1]);
    }
  }

  if (cookieToken) {
    try {
      const decoded = jwt.verify(cookieToken, config.get("jwtSecret"));
      req.user = decoded;
      return next();
    } catch (err) {
      // Token expired or invalid
      return res.status(401).json({ 
        error: "Unauthorized: Invalid or expired cookie token",
        details: err.message
      });
    }
  }

  // 3. Check Express session
  if (req.session && req.session.user) {
    req.user = req.session.user;
    return next();
  }

  // 4. Fallback: No authentication provided
  return res.status(401).json({ 
    error: "Unauthorized: No valid session, token, or auth cookie provided" 
  });
};