// server/middleware/requireApiKey.js
const config = require("../config");
const { matchesScopes } = require("../core/apiKeyService");

function getApiKeyService() {
  const service = config.get("apiKeyService");
  if (!service) {
    throw new Error("API key service is not configured");
  }
  return service;
}

/**
 * Middleware to require and validate a scoped API key
 * @param {string[]|string} [requiredScopes] - Required permission scopes
 * @returns {Function} Express middleware
 */
function requireApiKey(requiredScopes = []) {
  return async function apiKeyMiddleware(req, res, next) {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    let rawKey = null;

    if (authHeader && authHeader.startsWith("Bearer dak_")) {
      rawKey = authHeader.slice(7);
    } else if (req.headers["x-api-key"] && req.headers["x-api-key"].startsWith("dak_")) {
      rawKey = req.headers["x-api-key"];
    }

    if (!rawKey) {
      return res.status(401).json({
        error: "unauthorized",
        message: "Valid API key required (Bearer dak_... or x-api-key header)"
      });
    }

    let service;
    try {
      service = getApiKeyService();
    } catch (err) {
      return res.status(503).json({ error: "api_key_service_unavailable", message: err.message });
    }

    const keyRecord = await service.verifyKey(rawKey);
    if (!keyRecord) {
      return res.status(401).json({
        error: "invalid_api_key",
        message: "API key is invalid, expired, or has been revoked"
      });
    }

    // Verify granted scopes against required scopes
    if (requiredScopes && (!Array.isArray(requiredScopes) || requiredScopes.length > 0)) {
      const permitted = matchesScopes(keyRecord.scopes, requiredScopes);
      if (!permitted) {
        return res.status(403).json({
          error: "insufficient_scope",
          message: "API key does not possess the required permission scopes",
          requiredScopes: Array.isArray(requiredScopes) ? requiredScopes : [requiredScopes],
          grantedScopes: keyRecord.scopes
        });
      }
    }

    // Attach API key context and pseudo-user context to request
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
  };
}

module.exports = requireApiKey;
