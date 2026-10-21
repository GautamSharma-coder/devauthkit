// server/middleware/requireDPoP.js
const config = require("../config");
const { verifyDPoPProof, DPoPError } = require("../core/dpopService");

/**
 * Express middleware that strictly enforces an RFC 9449 DPoP proof of possession.
 * Can be used alongside requireAuth or independently on sensitive endpoints.
 */
module.exports = async function requireDPoP(req, res, next) {
  const dpopHeader = req.headers.dpop || req.headers.DPoP;
  if (!dpopHeader) {
    res.set("WWW-Authenticate", 'DPoP error="invalid_dpop_proof", error_description="DPoP header is required"');
    return res.status(401).json({
      error: "invalid_dpop_proof",
      message: "DPoP proof header is required for this endpoint"
    });
  }

  // If already verified by requireAuth and attached to req.dpop, proceed
  if (req.dpop && req.dpop.jkt) {
    return next();
  }

  // Extract access token if present
  const authHeader = req.headers.authorization || req.headers.Authorization;
  let token = null;
  if (authHeader) {
    if (authHeader.startsWith("DPoP ")) {
      token = authHeader.slice(5);
    } else if (authHeader.startsWith("Bearer ")) {
      token = authHeader.slice(7);
    }
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
      expectedAccessToken: token || undefined,
      expectedNonce: config.get("dpopNonce"),
      replayStore,
      maxClockSkewSeconds: config.get("dpopMaxClockSkewSeconds") || 60
    });

    // If an access token was provided with cnf.jkt claim, ensure match
    if (req.user?.cnf?.jkt && req.user.cnf.jkt !== verification.jkt) {
      res.set("WWW-Authenticate", 'DPoP error="invalid_dpop_proof", error_description="Key binding mismatch"');
      return res.status(401).json({
        error: "invalid_dpop_proof",
        message: "DPoP key binding does not match the access token claim"
      });
    }

    req.dpop = { jkt: verification.jkt, payload: verification.payload };
    return next();
  } catch (err) {
    const status = err instanceof DPoPError ? err.status : 401;
    const code = err instanceof DPoPError ? err.code : "invalid_dpop_proof";
    res.set("WWW-Authenticate", `DPoP error="${code}", error_description="${err.message}"`);
    return res.status(status).json({ error: code, message: err.message });
  }
};
