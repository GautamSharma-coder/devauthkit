const { verifyJwt } = require("../utils/webCrypto");
const config = require("../config");
const requireAuth = require("./requireAuth");

async function verifyStepUp(req, res, next) {
  const token = req.headers["x-mfa-token"];
  if (typeof token !== "string" || !token) {
    return res.status(403).json({
      error: "mfa_step_up_required",
      message: "A recent MFA verification is required"
    });
  }
  let claims;
  try {
    claims = await verifyJwt(token, config.get("jwtSecret"));
  } catch {
    return res.status(403).json({
      error: "mfa_step_up_invalid",
      message: "The MFA verification token is invalid or expired"
    });
  }
  const userId = String(req.user?.id ?? req.user?.sub ?? req.user?.email ?? "");
  if (
    !userId ||
    claims.purpose !== "mfa-step-up" ||
    claims.sub !== userId ||
    !Array.isArray(claims.amr) ||
    !claims.amr.includes("totp")
  ) {
    return res.status(403).json({
      error: "mfa_step_up_invalid",
      message: "The MFA verification token is invalid for this account"
    });
  }
  req.mfa = { verifiedAt: claims.iat, method: "totp" };
  return next();
}

module.exports = async function requireMfa(req, res, next) {
  if (req.user) return verifyStepUp(req, res, next);
  return requireAuth(req, res, (error) => {
    if (error) return next(error);
    if (!req.user) {
      return res.status(401).json({ error: "Unauthorized: Authentication required" });
    }
    return verifyStepUp(req, res, next);
  });
};
