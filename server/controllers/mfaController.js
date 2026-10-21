const config = require("../config");
const { MfaError, createMfaService } = require("../core/mfaService");

function userId(req) {
  return req.user?.id ?? req.user?.sub ?? req.user?.email;
}

function createService() {
  const store = config.get("mfaStore");
  if (!store) return null;
  return createMfaService(store, {
    issuer: config.get("mfaIssuer"),
    jwtSecret: config.get("jwtSecret"),
    stepUpExpiresInSeconds: config.get("mfaStepUpExpiresInSeconds")
  });
}

function unavailable(res) {
  return res.status(503).json({
    error: "mfa_store_unavailable",
    message: "MFA storage is not configured"
  });
}

function handleError(res, error, action) {
  if (error instanceof MfaError) {
    return res.status(error.status).json({ error: error.code, message: error.message });
  }
  console.error(`[DevAuthKit] Failed to ${action}:`, error);
  return res.status(500).json({ error: `Failed to ${action}` });
}

function sameOrigin(req, res, next) {
  if (req.headers["sec-fetch-site"] === "cross-site") {
    return res.status(403).json({ error: "MFA settings require a same-origin request" });
  }
  const origin = req.headers.origin;
  if (!origin) {
    const authorization = req.headers.authorization || "";
    if (/^(Bearer|DPoP)\s+/i.test(authorization)) return next();
    return res.status(403).json({ error: "MFA settings require an Origin header for cookie authentication" });
  }
  const configuredOrigins = config.get("corsOrigin");
  const allowedOrigins = Array.isArray(configuredOrigins) ? configuredOrigins : [configuredOrigins];
  if (!allowedOrigins.includes(origin)) {
    return res.status(403).json({ error: "MFA settings require a configured same-origin request" });
  }
  return next();
}

exports.sameOrigin = sameOrigin;

exports.status = async (req, res) => {
  const service = createService();
  if (!service) return unavailable(res);
  try {
    return res.json(await service.status(userId(req)));
  } catch (error) {
    return handleError(res, error, "read MFA status");
  }
};

exports.enroll = async (req, res) => {
  const service = createService();
  if (!service) return unavailable(res);
  try {
    const enrollment = await service.startEnrollment(
      userId(req),
      req.user?.email || String(userId(req))
    );
    return res.json(enrollment);
  } catch (error) {
    return handleError(res, error, "start MFA enrollment");
  }
};

exports.enable = async (req, res) => {
  const service = createService();
  if (!service) return unavailable(res);
  try {
    if (typeof req.body?.code !== "string") {
      return res.status(400).json({ error: "A six-digit authenticator code is required" });
    }
    const recoveryCodes = await service.activate(userId(req), req.body.code);
    return res.json({
      enabled: true,
      recoveryCodes,
      message: "Save these recovery codes now. They will not be shown again."
    });
  } catch (error) {
    return handleError(res, error, "enable MFA");
  }
};

exports.verify = async (req, res) => {
  const service = createService();
  if (!service) return unavailable(res);
  try {
    if (typeof req.body?.code !== "string") {
      return res.status(400).json({ error: "An authenticator or recovery code is required" });
    }
    const token = await service.verify(userId(req), req.body.code);
    return res.json({
      mfaToken: token,
      expiresIn: config.get("mfaStepUpExpiresInSeconds") ?? 300
    });
  } catch (error) {
    return handleError(res, error, "verify MFA");
  }
};

exports.disable = async (req, res) => {
  const service = createService();
  if (!service) return unavailable(res);
  try {
    await service.disable(userId(req));
    return res.json({ enabled: false });
  } catch (error) {
    return handleError(res, error, "disable MFA");
  }
};
