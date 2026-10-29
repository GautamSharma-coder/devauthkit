// server/controllers/sessionController.js
const config = require("../config");
const { defaultSessionService } = require("../core/sessionService");
const defaultRefreshTokenStore = require("../stores/defaultRefreshTokenStore");
const { emitAuditLog } = require("../core/auditLogService");
const { emitWebhookEvent } = require("../core/webhookDispatcher");

function getSessionService() {
  return config.get("sessionService") || defaultSessionService;
}

function getRefreshTokenStore() {
  return config.get("refreshTokenStore") || defaultRefreshTokenStore;
}

async function listSessions(req, res) {
  try {
    const service = getSessionService();
    const currentSessionId = req.user?.sid || null;
    const sessions = service.listUserSessions(req.user.id, currentSessionId);

    return res.json({ sessions });
  } catch (err) {
    console.error("[DevAuthKit] List sessions error:", err);
    return res.status(500).json({ error: "failed_to_list_sessions", message: err.message });
  }
}

async function revokeSession(req, res) {
  try {
    const service = getSessionService();
    const sessionId = req.params.id;
    if (!sessionId) {
      return res.status(400).json({ error: "missing_session_id" });
    }

    const success = service.revokeSession(sessionId, req.user.id);

    // Also revoke in refresh token store if applicable
    const tokenStore = getRefreshTokenStore();
    if (tokenStore && typeof tokenStore.revokeFamily === "function") {
      try {
        await tokenStore.revokeFamily(sessionId);
      } catch (err) {
        console.error("[DevAuthKit] Failed to revoke refresh token family:", err);
      }
    }

    await emitAuditLog({
      eventType: "session.revoked",
      actorId: req.user.id,
      actorType: req.user.role || "user",
      targetId: sessionId,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
      metadata: { sessionId }
    });

    emitWebhookEvent("session.revoked", {
      sessionId,
      userId: req.user.id
    });

    return res.json({ success, message: "Session revoked" });
  } catch (err) {
    console.error("[DevAuthKit] Revoke session error:", err);
    return res.status(500).json({ error: "failed_to_revoke_session", message: err.message });
  }
}

async function revokeOtherSessions(req, res) {
  try {
    const service = getSessionService();
    const currentSessionId = req.user?.sid;

    const revokedCount = service.revokeOtherSessions(req.user.id, currentSessionId);

    await emitAuditLog({
      eventType: "session.revoked_all",
      actorId: req.user.id,
      actorType: req.user.role || "user",
      targetId: req.user.id,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
      metadata: { revokedCount, keptSessionId: currentSessionId }
    });

    emitWebhookEvent("session.revoked_all", {
      userId: req.user.id,
      revokedCount
    });

    return res.json({
      success: true,
      revokedCount,
      message: `Revoked ${revokedCount} other active sessions`
    });
  } catch (err) {
    console.error("[DevAuthKit] Revoke other sessions error:", err);
    return res.status(500).json({ error: "failed_to_revoke_other_sessions", message: err.message });
  }
}

module.exports = {
  listSessions,
  revokeSession,
  revokeOtherSessions
};
