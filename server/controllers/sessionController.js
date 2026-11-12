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
    const userId = String(req.user.id ?? req.user.sub ?? req.user.email);
    const sessions = service.listUserSessions(userId, currentSessionId);

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

    const userId = String(req.user.id ?? req.user.sub ?? req.user.email);
    const success = service.revokeSession(sessionId, userId);
    const isOwnCurrentSid = Boolean(req.user?.sid && req.user.sid === sessionId);
    if (!success && !isOwnCurrentSid) {
      return res.status(404).json({ error: "session_not_found", message: "Session not found for this account" });
    }

    // Revoke in refresh token store only after verifying session ownership
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
      actorId: userId,
      actorType: req.user.role || "user",
      targetId: sessionId,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
      metadata: { sessionId }
    });

    emitWebhookEvent("session.revoked", {
      sessionId,
      userId
    });

    return res.json({ success: true, message: "Session revoked" });
  } catch (err) {
    console.error("[DevAuthKit] Revoke session error:", err);
    return res.status(500).json({ error: "failed_to_revoke_session", message: err.message });
  }
}

async function revokeOtherSessions(req, res) {
  try {
    const service = getSessionService();
    const currentSessionId = req.user?.sid;
    const userId = String(req.user.id ?? req.user.sub ?? req.user.email);

    const otherSessions = service
      .listUserSessions(userId, currentSessionId)
      .filter((s) => !s.isCurrent);
    const revokedCount = service.revokeOtherSessions(userId, currentSessionId);

    const tokenStore = getRefreshTokenStore();
    if (tokenStore && typeof tokenStore.revokeFamily === "function") {
      for (const s of otherSessions) {
        try {
          await tokenStore.revokeFamily(s.id);
        } catch (err) {
          console.error("[DevAuthKit] Failed to revoke other refresh token family:", err);
        }
      }
    }

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
