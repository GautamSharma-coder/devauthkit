// server/controllers/impersonationController.js
const { signJwt } = require("../utils/webCrypto");
const config = require("../config");
const { emitAuditLog } = require("../core/auditLogService");
const { emitWebhookEvent } = require("../core/webhookDispatcher");

async function startImpersonation(req, res) {
  try {
    // 1. Role validation: Must be an admin or superadmin
    const userRole = req.user?.role;
    if (userRole !== "admin" && userRole !== "superadmin") {
      return res.status(403).json({
        error: "forbidden",
        message: "Only administrators can initiate impersonation sessions"
      });
    }

    // 2. Invariant: Prohibit chained impersonation (Zero Delegation Depth)
    if (req.user?.act) {
      return res.status(403).json({
        error: "delegation_forbidden",
        message: "Cannot initiate impersonation from an already impersonated session"
      });
    }

    const { userId, reason } = req.body || {};
    if (!userId || typeof userId !== "string") {
      return res.status(400).json({ error: "missing_user_id", message: "Target userId is required" });
    }

    if (userId === req.user.id) {
      return res.status(400).json({ error: "invalid_target", message: "Cannot impersonate yourself" });
    }

    // 3. Resolve target user
    let targetUser = null;
    const userAdapter = config.get("userAdapter");
    if (userAdapter && typeof userAdapter.findUserById === "function") {
      targetUser = await userAdapter.findUserById(userId);
    } else if (userAdapter && typeof userAdapter.findUserByEmail === "function" && userId.includes("@")) {
      targetUser = await userAdapter.findUserByEmail(userId);
    }

    if (!targetUser) {
      // Fallback for default in-memory or synthetic user identifier
      targetUser = { id: userId, email: userId.includes("@") ? userId : `${userId}@example.com`, role: "user" };
    }

    // Prohibit impersonating other superadmins
    if (targetUser.role === "superadmin" && userRole !== "superadmin") {
      return res.status(403).json({
        error: "privilege_violation",
        message: "Cannot impersonate a superadmin user"
      });
    }

    // 4. Mint RFC 8693 Delegated Token
    const impersonationConfig = config.get("impersonation") || {};
    const ttlSeconds = impersonationConfig.maxTtlSeconds || 3600; // 1 hour default
    const now = Math.floor(Date.now() / 1000);

    const tokenClaims = {
      sub: targetUser.id,
      id: targetUser.id,
      email: targetUser.email,
      role: targetUser.role || "user",
      org_id: targetUser.org_id || null,
      scope: "impersonation:act_as",
      act: {
        sub: req.user.id,
        id: req.user.id,
        email: req.user.email,
        role: req.user.role,
        reason: reason || "Administrative Support Session",
        startedAt: now
      },
      iat: now,
      exp: now + ttlSeconds
    };

    const impersonationToken = await signJwt(tokenClaims, config.get("jwtSecret"));

    // 5. Audit Trail & Webhooks
    await emitAuditLog({
      eventType: "impersonation.started",
      actorId: req.user.id,
      actorType: "admin",
      targetId: targetUser.id,
      orgId: req.user.org_id,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
      metadata: {
        targetUserId: targetUser.id,
        targetEmail: targetUser.email,
        adminId: req.user.id,
        reason: reason || "Support Session",
        ttlSeconds
      }
    });

    emitWebhookEvent("impersonation.started", {
      actorId: req.user.id,
      targetUserId: targetUser.id,
      reason: reason || "Support Session"
    });

    return res.json({
      token: impersonationToken,
      expiresIn: ttlSeconds,
      targetUser: { id: targetUser.id, email: targetUser.email, role: targetUser.role },
      actor: { id: req.user.id, email: req.user.email }
    });
  } catch (err) {
    console.error("[DevAuthKit] Impersonation error:", err);
    return res.status(500).json({ error: "failed_to_impersonate", message: err.message });
  }
}

async function endImpersonation(req, res) {
  try {
    if (req.user?.act) {
      await emitAuditLog({
        eventType: "impersonation.ended",
        actorId: req.user.act.id || req.user.act.sub,
        actorType: "admin",
        targetId: req.user.id || req.user.sub,
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
        metadata: {
          targetUserId: req.user.id || req.user.sub,
          actorAdminId: req.user.act.id || req.user.act.sub
        }
      });

      emitWebhookEvent("impersonation.ended", {
        targetUserId: req.user.id || req.user.sub,
        actorAdminId: req.user.act.id || req.user.act.sub
      });
    }

    return res.json({ success: true, message: "Impersonation session ended" });
  } catch (err) {
    console.error("[DevAuthKit] End impersonation error:", err);
    return res.status(500).json({ error: "failed_to_end_impersonation", message: err.message });
  }
}

module.exports = {
  startImpersonation,
  endImpersonation
};
