// server/controllers/userManagementController.js
const config = require("../config");
const defaultRefreshTokenStore = require("../stores/defaultRefreshTokenStore");
const { emitAuditLog } = require("../core/auditLogService");
const { emitWebhookEvent } = require("../core/webhookDispatcher");

// In-memory fallback tracking for user status and revocation epochs
const userStatusRegistry = new Map(); // userId -> { status: "suspended"|"active", epoch: number, reason: string, updatedAt: number }

function getStatusEntry(userId) {
  if (!userStatusRegistry.has(userId)) {
    userStatusRegistry.set(userId, { status: "active", epoch: 1, reason: null, updatedAt: Date.now() });
  }
  return userStatusRegistry.get(userId);
}

function isUserBlocked(userId) {
  const entry = userStatusRegistry.get(userId);
  return entry ? entry.status === "suspended" : false;
}

function getUserEpoch(userId) {
  const entry = userStatusRegistry.get(userId);
  return entry ? entry.epoch : 1;
}

async function blockUser(req, res) {
  try {
    const callerRole = req.user?.role;
    if (callerRole !== "admin" && callerRole !== "superadmin") {
      return res.status(403).json({ error: "forbidden", message: "Only administrators can block users" });
    }

    const { userId } = req.params;
    const { reason } = req.body || {};

    if (!userId) {
      return res.status(400).json({ error: "missing_user_id" });
    }

    if (userId === req.user.id) {
      return res.status(400).json({ error: "cannot_block_self", message: "Cannot block your own user account" });
    }

    // 1. Update status and increment epoch in registry
    const entry = getStatusEntry(userId);
    entry.status = "suspended";
    entry.epoch += 1;
    entry.reason = reason || "Administrative suspension";
    entry.updatedAt = Date.now();

    // 2. Call user adapter if available
    const userAdapter = config.get("userAdapter");
    if (userAdapter && typeof userAdapter.blockUser === "function") {
      try {
        await userAdapter.blockUser(userId, reason);
      } catch (err) {
        console.error("[DevAuthKit] UserAdapter.blockUser failed:", err);
      }
    }

    // 3. Purge all refresh sessions for this user
    const refreshTokenStore = config.get("refreshTokenStore") || defaultRefreshTokenStore;
    if (refreshTokenStore && typeof refreshTokenStore.revokeAllUserSessions === "function") {
      try {
        await refreshTokenStore.revokeAllUserSessions(userId);
      } catch (err) {
        console.error("[DevAuthKit] Revoking user refresh sessions failed:", err);
      }
    }

    // 4. Suspend user API keys if configured
    const apiKeyService = config.get("apiKeyService");
    if (apiKeyService && apiKeyService.store) {
      try {
        const keys = await apiKeyService.listKeys(userId);
        for (const key of keys) {
          await apiKeyService.updateKey(key.id, userId, { status: "suspended" });
        }
      } catch (err) {
        console.error("[DevAuthKit] Suspending user API keys failed:", err);
      }
    }

    // 5. Emit Audit Log & Webhook
    await emitAuditLog({
      eventType: "user.blocked",
      actorId: req.user.id,
      actorType: "admin",
      targetId: userId,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
      metadata: { targetUserId: userId, reason: entry.reason, newEpoch: entry.epoch }
    });

    emitWebhookEvent("user.blocked", {
      userId,
      blockedBy: req.user.id,
      reason: entry.reason
    });

    return res.json({
      success: true,
      userId,
      status: "suspended",
      revocationEpoch: entry.epoch,
      message: "User suspended and all active sessions purged"
    });
  } catch (err) {
    console.error("[DevAuthKit] Block user error:", err);
    return res.status(500).json({ error: "failed_to_block_user", message: err.message });
  }
}

async function unblockUser(req, res) {
  try {
    const callerRole = req.user?.role;
    if (callerRole !== "admin" && callerRole !== "superadmin") {
      return res.status(403).json({ error: "forbidden", message: "Only administrators can unblock users" });
    }

    const { userId } = req.params;
    if (!userId) {
      return res.status(400).json({ error: "missing_user_id" });
    }

    const entry = getStatusEntry(userId);
    entry.status = "active";
    entry.reason = null;
    entry.updatedAt = Date.now();

    const userAdapter = config.get("userAdapter");
    if (userAdapter && typeof userAdapter.unblockUser === "function") {
      try {
        await userAdapter.unblockUser(userId);
      } catch (err) {
        console.error("[DevAuthKit] UserAdapter.unblockUser failed:", err);
      }
    }

    await emitAuditLog({
      eventType: "user.unblocked",
      actorId: req.user.id,
      actorType: "admin",
      targetId: userId,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
      metadata: { targetUserId: userId }
    });

    emitWebhookEvent("user.unblocked", {
      userId,
      unblockedBy: req.user.id
    });

    return res.json({
      success: true,
      userId,
      status: "active",
      message: "User account reactivated"
    });
  } catch (err) {
    console.error("[DevAuthKit] Unblock user error:", err);
    return res.status(500).json({ error: "failed_to_unblock_user", message: err.message });
  }
}

async function getUserStatus(req, res) {
  try {
    const { userId } = req.params;
    const entry = getStatusEntry(userId);

    return res.json({
      userId,
      status: entry.status,
      revocationEpoch: entry.epoch,
      updatedAt: entry.updatedAt
    });
  } catch (err) {
    console.error("[DevAuthKit] Get user status error:", err);
    return res.status(500).json({ error: "failed_to_get_user_status", message: err.message });
  }
}

module.exports = {
  blockUser,
  unblockUser,
  getUserStatus,
  isUserBlocked,
  getUserEpoch,
  userStatusRegistry
};
