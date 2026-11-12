// server/controllers/userManagementController.js
const config = require("../config");
const defaultRefreshTokenStore = require("../stores/defaultRefreshTokenStore");
const { defaultSessionService } = require("../core/sessionService");
const { emitAuditLog } = require("../core/auditLogService");
const { emitWebhookEvent } = require("../core/webhookDispatcher");
const { getActorId, isSystemAdmin } = require("../utils/accessControl");

// In-memory fallback tracking for user status and revocation epochs
const userStatusRegistry = new Map(); // String(userId) -> { status: "suspended"|"active", epoch: number, reason: string, updatedAt: number }

function normalizeUserId(userId) {
  if (userId === undefined || userId === null) return "";
  return String(userId);
}

function getStatusEntry(userId) {
  const key = normalizeUserId(userId);
  if (!userStatusRegistry.has(key)) {
    userStatusRegistry.set(key, { status: "active", epoch: 1, reason: null, updatedAt: Date.now() });
  }
  return userStatusRegistry.get(key);
}

function isUserBlocked(userId) {
  const key = normalizeUserId(userId);
  if (!key) return false;
  const entry = userStatusRegistry.get(key);
  return entry ? entry.status === "suspended" : false;
}

function getUserEpoch(userId) {
  const key = normalizeUserId(userId);
  if (!key) return 1;
  const entry = userStatusRegistry.get(key);
  return entry ? entry.epoch : 1;
}

async function blockUser(req, res) {
  try {
    if (!isSystemAdmin(req.user)) {
      return res.status(403).json({ error: "forbidden", message: "Only administrators can block users" });
    }

    const { userId } = req.params;
    const { reason } = req.body || {};

    if (!userId) {
      return res.status(400).json({ error: "missing_user_id" });
    }

    const targetUserId = normalizeUserId(userId);
    if (targetUserId === normalizeUserId(req.user.id)) {
      return res.status(400).json({ error: "cannot_block_self", message: "Cannot block your own user account" });
    }

    // 1. Update status and increment epoch in registry
    const entry = getStatusEntry(targetUserId);
    entry.status = "suspended";
    entry.epoch += 1;
    entry.reason = reason || "Administrative suspension";
    entry.updatedAt = Date.now();

    // 2. Call user adapter if available
    const userAdapter = config.get("userAdapter");
    if (userAdapter && typeof userAdapter.blockUser === "function") {
      try {
        await userAdapter.blockUser(targetUserId, reason);
      } catch (err) {
        console.error("[DevAuthKit] UserAdapter.blockUser failed:", err);
      }
    }

    // 3. Purge all refresh sessions and active device sessions for this user
    const refreshTokenStore = config.get("refreshTokenStore") || defaultRefreshTokenStore;
    if (refreshTokenStore && typeof refreshTokenStore.revokeAll === "function") {
      try {
        await refreshTokenStore.revokeAll(targetUserId);
      } catch (err) {
        console.error("[DevAuthKit] Revoking user refresh sessions failed:", err);
      }
    }
    const sessionService = config.get("sessionService") || defaultSessionService;
    if (sessionService && typeof sessionService.revokeAllUserSessions === "function") {
      sessionService.revokeAllUserSessions(targetUserId);
    }

    // 4. Suspend user API keys if configured
    const apiKeyService = config.get("apiKeyService");
    if (apiKeyService && apiKeyService.store) {
      try {
        const keys = await apiKeyService.listKeys(targetUserId);
        for (const key of keys) {
          await apiKeyService.updateKey(key.id, key.userId, { status: "suspended" });
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
    if (!isSystemAdmin(req.user)) {
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
    if (!isSystemAdmin(req.user) && getActorId(req.user) !== normalizeUserId(userId)) {
      return res.status(403).json({ error: "forbidden", message: "Cannot inspect another user's status" });
    }
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
