// server/controllers/apiKeyController.js
const config = require("../config");
const { emitAuditLog } = require("../core/auditLogService");
const { emitWebhookEvent } = require("../core/webhookDispatcher");

function getApiKeyService() {
  const service = config.get("apiKeyService");
  if (!service) {
    throw new Error("API key service is not configured");
  }
  return service;
}

async function createApiKey(req, res) {
  try {
    const service = getApiKeyService();
    const { name, scopes, expiresInDays, env, orgId } = req.body || {};

    if (!name || typeof name !== "string" || !name.trim()) {
      return res.status(400).json({ error: "missing_name", message: "API key name is required" });
    }

    const effectiveOrgId = req.user?.org_id || orgId || null;

    const { key, rawKey } = await service.createKey({
      userId: req.user.id,
      orgId: effectiveOrgId,
      name,
      scopes,
      expiresInDays,
      env: env || "live"
    });

    // Record audit event
    await emitAuditLog({
      eventType: "apikey.created",
      actorId: req.user.id,
      actorType: req.user.role || "user",
      targetId: key.id,
      orgId: effectiveOrgId,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
      metadata: { keyId: key.id, name: key.name, scopes: key.scopes, prefix: key.keyPrefix }
    });

    // Dispatch webhook
    emitWebhookEvent("apikey.created", {
      keyId: key.id,
      name: key.name,
      prefix: key.keyPrefix,
      userId: req.user.id,
      orgId: effectiveOrgId,
      scopes: key.scopes
    });

    return res.status(201).json({ key, rawKey });
  } catch (err) {
    console.error("[DevAuthKit] Create API key error:", err);
    return res.status(500).json({ error: "failed_to_create_api_key", message: err.message });
  }
}

async function listApiKeys(req, res) {
  try {
    const service = getApiKeyService();
    const effectiveOrgId = req.user?.org_id || req.query.orgId || undefined;
    const keys = await service.listKeys(req.user.id, effectiveOrgId);
    return res.json({ keys });
  } catch (err) {
    console.error("[DevAuthKit] List API keys error:", err);
    return res.status(500).json({ error: "failed_to_list_api_keys", message: err.message });
  }
}

async function getApiKey(req, res) {
  try {
    const service = getApiKeyService();
    const key = await service.getById(req.params.id);
    if (!key) {
      return res.status(404).json({ error: "api_key_not_found" });
    }

    // Tenant / Owner verification
    if (key.userId !== req.user.id && (!req.user.org_id || key.orgId !== req.user.org_id)) {
      return res.status(403).json({ error: "access_denied" });
    }

    const { keyDigest, ...safeKey } = key;
    return res.json({ key: safeKey });
  } catch (err) {
    console.error("[DevAuthKit] Get API key error:", err);
    return res.status(500).json({ error: "failed_to_get_api_key", message: err.message });
  }
}

async function updateApiKey(req, res) {
  try {
    const service = getApiKeyService();
    const { name, scopes } = req.body || {};

    const updated = await service.updateKey(req.params.id, req.user.id, {
      name,
      scopes
    });

    if (!updated) {
      return res.status(404).json({ error: "api_key_not_found" });
    }

    const { keyDigest, ...safeKey } = updated;
    return res.json({ key: safeKey });
  } catch (err) {
    console.error("[DevAuthKit] Update API key error:", err);
    return res.status(500).json({ error: "failed_to_update_api_key", message: err.message });
  }
}

async function revokeApiKey(req, res) {
  try {
    const service = getApiKeyService();
    const success = await service.revokeKey(req.params.id, req.user.id);
    if (!success) {
      return res.status(404).json({ error: "api_key_not_found" });
    }

    await emitAuditLog({
      eventType: "apikey.revoked",
      actorId: req.user.id,
      actorType: req.user.role || "user",
      targetId: req.params.id,
      orgId: req.user.org_id,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
      metadata: { keyId: req.params.id }
    });

    emitWebhookEvent("apikey.revoked", {
      keyId: req.params.id,
      userId: req.user.id,
      orgId: req.user.org_id
    });

    return res.json({ success: true, message: "API key revoked" });
  } catch (err) {
    console.error("[DevAuthKit] Revoke API key error:", err);
    return res.status(500).json({ error: "failed_to_revoke_api_key", message: err.message });
  }
}

async function rollApiKey(req, res) {
  try {
    const service = getApiKeyService();
    const { key, rawKey } = await service.rollKey(req.params.id, req.user.id);

    await emitAuditLog({
      eventType: "apikey.rolled",
      actorId: req.user.id,
      actorType: req.user.role || "user",
      targetId: key.id,
      orgId: req.user.org_id,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
      metadata: { oldKeyId: req.params.id, newKeyId: key.id }
    });

    emitWebhookEvent("apikey.rolled", {
      oldKeyId: req.params.id,
      newKeyId: key.id,
      userId: req.user.id
    });

    return res.json({ key, rawKey });
  } catch (err) {
    console.error("[DevAuthKit] Roll API key error:", err);
    return res.status(500).json({ error: "failed_to_roll_api_key", message: err.message });
  }
}

module.exports = {
  createApiKey,
  listApiKeys,
  getApiKey,
  updateApiKey,
  revokeApiKey,
  rollApiKey
};
