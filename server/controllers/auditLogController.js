// server/controllers/auditLogController.js
const config = require("../config");
const { AuditLogService } = require("../core/auditLogService");
const { isSystemAdmin, authorizeOrgAdmin } = require("../utils/accessControl");

function getAuditService() {
  const auditService = config.get("auditService");
  if (!auditService) {
    throw new Error("Audit log service is not configured");
  }
  return auditService;
}

async function resolveAuthorizedAuditOrgId(req, requestedOrgId) {
  if (isSystemAdmin(req.user)) {
    return { allowed: true, orgId: requestedOrgId || undefined };
  }
  const targetOrgId = req.user?.org_id || requestedOrgId;
  if (!targetOrgId) {
    return {
      allowed: false,
      status: 403,
      error: "Forbidden: Administrator or organization admin privileges required"
    };
  }
  const authz = await authorizeOrgAdmin(req, targetOrgId);
  if (!authz.allowed) return authz;
  return { allowed: true, orgId: String(targetOrgId) };
}

async function queryAuditLogs(req, res) {
  try {
    const service = getAuditService();
    const {
      actorId,
      eventType,
      orgId,
      targetId,
      since,
      until,
      limit,
      offset
    } = req.query;

    const scope = await resolveAuthorizedAuditOrgId(req, orgId);
    if (!scope.allowed) {
      return res.status(scope.status).json({ error: scope.error });
    }

    const result = await service.query({
      actorId,
      eventType,
      orgId: scope.orgId,
      targetId,
      since: since ? Number(since) : undefined,
      until: until ? Number(until) : undefined,
      limit: limit ? Number(limit) : 50,
      offset: offset ? Number(offset) : 0
    });

    return res.json(result);
  } catch (err) {
    console.error("[DevAuthKit] Audit query error:", err);
    return res.status(500).json({ error: "failed_to_query_audit_logs", message: err.message });
  }
}

async function getAuditLog(req, res) {
  try {
    const service = getAuditService();
    const entry = await service.getById(req.params.id);
    if (!entry) {
      return res.status(404).json({ error: "audit_entry_not_found" });
    }

    if (!isSystemAdmin(req.user)) {
      if (!entry.orgId) {
        return res.status(403).json({ error: "access_denied", message: "Administrator privileges required" });
      }
      const authz = await authorizeOrgAdmin(req, entry.orgId);
      if (!authz.allowed) {
        return res.status(403).json({ error: "access_denied", message: "Audit log belongs to another workspace" });
      }
    }

    return res.json({ entry });
  } catch (err) {
    console.error("[DevAuthKit] Audit get error:", err);
    return res.status(500).json({ error: "failed_to_get_audit_log", message: err.message });
  }
}

async function exportAuditLogs(req, res) {
  try {
    const service = getAuditService();
    const { since, until, eventType, orgId } = req.query;
    const scope = await resolveAuthorizedAuditOrgId(req, orgId);
    if (!scope.allowed) {
      return res.status(scope.status).json({ error: scope.error });
    }

    const ndjson = await service.exportNdjson({
      since: since ? Number(since) : undefined,
      until: until ? Number(until) : undefined,
      eventType,
      orgId: scope.orgId,
      limit: 5000
    });

    res.setHeader("Content-Type", "application/x-ndjson");
    res.setHeader("Content-Disposition", `attachment; filename="audit_logs_${Date.now()}.jsonl"`);
    return res.send(ndjson);
  } catch (err) {
    console.error("[DevAuthKit] Audit export error:", err);
    return res.status(500).json({ error: "failed_to_export_audit_logs", message: err.message });
  }
}

async function verifyAuditTrail(req, res) {
  try {
    if (!isSystemAdmin(req.user)) {
      return res.status(403).json({ error: "forbidden", message: "Only administrators can verify the audit chain" });
    }
    const service = getAuditService();
    const { entries } = await service.query({ limit: 1000 });
    // Verify in chronological order
    const chronological = [...entries].reverse();
    const verification = await AuditLogService.verifyChain(chronological);
    return res.json(verification);
  } catch (err) {
    console.error("[DevAuthKit] Audit verify error:", err);
    return res.status(500).json({ error: "failed_to_verify_audit_trail", message: err.message });
  }
}

module.exports = {
  queryAuditLogs,
  getAuditLog,
  exportAuditLogs,
  verifyAuditTrail
};
