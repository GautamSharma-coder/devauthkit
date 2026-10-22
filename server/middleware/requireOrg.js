// server/middleware/requireOrg.js
const requireAuth = require("./requireAuth");
const config = require("../config");
const { hasOrgPermission } = require("../core/organizationService");

/**
 * Middleware ensuring the authenticated request is scoped to a valid active organization.
 * Attaches `req.org` and `req.orgMember`.
 */
function requireOrg(req, res, next) {
  const proceed = async () => {
    try {
      const orgStore = config.get("organizationStore") || config.get("orgStore");
      if (!orgStore) {
        return res.status(500).json({ error: "Organizations feature is not configured on this server" });
      }

      // Resolve target organization ID from JWT claim, request headers, query, or params
      const orgId = req.user?.org_id ||
        req.headers["x-organization-id"] ||
        req.headers["x-org-id"] ||
        req.params?.orgId ||
        req.params?.id;

      if (!orgId || typeof orgId !== "string") {
        return res.status(400).json({ error: "Active organization context is required (missing org_id)" });
      }

      const userId = req.user.id !== undefined ? String(req.user.id) : req.user.email;
      const member = await orgStore.getMember(orgId, userId);
      if (!member) {
        return res.status(403).json({ error: "Forbidden: You are not an active member of this organization" });
      }

      const organization = await orgStore.getOrgById(orgId);
      if (!organization) {
        return res.status(404).json({ error: "Organization not found" });
      }

      req.org = organization;
      req.orgMember = member;
      return next();
    } catch (err) {
      return next(err);
    }
  };

  if (!req.user) {
    return requireAuth(req, res, (err) => {
      if (err) return next(err);
      if (!req.user) {
        return res.status(401).json({ error: "Unauthorized: Authentication required" });
      }
      return proceed();
    });
  }

  return proceed();
}

/**
 * Role-Based Access Control within an active Organization.
 * @param {string|string[]} allowedRoles - Role name or array (e.g. "admin", ["owner", "admin"])
 * @param {Object} [options]
 * @param {string} [options.errorMessage]
 */
function requireOrgRole(allowedRoles, options = {}) {
  const roles = Array.isArray(allowedRoles)
    ? allowedRoles
    : typeof allowedRoles === "string"
      ? [allowedRoles]
      : [];

  if (roles.length === 0) {
    throw new TypeError("requireOrgRole requires at least one allowed role (string or array of strings)");
  }

  const errorMessage = options.errorMessage || "Forbidden: Insufficient organization permissions";

  return function orgRoleMiddleware(req, res, next) {
    const checkRole = () => {
      const currentRole = req.orgMember?.role;
      // Owner always has super-admin access within the org
      const hasAccess = currentRole === "owner" || roles.includes(currentRole);
      if (!hasAccess) {
        return res.status(403).json({ error: errorMessage });
      }
      return next();
    };

    if (!req.org || !req.orgMember) {
      return requireOrg(req, res, (err) => {
        if (err) return next(err);
        return checkRole();
      });
    }

    return checkRole();
  };
}

/**
 * Permission-Based Access Control within an active Organization.
 * @param {string} requiredPermission - e.g. "billing:write", "members:invite"
 * @param {Object} [options]
 */
function requireOrgPermission(requiredPermission, options = {}) {
  if (!requiredPermission || typeof requiredPermission !== "string") {
    throw new TypeError("requireOrgPermission requires a permission string (e.g. 'members:invite')");
  }

  const errorMessage = options.errorMessage || `Forbidden: Missing required permission (${requiredPermission})`;

  return function orgPermissionMiddleware(req, res, next) {
    const checkPerm = () => {
      const currentRole = req.orgMember?.role;
      const customRoleMap = config.get("orgRoles");
      const hasAccess = hasOrgPermission(currentRole, requiredPermission, customRoleMap);
      if (!hasAccess) {
        return res.status(403).json({ error: errorMessage });
      }
      return next();
    };

    if (!req.org || !req.orgMember) {
      return requireOrg(req, res, (err) => {
        if (err) return next(err);
        return checkPerm();
      });
    }

    return checkPerm();
  };
}

module.exports = {
  requireOrg,
  requireOrgRole,
  requireOrgPermission
};
