// server/core/organizationService.js
const { randomUUID, randomString, sha256Hex } = require("../utils/webCrypto");

const DEFAULT_ORG_ROLES = {
  owner: {
    name: "Owner",
    description: "Full control over the organization, billing, and team",
    permissions: ["*"]
  },
  admin: {
    name: "Admin",
    description: "Can manage team members, send invitations, and configure workspace settings",
    permissions: [
      "org:read",
      "org:update",
      "members:read",
      "members:invite",
      "members:update",
      "members:remove",
      "invites:read",
      "invites:revoke",
      "projects:*"
    ]
  },
  member: {
    name: "Member",
    description: "Standard workspace collaborator with read and create access",
    permissions: [
      "org:read",
      "members:read",
      "projects:read",
      "projects:create"
    ]
  },
  billing: {
    name: "Billing Admin",
    description: "Can view and manage billing, subscriptions, and invoices",
    permissions: [
      "org:read",
      "billing:read",
      "billing:write"
    ]
  },
  viewer: {
    name: "Viewer",
    description: "Read-only access across the workspace",
    permissions: [
      "org:read",
      "members:read",
      "projects:read"
    ]
  }
};

const ROLE_RANK = {
  owner: 100,
  admin: 50,
  billing: 20,
  member: 10,
  viewer: 5
};

/**
 * Convert string into URL-friendly slug
 * @param {string} text
 * @returns {string}
 */
function slugify(text) {
  return String(text || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/[\s_-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/**
 * Check if a role possesses a requested permission
 * @param {string} role - Member role name
 * @param {string} requestedPermission - e.g. "members:invite"
 * @param {Object} [customRoleMap] - Optional custom role configuration
 * @returns {boolean}
 */
function hasOrgPermission(role, requestedPermission, customRoleMap = DEFAULT_ORG_ROLES) {
  if (!role || !requestedPermission) return false;
  const roleConfig = customRoleMap[role];
  if (!roleConfig || !Array.isArray(roleConfig.permissions)) return false;

  const perms = roleConfig.permissions;
  if (perms.includes("*")) return true;
  if (perms.includes(requestedPermission)) return true;

  // Check namespace wildcard: "projects:*" matches "projects:delete"
  const [namespace] = requestedPermission.split(":");
  if (perms.includes(`${namespace}:*`)) return true;

  return false;
}

/**
 * Resolve effective permissions array for a role
 * @param {string} role
 * @param {Object} [customRoleMap]
 * @returns {string[]}
 */
function getRolePermissions(role, customRoleMap = DEFAULT_ORG_ROLES) {
  const roleConfig = customRoleMap[role];
  return roleConfig?.permissions ? [...roleConfig.permissions] : [];
}

/**
 * Check if actor role can manage target role without privilege escalation
 * @param {string} actorRole
 * @param {string} targetRole
 * @returns {boolean}
 */
function canManageRole(actorRole, targetRole) {
  if (actorRole === "owner") return true;
  if (actorRole === "admin") {
    // Admins cannot create, promote to, or demote owners
    return targetRole !== "owner";
  }
  return false;
}

/**
 * Generate a 256-bit cryptographically secure raw invitation token
 * @returns {string} 64-character hex string
 */
function generateInvitationToken() {
  return randomString(32, "hex");
}

/**
 * Hash raw invitation token for database storage
 * @param {string} rawToken
 * @returns {Promise<string>}
 */
async function hashInvitationToken(rawToken) {
  if (typeof rawToken !== "string" || !rawToken.trim()) {
    throw new TypeError("Raw invitation token must be a non-empty string");
  }
  return sha256Hex(rawToken.trim());
}

module.exports = {
  DEFAULT_ORG_ROLES,
  ROLE_RANK,
  slugify,
  hasOrgPermission,
  getRolePermissions,
  canManageRole,
  generateInvitationToken,
  hashInvitationToken
};
