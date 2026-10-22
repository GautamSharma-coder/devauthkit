// server/core/scimService.js
const {
  constantTimeEqual,
  randomString,
  sha256Hex
} = require("../utils/webCrypto");

const SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
const SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
const SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/**
 * Generate a cryptographically secure SCIM Bearer token
 * @returns {string} e.g. "scim_live_..."
 */
function generateScimBearerToken() {
  return `scim_live_${randomString(32, "base64url")}`;
}

/**
 * Compute SHA-256 hash of SCIM Bearer token
 * @param {string} token
 * @returns {Promise<string>}
 */
async function hashScimBearerToken(token) {
  if (!token || typeof token !== "string") {
    throw new TypeError("SCIM token must be a string");
  }
  return sha256Hex(token.trim());
}

/**
 * Verify presented SCIM Bearer token against stored token hash using constant-time comparison
 * @param {string} presentedToken
 * @param {string} storedHash
 * @returns {Promise<boolean>}
 */
async function verifyScimBearerToken(presentedToken, storedHash) {
  if (!presentedToken || !storedHash) return false;
  try {
    const presentedHash = await sha256Hex(presentedToken.trim());
    return constantTimeEqual(presentedHash, storedHash);
  } catch {
    return false;
  }
}

/**
 * RFC 7643 ServiceProviderConfig specification
 */
function getServiceProviderConfig(baseUrl) {
  return {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    documentationUri: "https://gautamsharma-coder.github.io/devauthkit/docs.html",
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: 100 },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [
      {
        name: "OAuth Bearer Token",
        description: "Authentication scheme using the OAuth Bearer Token Standard",
        specUri: "https://tools.ietf.org/html/rfc6750",
        type: "oauthbearertoken",
        primary: true
      }
    ],
    meta: {
      location: `${baseUrl}/ServiceProviderConfig`,
      resourceType: "ServiceProviderConfig",
      created: "2026-01-01T00:00:00Z",
      lastModified: "2026-01-01T00:00:00Z"
    }
  };
}

/**
 * RFC 7643 Schemas endpoint
 */
function getSchemas() {
  return {
    schemas: [SCIM_LIST_SCHEMA],
    totalResults: 2,
    startIndex: 1,
    itemsPerPage: 2,
    Resources: [
      {
        id: SCIM_USER_SCHEMA,
        name: "User",
        description: "User Account",
        attributes: [
          { name: "userName", type: "string", multiValued: false, required: true },
          { name: "emails", type: "complex", multiValued: true, required: true },
          { name: "active", type: "boolean", multiValued: false, required: false }
        ]
      },
      {
        id: SCIM_GROUP_SCHEMA,
        name: "Group",
        description: "Group Resource",
        attributes: [
          { name: "displayName", type: "string", multiValued: false, required: true },
          { name: "members", type: "complex", multiValued: true, required: false }
        ]
      }
    ]
  };
}

/**
 * Format internal user and member mapping into standard SCIM User resource
 */
function formatScimUser(user, member, scimBaseUrl) {
  const userId = user.id ? String(user.id) : String(member.userId);
  const email = (user.email || member.email || "").toLowerCase().trim();
  const displayName = user.name || user.displayName || email;

  return {
    schemas: [SCIM_USER_SCHEMA],
    id: userId,
    externalId: user.externalId || userId,
    userName: email,
    name: {
      formatted: displayName,
      familyName: user.familyName || "",
      givenName: user.givenName || ""
    },
    displayName,
    emails: [
      {
        value: email,
        primary: true,
        type: "work"
      }
    ],
    active: member.active !== false,
    groups: Array.isArray(member.groups) ? member.groups.map((g) => ({ value: g, display: g })) : [],
    meta: {
      resourceType: "User",
      location: `${scimBaseUrl}/Users/${userId}`,
      created: new Date(member.createdAt || Date.now()).toISOString(),
      lastModified: new Date(member.updatedAt || Date.now()).toISOString()
    }
  };
}

/**
 * Format internal group representation into SCIM Group resource
 */
function formatScimGroup(group, scimBaseUrl) {
  return {
    schemas: [SCIM_GROUP_SCHEMA],
    id: group.id,
    displayName: group.displayName || group.name,
    members: (group.members || []).map((memberId) => ({
      value: String(memberId),
      $ref: `${scimBaseUrl}/Users/${memberId}`
    })),
    meta: {
      resourceType: "Group",
      location: `${scimBaseUrl}/Groups/${group.id}`,
      created: new Date(group.createdAt || Date.now()).toISOString()
    }
  };
}

/**
 * Format RFC 7644 ListResponse
 */
function formatScimList(resources, totalResults, startIndex = 1, count = 50) {
  return {
    schemas: [SCIM_LIST_SCHEMA],
    totalResults,
    startIndex,
    itemsPerPage: resources.length,
    Resources: resources
  };
}

/**
 * Format standard RFC 7644 Error response
 */
function formatScimError(status, detail, scimType = null) {
  return {
    schemas: [SCIM_ERROR_SCHEMA],
    status: String(status),
    detail: detail || "An error occurred",
    ...(scimType ? { scimType } : {})
  };
}

/**
 * Parse SCIM filter parameter (e.g. `userName eq "alice@example.com"`)
 * @param {string} filter
 * @returns {{ attribute: string, operator: string, value: string }|null}
 */
function parseScimFilter(filter) {
  if (!filter || typeof filter !== "string") return null;

  // Simple SCIM filter parser: <attribute> <op> "<value>"
  const match = filter.match(/^\s*([a-zA-Z0-9_.]+)\s+(eq|co|sw|ew)\s+["']?([^"']+)["']?\s*$/i);
  if (match) {
    return {
      attribute: match[1],
      operator: match[2].toLowerCase(),
      value: match[3]
    };
  }

  // emails[value eq "..."] format
  const complexMatch = filter.match(/emails\[value\s+(eq)\s+["']?([^"']+)["']?\]/i);
  if (complexMatch) {
    return {
      attribute: "userName",
      operator: complexMatch[1].toLowerCase(),
      value: complexMatch[2]
    };
  }

  return null;
}

/**
 * Parse SCIM PATCH operations
 * Detects attribute replacements, group additions/removals, and deactivations
 * @param {Array} operations
 * @returns {{ active?: boolean, updates: Object, addMembers: string[], removeMembers: string[] }}
 */
function parseScimPatchOperations(operations) {
  const result = {
    updates: {},
    addMembers: [],
    removeMembers: []
  };

  if (!Array.isArray(operations)) return result;

  for (const op of operations) {
    const opType = (op.op || "").toLowerCase();
    const path = (op.path || "").toLowerCase();
    const value = op.value;

    if (opType === "replace" || opType === "add") {
      // 1. Direct active status replacement: path="active", value=false
      if (path === "active") {
        result.active = value === true || value === "true";
      } else if (value && typeof value === "object" && value.active !== undefined) {
        // 2. Object replacement: value={ active: false }
        result.active = value.active === true || value.active === "true";
      }

      // Group member additions: path="members", value=[{ value: "usr_1" }]
      if (path === "members" && Array.isArray(value)) {
        for (const m of value) {
          if (m && m.value) result.addMembers.push(String(m.value));
        }
      }

      // Profile updates
      if (typeof value === "object") {
        Object.assign(result.updates, value);
      } else if (path) {
        result.updates[path] = value;
      }
    } else if (opType === "remove") {
      // Group member removal: path="members[value eq \"usr_1\"]"
      const memberMatch = path.match(/members\[value\s+eq\s+["']?([^"']+)["']?\]/i);
      if (memberMatch) {
        result.removeMembers.push(memberMatch[1]);
      }
    }
  }

  return result;
}

module.exports = {
  SCIM_USER_SCHEMA,
  SCIM_GROUP_SCHEMA,
  SCIM_LIST_SCHEMA,
  SCIM_ERROR_SCHEMA,
  SCIM_PATCH_SCHEMA,
  generateScimBearerToken,
  hashScimBearerToken,
  verifyScimBearerToken,
  getServiceProviderConfig,
  getSchemas,
  formatScimUser,
  formatScimGroup,
  formatScimList,
  formatScimError,
  parseScimFilter,
  parseScimPatchOperations
};
