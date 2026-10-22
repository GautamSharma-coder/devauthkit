// server/stores/memorySsoStore.js
const { randomUUID } = require("../utils/webCrypto");
const { generateDomainVerificationToken } = require("../core/ssoService");

class MemorySsoStore {
  constructor() {
    this.connections = new Map();
    this.assertions = new Map(); // assertionId -> expiresAt
    this.directories = new Map();
    this.userMappings = new Map();
    this.groupMappings = new Map();
  }

  // ==========================================
  // SSO Connection Management
  // ==========================================

  async createConnection(data) {
    if (!data.orgId) throw new Error("orgId is required for SSO connection");
    if (!data.name) throw new Error("name is required for SSO connection");

    const id = data.id || `conn_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const now = Date.now();
    const domains = Array.isArray(data.domains)
      ? data.domains.map((d) => d.toLowerCase().trim().replace(/^@/, ""))
      : [];

    const connection = {
      id,
      orgId: String(data.orgId),
      name: String(data.name).trim(),
      type: data.type === "OIDC" ? "OIDC" : "SAML",
      domains,
      domainVerified: Boolean(data.domainVerified),
      domainVerificationToken: data.domainVerificationToken || generateDomainVerificationToken(),
      idpEntityId: data.idpEntityId || null,
      idpSsoUrl: data.idpSsoUrl || null,
      idpSloUrl: data.idpSloUrl || null,
      idpCertificates: Array.isArray(data.idpCertificates) ? data.idpCertificates : (data.idpCertificates ? [data.idpCertificates] : []),
      spEntityId: data.spEntityId || `https://api.devauthkit.internal/auth/sso/saml/${id}`,
      spAcsUrl: data.spAcsUrl || `https://api.devauthkit.internal/auth/sso/saml/${id}/acs`,
      oidcIssuer: data.oidcIssuer || null,
      oidcClientId: data.oidcClientId || null,
      oidcClientSecret: data.oidcClientSecret || null,
      oidcDiscoveryUrl: data.oidcDiscoveryUrl || null,
      defaultRole: data.defaultRole || "member",
      attributeMapping: data.attributeMapping || {},
      active: data.active !== false,
      createdAt: now,
      updatedAt: now
    };

    this.connections.set(id, connection);
    return { ...connection };
  }

  async getConnection(id) {
    const conn = this.connections.get(id);
    return conn ? { ...conn } : null;
  }

  async listConnections(orgId) {
    const results = [];
    for (const conn of this.connections.values()) {
      if (!orgId || conn.orgId === String(orgId)) {
        results.push({ ...conn });
      }
    }
    return results;
  }

  async getConnectionByDomain(domain) {
    if (!domain) return null;
    const cleanDomain = domain.toLowerCase().trim().replace(/^@/, "");
    for (const conn of this.connections.values()) {
      if (conn.active && conn.domains.includes(cleanDomain)) {
        return { ...conn };
      }
    }
    return null;
  }

  async updateConnection(id, updates = {}) {
    const conn = this.connections.get(id);
    if (!conn) return null;

    const domains = updates.domains !== undefined
      ? (Array.isArray(updates.domains) ? updates.domains.map((d) => d.toLowerCase().trim().replace(/^@/, "")) : [])
      : conn.domains;

    const updated = {
      ...conn,
      ...updates,
      domains,
      updatedAt: Date.now()
    };

    this.connections.set(id, updated);
    return { ...updated };
  }

  async deleteConnection(id) {
    return this.connections.delete(id);
  }

  async verifyDomain(id) {
    const conn = this.connections.get(id);
    if (!conn) return null;
    conn.domainVerified = true;
    conn.updatedAt = Date.now();
    this.connections.set(id, conn);
    return { ...conn };
  }

  // ==========================================
  // Anti-Replay Assertion Storage
  // ==========================================

  async recordAssertion(assertionId, ttlSeconds = 600) {
    this.assertions.set(assertionId, Date.now() + ttlSeconds * 1000);
    return true;
  }

  async isAssertionReplayed(assertionId) {
    const expiry = this.assertions.get(assertionId);
    if (!expiry) return false;
    if (Date.now() > expiry) {
      this.assertions.delete(assertionId);
      return false;
    }
    return true;
  }

  // ==========================================
  // SCIM 2.0 Directory Management
  // ==========================================

  async createDirectory(data) {
    if (!data.orgId) throw new Error("orgId is required for SCIM directory");
    if (!data.bearerTokenHash) throw new Error("bearerTokenHash is required for SCIM directory");

    const id = data.id || `scim_dir_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const now = Date.now();
    const directory = {
      id,
      orgId: String(data.orgId),
      bearerTokenHash: data.bearerTokenHash,
      scimBaseUrl: data.scimBaseUrl || `/scim/v2`,
      active: data.active !== false,
      lastSyncedAt: null,
      createdAt: now,
      updatedAt: now
    };

    this.directories.set(id, directory);
    return { ...directory };
  }

  async getDirectory(id) {
    const dir = this.directories.get(id);
    return dir ? { ...dir } : null;
  }

  async getDirectoryByTokenHash(tokenHash) {
    for (const dir of this.directories.values()) {
      if (dir.bearerTokenHash === tokenHash && dir.active) {
        return { ...dir };
      }
    }
    return null;
  }

  async listDirectories(orgId) {
    const results = [];
    for (const dir of this.directories.values()) {
      if (!orgId || dir.orgId === String(orgId)) {
        results.push({ ...dir });
      }
    }
    return results;
  }

  async updateDirectory(id, updates = {}) {
    const dir = this.directories.get(id);
    if (!dir) return null;
    const updated = { ...dir, ...updates, updatedAt: Date.now() };
    this.directories.set(id, updated);
    return { ...updated };
  }

  async deleteDirectory(id) {
    return this.directories.delete(id);
  }

  // ==========================================
  // SCIM User Mappings
  // ==========================================

  async createScimUserMapping(data) {
    const id = data.id || `scim_usr_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const now = Date.now();
    const mapping = {
      id,
      directoryId: String(data.directoryId),
      orgId: String(data.orgId),
      userId: String(data.userId),
      idpExternalId: String(data.idpExternalId),
      attributes: data.attributes || {},
      active: data.active !== false,
      createdAt: now,
      updatedAt: now
    };
    this.userMappings.set(id, mapping);
    return { ...mapping };
  }

  async getScimUserMapping(directoryId, idpExternalId) {
    for (const mapping of this.userMappings.values()) {
      if (mapping.directoryId === String(directoryId) && mapping.idpExternalId === String(idpExternalId)) {
        return { ...mapping };
      }
    }
    return null;
  }

  async getScimUserMappingByUserId(directoryId, userId) {
    for (const mapping of this.userMappings.values()) {
      if (mapping.directoryId === String(directoryId) && mapping.userId === String(userId)) {
        return { ...mapping };
      }
    }
    return null;
  }

  async listScimUserMappings(directoryId) {
    const results = [];
    for (const mapping of this.userMappings.values()) {
      if (mapping.directoryId === String(directoryId)) {
        results.push({ ...mapping });
      }
    }
    return results;
  }

  async updateScimUserMapping(id, updates = {}) {
    const mapping = this.userMappings.get(id);
    if (!mapping) return null;
    const updated = { ...mapping, ...updates, updatedAt: Date.now() };
    this.userMappings.set(id, updated);
    return { ...updated };
  }

  async deleteScimUserMapping(id) {
    return this.userMappings.delete(id);
  }

  // ==========================================
  // SCIM Group Mappings
  // ==========================================

  async createScimGroupMapping(data) {
    const id = data.id || `scim_grp_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const mapping = {
      id,
      directoryId: String(data.directoryId),
      orgId: String(data.orgId),
      idpGroupId: String(data.idpGroupId),
      groupName: String(data.groupName),
      mappedOrgRole: data.mappedOrgRole || "member",
      members: Array.isArray(data.members) ? data.members.map(String) : [],
      createdAt: Date.now()
    };
    this.groupMappings.set(id, mapping);
    return { ...mapping };
  }

  async getScimGroupMapping(directoryId, idpGroupId) {
    for (const mapping of this.groupMappings.values()) {
      if (mapping.directoryId === String(directoryId) && mapping.idpGroupId === String(idpGroupId)) {
        return { ...mapping };
      }
    }
    return null;
  }

  async getScimGroupMappingById(id) {
    const mapping = this.groupMappings.get(id);
    return mapping ? { ...mapping } : null;
  }

  async listScimGroupMappings(directoryId) {
    const results = [];
    for (const mapping of this.groupMappings.values()) {
      if (mapping.directoryId === String(directoryId)) {
        results.push({ ...mapping });
      }
    }
    return results;
  }

  async updateScimGroupMapping(id, updates = {}) {
    const mapping = this.groupMappings.get(id);
    if (!mapping) return null;
    const updated = {
      ...mapping,
      ...updates,
      members: Array.isArray(updates.members) ? updates.members.map(String) : mapping.members
    };
    this.groupMappings.set(id, updated);
    return { ...updated };
  }

  async deleteScimGroupMapping(id) {
    return this.groupMappings.delete(id);
  }
}

module.exports = { MemorySsoStore };
