// server/stores/cloudflareD1SsoStore.js
const { randomUUID } = require("../utils/webCrypto");
const { generateDomainVerificationToken } = require("../core/ssoService");

function validateDatabase(database) {
  if (!database || typeof database.prepare !== "function" || typeof database.batch !== "function") {
    throw new TypeError("CloudflareD1SsoStore requires a D1 database with prepare and batch methods");
  }
}

function validatePrefix(value) {
  if (typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new TypeError("CloudflareD1SsoStore tablePrefix must be a valid SQL identifier prefix");
  }
  return value;
}

function mapConnectionRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    orgId: row.org_id,
    name: row.name,
    type: row.type,
    domains: JSON.parse(row.domains || "[]"),
    domainVerified: Boolean(row.domain_verified),
    domainVerificationToken: row.domain_verification_token,
    idpEntityId: row.idp_entity_id,
    idpSsoUrl: row.idp_sso_url,
    idpSloUrl: row.idp_slo_url,
    idpCertificates: JSON.parse(row.idp_certificates || "[]"),
    spEntityId: row.sp_entity_id,
    spAcsUrl: row.sp_acs_url,
    oidcIssuer: row.oidc_issuer,
    oidcClientId: row.oidc_client_id,
    oidcClientSecret: row.oidc_client_secret,
    oidcDiscoveryUrl: row.oidc_discovery_url,
    defaultRole: row.default_role || "member",
    attributeMapping: JSON.parse(row.attribute_mapping || "{}"),
    active: Boolean(row.active),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function mapDirectoryRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    orgId: row.org_id,
    bearerTokenHash: row.bearer_token_hash,
    scimBaseUrl: row.scim_base_url,
    active: Boolean(row.active),
    lastSyncedAt: row.last_synced_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function mapUserMappingRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    directoryId: row.directory_id,
    orgId: row.org_id,
    userId: row.user_id,
    idpExternalId: row.idp_external_id,
    attributes: JSON.parse(row.attributes || "{}"),
    active: Boolean(row.active),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function mapGroupMappingRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    directoryId: row.directory_id,
    orgId: row.org_id,
    idpGroupId: row.idp_group_id,
    groupName: row.group_name,
    mappedOrgRole: row.mapped_org_role,
    members: JSON.parse(row.members || "[]"),
    createdAt: row.created_at
  };
}

class CloudflareD1SsoStore {
  constructor(database, options = {}) {
    validateDatabase(database);
    this.database = database;
    this.tablePrefix = validatePrefix(options.tablePrefix ?? "devauthkit_");
  }

  get connectionsTable() {
    return `${this.tablePrefix}sso_connections`;
  }

  get assertionsTable() {
    return `${this.tablePrefix}saml_assertion_replays`;
  }

  get directoriesTable() {
    return `${this.tablePrefix}scim_directories`;
  }

  get userMappingsTable() {
    return `${this.tablePrefix}scim_user_mappings`;
  }

  get groupMappingsTable() {
    return `${this.tablePrefix}scim_group_mappings`;
  }

  async createTables() {
    await this.database.batch([
      this.database.prepare(`
        CREATE TABLE IF NOT EXISTS ${this.connectionsTable} (
          id TEXT PRIMARY KEY,
          org_id TEXT NOT NULL,
          name TEXT NOT NULL,
          type TEXT NOT NULL,
          domains TEXT NOT NULL,
          domain_verified INTEGER NOT NULL DEFAULT 0,
          domain_verification_token TEXT NOT NULL,
          idp_entity_id TEXT,
          idp_sso_url TEXT,
          idp_slo_url TEXT,
          idp_certificates TEXT,
          sp_entity_id TEXT NOT NULL,
          sp_acs_url TEXT NOT NULL,
          oidc_issuer TEXT,
          oidc_client_id TEXT,
          oidc_client_secret TEXT,
          oidc_discovery_url TEXT,
          default_role TEXT NOT NULL DEFAULT 'member',
          attribute_mapping TEXT,
          active INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        )
      `),
      this.database.prepare(`
        CREATE TABLE IF NOT EXISTS ${this.assertionsTable} (
          assertion_id TEXT PRIMARY KEY,
          expires_at INTEGER NOT NULL
        )
      `),
      this.database.prepare(`
        CREATE TABLE IF NOT EXISTS ${this.directoriesTable} (
          id TEXT PRIMARY KEY,
          org_id TEXT NOT NULL,
          bearer_token_hash TEXT NOT NULL,
          scim_base_url TEXT NOT NULL,
          active INTEGER NOT NULL DEFAULT 1,
          last_synced_at INTEGER,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        )
      `),
      this.database.prepare(`
        CREATE TABLE IF NOT EXISTS ${this.userMappingsTable} (
          id TEXT PRIMARY KEY,
          directory_id TEXT NOT NULL,
          org_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          idp_external_id TEXT NOT NULL,
          attributes TEXT,
          active INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        )
      `),
      this.database.prepare(`
        CREATE TABLE IF NOT EXISTS ${this.groupMappingsTable} (
          id TEXT PRIMARY KEY,
          directory_id TEXT NOT NULL,
          org_id TEXT NOT NULL,
          idp_group_id TEXT NOT NULL,
          group_name TEXT NOT NULL,
          mapped_org_role TEXT NOT NULL DEFAULT 'member',
          members TEXT,
          created_at INTEGER NOT NULL
        )
      `),
      this.database.prepare(`
        CREATE INDEX IF NOT EXISTS idx_${this.tablePrefix}sso_org
        ON ${this.connectionsTable} (org_id)
      `),
      this.database.prepare(`
        CREATE INDEX IF NOT EXISTS idx_${this.tablePrefix}saml_replays_exp
        ON ${this.assertionsTable} (expires_at)
      `),
      this.database.prepare(`
        CREATE INDEX IF NOT EXISTS idx_${this.tablePrefix}scim_dir_org
        ON ${this.directoriesTable} (org_id)
      `),
      this.database.prepare(`
        CREATE INDEX IF NOT EXISTS idx_${this.tablePrefix}scim_usr_dir_ext
        ON ${this.userMappingsTable} (directory_id, idp_external_id)
      `),
      this.database.prepare(`
        CREATE INDEX IF NOT EXISTS idx_${this.tablePrefix}scim_grp_dir_idp
        ON ${this.groupMappingsTable} (directory_id, idp_group_id)
      `)
    ]);
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
    const domainVerificationToken = data.domainVerificationToken || generateDomainVerificationToken();
    const type = data.type === "OIDC" ? "OIDC" : "SAML";
    const certs = Array.isArray(data.idpCertificates)
      ? data.idpCertificates
      : (data.idpCertificates ? [data.idpCertificates] : []);

    await this.database
      .prepare(`
        INSERT INTO ${this.connectionsTable} (
          id, org_id, name, type, domains, domain_verified, domain_verification_token,
          idp_entity_id, idp_sso_url, idp_slo_url, idp_certificates,
          sp_entity_id, sp_acs_url, oidc_issuer, oidc_client_id, oidc_client_secret,
          oidc_discovery_url, default_role, attribute_mapping, active, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        id,
        String(data.orgId),
        String(data.name).trim(),
        type,
        JSON.stringify(domains),
        data.domainVerified ? 1 : 0,
        domainVerificationToken,
        data.idpEntityId || null,
        data.idpSsoUrl || null,
        data.idpSloUrl || null,
        JSON.stringify(certs),
        data.spEntityId || `https://api.devauthkit.internal/auth/sso/saml/${id}`,
        data.spAcsUrl || `https://api.devauthkit.internal/auth/sso/saml/${id}/acs`,
        data.oidcIssuer || null,
        data.oidcClientId || null,
        data.oidcClientSecret || null,
        data.oidcDiscoveryUrl || null,
        data.defaultRole || "member",
        JSON.stringify(data.attributeMapping || {}),
        data.active !== false ? 1 : 0,
        now,
        now
      )
      .run();

    return this.getConnection(id);
  }

  async getConnection(id) {
    const row = await this.database
      .prepare(`SELECT * FROM ${this.connectionsTable} WHERE id = ?`)
      .bind(id)
      .first();
    return mapConnectionRow(row);
  }

  async listConnections(orgId) {
    let query = `SELECT * FROM ${this.connectionsTable}`;
    let params = [];
    if (orgId) {
      query += ` WHERE org_id = ?`;
      params.push(String(orgId));
    }
    query += ` ORDER BY created_at DESC`;

    const result = await this.database.prepare(query).bind(...params).all();
    return (result.results || []).map(mapConnectionRow);
  }

  async getConnectionByDomain(domain) {
    if (!domain) return null;
    const cleanDomain = domain.toLowerCase().trim().replace(/^@/, "");

    const result = await this.database
      .prepare(`SELECT * FROM ${this.connectionsTable} WHERE active = 1`)
      .all();

    for (const row of result.results || []) {
      const conn = mapConnectionRow(row);
      if (conn && conn.domains.includes(cleanDomain)) {
        return conn;
      }
    }
    return null;
  }

  async updateConnection(id, updates = {}) {
    const existing = await this.getConnection(id);
    if (!existing) return null;

    const fields = [];
    const values = [];

    if (updates.name !== undefined) {
      fields.push("name = ?");
      values.push(String(updates.name).trim());
    }
    if (updates.domains !== undefined) {
      const domains = Array.isArray(updates.domains)
        ? updates.domains.map((d) => d.toLowerCase().trim().replace(/^@/, ""))
        : [];
      fields.push("domains = ?");
      values.push(JSON.stringify(domains));
    }
    if (updates.domainVerified !== undefined) {
      fields.push("domain_verified = ?");
      values.push(updates.domainVerified ? 1 : 0);
    }
    if (updates.idpEntityId !== undefined) {
      fields.push("idp_entity_id = ?");
      values.push(updates.idpEntityId);
    }
    if (updates.idpSsoUrl !== undefined) {
      fields.push("idp_sso_url = ?");
      values.push(updates.idpSsoUrl);
    }
    if (updates.idpSloUrl !== undefined) {
      fields.push("idp_slo_url = ?");
      values.push(updates.idpSloUrl);
    }
    if (updates.idpCertificates !== undefined) {
      const certs = Array.isArray(updates.idpCertificates)
        ? updates.idpCertificates
        : (updates.idpCertificates ? [updates.idpCertificates] : []);
      fields.push("idp_certificates = ?");
      values.push(JSON.stringify(certs));
    }
    if (updates.defaultRole !== undefined) {
      fields.push("default_role = ?");
      values.push(updates.defaultRole);
    }
    if (updates.attributeMapping !== undefined) {
      fields.push("attribute_mapping = ?");
      values.push(JSON.stringify(updates.attributeMapping));
    }
    if (updates.active !== undefined) {
      fields.push("active = ?");
      values.push(updates.active ? 1 : 0);
    }

    fields.push("updated_at = ?");
    values.push(Date.now());
    values.push(id);

    await this.database
      .prepare(`UPDATE ${this.connectionsTable} SET ${fields.join(", ")} WHERE id = ?`)
      .bind(...values)
      .run();

    return this.getConnection(id);
  }

  async deleteConnection(id) {
    const result = await this.database
      .prepare(`DELETE FROM ${this.connectionsTable} WHERE id = ?`)
      .bind(id)
      .run();
    return (result.meta?.changes ?? 0) > 0;
  }

  async verifyDomain(id) {
    await this.database
      .prepare(`UPDATE ${this.connectionsTable} SET domain_verified = 1, updated_at = ? WHERE id = ?`)
      .bind(Date.now(), id)
      .run();
    return this.getConnection(id);
  }

  // ==========================================
  // Anti-Replay Assertion Storage
  // ==========================================

  async recordAssertion(assertionId, ttlSeconds = 600) {
    const expiresAt = Date.now() + ttlSeconds * 1000;
    await this.database
      .prepare(`INSERT OR REPLACE INTO ${this.assertionsTable} (assertion_id, expires_at) VALUES (?, ?)`)
      .bind(assertionId, expiresAt)
      .run();
    return true;
  }

  async isAssertionReplayed(assertionId) {
    const row = await this.database
      .prepare(`SELECT expires_at FROM ${this.assertionsTable} WHERE assertion_id = ?`)
      .bind(assertionId)
      .first();

    if (!row) return false;
    if (Date.now() > row.expires_at) {
      await this.database
        .prepare(`DELETE FROM ${this.assertionsTable} WHERE assertion_id = ?`)
        .bind(assertionId)
        .run();
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

    await this.database
      .prepare(`
        INSERT INTO ${this.directoriesTable} (id, org_id, bearer_token_hash, scim_base_url, active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        id,
        String(data.orgId),
        data.bearerTokenHash,
        data.scimBaseUrl || `/scim/v2`,
        data.active !== false ? 1 : 0,
        now,
        now
      )
      .run();

    return this.getDirectory(id);
  }

  async getDirectory(id) {
    const row = await this.database
      .prepare(`SELECT * FROM ${this.directoriesTable} WHERE id = ?`)
      .bind(id)
      .first();
    return mapDirectoryRow(row);
  }

  async getDirectoryByTokenHash(tokenHash) {
    const row = await this.database
      .prepare(`SELECT * FROM ${this.directoriesTable} WHERE bearer_token_hash = ? AND active = 1`)
      .bind(tokenHash)
      .first();
    return mapDirectoryRow(row);
  }

  async listDirectories(orgId) {
    let query = `SELECT * FROM ${this.directoriesTable}`;
    let params = [];
    if (orgId) {
      query += ` WHERE org_id = ?`;
      params.push(String(orgId));
    }
    query += ` ORDER BY created_at DESC`;

    const result = await this.database.prepare(query).bind(...params).all();
    return (result.results || []).map(mapDirectoryRow);
  }

  async updateDirectory(id, updates = {}) {
    const fields = [];
    const values = [];

    if (updates.bearerTokenHash !== undefined) {
      fields.push("bearer_token_hash = ?");
      values.push(updates.bearerTokenHash);
    }
    if (updates.active !== undefined) {
      fields.push("active = ?");
      values.push(updates.active ? 1 : 0);
    }
    if (updates.lastSyncedAt !== undefined) {
      fields.push("last_synced_at = ?");
      values.push(updates.lastSyncedAt);
    }

    fields.push("updated_at = ?");
    values.push(Date.now());
    values.push(id);

    await this.database
      .prepare(`UPDATE ${this.directoriesTable} SET ${fields.join(", ")} WHERE id = ?`)
      .bind(...values)
      .run();

    return this.getDirectory(id);
  }

  async deleteDirectory(id) {
    const result = await this.database
      .prepare(`DELETE FROM ${this.directoriesTable} WHERE id = ?`)
      .bind(id)
      .run();
    return (result.meta?.changes ?? 0) > 0;
  }

  // ==========================================
  // SCIM User Mappings
  // ==========================================

  async createScimUserMapping(data) {
    const id = data.id || `scim_usr_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const now = Date.now();

    await this.database
      .prepare(`
        INSERT INTO ${this.userMappingsTable} (id, directory_id, org_id, user_id, idp_external_id, attributes, active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        id,
        String(data.directoryId),
        String(data.orgId),
        String(data.userId),
        String(data.idpExternalId),
        JSON.stringify(data.attributes || {}),
        data.active !== false ? 1 : 0,
        now,
        now
      )
      .run();

    const row = await this.database
      .prepare(`SELECT * FROM ${this.userMappingsTable} WHERE id = ?`)
      .bind(id)
      .first();
    return mapUserMappingRow(row);
  }

  async getScimUserMapping(directoryId, idpExternalId) {
    const row = await this.database
      .prepare(`SELECT * FROM ${this.userMappingsTable} WHERE directory_id = ? AND idp_external_id = ?`)
      .bind(String(directoryId), String(idpExternalId))
      .first();
    return mapUserMappingRow(row);
  }

  async getScimUserMappingByUserId(directoryId, userId) {
    const row = await this.database
      .prepare(`SELECT * FROM ${this.userMappingsTable} WHERE directory_id = ? AND user_id = ?`)
      .bind(String(directoryId), String(userId))
      .first();
    return mapUserMappingRow(row);
  }

  async listScimUserMappings(directoryId) {
    const result = await this.database
      .prepare(`SELECT * FROM ${this.userMappingsTable} WHERE directory_id = ? ORDER BY created_at DESC`)
      .bind(String(directoryId))
      .all();
    return (result.results || []).map(mapUserMappingRow);
  }

  async updateScimUserMapping(id, updates = {}) {
    const fields = [];
    const values = [];

    if (updates.active !== undefined) {
      fields.push("active = ?");
      values.push(updates.active ? 1 : 0);
    }
    if (updates.attributes !== undefined) {
      fields.push("attributes = ?");
      values.push(JSON.stringify(updates.attributes));
    }

    fields.push("updated_at = ?");
    values.push(Date.now());
    values.push(id);

    await this.database
      .prepare(`UPDATE ${this.userMappingsTable} SET ${fields.join(", ")} WHERE id = ?`)
      .bind(...values)
      .run();

    const row = await this.database
      .prepare(`SELECT * FROM ${this.userMappingsTable} WHERE id = ?`)
      .bind(id)
      .first();
    return mapUserMappingRow(row);
  }

  async deleteScimUserMapping(id) {
    const result = await this.database
      .prepare(`DELETE FROM ${this.userMappingsTable} WHERE id = ?`)
      .bind(id)
      .run();
    return (result.meta?.changes ?? 0) > 0;
  }

  // ==========================================
  // SCIM Group Mappings
  // ==========================================

  async createScimGroupMapping(data) {
    const id = data.id || `scim_grp_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const now = Date.now();
    const members = Array.isArray(data.members) ? data.members.map(String) : [];

    await this.database
      .prepare(`
        INSERT INTO ${this.groupMappingsTable} (id, directory_id, org_id, idp_group_id, group_name, mapped_org_role, members, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        id,
        String(data.directoryId),
        String(data.orgId),
        String(data.idpGroupId),
        String(data.groupName),
        data.mappedOrgRole || "member",
        JSON.stringify(members),
        now
      )
      .run();

    return this.getScimGroupMappingById(id);
  }

  async getScimGroupMapping(directoryId, idpGroupId) {
    const row = await this.database
      .prepare(`SELECT * FROM ${this.groupMappingsTable} WHERE directory_id = ? AND idp_group_id = ?`)
      .bind(String(directoryId), String(idpGroupId))
      .first();
    return mapGroupMappingRow(row);
  }

  async getScimGroupMappingById(id) {
    const row = await this.database
      .prepare(`SELECT * FROM ${this.groupMappingsTable} WHERE id = ?`)
      .bind(id)
      .first();
    return mapGroupMappingRow(row);
  }

  async listScimGroupMappings(directoryId) {
    const result = await this.database
      .prepare(`SELECT * FROM ${this.groupMappingsTable} WHERE directory_id = ? ORDER BY created_at DESC`)
      .bind(String(directoryId))
      .all();
    return (result.results || []).map(mapGroupMappingRow);
  }

  async updateScimGroupMapping(id, updates = {}) {
    const fields = [];
    const values = [];

    if (updates.groupName !== undefined) {
      fields.push("group_name = ?");
      values.push(String(updates.groupName));
    }
    if (updates.mappedOrgRole !== undefined) {
      fields.push("mapped_org_role = ?");
      values.push(updates.mappedOrgRole);
    }
    if (updates.members !== undefined) {
      const members = Array.isArray(updates.members) ? updates.members.map(String) : [];
      fields.push("members = ?");
      values.push(JSON.stringify(members));
    }

    if (fields.length === 0) return this.getScimGroupMappingById(id);

    values.push(id);

    await this.database
      .prepare(`UPDATE ${this.groupMappingsTable} SET ${fields.join(", ")} WHERE id = ?`)
      .bind(...values)
      .run();

    return this.getScimGroupMappingById(id);
  }

  async deleteScimGroupMapping(id) {
    const result = await this.database
      .prepare(`DELETE FROM ${this.groupMappingsTable} WHERE id = ?`)
      .bind(id)
      .run();
    return (result.meta?.changes ?? 0) > 0;
  }
}

module.exports = { CloudflareD1SsoStore };
