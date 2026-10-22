// server/stores/cloudflareD1OrganizationStore.js
const { randomUUID } = require("../utils/webCrypto");
const { slugify } = require("../core/organizationService");

function validateDatabase(database) {
  if (!database || typeof database.prepare !== "function" || typeof database.batch !== "function") {
    throw new TypeError("CloudflareD1OrganizationStore requires a D1 database with prepare and batch methods");
  }
}

function validatePrefix(value) {
  if (typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new TypeError("CloudflareD1OrganizationStore tablePrefix must be a valid SQL identifier prefix");
  }
  return value;
}

class CloudflareD1OrganizationStore {
  constructor(database, options = {}) {
    validateDatabase(database);
    this.database = database;
    this.tablePrefix = validatePrefix(options.tablePrefix ?? "devauthkit_");
  }

  get orgsTable() {
    return `${this.tablePrefix}organizations`;
  }

  get membersTable() {
    return `${this.tablePrefix}organization_members`;
  }

  get invitationsTable() {
    return `${this.tablePrefix}organization_invitations`;
  }

  async createOrg({ name, slug, logoUrl = null, metadata = null, ownerUserId, ownerEmail = null }) {
    if (!name || typeof name !== "string") {
      throw new TypeError("Organization name must be a non-empty string");
    }
    if (!ownerUserId) {
      throw new TypeError("Organization creator/owner userId is required");
    }

    const orgId = `org_${randomUUID()}`;
    let resolvedSlug = slugify(slug || name);
    if (!resolvedSlug) resolvedSlug = `workspace-${Date.now().toString(36)}`;

    // Ensure slug uniqueness
    const existing = await this.database
      .prepare(`SELECT id FROM ${this.orgsTable} WHERE slug = ?`)
      .bind(resolvedSlug)
      .first();

    if (existing) {
      resolvedSlug = `${resolvedSlug}-${Math.random().toString(36).slice(2, 6)}`;
    }

    const now = Date.now();
    const memberId = `mem_${randomUUID()}`;
    const serializedMetadata = metadata ? JSON.stringify(metadata) : null;

    // Use atomic D1 batch transaction to create org and initial owner member
    await this.database.batch([
      this.database
        .prepare(`INSERT INTO ${this.orgsTable} (id, name, slug, logo_url, metadata, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .bind(orgId, name.trim(), resolvedSlug, logoUrl, serializedMetadata, now, now),
      this.database
        .prepare(`INSERT INTO ${this.membersTable} (id, org_id, user_id, email, role, joined_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .bind(memberId, orgId, String(ownerUserId), ownerEmail, "owner", now, now)
    ]);

    const org = {
      id: orgId,
      name: name.trim(),
      slug: resolvedSlug,
      logoUrl,
      metadata,
      createdAt: now,
      updatedAt: now
    };

    const member = {
      id: memberId,
      orgId,
      userId: String(ownerUserId),
      email: ownerEmail,
      role: "owner",
      joinedAt: now,
      updatedAt: now
    };

    return { organization: org, member };
  }

  async getOrgById(orgId) {
    if (!orgId) return null;
    const row = await this.database
      .prepare(`SELECT * FROM ${this.orgsTable} WHERE id = ?`)
      .bind(String(orgId))
      .first();

    if (!row) return null;
    return {
      id: row.id,
      name: row.name,
      slug: row.slug,
      logoUrl: row.logo_url,
      metadata: row.metadata ? JSON.parse(row.metadata) : null,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  async getOrgBySlug(slug) {
    if (!slug) return null;
    const row = await this.database
      .prepare(`SELECT * FROM ${this.orgsTable} WHERE slug = ?`)
      .bind(String(slug).toLowerCase().trim())
      .first();

    if (!row) return null;
    return {
      id: row.id,
      name: row.name,
      slug: row.slug,
      logoUrl: row.logo_url,
      metadata: row.metadata ? JSON.parse(row.metadata) : null,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  async updateOrg(orgId, updates = {}) {
    const current = await this.getOrgById(orgId);
    if (!current) return null;

    let newSlug = current.slug;
    if (updates.slug && typeof updates.slug === "string") {
      newSlug = slugify(updates.slug);
      if (newSlug !== current.slug) {
        const existing = await this.database
          .prepare(`SELECT id FROM ${this.orgsTable} WHERE slug = ? AND id != ?`)
          .bind(newSlug, orgId)
          .first();
        if (existing) {
          throw new Error(`Organization slug "${newSlug}" is already taken`);
        }
      }
    }

    const name = updates.name !== undefined ? updates.name.trim() : current.name;
    const logoUrl = updates.logoUrl !== undefined ? updates.logoUrl : current.logoUrl;
    const metadata = updates.metadata !== undefined ? updates.metadata : current.metadata;
    const now = Date.now();

    await this.database
      .prepare(`UPDATE ${this.orgsTable} SET name = ?, slug = ?, logo_url = ?, metadata = ?, updated_at = ? WHERE id = ?`)
      .bind(name, newSlug, logoUrl, metadata ? JSON.stringify(metadata) : null, now, orgId)
      .run();

    return {
      id: orgId,
      name,
      slug: newSlug,
      logoUrl,
      metadata,
      createdAt: current.createdAt,
      updatedAt: now
    };
  }

  async deleteOrg(orgId) {
    if (!orgId) return false;
    const id = String(orgId);

    // Cascading delete using D1 batch transaction
    await this.database.batch([
      this.database.prepare(`DELETE FROM ${this.invitationsTable} WHERE org_id = ?`).bind(id),
      this.database.prepare(`DELETE FROM ${this.membersTable} WHERE org_id = ?`).bind(id),
      this.database.prepare(`DELETE FROM ${this.orgsTable} WHERE id = ?`).bind(id)
    ]);
    return true;
  }

  async listUserOrgs(userId) {
    if (!userId) return [];
    const rows = await this.database
      .prepare(`
        SELECT 
          o.id as org_id, o.name as org_name, o.slug as org_slug, o.logo_url, o.metadata, o.created_at as org_created_at, o.updated_at as org_updated_at,
          m.id as member_id, m.role as member_role, m.joined_at, m.email as member_email
        FROM ${this.membersTable} m
        JOIN ${this.orgsTable} o ON m.org_id = o.id
        WHERE m.user_id = ?
        ORDER BY m.joined_at DESC
      `)
      .bind(String(userId))
      .all();

    return (rows.results || []).map((row) => ({
      id: row.org_id,
      name: row.org_name,
      slug: row.org_slug,
      logoUrl: row.logo_url,
      metadata: row.metadata ? JSON.parse(row.metadata) : null,
      createdAt: row.org_created_at,
      updatedAt: row.org_updated_at,
      organization: {
        id: row.org_id,
        name: row.org_name,
        slug: row.org_slug,
        logoUrl: row.logo_url,
        metadata: row.metadata ? JSON.parse(row.metadata) : null,
        createdAt: row.org_created_at,
        updatedAt: row.org_updated_at
      },
      member: {
        id: row.member_id,
        orgId: row.org_id,
        userId: String(userId),
        email: row.member_email,
        role: row.member_role,
        joinedAt: row.joined_at
      },
      role: row.member_role,
      joinedAt: row.joined_at
    }));
  }

  async getMember(orgId, userId) {
    if (!orgId || !userId) return null;
    const row = await this.database
      .prepare(`SELECT * FROM ${this.membersTable} WHERE org_id = ? AND user_id = ?`)
      .bind(String(orgId), String(userId))
      .first();

    if (!row) return null;
    return {
      id: row.id,
      orgId: row.org_id,
      userId: row.user_id,
      email: row.email,
      role: row.role,
      joinedAt: row.joined_at,
      updatedAt: row.updated_at
    };
  }

  async listMembers(orgId) {
    if (!orgId) return [];
    const rows = await this.database
      .prepare(`SELECT * FROM ${this.membersTable} WHERE org_id = ? ORDER BY joined_at ASC`)
      .bind(String(orgId))
      .all();

    return (rows.results || []).map((row) => ({
      id: row.id,
      orgId: row.org_id,
      userId: row.user_id,
      email: row.email,
      role: row.role,
      joinedAt: row.joined_at,
      updatedAt: row.updated_at
    }));
  }

  async addMember(orgId, userId, role = "member", email = null) {
    const existing = await this.getMember(orgId, userId);
    if (existing) {
      throw new Error("User is already a member of this organization");
    }

    const memberId = `mem_${randomUUID()}`;
    const now = Date.now();

    await this.database
      .prepare(`INSERT INTO ${this.membersTable} (id, org_id, user_id, email, role, joined_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .bind(memberId, String(orgId), String(userId), email, role, now, now)
      .run();

    return {
      id: memberId,
      orgId: String(orgId),
      userId: String(userId),
      email,
      role,
      joinedAt: now,
      updatedAt: now
    };
  }

  async updateMemberRole(orgId, userId, role) {
    const member = await this.getMember(orgId, userId);
    if (!member) return null;

    const now = Date.now();
    await this.database
      .prepare(`UPDATE ${this.membersTable} SET role = ?, updated_at = ? WHERE org_id = ? AND user_id = ?`)
      .bind(role, now, String(orgId), String(userId))
      .run();

    return {
      ...member,
      role,
      updatedAt: now
    };
  }

  async removeMember(orgId, userId) {
    const member = await this.getMember(orgId, userId);
    if (!member) return false;

    await this.database
      .prepare(`DELETE FROM ${this.membersTable} WHERE org_id = ? AND user_id = ?`)
      .bind(String(orgId), String(userId))
      .run();
    return true;
  }

  async createInvitation({ orgId, email, role = "member", inviterId, tokenHash, expiresAt }) {
    if (!orgId || !email || !tokenHash) {
      throw new TypeError("createInvitation requires orgId, email, and tokenHash");
    }

    const inviteId = `inv_${randomUUID()}`;
    const now = Date.now();

    await this.database
      .prepare(`INSERT INTO ${this.invitationsTable} (id, org_id, email, role, token_hash, inviter_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(inviteId, String(orgId), String(email).toLowerCase().trim(), role, tokenHash, String(inviterId), Number(expiresAt), now)
      .run();

    return {
      id: inviteId,
      orgId: String(orgId),
      email: String(email).toLowerCase().trim(),
      role,
      inviterId: String(inviterId),
      tokenHash,
      expiresAt: Number(expiresAt),
      createdAt: now
    };
  }

  async getInvitationByTokenHash(tokenHash) {
    if (!tokenHash) return null;
    const now = Date.now();
    const row = await this.database
      .prepare(`SELECT * FROM ${this.invitationsTable} WHERE token_hash = ? AND expires_at > ?`)
      .bind(tokenHash, now)
      .first();

    if (!row) return null;
    return {
      id: row.id,
      orgId: row.org_id,
      email: row.email,
      role: row.role,
      inviterId: row.inviter_id,
      tokenHash: row.token_hash,
      expiresAt: row.expires_at,
      createdAt: row.created_at
    };
  }

  async listInvitations(orgId) {
    if (!orgId) return [];
    const now = Date.now();
    const rows = await this.database
      .prepare(`SELECT * FROM ${this.invitationsTable} WHERE org_id = ? AND expires_at > ? ORDER BY created_at DESC`)
      .bind(String(orgId), now)
      .all();

    return (rows.results || []).map((row) => ({
      id: row.id,
      orgId: row.org_id,
      email: row.email,
      role: row.role,
      inviterId: row.inviter_id,
      expiresAt: row.expires_at,
      createdAt: row.created_at
    }));
  }

  async deleteInvitation(inviteId) {
    if (!inviteId) return false;
    await this.database
      .prepare(`DELETE FROM ${this.invitationsTable} WHERE id = ?`)
      .bind(String(inviteId))
      .run();
    return true;
  }
}

module.exports = { CloudflareD1OrganizationStore };
