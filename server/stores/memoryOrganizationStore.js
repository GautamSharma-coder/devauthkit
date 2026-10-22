// server/stores/memoryOrganizationStore.js
const { randomUUID } = require("../utils/webCrypto");
const { slugify } = require("../core/organizationService");

class MemoryOrganizationStore {
  constructor() {
    this.orgs = new Map();
    this.slugToId = new Map();
    this.members = new Map(); // memberId -> member
    this.orgUserToMemberId = new Map(); // `${orgId}:${userId}` -> memberId
    this.invitations = new Map(); // invitationId -> invitation
    this.tokenHashToInviteId = new Map(); // tokenHash -> invitationId
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

    // Ensure unique slug
    let counter = 1;
    let candidateSlug = resolvedSlug;
    while (this.slugToId.has(candidateSlug)) {
      candidateSlug = `${resolvedSlug}-${counter++}`;
    }
    resolvedSlug = candidateSlug;

    const now = Date.now();
    const org = {
      id: orgId,
      name: name.trim(),
      slug: resolvedSlug,
      logoUrl: logoUrl || null,
      metadata: metadata || null,
      createdAt: now,
      updatedAt: now
    };

    this.orgs.set(orgId, org);
    this.slugToId.set(resolvedSlug, orgId);

    // Create initial owner membership
    const memberId = `mem_${randomUUID()}`;
    const member = {
      id: memberId,
      orgId,
      userId: String(ownerUserId),
      email: ownerEmail || null,
      role: "owner",
      joinedAt: now,
      updatedAt: now
    };

    this.members.set(memberId, member);
    this.orgUserToMemberId.set(`${orgId}:${ownerUserId}`, memberId);

    return { organization: { ...org }, member: { ...member } };
  }

  async getOrgById(orgId) {
    if (!orgId) return null;
    const org = this.orgs.get(String(orgId));
    return org ? { ...org } : null;
  }

  async getOrgBySlug(slug) {
    if (!slug) return null;
    const orgId = this.slugToId.get(String(slug).toLowerCase().trim());
    if (!orgId) return null;
    return this.getOrgById(orgId);
  }

  async updateOrg(orgId, updates = {}) {
    const org = this.orgs.get(String(orgId));
    if (!org) return null;

    if (updates.name && typeof updates.name === "string") {
      org.name = updates.name.trim();
    }
    if (updates.slug && typeof updates.slug === "string") {
      const newSlug = slugify(updates.slug);
      if (newSlug && newSlug !== org.slug) {
        if (this.slugToId.has(newSlug)) {
          throw new Error(`Organization slug "${newSlug}" is already taken`);
        }
        this.slugToId.delete(org.slug);
        org.slug = newSlug;
        this.slugToId.set(newSlug, org.id);
      }
    }
    if (updates.logoUrl !== undefined) {
      org.logoUrl = updates.logoUrl;
    }
    if (updates.metadata !== undefined) {
      org.metadata = updates.metadata;
    }
    org.updatedAt = Date.now();
    return { ...org };
  }

  async deleteOrg(orgId) {
    const org = this.orgs.get(String(orgId));
    if (!org) return false;

    // Delete members
    for (const [key, memberId] of this.orgUserToMemberId.entries()) {
      if (key.startsWith(`${orgId}:`)) {
        this.members.delete(memberId);
        this.orgUserToMemberId.delete(key);
      }
    }

    // Delete invitations
    for (const [inviteId, invite] of this.invitations.entries()) {
      if (invite.orgId === orgId) {
        this.tokenHashToInviteId.delete(invite.tokenHash);
        this.invitations.delete(inviteId);
      }
    }

    this.slugToId.delete(org.slug);
    this.orgs.delete(String(orgId));
    return true;
  }

  async listUserOrgs(userId) {
    if (!userId) return [];
    const uid = String(userId);
    const results = [];

    for (const member of this.members.values()) {
      if (member.userId === uid) {
        const org = this.orgs.get(member.orgId);
        if (org) {
          results.push({
            ...org,
            organization: { ...org },
            member: { ...member },
            role: member.role,
            joinedAt: member.joinedAt
          });
        }
      }
    }
    return results;
  }

  async getMember(orgId, userId) {
    if (!orgId || !userId) return null;
    const memberId = this.orgUserToMemberId.get(`${orgId}:${userId}`);
    if (!memberId) return null;
    const member = this.members.get(memberId);
    return member ? { ...member } : null;
  }

  async listMembers(orgId) {
    if (!orgId) return [];
    const results = [];
    for (const member of this.members.values()) {
      if (member.orgId === String(orgId)) {
        results.push({ ...member });
      }
    }
    return results;
  }

  async addMember(orgId, userId, role = "member", email = null) {
    const existing = await this.getMember(orgId, userId);
    if (existing) {
      throw new Error("User is already a member of this organization");
    }

    const memberId = `mem_${randomUUID()}`;
    const now = Date.now();
    const member = {
      id: memberId,
      orgId: String(orgId),
      userId: String(userId),
      email: email || null,
      role: role || "member",
      joinedAt: now,
      updatedAt: now
    };

    this.members.set(memberId, member);
    this.orgUserToMemberId.set(`${orgId}:${userId}`, memberId);
    return { ...member };
  }

  async updateMemberRole(orgId, userId, role) {
    const member = await this.getMember(orgId, userId);
    if (!member) return null;

    const stored = this.members.get(member.id);
    stored.role = role;
    stored.updatedAt = Date.now();
    return { ...stored };
  }

  async removeMember(orgId, userId) {
    const member = await this.getMember(orgId, userId);
    if (!member) return false;

    this.members.delete(member.id);
    this.orgUserToMemberId.delete(`${orgId}:${userId}`);
    return true;
  }

  async createInvitation({ orgId, email, role = "member", inviterId, tokenHash, expiresAt }) {
    if (!orgId || !email || !tokenHash) {
      throw new TypeError("createInvitation requires orgId, email, and tokenHash");
    }

    const inviteId = `inv_${randomUUID()}`;
    const invitation = {
      id: inviteId,
      orgId: String(orgId),
      email: String(email).toLowerCase().trim(),
      role: role || "member",
      inviterId: String(inviterId),
      tokenHash,
      expiresAt: Number(expiresAt),
      createdAt: Date.now()
    };

    this.invitations.set(inviteId, invitation);
    this.tokenHashToInviteId.set(tokenHash, inviteId);
    return { ...invitation };
  }

  async getInvitationByTokenHash(tokenHash) {
    if (!tokenHash) return null;
    const inviteId = this.tokenHashToInviteId.get(tokenHash);
    if (!inviteId) return null;
    const invitation = this.invitations.get(inviteId);
    if (!invitation) return null;

    if (invitation.expiresAt <= Date.now()) {
      return null; // Expired
    }
    return { ...invitation };
  }

  async listInvitations(orgId) {
    if (!orgId) return [];
    const now = Date.now();
    const results = [];
    for (const invite of this.invitations.values()) {
      if (invite.orgId === String(orgId) && invite.expiresAt > now) {
        results.push({
          id: invite.id,
          orgId: invite.orgId,
          email: invite.email,
          role: invite.role,
          inviterId: invite.inviterId,
          expiresAt: invite.expiresAt,
          createdAt: invite.createdAt
        });
      }
    }
    return results;
  }

  async deleteInvitation(inviteId) {
    const invite = this.invitations.get(String(inviteId));
    if (!invite) return false;

    this.tokenHashToInviteId.delete(invite.tokenHash);
    this.invitations.delete(String(inviteId));
    return true;
  }

  clear() {
    this.orgs.clear();
    this.slugToId.clear();
    this.members.clear();
    this.orgUserToMemberId.clear();
    this.invitations.clear();
    this.tokenHashToInviteId.clear();
  }
}

module.exports = { MemoryOrganizationStore };
