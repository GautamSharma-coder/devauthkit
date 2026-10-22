// server/controllers/organizationController.js
const config = require("../config");
const {
  DEFAULT_ORG_ROLES,
  getRolePermissions,
  canManageRole,
  generateInvitationToken,
  hashInvitationToken
} = require("../core/organizationService");
const { sendOrgInvitation } = require("../utils/mailer");
const { signJwt } = require("../utils/webCrypto");
const { emitWebhookEvent } = require("../core/webhookDispatcher");

function getOrgStore() {
  const store = config.get("organizationStore") || config.get("orgStore");
  if (!store) {
    throw new Error("Organizations feature is not enabled; please configure an organizationStore in devAuthKit options.");
  }
  return store;
}

function getUserId(user) {
  if (!user) return null;
  return user.id !== undefined && user.id !== null ? String(user.id) : user.email;
}

/**
 * POST /auth/orgs - Create a new organization
 */
async function createOrg(req, res) {
  try {
    const store = getOrgStore();
    const { name, slug, logoUrl, metadata } = req.body || {};
    if (!name || typeof name !== "string" || !name.trim()) {
      return res.status(400).json({ error: "Organization name is required" });
    }

    const userId = getUserId(req.user);
    const { organization, member } = await store.createOrg({
      name,
      slug,
      logoUrl,
      metadata,
      ownerUserId: userId,
      ownerEmail: req.user.email
    });

    emitWebhookEvent("org.created", {
      organization,
      member,
      actor: req.user
    });

    return res.status(201).json({
      success: true,
      organization,
      member
    });
  } catch (err) {
    return res.status(400).json({ error: err.message || "Failed to create organization" });
  }
}

/**
 * GET /auth/orgs - List organizations current user belongs to
 */
async function listUserOrgs(req, res) {
  try {
    const store = getOrgStore();
    const userId = getUserId(req.user);
    const organizations = await store.listUserOrgs(userId);
    return res.json({ success: true, organizations });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to list organizations" });
  }
}

/**
 * GET /auth/orgs/:id - Get organization details & members
 */
async function getOrg(req, res) {
  try {
    const store = getOrgStore();
    const orgId = req.params.id;
    const userId = getUserId(req.user);

    const member = await store.getMember(orgId, userId);
    if (!member) {
      return res.status(403).json({ error: "Forbidden: You are not a member of this organization" });
    }

    const organization = await store.getOrgById(orgId);
    if (!organization) {
      return res.status(404).json({ error: "Organization not found" });
    }

    const members = await store.listMembers(orgId);
    return res.json({
      success: true,
      organization,
      member,
      members
    });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to get organization" });
  }
}

/**
 * PATCH /auth/orgs/:id - Update organization settings
 */
async function updateOrg(req, res) {
  try {
    const store = getOrgStore();
    const orgId = req.params.id;
    const userId = getUserId(req.user);

    const member = await store.getMember(orgId, userId);
    if (!member || (member.role !== "owner" && member.role !== "admin")) {
      return res.status(403).json({ error: "Forbidden: Only owners and admins can update organization settings" });
    }

    const updated = await store.updateOrg(orgId, req.body || {});
    emitWebhookEvent("org.updated", {
      organization: updated,
      actor: req.user
    });
    return res.json({ success: true, organization: updated });
  } catch (err) {
    return res.status(400).json({ error: err.message || "Failed to update organization" });
  }
}

/**
 * DELETE /auth/orgs/:id - Permanently delete organization
 */
async function deleteOrg(req, res) {
  try {
    const store = getOrgStore();
    const orgId = req.params.id;
    const userId = getUserId(req.user);

    const member = await store.getMember(orgId, userId);
    if (!member || member.role !== "owner") {
      return res.status(403).json({ error: "Forbidden: Only the organization owner can delete the organization" });
    }

    await store.deleteOrg(orgId);
    emitWebhookEvent("org.deleted", {
      orgId,
      actor: req.user
    });
    return res.json({ success: true, message: "Organization deleted successfully" });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to delete organization" });
  }
}

/**
 * POST /auth/orgs/:id/switch - Switch active workspace & return tenant-scoped token
 */
async function switchOrg(req, res) {
  try {
    const store = getOrgStore();
    const orgId = req.params.id;
    const userId = getUserId(req.user);

    const member = await store.getMember(orgId, userId);
    if (!member) {
      return res.status(403).json({ error: "Forbidden: You are not an active member of this organization" });
    }

    const organization = await store.getOrgById(orgId);
    if (!organization) {
      return res.status(404).json({ error: "Organization not found" });
    }

    const permissions = getRolePermissions(member.role, config.get("orgRoles") || DEFAULT_ORG_ROLES);
    const mapUserPayload = config.get("mapUserPayload");

    const basePayload = typeof mapUserPayload === "function"
      ? (await mapUserPayload(req.user))
      : { id: req.user.id, email: req.user.email, role: req.user.role };

    const tokenPayload = {
      ...basePayload,
      sub: userId,
      org_id: organization.id,
      org_slug: organization.slug,
      org_role: member.role,
      org_permissions: permissions,
      ...(req.user.cnf ? { cnf: req.user.cnf } : {}) // PRESERVE DPoP KEY BINDING!
    };

    const token = await signJwt(
      tokenPayload,
      config.get("jwtSecret"),
      config.get("jwtExpiresIn") || "7d"
    );

    const tokenType = req.user.cnf ? "DPoP" : "Bearer";

    if (config.get("setHttpOnlyCookie")) {
      const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/"
      };
      res.cookie(config.get("cookieName") || "devauth_token", token, cookieOptions);
    }

    return res.json({
      success: true,
      token,
      tokenType,
      organization,
      member
    });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to switch organization" });
  }
}

/**
 * POST /auth/orgs/:id/invites - Send team invitation
 */
async function inviteMember(req, res) {
  try {
    const store = getOrgStore();
    const orgId = req.params.id;
    const userId = getUserId(req.user);

    const member = await store.getMember(orgId, userId);
    if (!member || (member.role !== "owner" && member.role !== "admin")) {
      return res.status(403).json({ error: "Forbidden: Only owners and admins can invite members" });
    }

    const { email, role = "member" } = req.body || {};
    if (!email || typeof email !== "string" || !email.includes("@")) {
      return res.status(400).json({ error: "A valid email address is required" });
    }

    if (!canManageRole(member.role, role)) {
      return res.status(403).json({ error: `Forbidden: As an ${member.role}, you cannot invite an ${role}` });
    }

    const organization = await store.getOrgById(orgId);
    const rawToken = generateInvitationToken();
    const tokenHash = await hashInvitationToken(rawToken);
    const expiresAt = Date.now() + 7 * 86400 * 1000; // 7 days

    const invitation = await store.createInvitation({
      orgId,
      email: email.trim().toLowerCase(),
      role,
      inviterId: userId,
      tokenHash,
      expiresAt
    });

    const isDevMode = config.get("devMode");
    const baseUrl = config.get("appUrl") || "";
    const inviteLink = baseUrl ? `${baseUrl}/auth/orgs/join?token=${rawToken}` : null;

    await sendOrgInvitation({
      email: email.trim().toLowerCase(),
      organizationName: organization.name,
      role,
      inviterEmail: req.user.email,
      inviteLink,
      inviteToken: rawToken
    });

    emitWebhookEvent("org.invitation_created", {
      orgId,
      invitation: {
        id: invitation.id,
        email: invitation.email,
        role: invitation.role,
        expiresAt: invitation.expiresAt
      },
      actor: req.user
    });

    return res.status(201).json({
      success: true,
      invitation: {
        id: invitation.id,
        email: invitation.email,
        role: invitation.role,
        expiresAt: invitation.expiresAt,
        createdAt: invitation.createdAt
      },
      devModeInviteToken: isDevMode ? rawToken : undefined
    });
  } catch (err) {
    return res.status(400).json({ error: err.message || "Failed to send invitation" });
  }
}

/**
 * GET /auth/orgs/:id/invites - List pending invitations
 */
async function listInvitations(req, res) {
  try {
    const store = getOrgStore();
    const orgId = req.params.id;
    const userId = getUserId(req.user);

    const member = await store.getMember(orgId, userId);
    if (!member || (member.role !== "owner" && member.role !== "admin")) {
      return res.status(403).json({ error: "Forbidden: Only owners and admins can view invitations" });
    }

    const invitations = await store.listInvitations(orgId);
    return res.json({ success: true, invitations });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to list invitations" });
  }
}

/**
 * DELETE /auth/orgs/:id/invites/:inviteId - Revoke invitation
 */
async function revokeInvitation(req, res) {
  try {
    const store = getOrgStore();
    const orgId = req.params.id;
    const userId = getUserId(req.user);

    const member = await store.getMember(orgId, userId);
    if (!member || (member.role !== "owner" && member.role !== "admin")) {
      return res.status(403).json({ error: "Forbidden: Only owners and admins can revoke invitations" });
    }

    await store.deleteInvitation(req.params.inviteId);
    emitWebhookEvent("org.invitation_revoked", {
      orgId,
      invitationId: req.params.inviteId,
      actor: req.user
    });
    return res.json({ success: true, message: "Invitation revoked successfully" });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to revoke invitation" });
  }
}

/**
 * POST /auth/orgs/join - Accept invitation token and join workspace
 */
async function joinOrg(req, res) {
  try {
    const store = getOrgStore();
    const { token } = req.body || {};
    if (!token || typeof token !== "string" || !token.trim()) {
      return res.status(400).json({ error: "Invitation token is required" });
    }

    const tokenHash = await hashInvitationToken(token.trim());
    const invitation = await store.getInvitationByTokenHash(tokenHash);
    if (!invitation) {
      return res.status(400).json({ error: "Invalid or expired invitation token" });
    }

    const userId = getUserId(req.user);
    const existing = await store.getMember(invitation.orgId, userId);
    if (existing) {
      await store.deleteInvitation(invitation.id);
      return res.status(400).json({ error: "You are already a member of this organization" });
    }

    const member = await store.addMember(invitation.orgId, userId, invitation.role, req.user.email);
    await store.deleteInvitation(invitation.id);

    const organization = await store.getOrgById(invitation.orgId);
    const permissions = getRolePermissions(member.role, config.get("orgRoles") || DEFAULT_ORG_ROLES);
    const mapUserPayload = config.get("mapUserPayload");

    const basePayload = typeof mapUserPayload === "function"
      ? (await mapUserPayload(req.user))
      : { id: req.user.id, email: req.user.email, role: req.user.role };

    const tokenPayload = {
      ...basePayload,
      sub: userId,
      org_id: organization.id,
      org_slug: organization.slug,
      org_role: member.role,
      org_permissions: permissions,
      ...(req.user.cnf ? { cnf: req.user.cnf } : {})
    };

    const jwtToken = await signJwt(
      tokenPayload,
      config.get("jwtSecret"),
      config.get("jwtExpiresIn") || "7d"
    );

    emitWebhookEvent("org.member_added", {
      orgId: invitation.orgId,
      member,
      actor: req.user
    });

    return res.json({
      success: true,
      organization,
      member,
      token: jwtToken,
      tokenType: req.user.cnf ? "DPoP" : "Bearer"
    });
  } catch (err) {
    return res.status(400).json({ error: err.message || "Failed to join organization" });
  }
}

/**
 * PATCH /auth/orgs/:id/members/:userId - Update member role
 */
async function updateMemberRole(req, res) {
  try {
    const store = getOrgStore();
    const orgId = req.params.id;
    const actorUserId = getUserId(req.user);
    const targetUserId = req.params.userId;

    const actor = await store.getMember(orgId, actorUserId);
    if (!actor || (actor.role !== "owner" && actor.role !== "admin")) {
      return res.status(403).json({ error: "Forbidden: Only owners and admins can update member roles" });
    }

    const target = await store.getMember(orgId, targetUserId);
    if (!target) {
      return res.status(404).json({ error: "Member not found in this organization" });
    }

    const { role } = req.body || {};
    if (!role || typeof role !== "string") {
      return res.status(400).json({ error: "Valid role is required" });
    }

    if (!canManageRole(actor.role, role) || !canManageRole(actor.role, target.role)) {
      return res.status(403).json({ error: `Forbidden: As an ${actor.role}, you cannot modify an ${target.role} to ${role}` });
    }

    // If transferring ownership, actor becomes admin
    if (role === "owner") {
      if (actor.role !== "owner") {
        return res.status(403).json({ error: "Only the current owner can transfer ownership" });
      }
      await store.updateMemberRole(orgId, actorUserId, "admin");
    }

    const updated = await store.updateMemberRole(orgId, targetUserId, role);
    emitWebhookEvent("org.member_updated", {
      orgId,
      member: updated,
      actor: req.user
    });
    return res.json({ success: true, member: updated });
  } catch (err) {
    return res.status(400).json({ error: err.message || "Failed to update member role" });
  }
}

/**
 * DELETE /auth/orgs/:id/members/:userId - Remove member or leave workspace
 */
async function removeMember(req, res) {
  try {
    const store = getOrgStore();
    const orgId = req.params.id;
    const actorUserId = getUserId(req.user);
    const targetUserId = req.params.userId;

    const isSelf = actorUserId === targetUserId;
    const actor = await store.getMember(orgId, actorUserId);
    if (!actor) {
      return res.status(403).json({ error: "Forbidden: You are not a member of this organization" });
    }

    const target = await store.getMember(orgId, targetUserId);
    if (!target) {
      return res.status(404).json({ error: "Member not found in this organization" });
    }

    // Owner cannot leave without transferring ownership
    if (target.role === "owner") {
      return res.status(400).json({ error: "The organization owner cannot leave without transferring ownership first" });
    }

    if (!isSelf && actor.role !== "owner" && actor.role !== "admin") {
      return res.status(403).json({ error: "Forbidden: Only owners and admins can remove team members" });
    }

    if (!isSelf && !canManageRole(actor.role, target.role)) {
      return res.status(403).json({ error: `Forbidden: As an ${actor.role}, you cannot remove an ${target.role}` });
    }

    await store.removeMember(orgId, targetUserId);
    emitWebhookEvent("org.member_removed", {
      orgId,
      memberId: targetUserId,
      isSelf,
      actor: req.user
    });
    return res.json({ success: true, message: isSelf ? "Left organization successfully" : "Member removed successfully" });
  } catch (err) {
    return res.status(400).json({ error: err.message || "Failed to remove member" });
  }
}

module.exports = {
  createOrg,
  listUserOrgs,
  getOrg,
  updateOrg,
  deleteOrg,
  switchOrg,
  inviteMember,
  listInvitations,
  revokeInvitation,
  joinOrg,
  updateMemberRole,
  removeMember
};
