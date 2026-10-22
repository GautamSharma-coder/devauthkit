// server/controllers/scimController.js
const config = require("../config");
const {
  SCIM_USER_SCHEMA,
  SCIM_GROUP_SCHEMA,
  generateScimBearerToken,
  hashScimBearerToken,
  verifyScimBearerToken,
  getServiceProviderConfig: serviceProviderConfigSchema,
  getSchemas: schemasResponse,
  formatScimUser,
  formatScimGroup,
  formatScimList,
  formatScimError,
  parseScimFilter,
  parseScimPatchOperations
} = require("../core/scimService");
const { emitWebhookEvent } = require("../core/webhookDispatcher");

function getSsoStore() {
  const store = config.get("ssoStore") || config.get("sso")?.store;
  if (!store) {
    throw new Error("Enterprise SSO & SCIM is not enabled; please configure an ssoStore in devAuthKit options.");
  }
  return store;
}

function getOrgStore() {
  return config.get("organizationStore") || config.get("orgStore") || null;
}

function getUserAdapter() {
  return config.get("userAdapter") || null;
}

function getRefreshTokenStore() {
  return config.get("refreshTokenStore") || null;
}

// ==========================================
// SCIM Bearer Token Authentication Middleware
// ==========================================

async function authenticateScimBearer(req, res, next) {
  try {
    const authHeader = req.headers?.authorization || req.headers?.Authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      if (typeof res.setHeader === "function") {
        res.setHeader("Content-Type", "application/scim+json; charset=utf-8");
      }
      return res.status(401).json(formatScimError(401, "Authorization Bearer token is required"));
    }

    const token = authHeader.slice(7).trim();
    const tokenHash = await hashScimBearerToken(token);
    const store = getSsoStore();
    const directory = await store.getDirectoryByTokenHash(tokenHash);

    if (!directory || !directory.active) {
      if (typeof res.setHeader === "function") {
        res.setHeader("Content-Type", "application/scim+json; charset=utf-8");
      }
      return res.status(401).json(formatScimError(401, "Invalid or revoked SCIM Bearer token"));
    }

    req.scimDirectory = directory;
    if (typeof res.setHeader === "function") {
      res.setHeader("Content-Type", "application/scim+json; charset=utf-8");
    }
    if (typeof next === "function") return next();
  } catch (err) {
    if (typeof res.setHeader === "function") {
      res.setHeader("Content-Type", "application/scim+json; charset=utf-8");
    }
    return res.status(500).json(formatScimError(500, err.message || "SCIM authentication failed"));
  }
}

// ==========================================
// SCIM Directory Management (Admin APIs)
// ==========================================

/**
 * POST /auth/scim/directories - Create new SCIM directory & bearer token
 */
async function createDirectory(req, res) {
  try {
    const store = getSsoStore();
    const { orgId, scimBaseUrl } = req.body || {};
    if (!orgId) {
      return res.status(400).json({ error: "orgId is required to create a SCIM directory" });
    }

    const bearerToken = generateScimBearerToken();
    const bearerTokenHash = await hashScimBearerToken(bearerToken);

    const directory = await store.createDirectory({
      orgId,
      bearerTokenHash,
      scimBaseUrl: scimBaseUrl || "/scim/v2"
    });

    emitWebhookEvent("scim.directory_created", {
      directory,
      orgId,
      actor: req.user
    });

    return res.status(201).json({
      success: true,
      directory,
      bearerToken // Returned ONLY once upon creation
    });
  } catch (err) {
    return res.status(400).json({ error: err.message || "Failed to create SCIM directory" });
  }
}

/**
 * GET /auth/scim/directories - List SCIM directories
 */
async function listDirectories(req, res) {
  try {
    const store = getSsoStore();
    const orgId = req.query.orgId || req.params.orgId || req.org?.id;
    const directories = await store.listDirectories(orgId);
    return res.json({ success: true, directories });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to list SCIM directories" });
  }
}

/**
 * GET /auth/scim/directories/:id - Get specific SCIM directory
 */
async function getDirectory(req, res) {
  try {
    const store = getSsoStore();
    const directory = await store.getDirectory(req.params.id);
    if (!directory) {
      return res.status(404).json({ error: "SCIM directory not found" });
    }
    return res.json({ success: true, directory });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to get SCIM directory" });
  }
}

/**
 * POST /auth/scim/directories/:id/rotate-token - Rotate SCIM Bearer token
 */
async function rotateToken(req, res) {
  try {
    const store = getSsoStore();
    const directory = await store.getDirectory(req.params.id);
    if (!directory) {
      return res.status(404).json({ error: "SCIM directory not found" });
    }

    const newBearerToken = generateScimBearerToken();
    const bearerTokenHash = await hashScimBearerToken(newBearerToken);

    const updated = await store.updateDirectory(directory.id, { bearerTokenHash });

    emitWebhookEvent("scim.token_rotated", {
      directoryId: directory.id,
      orgId: directory.orgId,
      actor: req.user
    });

    return res.json({
      success: true,
      directory: updated,
      bearerToken: newBearerToken
    });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to rotate SCIM token" });
  }
}

/**
 * DELETE /auth/scim/directories/:id - Delete SCIM directory
 */
async function deleteDirectory(req, res) {
  try {
    const store = getSsoStore();
    const directory = await store.getDirectory(req.params.id);
    if (!directory) {
      return res.status(404).json({ error: "SCIM directory not found" });
    }

    await store.deleteDirectory(req.params.id);

    emitWebhookEvent("scim.directory_deleted", {
      directoryId: req.params.id,
      orgId: directory.orgId,
      actor: req.user
    });

    return res.json({ success: true, message: "SCIM directory deleted successfully" });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to delete SCIM directory" });
  }
}

// ==========================================
// SCIM 2.0 Protocol Handlers (RFC 7643 & 7644)
// ==========================================

/**
 * GET /scim/v2/ServiceProviderConfig
 */
async function getServiceProviderConfig(req, res) {
  const host = (req.get && req.get("host")) || req.headers?.host || "localhost";
  const protocol = req.protocol || "https";
  const baseUrl = `${protocol}://${host}/scim/v2`;
  return res.json(serviceProviderConfigSchema(baseUrl));
}

/**
 * GET /scim/v2/Schemas
 */
async function getSchemas(req, res) {
  return res.json(schemasResponse());
}

/**
 * GET /scim/v2/Users - Search/List users
 */
async function listUsers(req, res) {
  try {
    const store = getSsoStore();
    const directory = req.scimDirectory;
    const filter = parseScimFilter(req.query.filter);
    const mappings = await store.listScimUserMappings(directory.id);

    let filtered = mappings;
    if (filter) {
      filtered = mappings.filter((m) => {
        const email = (m.attributes?.email || m.userId || "").toLowerCase();
        const userName = (m.attributes?.userName || email).toLowerCase();
        const targetVal = (filter.value || "").toLowerCase();

        if (filter.attribute === "userName" || filter.attribute === "emails.value") {
          return userName === targetVal || email === targetVal;
        }
        if (filter.attribute === "externalId") {
          return m.idpExternalId.toLowerCase() === targetVal;
        }
        return false;
      });
    }

    const host = (req.get && req.get("host")) || req.headers?.host || "localhost";
    const protocol = req.protocol || "https";
    const scimBaseUrl = `${protocol}://${host}/scim/v2`;

    const resources = filtered.map((m) =>
      formatScimUser(
        { id: m.userId, email: m.attributes?.email || m.userId, name: m.attributes?.name },
        m,
        scimBaseUrl
      )
    );

    return res.json(formatScimList(resources, resources.length));
  } catch (err) {
    return res.status(500).json(formatScimError(500, err.message));
  }
}

/**
 * GET /scim/v2/Users/:id - Get specific user
 */
async function getUser(req, res) {
  try {
    const store = getSsoStore();
    const directory = req.scimDirectory;
    const mapping = await store.getScimUserMapping(directory.id, req.params.id) ||
      await store.getScimUserMappingByUserId(directory.id, req.params.id);

    if (!mapping) {
      return res.status(404).json(formatScimError(404, `User '${req.params.id}' not found`));
    }

    const host = (req.get && req.get("host")) || req.headers?.host || "localhost";
    const protocol = req.protocol || "https";
    const scimBaseUrl = `${protocol}://${host}/scim/v2`;

    return res.json(
      formatScimUser(
        { id: mapping.userId, email: mapping.attributes?.email || mapping.userId, name: mapping.attributes?.name },
        mapping,
        scimBaseUrl
      )
    );
  } catch (err) {
    return res.status(500).json(formatScimError(500, err.message));
  }
}

/**
 * POST /scim/v2/Users - Create / JIT Provision user
 */
async function createUser(req, res) {
  try {
    const store = getSsoStore();
    const directory = req.scimDirectory;
    const body = req.body || {};

    const emails = Array.isArray(body.emails) ? body.emails : [];
    const primaryEmail = (emails.find((e) => e.primary)?.value || emails[0]?.value || body.userName || "").toLowerCase().trim();

    if (!primaryEmail) {
      return res.status(400).json(formatScimError(400, "userName or primary email is required", "invalidValue"));
    }

    const externalId = body.externalId || body.id || primaryEmail;
    const displayName = body.displayName || (body.name ? `${body.name.givenName || ""} ${body.name.familyName || ""}`.trim() : primaryEmail);

    // Check if mapping already exists
    const existing = await store.getScimUserMapping(directory.id, externalId);
    if (existing) {
      return res.status(409).json(formatScimError(409, "User already exists", "uniqueness"));
    }

    // Provision User in userAdapter if present
    const userAdapter = getUserAdapter();
    let dbUser = null;
    if (userAdapter && typeof userAdapter.findOrCreateUser === "function") {
      dbUser = await userAdapter.findOrCreateUser({
        email: primaryEmail,
        name: displayName
      });
    }

    const userId = dbUser?.id !== undefined ? String(dbUser.id) : primaryEmail;

    // Provision Org Membership in organizationStore if present
    const orgStore = getOrgStore();
    let member = null;
    if (orgStore && directory.orgId) {
      member = await orgStore.getMember(directory.orgId, userId);
      if (!member) {
        member = await orgStore.addMember(directory.orgId, userId, "member", primaryEmail);
        emitWebhookEvent("org.member_joined", {
          orgId: directory.orgId,
          member,
          scimDirectoryId: directory.id
        });
      }
    }

    const mapping = await store.createScimUserMapping({
      directoryId: directory.id,
      orgId: directory.orgId,
      userId,
      idpExternalId: externalId,
      attributes: {
        email: primaryEmail,
        userName: body.userName || primaryEmail,
        name: displayName,
        active: body.active !== false
      },
      active: body.active !== false
    });

    emitWebhookEvent("scim.user_provisioned", {
      directoryId: directory.id,
      orgId: directory.orgId,
      userId,
      externalId,
      email: primaryEmail
    });

    const host = (req.get && req.get("host")) || req.headers?.host || "localhost";
    const protocol = req.protocol || "https";
    const scimBaseUrl = `${protocol}://${host}/scim/v2`;

    return res.status(201).json(
      formatScimUser(
        { id: userId, email: primaryEmail, name: displayName, externalId },
        mapping,
        scimBaseUrl
      )
    );
  } catch (err) {
    return res.status(500).json(formatScimError(500, err.message));
  }
}

/**
 * PATCH /scim/v2/Users/:id - Update user / Deactivate / Instant Deprovisioning Cascade
 */
async function patchUser(req, res) {
  try {
    const store = getSsoStore();
    const directory = req.scimDirectory;
    const mapping = await store.getScimUserMapping(directory.id, req.params.id) ||
      await store.getScimUserMappingByUserId(directory.id, req.params.id);

    if (!mapping) {
      return res.status(404).json(formatScimError(404, `User '${req.params.id}' not found`));
    }

    const patch = parseScimPatchOperations(req.body?.Operations);
    const updates = { attributes: { ...mapping.attributes } };

    // Handle deprovisioning / activation toggle
    if (patch.active !== undefined) {
      updates.active = patch.active;
      updates.attributes.active = patch.active;

      // INSTANT DEPROVISIONING CASCADE
      if (patch.active === false) {
        // 1. Remove/deactivate org membership
        const orgStore = getOrgStore();
        if (orgStore && directory.orgId) {
          try {
            await orgStore.removeMember(directory.orgId, mapping.userId);
          } catch {
            // member may already be removed
          }
        }

        // 2. Invalidate all active sessions in refreshTokenStore
        const refreshTokenStore = getRefreshTokenStore();
        if (refreshTokenStore && typeof refreshTokenStore.revokeAll === "function") {
          await refreshTokenStore.revokeAll(mapping.userId);
        }

        // 3. Emit deprovisioning webhook events
        emitWebhookEvent("session.revoked_all", {
          userId: mapping.userId,
          reason: "scim_deprovisioned",
          directoryId: directory.id,
          orgId: directory.orgId
        });

        emitWebhookEvent("org.member_removed", {
          orgId: directory.orgId,
          userId: mapping.userId,
          reason: "scim_deprovisioned"
        });

        emitWebhookEvent("scim.user_deprovisioned", {
          directoryId: directory.id,
          orgId: directory.orgId,
          userId: mapping.userId,
          externalId: mapping.idpExternalId
        });
      }
    }

    if (Object.keys(patch.updates).length > 0) {
      Object.assign(updates.attributes, patch.updates);
    }

    const updated = await store.updateScimUserMapping(mapping.id, updates);

    const host = (req.get && req.get("host")) || req.headers?.host || "localhost";
    const protocol = req.protocol || "https";
    const scimBaseUrl = `${protocol}://${host}/scim/v2`;

    return res.json(
      formatScimUser(
        { id: updated.userId, email: updated.attributes.email || updated.userId, name: updated.attributes.name },
        updated,
        scimBaseUrl
      )
    );
  } catch (err) {
    return res.status(500).json(formatScimError(500, err.message));
  }
}

/**
 * DELETE /scim/v2/Users/:id - Hard deprovision user
 */
async function deleteUser(req, res) {
  try {
    const store = getSsoStore();
    const directory = req.scimDirectory;
    const mapping = await store.getScimUserMapping(directory.id, req.params.id) ||
      await store.getScimUserMappingByUserId(directory.id, req.params.id);

    if (!mapping) {
      return res.status(404).json(formatScimError(404, `User '${req.params.id}' not found`));
    }

    // Deprovision org member & purge sessions
    const orgStore = getOrgStore();
    if (orgStore && directory.orgId) {
      try {
        await orgStore.removeMember(directory.orgId, mapping.userId);
      } catch {}
    }

    const refreshTokenStore = getRefreshTokenStore();
    if (refreshTokenStore && typeof refreshTokenStore.revokeAll === "function") {
      await refreshTokenStore.revokeAll(mapping.userId);
    }

    await store.deleteScimUserMapping(mapping.id);

    emitWebhookEvent("scim.user_deprovisioned", {
      directoryId: directory.id,
      orgId: directory.orgId,
      userId: mapping.userId,
      externalId: mapping.idpExternalId
    });

    return res.status(204).send();
  } catch (err) {
    return res.status(500).json(formatScimError(500, err.message));
  }
}

/**
 * GET /scim/v2/Groups - List groups
 */
async function listGroups(req, res) {
  try {
    const store = getSsoStore();
    const directory = req.scimDirectory;
    const groups = await store.listScimGroupMappings(directory.id);

    const host = (req.get && req.get("host")) || req.headers?.host || "localhost";
    const protocol = req.protocol || "https";
    const scimBaseUrl = `${protocol}://${host}/scim/v2`;

    const resources = groups.map((g) => formatScimGroup(g, scimBaseUrl));
    return res.json(formatScimList(resources, resources.length));
  } catch (err) {
    return res.status(500).json(formatScimError(500, err.message));
  }
}

/**
 * GET /scim/v2/Groups/:id - Get specific group
 */
async function getGroup(req, res) {
  try {
    const store = getSsoStore();
    const directory = req.scimDirectory;
    const group = await store.getScimGroupMapping(directory.id, req.params.id) ||
      await store.getScimGroupMappingById(req.params.id);

    if (!group) {
      return res.status(404).json(formatScimError(404, `Group '${req.params.id}' not found`));
    }

    const host = (req.get && req.get("host")) || req.headers?.host || "localhost";
    const protocol = req.protocol || "https";
    const scimBaseUrl = `${protocol}://${host}/scim/v2`;

    return res.json(formatScimGroup(group, scimBaseUrl));
  } catch (err) {
    return res.status(500).json(formatScimError(500, err.message));
  }
}

/**
 * POST /scim/v2/Groups - Create group mapping
 */
async function createGroup(req, res) {
  try {
    const store = getSsoStore();
    const directory = req.scimDirectory;
    const { displayName, members } = req.body || {};

    if (!displayName) {
      return res.status(400).json(formatScimError(400, "displayName is required for Group"));
    }

    const memberIds = Array.isArray(members) ? members.map((m) => m.value || m).filter(Boolean) : [];
    const group = await store.createScimGroupMapping({
      directoryId: directory.id,
      orgId: directory.orgId,
      idpGroupId: req.body?.id || `grp_${Date.now().toString(36)}`,
      groupName: displayName,
      members: memberIds
    });

    const host = (req.get && req.get("host")) || req.headers?.host || "localhost";
    const protocol = req.protocol || "https";
    const scimBaseUrl = `${protocol}://${host}/scim/v2`;

    return res.status(201).json(formatScimGroup(group, scimBaseUrl));
  } catch (err) {
    return res.status(500).json(formatScimError(500, err.message));
  }
}

/**
 * PATCH /scim/v2/Groups/:id - Update group members
 */
async function patchGroup(req, res) {
  try {
    const store = getSsoStore();
    const directory = req.scimDirectory;
    const group = await store.getScimGroupMapping(directory.id, req.params.id) ||
      await store.getScimGroupMappingById(req.params.id);

    if (!group) {
      return res.status(404).json(formatScimError(404, `Group '${req.params.id}' not found`));
    }

    const patch = parseScimPatchOperations(req.body?.Operations);
    let members = [...group.members];

    if (patch.addMembers.length > 0) {
      for (const m of patch.addMembers) {
        if (!members.includes(m)) members.push(m);
      }
    }
    if (patch.removeMembers.length > 0) {
      members = members.filter((m) => !patch.removeMembers.includes(m));
    }

    const updated = await store.updateScimGroupMapping(group.id, {
      groupName: patch.updates.displayName || group.groupName,
      members
    });

    const host = (req.get && req.get("host")) || req.headers?.host || "localhost";
    const protocol = req.protocol || "https";
    const scimBaseUrl = `${protocol}://${host}/scim/v2`;

    return res.json(formatScimGroup(updated, scimBaseUrl));
  } catch (err) {
    return res.status(500).json(formatScimError(500, err.message));
  }
}

module.exports = {
  authenticateScimBearer,
  createDirectory,
  listDirectories,
  getDirectory,
  rotateToken,
  deleteDirectory,
  getServiceProviderConfig,
  getSchemas,
  listUsers,
  getUser,
  createUser,
  patchUser,
  deleteUser,
  listGroups,
  getGroup,
  createGroup,
  patchGroup
};
