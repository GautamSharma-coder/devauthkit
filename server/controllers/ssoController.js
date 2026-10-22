// server/controllers/ssoController.js
const config = require("../config");
const {
  verifySamlResponse,
  generateSamlAuthnRequest,
  generateSpMetadataXml,
  verifyDomainTxt,
  SsoError
} = require("../core/ssoService");
const { emitWebhookEvent } = require("../core/webhookDispatcher");
const { signJwt } = require("../utils/webCrypto");

function getSsoStore() {
  const store = config.get("ssoStore") || config.get("sso")?.store;
  if (!store) {
    throw new Error("Enterprise SSO is not enabled; please configure an ssoStore in devAuthKit options.");
  }
  return store;
}

function getOrgStore() {
  return config.get("organizationStore") || config.get("orgStore") || null;
}

function getUserAdapter() {
  return config.get("userAdapter") || null;
}

function setAuthCookie(res, token) {
  if (!config.get("setHttpOnlyCookie")) return;
  const cookieName = config.get("cookieName") || "devauth_token";
  const isProd = process.env.NODE_ENV === "production";
  if (typeof res.cookie === "function") {
    res.cookie(cookieName, token, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "strict" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
  }
}

/**
 * POST /auth/sso/connections - Create a new SSO connection
 */
async function createConnection(req, res) {
  try {
    const store = getSsoStore();
    const {
      id,
      orgId,
      name,
      type,
      domains,
      idpEntityId,
      idpSsoUrl,
      idpSloUrl,
      idpCertificates,
      spEntityId,
      spAcsUrl,
      oidcIssuer,
      oidcClientId,
      oidcClientSecret,
      oidcDiscoveryUrl,
      defaultRole,
      attributeMapping,
      active
    } = req.body || {};

    if (!orgId) {
      return res.status(400).json({ error: "orgId is required to create an SSO connection" });
    }
    if (!name || typeof name !== "string" || !name.trim()) {
      return res.status(400).json({ error: "Connection name is required" });
    }

    const host = (req.get && req.get("host")) || req.headers?.host || "localhost";
    const protocol = req.protocol || "http";
    const apiPrefix = (config.get("apiPrefix") || "/auth").replace(/\/+$/, "");

    // Generate SP metadata defaults if not provided
    const tempId = id || `conn_${Date.now().toString(36)}`;
    const resolvedSpEntityId = spEntityId || `${protocol}://${host}${apiPrefix}/sso/saml/${tempId}/metadata.xml`;
    const resolvedSpAcsUrl = spAcsUrl || `${protocol}://${host}${apiPrefix}/sso/saml/${tempId}/acs`;

    const connection = await store.createConnection({
      id,
      orgId,
      name,
      type: type === "OIDC" ? "OIDC" : "SAML",
      domains,
      idpEntityId,
      idpSsoUrl,
      idpSloUrl,
      idpCertificates,
      spEntityId: resolvedSpEntityId,
      spAcsUrl: resolvedSpAcsUrl,
      oidcIssuer,
      oidcClientId,
      oidcClientSecret,
      oidcDiscoveryUrl,
      defaultRole: defaultRole || "member",
      attributeMapping,
      active
    });

    emitWebhookEvent("sso.connection_created", {
      connection,
      orgId: connection.orgId,
      actor: req.user
    });

    return res.status(201).json({ success: true, connection });
  } catch (err) {
    return res.status(400).json({ error: err.message || "Failed to create SSO connection" });
  }
}

/**
 * GET /auth/sso/connections - List SSO connections
 */
async function listConnections(req, res) {
  try {
    const store = getSsoStore();
    const orgId = req.query.orgId || req.params.orgId || req.org?.id;
    const connections = await store.listConnections(orgId);
    return res.json({ success: true, connections });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to list SSO connections" });
  }
}

/**
 * GET /auth/sso/connections/:id - Get a specific SSO connection
 */
async function getConnection(req, res) {
  try {
    const store = getSsoStore();
    const connection = await store.getConnection(req.params.id);
    if (!connection) {
      return res.status(404).json({ error: "SSO connection not found" });
    }
    return res.json({ success: true, connection });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to get SSO connection" });
  }
}

/**
 * PATCH /auth/sso/connections/:id - Update an SSO connection
 */
async function updateConnection(req, res) {
  try {
    const store = getSsoStore();
    const connection = await store.updateConnection(req.params.id, req.body || {});
    if (!connection) {
      return res.status(404).json({ error: "SSO connection not found" });
    }

    emitWebhookEvent("sso.connection_updated", {
      connection,
      orgId: connection.orgId,
      actor: req.user
    });

    return res.json({ success: true, connection });
  } catch (err) {
    return res.status(400).json({ error: err.message || "Failed to update SSO connection" });
  }
}

/**
 * DELETE /auth/sso/connections/:id - Delete an SSO connection
 */
async function deleteConnection(req, res) {
  try {
    const store = getSsoStore();
    const existing = await store.getConnection(req.params.id);
    if (!existing) {
      return res.status(404).json({ error: "SSO connection not found" });
    }

    await store.deleteConnection(req.params.id);

    emitWebhookEvent("sso.connection_deleted", {
      connectionId: req.params.id,
      orgId: existing.orgId,
      actor: req.user
    });

    return res.json({ success: true, message: "SSO connection deleted successfully" });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to delete SSO connection" });
  }
}

/**
 * POST /auth/sso/connections/:id/verify-domain - Verify domain DNS TXT record
 */
async function verifyDomain(req, res) {
  try {
    const store = getSsoStore();
    const connection = await store.getConnection(req.params.id);
    if (!connection) {
      return res.status(404).json({ error: "SSO connection not found" });
    }

    const domain = (req.body?.domain || connection.domains[0] || "").toLowerCase().trim().replace(/^@/, "");
    if (!domain) {
      return res.status(400).json({ error: "Domain name is required to verify ownership" });
    }

    const verified = await verifyDomainTxt(domain, connection.domainVerificationToken);
    if (!verified) {
      return res.status(400).json({
        success: false,
        verified: false,
        domain,
        expectedRecord: `_devauth-verify.${domain}`,
        expectedValue: connection.domainVerificationToken,
        error: "DNS TXT record matching verification token was not found"
      });
    }

    const updated = await store.verifyDomain(connection.id);

    emitWebhookEvent("sso.domain_verified", {
      connectionId: connection.id,
      orgId: connection.orgId,
      domain,
      actor: req.user
    });

    return res.json({ success: true, verified: true, domain, connection: updated });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to verify domain ownership" });
  }
}

/**
 * POST /auth/sso/resolve or GET /auth/sso/resolve - Domain-based SSO discovery and AuthnRequest dispatch
 */
async function resolveSso(req, res) {
  try {
    const store = getSsoStore();
    const email = req.body?.email || req.query?.email;
    const domainInput = req.body?.domain || req.query?.domain;
    const relayState = req.body?.relayState || req.query?.relayState;

    let domain = "";
    if (domainInput && typeof domainInput === "string") {
      domain = domainInput.toLowerCase().trim().replace(/^@/, "");
    } else if (email && typeof email === "string" && email.includes("@")) {
      domain = email.split("@")[1].toLowerCase().trim();
    }

    if (!domain) {
      return res.status(400).json({ error: "A valid email address or domain is required to resolve SSO" });
    }

    const connection = await store.getConnectionByDomain(domain);
    if (!connection || !connection.active) {
      return res.status(404).json({ error: `No active Enterprise SSO connection found for domain '${domain}'` });
    }

    if (connection.type === "SAML") {
      if (!connection.idpSsoUrl) {
        return res.status(400).json({ error: "SAML connection is missing idpSsoUrl configuration" });
      }

      const authn = generateSamlAuthnRequest({
        spEntityId: connection.spEntityId,
        acsUrl: connection.spAcsUrl,
        idpSsoUrl: connection.idpSsoUrl,
        relayState
      });

      return res.json({
        success: true,
        type: "SAML",
        connectionId: connection.id,
        redirectUrl: authn.redirectUrl,
        requestId: authn.id
      });
    }

    if (connection.type === "OIDC") {
      if (!connection.idpSsoUrl && !connection.oidcDiscoveryUrl) {
        return res.status(400).json({ error: "OIDC connection is missing idpSsoUrl / oidcDiscoveryUrl" });
      }
      return res.json({
        success: true,
        type: "OIDC",
        connectionId: connection.id,
        redirectUrl: connection.idpSsoUrl || connection.oidcDiscoveryUrl
      });
    }

    return res.status(400).json({ error: `Unsupported SSO connection type '${connection.type}'` });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to resolve SSO connection" });
  }
}

/**
 * GET /auth/sso/saml/:connectionId/metadata.xml - Generate and serve SP Metadata XML
 */
async function getSpMetadata(req, res) {
  try {
    const store = getSsoStore();
    const connectionId = req.params.connectionId || req.query.connectionId;
    let spEntityId = "";
    let acsUrl = "";
    let sloUrl = null;

    if (connectionId) {
      const connection = await store.getConnection(connectionId);
      if (!connection) {
        return res.status(404).send("SSO connection not found");
      }
      spEntityId = connection.spEntityId;
      acsUrl = connection.spAcsUrl;
      sloUrl = connection.idpSloUrl;
    } else {
      const host = (req.get && req.get("host")) || req.headers?.host || "localhost";
      const protocol = req.protocol || "http";
      const apiPrefix = (config.get("apiPrefix") || "/auth").replace(/\/+$/, "");
      spEntityId = `${protocol}://${host}${apiPrefix}/sso/saml/metadata.xml`;
      acsUrl = `${protocol}://${host}${apiPrefix}/sso/saml/acs`;
    }

    const xml = generateSpMetadataXml({
      spEntityId,
      acsUrl,
      sloUrl,
      signingCert: config.get("sso")?.signingCert || null
    });

    if (typeof res.setHeader === "function") {
      res.setHeader("Content-Type", "application/xml; charset=utf-8");
    }
    return res.send(xml);
  } catch (err) {
    return res.status(500).send(`Failed to generate SP metadata: ${err.message}`);
  }
}

/**
 * POST /auth/sso/saml/:connectionId/acs - SAML 2.0 Assertion Consumer Service
 */
async function handleSamlAcs(req, res) {
  try {
    const store = getSsoStore();
    const connectionId = req.params.connectionId || req.body?.connectionId || req.query?.connectionId;
    if (!connectionId) {
      return res.status(400).json({ error: "connectionId is required for SAML ACS" });
    }

    const connection = await store.getConnection(connectionId);
    if (!connection || !connection.active) {
      return res.status(404).json({ error: "SSO connection not found or inactive" });
    }

    const samlResponse = req.body?.SAMLResponse || req.body?.samlResponse;
    const relayState = req.body?.RelayState || req.body?.relayState;

    if (!samlResponse) {
      return res.status(400).json({ error: "SAMLResponse is required in POST payload" });
    }

    // Parse and verify assertion
    const assertion = await verifySamlResponse({
      samlResponse,
      idpCertificates: connection.idpCertificates,
      spEntityId: connection.spEntityId,
      clockSkewSeconds: config.get("sso")?.maxClockSkewSeconds ?? 300,
      replayStore: store
    });

    // Check certificate promotion if secondary certificate was used
    if (assertion.promotedCert && connection.idpCertificates.length > 1) {
      const remainingCerts = connection.idpCertificates.filter((c) => c !== assertion.promotedCert);
      await store.updateConnection(connection.id, {
        idpCertificates: [assertion.promotedCert, ...remainingCerts]
      });
      emitWebhookEvent("sso.certificate_promoted", {
        connectionId: connection.id,
        orgId: connection.orgId
      });
    }

    // Resolve user claims from attribute mapping
    const mapping = connection.attributeMapping || {};
    const emailAttr = mapping.email || "email";
    const nameAttr = mapping.name || "name";

    const email = (assertion.attributes[emailAttr] || assertion.email || assertion.nameId || "").toLowerCase().trim();
    const name = assertion.attributes[nameAttr] || assertion.displayName || assertion.firstName || "";

    if (!email) {
      return res.status(400).json({ error: "SAML assertion did not contain a valid email address or NameID" });
    }

    // JIT User Provisioning via userAdapter
    const userAdapter = getUserAdapter();
    let dbUser = null;
    if (userAdapter && typeof userAdapter.findOrCreateUser === "function") {
      dbUser = await userAdapter.findOrCreateUser({
        email,
        name: name || undefined
      });
    }

    const userPayload = {
      id: dbUser?.id !== undefined ? dbUser.id : email,
      email,
      name: name || dbUser?.name,
      ...(dbUser?.role ? { role: dbUser.role } : {})
    };

    // JIT Organization Membership Provisioning
    const orgStore = getOrgStore();
    let member = null;
    if (orgStore && connection.orgId) {
      member = await orgStore.getMember(connection.orgId, userPayload.id);
      if (!member) {
        member = await orgStore.addMember(
          connection.orgId,
          userPayload.id,
          connection.defaultRole || "member",
          email
        );
        emitWebhookEvent("org.member_joined", {
          orgId: connection.orgId,
          member,
          ssoConnectionId: connection.id
        });
      }
    }

    // Attach tenant SSO claims
    if (connection.orgId) {
      userPayload.orgId = connection.orgId;
      userPayload.orgRole = member?.role || connection.defaultRole || "member";
    }
    userPayload.ssoConnectionId = connection.id;

    // Issue signed JWT token
    const token = await signJwt(
      userPayload,
      config.get("jwtSecret"),
      config.get("jwtExpiresIn") || "1h"
    );

    setAuthCookie(res, token);

    emitWebhookEvent("sso.login_success", {
      connectionId: connection.id,
      orgId: connection.orgId,
      user: userPayload,
      nameId: assertion.nameId,
      assertionId: assertion.assertionId
    });

    emitWebhookEvent("user.authenticated", {
      userId: String(userPayload.id ?? userPayload.email),
      user: userPayload,
      provider: "sso_saml"
    });

    // Check for redirect URL in RelayState
    if (relayState && typeof relayState === "string") {
      try {
        const targetUrl = new URL(relayState);
        targetUrl.searchParams.set("token", token);
        return res.redirect(targetUrl.toString());
      } catch {
        // RelayState is not an absolute URL, return JSON
      }
    }

    return res.json({
      success: true,
      message: "SSO authentication succeeded",
      token,
      user: userPayload
    });
  } catch (err) {
    if (err instanceof SsoError) {
      return res.status(err.status || 400).json({ error: err.message, code: err.code });
    }
    return res.status(500).json({ error: err.message || "SAML authentication failed" });
  }
}

module.exports = {
  createConnection,
  listConnections,
  getConnection,
  updateConnection,
  deleteConnection,
  verifyDomain,
  resolveSso,
  getSpMetadata,
  handleSamlAcs
};
