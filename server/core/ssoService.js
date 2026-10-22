// server/core/ssoService.js
const {
  constantTimeEqual,
  randomString,
  randomUUID,
  sha256Base64Url,
  sha256Hex
} = require("../utils/webCrypto");

class SsoError extends Error {
  constructor(message, code = "ERR_SSO_FAILED", status = 400) {
    super(message);
    this.name = "SsoError";
    this.code = code;
    this.status = status;
  }
}

/**
 * Deflate data using raw deflate algorithm (no zlib headers) for SAML HTTP-Redirect binding
 * @param {string|Buffer} strOrBuf
 * @returns {Buffer}
 */
function deflateRaw(strOrBuf) {
  try {
    const zlib = require("zlib");
    return zlib.deflateRawSync(typeof strOrBuf === "string" ? Buffer.from(strOrBuf, "utf8") : strOrBuf);
  } catch {
    return Buffer.from(strOrBuf, "utf8");
  }
}

/**
 * Inflate raw deflated data
 * @param {Buffer} buf
 * @returns {Buffer}
 */
function inflateRaw(buf) {
  try {
    const zlib = require("zlib");
    return zlib.inflateRawSync(buf);
  } catch {
    return buf;
  }
}

/**
 * Format a raw base64 or messy string into valid PEM certificate format
 * @param {string} rawCert
 * @returns {string}
 */
function formatX509Cert(rawCert) {
  if (!rawCert || typeof rawCert !== "string") {
    throw new SsoError("X.509 certificate must be a non-empty string", "ERR_INVALID_CERTIFICATE");
  }
  if (
    rawCert.includes("-----BEGIN CERTIFICATE-----") ||
    rawCert.includes("-----BEGIN PUBLIC KEY-----") ||
    rawCert.includes("-----BEGIN RSA PUBLIC KEY-----")
  ) {
    return rawCert.trim();
  }
  const clean = rawCert.replace(/[\r\n\s]/g, "");
  const lines = clean.match(/.{1,64}/g) || [clean];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

/**
 * Clean and normalize XML for Exclusive Canonicalization (C14N)
 * @param {string} xmlString
 * @returns {string}
 */
function canonicalizeXml(xmlString) {
  if (!xmlString || typeof xmlString !== "string") return "";

  // 1. Remove XML declaration (<?xml ... ?>) and DOCTYPE comments
  let xml = xmlString
    .replace(/<\?xml[^>]*\?>/gi, "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .trim();

  // 2. Normalize Windows/Mac line endings to \n
  xml = xml.replace(/\r\n/g, "\n").replace(/\r/g, "\n");

  // 3. Normalize whitespace between attributes and sort attributes lexicographically
  xml = xml.replace(/<([a-zA-Z0-9_:\-]+)([^>]*)>/g, (match, tagName, attrString) => {
    const isSelfClosing = attrString.trim().endsWith("/");
    const cleanAttrs = isSelfClosing ? attrString.trim().slice(0, -1).trim() : attrString.trim();

    if (!cleanAttrs) {
      return isSelfClosing ? `<${tagName}></${tagName}>` : `<${tagName}>`;
    }

    // Parse attributes
    const attrRegex = /([a-zA-Z0-9_:\-]+)="([^"]*)"/g;
    const attrs = [];
    let attrMatch;
    while ((attrMatch = attrRegex.exec(cleanAttrs)) !== null) {
      attrs.push({ name: attrMatch[1], value: attrMatch[2] });
    }

    // Sort attributes: xmlns namespaces first, then regular attributes alphabetically
    attrs.sort((a, b) => {
      const aIsXmlns = a.name === "xmlns" || a.name.startsWith("xmlns:");
      const bIsXmlns = b.name === "xmlns" || b.name.startsWith("xmlns:");
      if (aIsXmlns && !bIsXmlns) return -1;
      if (!aIsXmlns && bIsXmlns) return 1;
      return a.name.localeCompare(b.name);
    });

    const formattedAttrs = attrs.map((a) => `${a.name}="${a.value}"`).join(" ");
    return isSelfClosing
      ? `<${tagName} ${formattedAttrs}></${tagName}>`
      : `<${tagName} ${formattedAttrs}>`;
  });

  // 4. Normalize whitespace between tags
  xml = xml.replace(/>\s+</g, "><");

  return xml.trim();
}

/**
 * Deflate string using Node zlib or Web CompressionStream
 * @param {string} str
 * @returns {Buffer}
 */
function deflateRaw(str) {
  try {
    const zlib = require("zlib");
    return zlib.deflateRawSync(str);
  } catch (err) {
    throw new SsoError(`Failed to deflate SAML payload: ${err.message}`, "ERR_DEFLATE_FAILED");
  }
}

/**
 * Inflate deflated raw Buffer to string
 * @param {Buffer|Uint8Array} buf
 * @returns {string}
 */
function inflateRaw(buf) {
  try {
    const zlib = require("zlib");
    return zlib.inflateRawSync(buf).toString("utf8");
  } catch (err) {
    throw new SsoError(`Failed to inflate SAML payload: ${err.message}`, "ERR_INFLATE_FAILED");
  }
}

/**
 * Compute Base64 digest of canonicalized XML using SHA-256 or SHA-1
 * @param {string} xml
 * @param {string} [algorithm="sha256"]
 * @returns {string} Base64 digest
 */
function computeXmlDigest(xml, algorithm = "sha256") {
  const crypto = require("crypto");
  const algo = algorithm.toLowerCase().includes("sha1") ? "sha1" : "sha256";
  const hash = crypto.createHash(algo);
  hash.update(xml, "utf8");
  return hash.digest("base64");
}

/**
 * Verify RSA-SHA256 or RSA-SHA1 signature
 * @param {string} data - Canonicalized SignedInfo
 * @param {string} signatureBase64 - Base64 SignatureValue
 * @param {string} certPem - X.509 Certificate in PEM format
 * @param {string} [algorithm="RSA-SHA256"]
 * @returns {boolean}
 */
function verifyRsaSignature(data, signatureBase64, certPem, algorithm = "RSA-SHA256") {
  try {
    const crypto = require("crypto");
    const algo = algorithm.toUpperCase().includes("SHA1") ? "RSA-SHA1" : "RSA-SHA256";
    const formatted = formatX509Cert(certPem);
    const sigBuffer = Buffer.from(signatureBase64, "base64");

    try {
      const verifier = crypto.createVerify(algo);
      verifier.update(data, "utf8");
      if (verifier.verify(formatted, sigBuffer)) return true;
    } catch {
      // Fallback: try converting CERTIFICATE header to PUBLIC KEY or vice-versa
      try {
        const altPem = formatted.includes("CERTIFICATE")
          ? formatted.replace(/CERTIFICATE/g, "PUBLIC KEY")
          : formatted.replace(/PUBLIC KEY/g, "CERTIFICATE");
        const altVerifier = crypto.createVerify(algo);
        altVerifier.update(data, "utf8");
        return altVerifier.verify(altPem, sigBuffer);
      } catch {
        return false;
      }
    }
    return false;
  } catch (err) {
    return false;
  }
}

/**
 * Extract an XML tag's inner text or attributes cleanly
 */
function getTagContent(xml, tagName) {
  const regex = new RegExp(`<(?:[a-zA-Z0-9_]+:)?${tagName}\\b[^>]*>([\\s\\S]*?)<\\/(?:[a-zA-Z0-9_]+:)?${tagName}>`, "i");
  const match = xml.match(regex);
  return match ? match[1].trim() : null;
}

function getTagAttribute(xml, tagName, attrName) {
  const regex = new RegExp(`<(?:[a-zA-Z0-9_]+:)?${tagName}\\b[^>]*\\b${attrName}="([^"]*)"`, "i");
  const match = xml.match(regex);
  return match ? match[1] : null;
}

/**
 * Parse SAML 2.0 Response XML and verify cryptographic signature, anti-replay, and time conditions
 * @param {Object} options
 * @param {string} options.samlResponse - Base64 encoded or raw XML string
 * @param {string|string[]} options.idpCertificates - One or more trusted X.509 certs
 * @param {string} options.spEntityId - Expected Service Provider Entity ID / Audience
 * @param {number} [options.clockSkewSeconds=60] - Allowable clock skew
 * @param {Object} [options.replayStore] - Assertion ID replay store
 * @returns {Promise<Object>} Verified assertion identity & attributes
 */
async function verifySamlResponse({
  samlResponse,
  idpCertificates,
  spEntityId,
  clockSkewSeconds = 60,
  replayStore
}) {
  if (!samlResponse) throw new SsoError("SAML Response is required", "ERR_MISSING_SAML_RESPONSE");
  if (!idpCertificates || (Array.isArray(idpCertificates) && idpCertificates.length === 0)) {
    throw new SsoError("IdP X.509 certificate is required for verification", "ERR_MISSING_IDP_CERT");
  }

  // 1. Decode Base64 if needed
  let rawXml = samlResponse.trim();
  if (!rawXml.startsWith("<")) {
    try {
      rawXml = Buffer.from(rawXml, "base64").toString("utf8");
    } catch {
      throw new SsoError("Failed to decode Base64 SAMLResponse", "ERR_INVALID_SAML_BASE64");
    }
  }

  // 2. XXE (XML External Entity) Protection
  if (/<!DOCTYPE/i.test(rawXml) || /<!ENTITY/i.test(rawXml)) {
    throw new SsoError("XML DOCTYPE and ENTITY declarations are forbidden for security", "ERR_XXE_DETECTED");
  }

  // 3. Extract Assertion element
  const assertionMatch = rawXml.match(/<(?:[a-zA-Z0-9_]+:)?Assertion\b[\s\S]*?<\/(?:[a-zA-Z0-9_]+:)?Assertion>/i);
  if (!assertionMatch) {
    throw new SsoError("SAML Response does not contain a valid <Assertion> element", "ERR_MISSING_ASSERTION");
  }
  const assertionXml = assertionMatch[0];

  // XML Signature Wrapping (XSW) Defense: Ensure only one Assertion is present
  const allAssertions = rawXml.match(/<(?:[a-zA-Z0-9_]+:)?Assertion\b/gi) || [];
  if (allAssertions.length > 1) {
    throw new SsoError("Multiple <Assertion> elements detected in SAML response (potential XSW attack)", "ERR_XSW_DETECTED");
  }

  // 4. Extract Assertion ID
  const assertionId = getTagAttribute(assertionXml, "Assertion", "ID") ||
    getTagAttribute(rawXml, "Response", "ID");
  if (!assertionId) {
    throw new SsoError("SAML Assertion is missing an ID attribute", "ERR_MISSING_ASSERTION_ID");
  }

  // 5. Anti-Replay Assertion ID check
  if (replayStore) {
    const isReplayed = typeof replayStore.isAssertionReplayed === "function"
      ? await replayStore.isAssertionReplayed(assertionId)
      : (typeof replayStore.isUsed === "function"
        ? await replayStore.isUsed(assertionId)
        : false);
    if (isReplayed) {
      throw new SsoError(`SAML Assertion ID '${assertionId}' has already been processed`, "ERR_SAML_ASSERTION_REPLAYED");
    }
    if (typeof replayStore.recordAssertion === "function") {
      await replayStore.recordAssertion(assertionId, 10 * 60); // 10 minutes TTL
    } else if (typeof replayStore.record === "function") {
      await replayStore.record(assertionId, 10 * 60);
    }
  }

  // 6. Time Validity & Conditions
  const notBeforeStr = getTagAttribute(assertionXml, "Conditions", "NotBefore");
  const notOnOrAfterStr = getTagAttribute(assertionXml, "Conditions", "NotOnOrAfter");
  const now = Date.now();

  if (notBeforeStr) {
    const notBefore = new Date(notBeforeStr).getTime();
    if (!Number.isNaN(notBefore) && now + clockSkewSeconds * 1000 < notBefore) {
      throw new SsoError(`SAML Assertion is not yet valid (NotBefore: ${notBeforeStr})`, "ERR_SAML_TIMESTAMP_OUTSIDE_TOLERANCE");
    }
  }

  if (notOnOrAfterStr) {
    const notOnOrAfter = new Date(notOnOrAfterStr).getTime();
    if (!Number.isNaN(notOnOrAfter) && now - clockSkewSeconds * 1000 >= notOnOrAfter) {
      throw new SsoError(`SAML Assertion has expired (NotOnOrAfter: ${notOnOrAfterStr})`, "ERR_SAML_TIMESTAMP_OUTSIDE_TOLERANCE");
    }
  }

  // 7. Audience Restriction Check
  if (spEntityId) {
    const audience = getTagContent(assertionXml, "Audience");
    if (audience && audience !== spEntityId) {
      throw new SsoError(`SAML Audience mismatch: expected '${spEntityId}' but received '${audience}'`, "ERR_SAML_AUDIENCE_MISMATCH");
    }
  }

  // 8. Signature & Certificate Verification
  const signedInfoMatch = rawXml.match(/<(?:[a-zA-Z0-9_]+:)?SignedInfo\b[\s\S]*?<\/(?:[a-zA-Z0-9_]+:)?SignedInfo>/i);
  const signatureValueMatch = rawXml.match(/<(?:[a-zA-Z0-9_]+:)?SignatureValue\b[^>]*>([\s\S]*?)<\/(?:[a-zA-Z0-9_]+:)?SignatureValue>/i);
  const digestValueMatch = rawXml.match(/<(?:[a-zA-Z0-9_]+:)?DigestValue\b[^>]*>([\s\S]*?)<\/(?:[a-zA-Z0-9_]+:)?DigestValue>/i);

  if (!signedInfoMatch || !signatureValueMatch || !digestValueMatch) {
    throw new SsoError("SAML Response is unsigned or missing XML digital signature elements", "ERR_MISSING_SIGNATURE");
  }

  const rawSignedInfo = signedInfoMatch[0];
  const signatureValue = signatureValueMatch[1].replace(/[\r\n\s]/g, "");
  const expectedDigest = digestValueMatch[1].replace(/[\r\n\s]/g, "");

  // Detect signature algorithm
  const sigMethodMatch = rawSignedInfo.match(/SignatureMethod\s+Algorithm="([^"]*)"/i);
  const sigAlgorithm = sigMethodMatch && sigMethodMatch[1].includes("sha1") ? "RSA-SHA1" : "RSA-SHA256";

  // Check Digest of target element
  const canonicalSignedInfo = canonicalizeXml(rawSignedInfo);
  // Remove <Signature> element from Assertion to compute enveloped digest
  const assertionWithoutSignature = assertionXml.replace(/<(?:[a-zA-Z0-9_]+:)?Signature\b[\s\S]*?<\/(?:[a-zA-Z0-9_]+:)?Signature>/i, "");
  const canonicalAssertion = canonicalizeXml(assertionWithoutSignature);
  const computedDigest = computeXmlDigest(canonicalAssertion, sigAlgorithm);

  if (computedDigest !== expectedDigest) {
    // If enveloped assertion digest does not match, check response-level signed digest
    const responseWithoutSignature = rawXml.replace(/<(?:[a-zA-Z0-9_]+:)?Signature\b[\s\S]*?<\/(?:[a-zA-Z0-9_]+:)?Signature>/i, "");
    const canonicalResponse = canonicalizeXml(responseWithoutSignature);
    const computedResponseDigest = computeXmlDigest(canonicalResponse, sigAlgorithm);
    if (computedResponseDigest !== expectedDigest) {
      throw new SsoError("SAML XML DigestValue mismatch (tampered payload or canonicalization mismatch)", "ERR_SAML_DIGEST_MISMATCH");
    }
  }

  // Verify RSA signature against available trusted certificates (supporting dual rolling certificates)
  const certList = Array.isArray(idpCertificates) ? idpCertificates : [idpCertificates];
  let signatureValid = false;
  let verifiedCertIndex = -1;

  for (let i = 0; i < certList.length; i++) {
    const cert = certList[i];
    if (verifyRsaSignature(canonicalSignedInfo, signatureValue, cert, sigAlgorithm)) {
      signatureValid = true;
      verifiedCertIndex = i;
      break;
    }
  }

  if (!signatureValid) {
    throw new SsoError("SAML Signature verification failed against trusted IdP certificates", "ERR_SAML_SIGNATURE_MISMATCH");
  }

  // 9. Extract Subject NameID (User identifier / Email)
  const nameId = getTagContent(assertionXml, "NameID");
  if (!nameId) {
    throw new SsoError("SAML Assertion is missing a Subject <NameID> element", "ERR_MISSING_NAMEID");
  }

  // 10. Extract Attributes
  const attributes = {};
  const attrRegex = /<(?:[a-zA-Z0-9_]+:)?Attribute\b[^>]*\bName="([^"]*)"[\s\S]*?<\/(?:[a-zA-Z0-9_]+:)?Attribute>/gi;
  let attrBlock;
  while ((attrBlock = attrRegex.exec(assertionXml)) !== null) {
    const attrName = attrBlock[1];
    const valRegex = /<(?:[a-zA-Z0-9_]+:)?AttributeValue\b[^>]*>([\s\S]*?)<\/(?:[a-zA-Z0-9_]+:)?AttributeValue>/gi;
    const values = [];
    let valMatch;
    while ((valMatch = valRegex.exec(attrBlock[0])) !== null) {
      values.push(valMatch[1].trim());
    }
    attributes[attrName] = values.length <= 1 ? (values[0] || "") : values;
  }

  // Standard claim shortcuts
  const emailClaim = attributes["email"] ||
    attributes["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"] ||
    (nameId.includes("@") ? nameId : null);

  const firstName = attributes["firstName"] ||
    attributes["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"] ||
    "";
  const lastName = attributes["lastName"] ||
    attributes["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"] ||
    "";
  const displayName = attributes["displayName"] ||
    attributes["http://schemas.microsoft.com/identity/claims/displayname"] ||
    [firstName, lastName].filter(Boolean).join(" ") ||
    undefined;

  const groups = attributes["groups"] ||
    attributes["http://schemas.xmlsoap.org/claims/Group"] ||
    [];

  return {
    nameId,
    email: emailClaim ? emailClaim.toLowerCase().trim() : nameId.toLowerCase().trim(),
    displayName,
    firstName,
    lastName,
    groups: Array.isArray(groups) ? groups : [groups].filter(Boolean),
    attributes,
    assertionId,
    promotedCert: verifiedCertIndex > 0 ? certList[verifiedCertIndex] : null
  };
}

/**
 * Generate SAML 2.0 <samlp:AuthnRequest> XML and HTTP-Redirect query parameters
 * @param {Object} options
 * @param {string} options.spEntityId - Service Provider Entity ID
 * @param {string} options.acsUrl - Assertion Consumer Service URL
 * @param {string} options.idpSsoUrl - Target IdP Single Sign-On URL
 * @param {string} [options.relayState] - Opaque client state
 * @returns {{ id: string, xml: string, redirectUrl: string }}
 */
function generateSamlAuthnRequest({ spEntityId, acsUrl, idpSsoUrl, relayState }) {
  if (!spEntityId) throw new SsoError("spEntityId is required to generate AuthnRequest", "ERR_CONFIG");
  if (!acsUrl) throw new SsoError("acsUrl is required to generate AuthnRequest", "ERR_CONFIG");
  if (!idpSsoUrl) throw new SsoError("idpSsoUrl is required to generate AuthnRequest", "ERR_CONFIG");

  const id = `pfx_${randomUUID().replace(/-/g, "")}`;
  const instant = new Date().toISOString();

  const xml = [
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`,
    ` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`,
    ` ID="${id}"`,
    ` Version="2.0"`,
    ` IssueInstant="${instant}"`,
    ` Destination="${idpSsoUrl}"`,
    ` AssertionConsumerServiceURL="${acsUrl}"`,
    ` ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">`,
    `  <saml:Issuer>${spEntityId}</saml:Issuer>`,
    `  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>`,
    `</samlp:AuthnRequest>`
  ].join("\n");

  // Deflate + Base64 encode for HTTP-Redirect binding
  const deflated = deflateRaw(xml);
  const base64Request = deflated.toString("base64");

  const url = new URL(idpSsoUrl);
  url.searchParams.set("SAMLRequest", base64Request);
  if (relayState) {
    url.searchParams.set("RelayState", relayState);
  }

  return {
    id,
    xml,
    base64Request,
    redirectUrl: url.toString()
  };
}

/**
 * Generate standard SAML 2.0 Service Provider (SP) Metadata XML
 * @param {Object} options
 * @param {string} options.spEntityId
 * @param {string} options.acsUrl
 * @param {string} [options.sloUrl]
 * @param {string} [options.signingCert]
 * @returns {string} XML string
 */
function generateSpMetadataXml({ spEntityId, acsUrl, sloUrl, signingCert }) {
  const cleanCert = signingCert ? signingCert.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|[\r\n\s]/g, "") : null;

  return [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${spEntityId}">`,
    `  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`,
    cleanCert ? [
      `    <md:KeyDescriptor use="signing">`,
      `      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`,
      `        <ds:X509Data>`,
      `          <ds:X509Certificate>${cleanCert}</ds:X509Certificate>`,
      `        </ds:X509Data>`,
      `      </ds:KeyInfo>`,
      `    </md:KeyDescriptor>`
    ].join("\n") : "",
    sloUrl ? `    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${sloUrl}"/>` : "",
    `    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>`,
    `    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${acsUrl}" index="1" isDefault="true"/>`,
    `  </md:SPSSODescriptor>`,
    `</md:EntityDescriptor>`
  ].filter(Boolean).join("\n");
}

/**
 * Generate random 256-bit token for DNS TXT domain verification
 * @returns {string}
 */
function generateDomainVerificationToken() {
  return `devauth-domain-verification=${randomString(32, "hex")}`;
}

/**
 * Verify domain ownership via DNS TXT record matching _devauth-verify.<domain>
 * Supports DNS-over-HTTPS (DoH) or Node.js native dns
 * @param {string} domain - Domain name e.g. "acme.com"
 * @param {string} expectedToken - e.g. "devauth-domain-verification=..."
 * @param {Function} [customFetch] - Optional custom fetch override for testing/DoH
 * @returns {Promise<boolean>}
 */
async function verifyDomainTxt(domain, expectedToken, customFetch = null) {
  if (!domain || typeof domain !== "string") return false;
  if (!expectedToken || typeof expectedToken !== "string") return false;

  const cleanDomain = domain.toLowerCase().trim().replace(/^@/, "");
  const recordName = `_devauth-verify.${cleanDomain}`;

  // 1. Try Node.js dns.promises if available
  try {
    const dns = require("dns").promises;
    if (dns && typeof dns.resolveTxt === "function") {
      const records = await dns.resolveTxt(recordName);
      const flatRecords = records.flat();
      if (flatRecords.some((txt) => txt.includes(expectedToken))) {
        return true;
      }
    }
  } catch (err) {
    // Fall back to DNS-over-HTTPS (DoH)
  }

  // 2. DNS-over-HTTPS (DoH) fallback via Cloudflare (1.1.1.1)
  try {
    const fetchImpl = customFetch || globalThis.fetch;
    if (typeof fetchImpl === "function") {
      const dohUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(recordName)}&type=TXT`;
      const res = await fetchImpl(dohUrl, {
        headers: { Accept: "application/dns-json" }
      });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.Answer)) {
          for (const answer of data.Answer) {
            if (answer.data && answer.data.includes(expectedToken)) {
              return true;
            }
          }
        }
      }
    }
  } catch (err) {
    // Non-blocking catch
  }

  return false;
}

module.exports = {
  SsoError,
  formatX509Cert,
  canonicalizeXml,
  computeXmlDigest,
  verifyRsaSignature,
  verifySamlResponse,
  generateSamlAuthnRequest,
  generateSpMetadataXml,
  generateDomainVerificationToken,
  verifyDomainTxt,
  deflateRaw,
  inflateRaw
};
