// server/core/dpopService.js
const {
  cryptoApi,
  fromBase64Url,
  randomUUID,
  sha256Base64Url,
  toBase64Url
} = require("../utils/webCrypto");

const encoder = new TextEncoder();
const decoder = new TextDecoder();

class DPoPError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "DPoPError";
    this.status = status;
    this.code = code;
  }
}

/**
 * Normalizes an HTTP target URI by removing query strings and fragments.
 * Matches RFC 9449 Section 4.3.
 *
 * @param {string} uri
 * @returns {string}
 */
function normalizeTargetUri(uri) {
  if (typeof uri !== "string" || !uri.trim()) return "";
  try {
    const isRelative = uri.startsWith("/");
    const parsed = new URL(uri, "https://placeholder.internal");
    if (isRelative) {
      return parsed.pathname;
    }
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return uri.split("?")[0].split("#")[0];
  }
}

/**
 * Calculates the RFC 7638 SHA-256 JSON Web Key (JWK) Thumbprint for an EC P-256 key.
 * Member keys are lexicographically sorted: "crv", "kty", "x", "y".
 *
 * @param {Object} jwk
 * @returns {Promise<string>} Base64URL-encoded SHA-256 thumbprint
 */
async function calculateJwkThumbprint(jwk) {
  if (!jwk || typeof jwk !== "object") {
    throw new DPoPError(400, "invalid_dpop_proof", "Invalid JWK object for thumbprint");
  }
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new DPoPError(400, "invalid_dpop_proof", "Only EC P-256 keys are currently supported for DPoP");
  }

  // Canonical JSON representation: ordered keys without whitespace
  const canonicalJson = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y
  });

  return sha256Base64Url(canonicalJson);
}

/**
 * Calculates the Access Token Hash (ath) according to RFC 9449 Section 4.2.
 * ath = Base64URL(SHA-256(ASCII(access_token)))
 *
 * @param {string} accessToken
 * @returns {Promise<string>}
 */
async function calculateAccessTokenHash(accessToken) {
  if (typeof accessToken !== "string" || !accessToken) {
    throw new DPoPError(400, "invalid_dpop_proof", "Access token must be a non-empty string");
  }
  return sha256Base64Url(accessToken);
}

/**
 * Generates an ECDSA P-256 key pair suitable for DPoP signing.
 *
 * @returns {Promise<{ keyPair: CryptoKeyPair, jwk: Object, privateKey: CryptoKey, publicKey: CryptoKey }>}
 */
async function generateDPoPKeyPair() {
  const subtle = cryptoApi().subtle;
  const keyPair = await subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );

  const exportedJwk = await subtle.exportKey("jwk", keyPair.publicKey);
  const publicJwk = {
    kty: exportedJwk.kty,
    crv: exportedJwk.crv,
    x: exportedJwk.x,
    y: exportedJwk.y
  };

  return {
    keyPair,
    jwk: publicJwk,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey
  };
}

/**
 * Creates and signs an RFC 9449 DPoP proof JWT.
 *
 * @param {Object} options
 * @param {CryptoKey} options.privateKey - Private key for signing
 * @param {Object} options.jwk - Public JWK to embed in header
 * @param {string} options.method - HTTP method (e.g. "POST", "GET")
 * @param {string} options.uri - Target URI (e.g. "https://api.example.com/auth/verify-otp")
 * @param {string} [options.accessToken] - Associated access token (adds ath claim)
 * @param {string} [options.nonce] - Server nonce
 * @param {string} [options.jti] - Unique JWT ID (defaults to UUID)
 * @param {number} [options.iat] - Epoch seconds (defaults to current time)
 * @returns {Promise<string>} Signed DPoP proof JWT
 */
async function createDPoPProof({
  privateKey,
  jwk,
  method,
  uri,
  accessToken,
  nonce,
  jti,
  iat
}) {
  if (!privateKey || !jwk) {
    throw new TypeError("DPoP proof generation requires privateKey and public jwk");
  }
  if (!method || !uri) {
    throw new TypeError("DPoP proof generation requires method and uri");
  }

  const subtle = cryptoApi().subtle;
  const now = Math.floor(Date.now() / 1000);

  const headerObj = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y
    }
  };

  const payloadObj = {
    jti: jti || randomUUID(),
    htm: method.toUpperCase(),
    htu: normalizeTargetUri(uri),
    iat: typeof iat === "number" ? iat : now
  };

  if (accessToken) {
    payloadObj.ath = await calculateAccessTokenHash(accessToken);
  }

  if (nonce) {
    payloadObj.nonce = nonce;
  }

  const encodedHeader = toBase64Url(encoder.encode(JSON.stringify(headerObj)));
  const encodedPayload = toBase64Url(encoder.encode(JSON.stringify(payloadObj)));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signatureBuffer = await subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    privateKey,
    encoder.encode(signingInput)
  );

  const signatureBase64 = toBase64Url(new Uint8Array(signatureBuffer));
  return `${signingInput}.${signatureBase64}`;
}

/**
 * Verifies an RFC 9449 DPoP proof JWT.
 *
 * @param {Object} options
 * @param {string} options.proofJwt - The raw DPoP proof JWT string from the DPoP header
 * @param {string} options.expectedMethod - The HTTP method of the request
 * @param {string} options.expectedUri - The target URI of the request
 * @param {string} [options.expectedAccessToken] - The access token presented with the request
 * @param {string} [options.expectedNonce] - Server nonce if nonce checking is enforced
 * @param {Object} [options.replayStore] - Store implementing record(jti, ttl) for replay protection
 * @param {number} [options.maxClockSkewSeconds=60] - Allowed clock skew in seconds
 * @param {number} [options.currentTime=Date.now()] - Current epoch timestamp in ms (for testing)
 * @returns {Promise<{ valid: boolean, jkt: string, payload: Object, jwk: Object }>}
 */
async function verifyDPoPProof({
  proofJwt,
  expectedMethod,
  expectedUri,
  expectedAccessToken,
  expectedNonce,
  replayStore,
  maxClockSkewSeconds = 60,
  currentTime = Date.now()
}) {
  if (typeof proofJwt !== "string" || !proofJwt.trim()) {
    throw new DPoPError(400, "invalid_dpop_proof", "Missing or malformed DPoP proof header");
  }

  const parts = proofJwt.split(".");
  if (parts.length !== 3) {
    throw new DPoPError(400, "invalid_dpop_proof", "DPoP proof must be a compact 3-part JWT");
  }

  let header;
  let payload;
  try {
    header = JSON.parse(decoder.decode(fromBase64Url(parts[0])));
  } catch {
    throw new DPoPError(400, "invalid_dpop_proof", "DPoP proof header is not valid JSON");
  }

  try {
    payload = JSON.parse(decoder.decode(fromBase64Url(parts[1])));
  } catch {
    throw new DPoPError(400, "invalid_dpop_proof", "DPoP proof payload is not valid JSON");
  }

  // 1. Validate Header
  if (header.typ !== "dpop+jwt") {
    throw new DPoPError(400, "invalid_dpop_proof", `Invalid DPoP header typ: expected 'dpop+jwt', got '${header.typ}'`);
  }

  if (header.alg !== "ES256") {
    throw new DPoPError(400, "invalid_dpop_proof", `Unsupported DPoP algorithm '${header.alg}'. Only ES256 is supported`);
  }

  if (!header.jwk || typeof header.jwk !== "object") {
    throw new DPoPError(400, "invalid_dpop_proof", "DPoP proof header must contain a public 'jwk'");
  }

  // RFC 9449 Section 4.2: MUST NOT contain private key material
  if (header.jwk.d !== undefined) {
    throw new DPoPError(400, "invalid_dpop_proof", "DPoP public JWK must not contain private key material ('d')");
  }

  if (header.jwk.kty !== "EC" || header.jwk.crv !== "P-256" || !header.jwk.x || !header.jwk.y) {
    throw new DPoPError(400, "invalid_dpop_proof", "DPoP JWK must be an EC P-256 key with 'x' and 'y' coordinates");
  }

  // 2. Validate Cryptographic Signature
  const subtle = cryptoApi().subtle;
  let importedPublicKey;
  try {
    importedPublicKey = await subtle.importKey(
      "jwk",
      {
        kty: header.jwk.kty,
        crv: header.jwk.crv,
        x: header.jwk.x,
        y: header.jwk.y
      },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
  } catch (error) {
    throw new DPoPError(400, "invalid_dpop_proof", `Failed to import DPoP public JWK: ${error.message}`);
  }

  const signingInput = `${parts[0]}.${parts[1]}`;
  const signatureBytes = fromBase64Url(parts[2]);

  let isValidSignature = false;
  try {
    isValidSignature = await subtle.verify(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      importedPublicKey,
      signatureBytes,
      encoder.encode(signingInput)
    );
  } catch (error) {
    throw new DPoPError(401, "invalid_dpop_proof", `Cryptographic verification error: ${error.message}`);
  }

  if (!isValidSignature) {
    throw new DPoPError(401, "invalid_dpop_proof", "Invalid DPoP proof signature");
  }

  // 3. Validate Payload Claims
  if (typeof payload.jti !== "string" || !payload.jti.trim()) {
    throw new DPoPError(400, "invalid_dpop_proof", "DPoP proof requires a unique 'jti' claim");
  }

  // 3.1 HTTP Method (htm)
  if (typeof payload.htm !== "string" || !payload.htm.trim()) {
    throw new DPoPError(400, "invalid_dpop_proof", "DPoP proof requires an 'htm' (HTTP method) claim");
  }
  if (expectedMethod && payload.htm.toUpperCase() !== expectedMethod.toUpperCase()) {
    throw new DPoPError(
      401,
      "invalid_dpop_proof",
      `DPoP method mismatch: proof specifies '${payload.htm}', request method is '${expectedMethod}'`
    );
  }

  // 3.2 HTTP Target URI (htu)
  if (typeof payload.htu !== "string" || !payload.htu.trim()) {
    throw new DPoPError(400, "invalid_dpop_proof", "DPoP proof requires an 'htu' (HTTP target URI) claim");
  }

  if (expectedUri) {
    const normalizedProofUri = normalizeTargetUri(payload.htu);
    const normalizedExpectedUri = normalizeTargetUri(expectedUri);

    // Allow match if full URL matches, or if paths match when one is relative
    const urisMatch =
      normalizedProofUri === normalizedExpectedUri ||
      (normalizedProofUri.startsWith("/") && normalizedExpectedUri.endsWith(normalizedProofUri)) ||
      (normalizedExpectedUri.startsWith("/") && normalizedProofUri.endsWith(normalizedExpectedUri));

    if (!urisMatch) {
      throw new DPoPError(
        401,
        "invalid_dpop_proof",
        `DPoP target URI mismatch: proof specifies '${normalizedProofUri}', expected '${normalizedExpectedUri}'`
      );
    }
  }

  // 3.3 Creation Timestamp (iat) & Clock Skew
  if (typeof payload.iat !== "number" || !Number.isFinite(payload.iat)) {
    throw new DPoPError(400, "invalid_dpop_proof", "DPoP proof requires a numeric 'iat' claim");
  }

  const nowSeconds = Math.floor(currentTime / 1000);
  const skew = Math.abs(nowSeconds - payload.iat);
  if (skew > maxClockSkewSeconds) {
    throw new DPoPError(
      401,
      "invalid_dpop_proof",
      `DPoP proof timestamp outside acceptable window (clock skew: ${skew}s, max allowed: ${maxClockSkewSeconds}s)`
    );
  }

  // 3.4 Access Token Hash (ath)
  if (expectedAccessToken) {
    if (!payload.ath || typeof payload.ath !== "string") {
      throw new DPoPError(401, "invalid_dpop_proof", "DPoP proof missing required 'ath' claim for access token binding");
    }
    const expectedAth = await calculateAccessTokenHash(expectedAccessToken);
    if (payload.ath !== expectedAth) {
      throw new DPoPError(401, "invalid_dpop_proof", "DPoP 'ath' claim does not match the presented access token");
    }
  }

  // 3.5 Server Nonce (if required)
  if (expectedNonce) {
    if (!payload.nonce || payload.nonce !== expectedNonce) {
      throw new DPoPError(401, "use_dpop_nonce", "DPoP proof requires a valid and fresh server nonce");
    }
  }

  // 4. Replay Protection
  if (replayStore && typeof replayStore.record === "function") {
    let isNew;
    try {
      isNew = await replayStore.record(payload.jti, maxClockSkewSeconds * 2);
    } catch (error) {
      const storeError = new DPoPError(
        503,
        "dpop_replay_store_unavailable",
        "DPoP replay store could not record the proof"
      );
      storeError.cause = error;
      throw storeError;
    }
    if (!isNew) {
      throw new DPoPError(401, "invalid_dpop_proof", `DPoP proof replay detected: jti '${payload.jti}' has already been used`);
    }
  }

  // 5. Compute JWK Thumbprint (jkt)
  const jkt = await calculateJwkThumbprint(header.jwk);

  return {
    valid: true,
    jkt,
    payload,
    jwk: header.jwk
  };
}

module.exports = {
  DPoPError,
  calculateAccessTokenHash,
  calculateJwkThumbprint,
  createDPoPProof,
  generateDPoPKeyPair,
  normalizeTargetUri,
  verifyDPoPProof
};
