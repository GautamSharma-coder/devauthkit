// server/core/webhookService.js
const {
  constantTimeEqual,
  hmacSha256Hex,
  randomString,
  randomUUID
} = require("../utils/webCrypto");

class WebhookVerificationError extends Error {
  constructor(message, code = "ERR_WEBHOOK_VERIFICATION_FAILED") {
    super(message);
    this.name = "WebhookVerificationError";
    this.code = code;
  }
}

/**
 * Generate cryptographically secure webhook secret prefixed with "whsec_"
 * @param {string} [prefix="whsec_"] - Optional custom secret prefix
 * @returns {string}
 */
function generateWebhookSecret(prefix = "whsec_") {
  return `${prefix}${randomString(32, "base64url")}`;
}

/**
 * Compute HMAC-SHA256 signature for signed payload: `${timestamp}.${payload}`
 * @param {string|Buffer} payload - Raw request body
 * @param {string} secret - Webhook signing secret ("whsec_...")
 * @param {number} timestamp - Unix epoch timestamp in seconds
 * @returns {Promise<string>} Hex-encoded HMAC signature
 */
async function computeWebhookSignature(payload, secret, timestamp) {
  if (!secret || typeof secret !== "string") {
    throw new TypeError("Webhook secret must be a non-empty string");
  }
  const payloadStr = typeof payload === "string" ? payload : payload.toString("utf8");
  const signedPayload = `${timestamp}.${payloadStr}`;
  return hmacSha256Hex(signedPayload, secret);
}

/**
 * Construct standard Stripe/Svix compatible DevAuth-Signature header
 * @param {string} signature - Hex HMAC signature
 * @param {number} timestamp - Unix timestamp in seconds
 * @returns {string} Formatted header e.g. "t=1729528000,v1=5257ab44..."
 */
function buildSignatureHeader(signature, timestamp) {
  return `t=${timestamp},v1=${signature}`;
}

/**
 * Parse standard signature header into timestamp and signature versions
 * @param {string} header - e.g. "t=1729528000,v1=5257ab...,v1=another..."
 * @returns {{ timestamp: number, signatures: string[] }}
 */
function parseSignatureHeader(header) {
  if (!header || typeof header !== "string") {
    throw new WebhookVerificationError("Missing or invalid signature header", "ERR_MISSING_HEADER");
  }

  const parts = header.trim().split(",");
  let timestamp = null;
  const signatures = [];

  for (const part of parts) {
    const [key, value] = part.split("=").map((s) => s.trim());
    if (key === "t") {
      const parsed = parseInt(value, 10);
      if (!Number.isNaN(parsed) && parsed > 0) {
        timestamp = parsed;
      }
    } else if (key === "v1" && value) {
      signatures.push(value.toLowerCase());
    }
  }

  if (!timestamp) {
    throw new WebhookVerificationError("Signature header missing valid timestamp 't'", "ERR_INVALID_TIMESTAMP");
  }
  if (signatures.length === 0) {
    throw new WebhookVerificationError("Signature header missing valid signature 'v1'", "ERR_INVALID_SIGNATURE");
  }

  return { timestamp, signatures };
}

/**
 * Verify webhook payload signature and freshness
 * @param {Object} options
 * @param {string|Buffer} options.payload - Raw body string or Buffer
 * @param {string} options.signatureHeader - Raw header value
 * @param {string} options.secret - Webhook signing secret
 * @param {number} [options.toleranceSeconds=300] - Replay tolerance window (default: 5 min)
 * @param {number} [options.currentTimestamp] - Optional override for current timestamp in seconds
 * @returns {Promise<Object>} Verified and parsed event object
 */
async function verifyWebhookSignature({
  payload,
  rawBody,
  signatureHeader,
  secret,
  toleranceSeconds = 300,
  currentTimestamp
}) {
  const content = payload !== undefined && payload !== null ? payload : rawBody;
  if (content === undefined || content === null) {
    throw new WebhookVerificationError("Webhook payload is required", "ERR_MISSING_PAYLOAD");
  }
  if (!secret || typeof secret !== "string") {
    throw new WebhookVerificationError("Webhook secret is required", "ERR_MISSING_SECRET");
  }

  const { timestamp, signatures } = parseSignatureHeader(signatureHeader);
  const now = currentTimestamp !== undefined ? currentTimestamp : Math.floor(Date.now() / 1000);

  // Anti-replay tolerance check
  if (Math.abs(now - timestamp) > toleranceSeconds) {
    throw new WebhookVerificationError(
      `Webhook timestamp outside tolerance window (${Math.abs(now - timestamp)}s > ${toleranceSeconds}s)`,
      "ERR_TIMESTAMP_OUTSIDE_TOLERANCE"
    );
  }

  const payloadStr = typeof content === "string" ? content : content.toString("utf8");
  const expectedSig = await computeWebhookSignature(payloadStr, secret, timestamp);

  const matched = signatures.some((sig) => constantTimeEqual(sig, expectedSig));
  if (!matched) {
    throw new WebhookVerificationError(
      "Webhook signature mismatch",
      "ERR_SIGNATURE_MISMATCH"
    );
  }

  try {
    return JSON.parse(payloadStr);
  } catch (err) {
    throw new WebhookVerificationError("Payload is not valid JSON", "ERR_INVALID_JSON");
  }
}

/**
 * Check if an event matches a subscription pattern (supports exact match & wildcards)
 * e.g. "org.*" matches "org.created", "org.member_added"
 * e.g. "*" matches any event
 * e.g. ["user.*", "org.*"] matches both user and org events
 * @param {string|string[]} pattern - Subscription pattern or array of patterns
 * @param {string} eventName - Actual event name
 * @returns {boolean}
 */
function matchesEvent(pattern, eventName) {
  if (!pattern || !eventName) return false;
  if (Array.isArray(pattern)) {
    return pattern.some((p) => matchesEvent(p, eventName));
  }
  if (pattern === "*" || pattern === eventName) return true;
  if (typeof pattern === "string" && pattern.endsWith(".*")) {
    const prefix = pattern.slice(0, -2);
    return eventName.startsWith(`${prefix}.`);
  }
  return false;
}

/**
 * Express middleware helper to consume verified webhooks
 * @param {Object} options
 * @param {string} options.secret - Webhook signing secret
 * @param {number} [options.toleranceSeconds=300]
 * @param {Function} options.onEvent - (event, req, res) handler
 */
function createWebhookHandler({ secret, toleranceSeconds = 300, onEvent }) {
  if (!secret) throw new TypeError("createWebhookHandler requires a secret");
  if (typeof onEvent !== "function") throw new TypeError("createWebhookHandler requires an onEvent function");

  return async function webhookMiddleware(req, res, next) {
    try {
      const header = req.headers["devauth-signature"] || req.headers["x-devauth-signature"];
      const rawBody = req.rawBody || req.body;
      const event = await verifyWebhookSignature({
        payload: rawBody,
        signatureHeader: header,
        secret,
        toleranceSeconds
      });
      const result = await onEvent(event, req, res);
      if (res && !res.headersSent) {
        return res.json({ received: true });
      }
      return result;
    } catch (err) {
      if (err instanceof WebhookVerificationError) {
        return res.status(400).json({ error: `Webhook verification failed: ${err.message}`, code: err.code });
      }
      if (typeof next === "function") return next(err);
      return res.status(500).json({ error: err.message });
    }
  };
}

module.exports = {
  WebhookVerificationError,
  generateWebhookSecret,
  computeWebhookSignature,
  buildSignatureHeader,
  parseSignatureHeader,
  verifyWebhookSignature,
  matchesEvent,
  createWebhookHandler
};
