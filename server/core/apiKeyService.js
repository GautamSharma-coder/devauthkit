// server/core/apiKeyService.js
const { sha256Hex, randomString, randomUUID } = require("../utils/webCrypto");

// Standard CRC32 lookup table
const CRC_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) {
    c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  }
  CRC_TABLE[i] = c;
}

/**
 * Calculates 8-character hex CRC32 checksum for fast-path validation
 * @param {string} str
 * @returns {string} 8-character lowercase hex string
 */
function crc32Hex(str) {
  let crc = 0xffffffff;
  const len = str.length;
  for (let i = 0; i < len; i++) {
    const byte = str.charCodeAt(i) & 0xff;
    crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return ((crc ^ 0xffffffff) >>> 0).toString(16).padStart(8, "0");
}

/**
 * Verifies format and CRC32 checksum of an API key in < 0.01ms
 * @param {string} rawKey - Full API key string
 * @returns {boolean}
 */
function verifyKeyChecksum(rawKey) {
  if (typeof rawKey !== "string") return false;
  const parts = rawKey.split("_");
  // Expected format: dak_live_<entropy>_<crc32> or dak_test_<entropy>_<crc32>
  if (parts.length !== 4) return false;
  const [prefix, env, entropy, checksum] = parts;
  if (prefix !== "dak") return false;
  if (env !== "live" && env !== "test") return false;
  if (!entropy || entropy.length < 24) return false;
  if (!checksum || checksum.length !== 8) return false;

  const payload = `${prefix}_${env}_${entropy}`;
  const computed = crc32Hex(payload);
  return computed.toLowerCase() === checksum.toLowerCase();
}

/**
 * Hashes raw API key into secure salted SHA-256 digest for storage
 * @param {string} rawKey
 * @param {string} [salt=""]
 * @returns {Promise<string>}
 */
async function hashApiKey(rawKey, salt = "devauthkit_key_salt_") {
  return sha256Hex(`${salt}:${rawKey}`);
}

/**
 * Evaluates whether an API key's granted scopes satisfy required scopes
 * Supports exact match, wildcard '*', and hierarchical namespace wildcards ('org:*', 'org:billing:*')
 * @param {string[]|string} grantedScopes
 * @param {string[]|string} requiredScopes
 * @returns {boolean}
 */
function matchesScopes(grantedScopes, requiredScopes) {
  const granted = Array.isArray(grantedScopes)
    ? grantedScopes
    : typeof grantedScopes === "string"
      ? grantedScopes.split(/[,\s]+/).filter(Boolean)
      : [];

  const required = Array.isArray(requiredScopes)
    ? requiredScopes
    : typeof requiredScopes === "string"
      ? requiredScopes.split(/[,\s]+/).filter(Boolean)
      : [];

  if (required.length === 0) return true;
  if (granted.includes("*")) return true;

  return required.every((req) => {
    if (granted.includes(req)) return true;
    // Check hierarchical wildcards (e.g. "org:*" satisfies "org:read")
    const parts = req.split(":");
    for (let i = 1; i < parts.length; i++) {
      const parentWildcard = `${parts.slice(0, i).join(":")}:*`;
      if (granted.includes(parentWildcard)) return true;
    }
    return false;
  });
}

/**
 * Masks an API key for safe public display: dak_live_...a8b2c1d3
 * @param {string} rawKey
 * @returns {string}
 */
function maskApiKey(rawKey) {
  if (typeof rawKey !== "string" || rawKey.length < 16) return "dak_***";
  const prefix = rawKey.slice(0, 8); // e.g. "dak_live"
  const suffix = rawKey.slice(-8);   // CRC checksum
  return `${prefix}_...${suffix}`;
}

/**
 * Core ApiKeyService managing API key generation, validation, and caching
 */
class ApiKeyService {
  /**
   * @param {Object} options
   * @param {Object} [options.store] - ApiKeyStore
   * @param {number} [options.cacheTtlMs=60000] - Fast-path cache TTL (1 minute)
   */
  constructor(options = {}) {
    this.store = options.store || null;
    this.cacheTtlMs = options.cacheTtlMs || 60000;
    this._cache = new Map(); // digest -> { record, cachedAt }
  }

  setStore(store) {
    this.store = store;
  }

  /**
   * Generates a new cryptographically secure API key
   * @param {Object} params
   * @param {string} params.userId - User owner ID
   * @param {string} [params.orgId] - Organization ID
   * @param {string} params.name - Descriptive key name
   * @param {string[]|string} [params.scopes=["*"]] - Allowed scopes
   * @param {string} [params.env="live"] - "live" | "test"
   * @param {number} [params.expiresInDays] - Optional expiry in days
   * @returns {Promise<{ key: Object, rawKey: string }>}
   */
  async createKey(params) {
    if (!params.userId) throw new TypeError("userId is required to create an API key");
    if (!params.name || !params.name.trim()) throw new TypeError("Key name is required");

    const env = params.env === "test" ? "test" : "live";
    const entropy = randomString(24, "hex");
    const payload = `dak_${env}_${entropy}`;
    const checksum = crc32Hex(payload);
    const rawKey = `${payload}_${checksum}`;

    const keyId = `key_${randomUUID()}`;
    const keyDigest = await hashApiKey(rawKey);
    const keyPrefix = `dak_${env}`;
    const maskedKey = maskApiKey(rawKey);

    const scopes = Array.isArray(params.scopes)
      ? params.scopes
      : typeof params.scopes === "string"
        ? params.scopes.split(/[,\s]+/).filter(Boolean)
        : ["*"];

    const now = Date.now();
    const expiresAt = params.expiresInDays
      ? now + params.expiresInDays * 86400 * 1000
      : params.expiresAt || null;

    const keyRecord = {
      id: keyId,
      userId: params.userId,
      orgId: params.orgId || null,
      name: params.name.trim(),
      keyPrefix,
      keyDigest,
      crc32Checksum: checksum,
      maskedKey,
      scopes,
      status: "active",
      lastUsedAt: null,
      expiresAt,
      createdAt: now
    };

    if (this.store && typeof this.store.createKey === "function") {
      await this.store.createKey(keyRecord);
    }

    return {
      key: keyRecord,
      rawKey // Only returned once!
    };
  }

  /**
   * Fast-path verification of an API key
   * 1. CRC32 Checksum Check (< 0.01ms)
   * 2. In-Memory LRU Cache Hit (< 0.1ms)
   * 3. SHA-256 Digest Store Query (< 2ms)
   * @param {string} rawKey
   * @returns {Promise<Object|null>} Key record or null if invalid/revoked
   */
  async verifyKey(rawKey) {
    if (!rawKey || typeof rawKey !== "string") return null;

    // Stage 1: CRC32 Checksum fast-path (< 0.01ms)
    if (!verifyKeyChecksum(rawKey)) {
      return null;
    }

    // Stage 2: Digest Computation
    const digest = await hashApiKey(rawKey);

    // Check memory cache
    const cached = this._cache.get(digest);
    const now = Date.now();
    if (cached && (now - cached.cachedAt) < this.cacheTtlMs) {
      if (cached.record.status !== "active") return null;
      if (cached.record.expiresAt && cached.record.expiresAt < now) return null;
      return cached.record;
    }

    // Stage 3: Query Store
    if (!this.store || typeof this.store.getByKeyDigest !== "function") {
      return null;
    }

    const record = await this.store.getByKeyDigest(digest);
    if (!record || record.status !== "active") {
      this._cache.delete(digest);
      return null;
    }

    // Check expiration
    if (record.expiresAt && record.expiresAt < now) {
      this._cache.delete(digest);
      return null;
    }

    // Cache valid record
    this._cache.set(digest, { record, cachedAt: now });

    // Update lastUsedAt asynchronously
    if (typeof this.store.touchLastUsed === "function") {
      this.store.touchLastUsed(record.id, now).catch(() => {});
    }

    return record;
  }

  /**
   * Rotates an API key: revokes the old one and generates a fresh one with identical scopes
   * @param {string} keyId
   * @param {string} userId
   * @returns {Promise<{ key: Object, rawKey: string }>}
   */
  async rollKey(keyId, userId) {
    if (!this.store) throw new Error("Store is not configured");
    const existing = await this.store.getById(keyId);
    if (!existing) throw new Error("API key not found");
    if (existing.userId !== userId) throw new Error("Unauthorized to roll this API key");

    // Revoke old key
    await this.revokeKey(keyId, userId);

    // Generate replacement
    return this.createKey({
      userId: existing.userId,
      orgId: existing.orgId,
      name: existing.name,
      scopes: existing.scopes,
      env: existing.keyPrefix.includes("test") ? "test" : "live"
    });
  }

  async revokeKey(keyId, userId) {
    if (!this.store) throw new Error("Store is not configured");
    const existing = await this.store.getById(keyId);
    if (!existing) throw new Error("API key not found");
    if (existing.userId !== userId) throw new Error("Unauthorized to revoke this API key");

    // Clear from cache
    if (existing.keyDigest) {
      this._cache.delete(existing.keyDigest);
    }

    return this.store.revokeKey(keyId);
  }

  async listKeys(userId, orgId) {
    if (!this.store) return [];
    return this.store.listKeys({ userId, orgId });
  }

  async getById(keyId) {
    if (!this.store) return null;
    return this.store.getById(keyId);
  }

  async updateKey(keyId, userId, updates) {
    if (!this.store) throw new Error("Store is not configured");
    const existing = await this.store.getById(keyId);
    if (!existing) throw new Error("API key not found");
    if (existing.userId !== userId) throw new Error("Unauthorized to update this API key");

    if (existing.keyDigest) {
      this._cache.delete(existing.keyDigest);
    }

    return this.store.updateKey(keyId, updates);
  }
}

module.exports = {
  ApiKeyService,
  crc32Hex,
  verifyKeyChecksum,
  hashApiKey,
  matchesScopes,
  maskApiKey
};
