// server/core/auditLogService.js
const { sha256Hex, randomUUID } = require("../utils/webCrypto");

const GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

/**
 * Deterministically computes the SHA-256 Merkle hash for an audit log entry
 * @param {string} prevHash - SHA-256 digest of preceding audit log entry
 * @param {Object} entry - Audit log entry fields
 * @returns {Promise<string>} Hex-encoded SHA-256 digest
 */
async function computeEntryHash(prevHash, entry) {
  const normalizedPrev = prevHash || GENESIS_HASH;
  const ts = entry.timestamp || entry.createdAt || 0;
  const canonicalData = [
    normalizedPrev,
    ts,
    entry.actorId || "system",
    entry.actorType || "system",
    entry.eventType || "unknown",
    entry.targetId || "",
    entry.orgId || "",
    entry.ipAddress || "",
    entry.metadata ? JSON.stringify(entry.metadata) : "{}"
  ].join("|");

  return sha256Hex(canonicalData);
}

/**
 * AuditLogService handles immutable, tamper-evident audit trail management
 */
class AuditLogService {
  /**
   * @param {Object} options
   * @param {Object} [options.store] - Audit log store implementation
   * @param {boolean} [options.enabled=true] - Whether audit logging is active
   */
  constructor(options = {}) {
    this.store = options.store || null;
    this.enabled = options.enabled !== false;
    this.lastHash = GENESIS_HASH;
    this._flushScheduled = false;
    this._queue = [];
  }

  setStore(store) {
    this.store = store;
  }

  /**
   * Records a security or system event into the audit trail
   * Non-blocking: computes hash and appends asynchronously.
   * @param {Object} event
   * @param {string} event.eventType - e.g. "user.login_succeeded", "session.revoked"
   * @param {string} [event.actorId] - ID of user, API key, or system agent
   * @param {string} [event.actorType="user"] - "user" | "apikey" | "system" | "impersonator"
   * @param {string} [event.targetId] - Target resource ID
   * @param {string} [event.orgId] - Workspace / Organization context
   * @param {string} [event.ipAddress] - Originating IP address
   * @param {string} [event.userAgent] - Originating User-Agent
   * @param {Object} [event.metadata] - Structured event metadata
   * @returns {Promise<Object>} Created audit log entry
   */
  async record(event) {
    if (!this.enabled) return null;

    const id = `aud_${randomUUID()}`;
    const timestamp = event.timestamp || Date.now();
    const actorId = event.actorId || "system";
    const actorType = event.actorType || "user";
    const targetId = event.targetId || null;
    const orgId = event.orgId || null;
    const eventType = event.eventType;
    const ipAddress = event.ipAddress || null;
    const userAgent = event.userAgent || null;
    const metadata = event.metadata || {};

    // Get the previous hash from store or memory
    let prevHash = this.lastHash;
    if (this.store && typeof this.store.getLastHash === "function") {
      try {
        const storedLastHash = await this.store.getLastHash();
        if (storedLastHash) prevHash = storedLastHash;
      } catch {
        // Fall back to memory lastHash
      }
    }

    const partialEntry = {
      timestamp,
      actorId,
      actorType,
      targetId,
      orgId,
      eventType,
      ipAddress,
      metadata
    };

    const entryHash = await computeEntryHash(prevHash, partialEntry);
    this.lastHash = entryHash;

    const record = {
      id,
      orgId,
      actorId,
      actorType,
      targetId,
      eventType,
      ipAddress,
      userAgent,
      prevHash,
      entryHash,
      metadata,
      timestamp,
      createdAt: timestamp
    };

    if (this.store && typeof this.store.createEntry === "function") {
      try {
        await this.store.createEntry(record);
      } catch (err) {
        console.error("[DevAuthKit] Failed to persist audit log entry:", err);
      }
    }

    return record;
  }

  /**
   * Queries audit logs with filtering and pagination
   * @param {Object} filters
   * @param {string} [filters.actorId]
   * @param {string} [filters.eventType]
   * @param {string} [filters.orgId]
   * @param {string} [filters.targetId]
   * @param {number} [filters.since]
   * @param {number} [filters.until]
   * @param {number} [filters.limit=50]
   * @param {number} [filters.offset=0]
   * @returns {Promise<{ entries: Array, total: number }>}
   */
  async query(filters = {}) {
    if (!this.store || typeof this.store.query !== "function") {
      return { entries: [], total: 0 };
    }
    return this.store.query(filters);
  }

  /**
   * Retrieves a single audit log entry by ID
   * @param {string} id
   * @returns {Promise<Object|null>}
   */
  async getById(id) {
    if (!this.store || typeof this.store.getById !== "function") {
      return null;
    }
    return this.store.getById(id);
  }

  /**
   * Exports audit logs formatted as Newline-Delimited JSON (NDJSON) for SIEM ingestion
   * @param {Object} filters
   * @returns {Promise<string>}
   */
  async exportNdjson(filters = {}) {
    const { entries } = await this.query({ ...filters, limit: filters.limit || 1000 });
    return entries.map((entry) => JSON.stringify(entry)).join("\n");
  }

  /**
   * Verifies the cryptographic Merkle hash chain across a sequential array of records
   * @param {Array<Object>} records - Chronologically ordered audit records
   * @returns {Promise<{ valid: boolean, brokenIndex: number|null, message: string }>}
   */
  static async verifyChain(records) {
    if (!Array.isArray(records) || records.length === 0) {
      return { valid: true, brokenIndex: null, message: "Chain is empty" };
    }

    for (let i = 0; i < records.length; i++) {
      const current = records[i];
      const expectedPrev = i === 0 ? current.prevHash : records[i - 1].entryHash;

      if (current.prevHash !== expectedPrev) {
        return {
          valid: false,
          brokenIndex: i,
          message: `Hash link broken at index ${i}: prevHash does not match entryHash of index ${i - 1}`
        };
      }

      const computedHash = await computeEntryHash(current.prevHash, current);
      if (computedHash !== current.entryHash) {
        return {
          valid: false,
          brokenIndex: i,
          message: `Digest mismatch at index ${i}: stored entryHash does not match computed digest`
        };
      }
    }

    return { valid: true, brokenIndex: null, message: "Cryptographic chain verified" };
  }
}

/**
 * Global helper to record an audit log event
 * @param {Object} event
 * @returns {Promise<Object|null>}
 */
function emitAuditLog(event) {
  try {
    const config = require("../config");
    const auditService = config.get("auditService");
    if (auditService && typeof auditService.record === "function") {
      return auditService.record(event);
    }
  } catch {
    // Non-blocking catch
  }
  return Promise.resolve(null);
}

module.exports = {
  AuditLogService,
  computeEntryHash,
  emitAuditLog,
  GENESIS_HASH
};
