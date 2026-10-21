// server/stores/cloudflareD1DpopReplayStore.js
const { sha256Hex } = require("../utils/webCrypto");

function validateDatabase(database) {
  if (!database || typeof database.prepare !== "function" || typeof database.batch !== "function") {
    throw new TypeError("CloudflareD1DpopReplayStore requires a D1 database with prepare and batch methods");
  }
}

function validatePrefix(value) {
  if (typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new TypeError("CloudflareD1DpopReplayStore tablePrefix must be a valid SQL identifier prefix");
  }
  return value;
}

class CloudflareD1DpopReplayStore {
  constructor(database, options = {}) {
    validateDatabase(database);
    this.database = database;
    this.table = `${validatePrefix(options.tablePrefix || "devauthkit_dpop_replay_")}jtis`;
  }

  async createTables() {
    await this.database.batch([
      this.database.prepare(
        `CREATE TABLE IF NOT EXISTS ${this.table} (` +
        "jti_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)"
      ),
      this.database.prepare(
        `CREATE INDEX IF NOT EXISTS ${this.table}_expires_idx ON ${this.table}(expires_at)`
      )
    ]);
  }

  /**
   * Attempt to record a JTI in D1.
   * Returns true if newly recorded, false if already exists and active (replay).
   *
   * @param {string} jti - Unique JWT ID from the DPoP proof
   * @param {number} [ttlSeconds=120] - TTL in seconds
   * @returns {Promise<boolean>}
   */
  async record(jti, ttlSeconds = 120) {
    if (typeof jti !== "string" || !jti.trim()) {
      throw new TypeError("D1 DPoP replay store requires a non-empty jti string");
    }
    const jtiHash = await sha256Hex(jti);
    const now = Date.now();
    const expiresAt = now + Math.max(1, ttlSeconds) * 1000;

    const result = await this.database
      .prepare(
        `INSERT INTO ${this.table} (jti_hash, expires_at) VALUES (?, ?) ` +
        "ON CONFLICT(jti_hash) DO UPDATE SET expires_at = excluded.expires_at " +
        "WHERE expires_at <= ?"
      )
      .bind(jtiHash, expiresAt, now)
      .run();

    if (typeof result?.meta?.changes !== "number") {
      throw new Error("D1 DPoP replay store did not return a change count");
    }
    return result.meta.changes === 1;
  }

  /**
   * Check if a JTI has already been consumed.
   *
   * @param {string} jti
   * @returns {Promise<boolean>}
   */
  async isUsed(jti) {
    if (typeof jti !== "string" || !jti.trim()) return false;
    const jtiHash = await sha256Hex(jti);
    const now = Date.now();
    const row = await this.database
      .prepare(`SELECT expires_at FROM ${this.table} WHERE jti_hash = ? AND expires_at > ?`)
      .bind(jtiHash, now)
      .first();
    return Boolean(row);
  }

  /**
   * Delete expired entries.
   */
  async cleanup() {
    const now = Date.now();
    await this.database
      .prepare(`DELETE FROM ${this.table} WHERE expires_at <= ?`)
      .bind(now)
      .run();
  }
}

module.exports = { CloudflareD1DpopReplayStore };
