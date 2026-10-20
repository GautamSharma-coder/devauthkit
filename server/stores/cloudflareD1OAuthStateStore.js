const { sha256Hex } = require("../utils/webCrypto");

function validateDatabase(database) {
  if (!database || typeof database.prepare !== "function" || typeof database.batch !== "function") {
    throw new TypeError("CloudflareD1OAuthStateStore requires a D1 database with prepare and batch methods");
  }
}

function validatePrefix(value) {
  if (typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new TypeError("CloudflareD1OAuthStateStore tablePrefix must be a valid SQL identifier prefix");
  }
  return value;
}

class CloudflareD1OAuthStateStore {
  constructor(database, options = {}) {
    validateDatabase(database);
    this.database = database;
    this.table = `${validatePrefix(options.tablePrefix || "devauthkit_oauth_")}states`;
  }

  async createTables() {
    await this.database.batch([
      this.database.prepare(
        `CREATE TABLE IF NOT EXISTS ${this.table} (` +
        "state_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)"
      ),
      this.database.prepare(
        `CREATE INDEX IF NOT EXISTS ${this.table}_expires_idx ON ${this.table}(expires_at)`
      )
    ]);
  }

  async put(state, expiresAt) {
    if (typeof state !== "string" || !state || !Number.isFinite(expiresAt)) {
      throw new TypeError("OAuth state and finite expiry are required");
    }
    const hash = await sha256Hex(state);
    const now = Date.now();
    await this.database.batch([
      this.database.prepare(`DELETE FROM ${this.table} WHERE expires_at <= ?`).bind(now),
      this.database.prepare(
        `INSERT INTO ${this.table} (state_hash, expires_at) VALUES (?, ?)`
      ).bind(hash, expiresAt)
    ]);
  }

  async consume(state) {
    if (typeof state !== "string" || !state) return false;
    const hash = await sha256Hex(state);
    const consumed = await this.database.prepare(
      `DELETE FROM ${this.table} WHERE state_hash = ? AND expires_at > ? RETURNING state_hash`
    ).bind(hash, Date.now()).first();
    return Boolean(consumed);
  }
}

module.exports = { CloudflareD1OAuthStateStore };
