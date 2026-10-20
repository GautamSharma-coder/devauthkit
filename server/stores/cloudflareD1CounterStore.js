const { sha256Hex } = require("../utils/webCrypto");

function validateDatabase(database) {
  if (!database || typeof database.prepare !== "function" || typeof database.batch !== "function") {
    throw new TypeError("CloudflareD1CounterStore requires a D1 database with prepare and batch methods");
  }
}

function validatePrefix(value) {
  if (typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new TypeError("CloudflareD1CounterStore tablePrefix must be a valid SQL identifier prefix");
  }
  return value;
}

class CloudflareD1CounterStore {
  constructor(database, options = {}) {
    validateDatabase(database);
    this.database = database;
    this.table = `${validatePrefix(options.tablePrefix || "devauthkit_counters_")}values`;
  }

  async createTables() {
    await this.database.batch([
      this.database.prepare(
        `CREATE TABLE IF NOT EXISTS ${this.table} (` +
        "counter_key TEXT PRIMARY KEY, counter_value INTEGER NOT NULL, expires_at INTEGER NOT NULL)"
      ),
      this.database.prepare(
        `CREATE INDEX IF NOT EXISTS ${this.table}_expires_idx ON ${this.table}(expires_at)`
      )
    ]);
  }

  async get(key) {
    if (typeof key !== "string" || !key) {
      throw new TypeError("D1 counter key must be a non-empty string");
    }
    const keyHash = await sha256Hex(key);
    const now = Date.now();
    const row = await this.database.prepare(
      `SELECT counter_value FROM ${this.table} WHERE counter_key = ? AND expires_at > ?`
    ).bind(keyHash, now).first();
    if (!row) return 0;
    if (!Number.isSafeInteger(row.counter_value) || row.counter_value < 0) {
      throw new TypeError("D1 counter store contains an invalid count");
    }
    return row.counter_value;
  }

  async increment(key, ttlMs) {
    if (typeof key !== "string" || !key) {
      throw new TypeError("D1 counter key must be a non-empty string");
    }
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) {
      throw new TypeError("D1 counter ttlMs must be a positive safe integer");
    }
    const keyHash = await sha256Hex(key);
    const now = Date.now();
    const expiresAt = now + ttlMs;
    const row = await this.database.prepare(
      `INSERT INTO ${this.table} (counter_key, counter_value, expires_at) VALUES (?, 1, ?) ` +
      "ON CONFLICT(counter_key) DO UPDATE SET " +
      `counter_value = CASE WHEN ${this.table}.expires_at <= ? THEN 1 ELSE ${this.table}.counter_value + 1 END, ` +
      `expires_at = CASE WHEN ${this.table}.expires_at <= ? THEN excluded.expires_at ELSE ${this.table}.expires_at END ` +
      "RETURNING counter_value"
    ).bind(keyHash, expiresAt, now, now).first();
    if (!row || !Number.isSafeInteger(row.counter_value) || row.counter_value < 1) {
      throw new TypeError("D1 atomic counter operation returned an invalid count");
    }
    return row.counter_value;
  }

  async delete(key) {
    if (typeof key !== "string" || !key) {
      throw new TypeError("D1 counter key must be a non-empty string");
    }
    const keyHash = await sha256Hex(key);
    await this.database.prepare(
      `DELETE FROM ${this.table} WHERE counter_key = ?`
    ).bind(keyHash).run();
  }
}

module.exports = { CloudflareD1CounterStore };
