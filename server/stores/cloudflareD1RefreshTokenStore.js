function tablePrefix(value) {
  if (typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new TypeError("CloudflareD1RefreshTokenStore tablePrefix must be a valid SQL identifier prefix");
  }
  return value;
}

function validateDatabase(database) {
  if (!database || typeof database.prepare !== "function" || typeof database.batch !== "function") {
    throw new TypeError("CloudflareD1RefreshTokenStore requires a D1 database with prepare and batch methods");
  }
}

class CloudflareD1RefreshTokenStore {
  constructor(database, options = {}) {
    validateDatabase(database);
    this.database = database;
    this.prefix = tablePrefix(options.tablePrefix || "devauthkit_refresh_");
    this.tokensTable = `${this.prefix}tokens`;
    this.familiesTable = `${this.prefix}families`;
  }

  async createTables() {
    await this.database.batch([
      this.database.prepare(
        `CREATE TABLE IF NOT EXISTS ${this.familiesTable} (` +
        "family_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)"
      ),
      this.database.prepare(
        `CREATE TABLE IF NOT EXISTS ${this.tokensTable} (` +
        "token_hash TEXT PRIMARY KEY, family_id TEXT NOT NULL, user_id TEXT NOT NULL, user_json TEXT NOT NULL, " +
        "expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0, rotated_by TEXT)"
      ),
      this.database.prepare(`CREATE INDEX IF NOT EXISTS ${this.prefix}tokens_family_idx ON ${this.tokensTable}(family_id)`),
      this.database.prepare(`CREATE INDEX IF NOT EXISTS ${this.prefix}tokens_user_idx ON ${this.tokensTable}(user_id)`)
    ]);
  }

  async create(tokenHash, record) {
    const userJson = JSON.stringify(record.user);
    await this.database.batch([
      this.database.prepare(
        `INSERT INTO ${this.familiesTable} (family_id, user_id, expires_at, revoked) VALUES (?, ?, ?, 0) ` +
        "ON CONFLICT(family_id) DO UPDATE SET expires_at = MAX(expires_at, excluded.expires_at)"
      ).bind(record.familyId, record.userId, record.expiresAt),
      this.database.prepare(
        `INSERT INTO ${this.tokensTable} (token_hash, family_id, user_id, user_json, expires_at, used, rotated_by) ` +
        "VALUES (?, ?, ?, ?, ?, 0, NULL)"
      ).bind(tokenHash, record.familyId, record.userId, userJson, record.expiresAt)
    ]);
  }

  async rotate(tokenHash, replacementHash, replacement) {
    const now = Date.now();
    const current = await this.database.prepare(
      `SELECT token_hash, family_id, user_id, user_json, expires_at, used FROM ${this.tokensTable} WHERE token_hash = ?`
    ).bind(tokenHash).first();
    if (!current || current.expires_at <= now) return { status: "invalid" };

    const update = this.database.prepare(
      `UPDATE ${this.tokensTable} SET used = 1, rotated_by = ? ` +
      "WHERE token_hash = ? AND used = 0 AND expires_at > ? " +
      `AND EXISTS (SELECT 1 FROM ${this.familiesTable} WHERE family_id = ? AND revoked = 0 AND expires_at > ?)`
    ).bind(replacementHash, tokenHash, now, current.family_id, now);
    const insert = this.database.prepare(
      `INSERT INTO ${this.tokensTable} (token_hash, family_id, user_id, user_json, expires_at, used, rotated_by) ` +
      `SELECT ?, family_id, user_id, user_json, ?, 0, NULL FROM ${this.tokensTable} ` +
      "WHERE token_hash = ? AND used = 1 AND rotated_by = ? " +
      `AND EXISTS (SELECT 1 FROM ${this.familiesTable} WHERE family_id = ? AND revoked = 0 AND expires_at > ?)`
    ).bind(replacementHash, replacement.expiresAt, tokenHash, replacementHash, current.family_id, now);
    const extendFamily = this.database.prepare(
      `UPDATE ${this.familiesTable} SET expires_at = MAX(expires_at, ?) ` +
      "WHERE family_id = ? AND revoked = 0 " +
      `AND EXISTS (SELECT 1 FROM ${this.tokensTable} WHERE token_hash = ? AND used = 0)`
    ).bind(replacement.expiresAt, current.family_id, replacementHash);
    const [updated, inserted] = await this.database.batch([update, insert, extendFamily]);

    if (updated?.meta?.changes === 1 && inserted?.meta?.changes === 1) {
      let user;
      try {
        user = JSON.parse(current.user_json);
      } catch (error) {
        throw new TypeError(`D1 refresh-token record contains invalid user JSON: ${error.message}`);
      }
      return {
        status: "rotated",
        record: {
          familyId: current.family_id,
          userId: current.user_id,
          user,
          expiresAt: current.expires_at
        }
      };
    }

    const latest = await this.database.prepare(
      `SELECT used, expires_at, family_id FROM ${this.tokensTable} WHERE token_hash = ?`
    ).bind(tokenHash).first();
    if (!latest || latest.expires_at <= now) return { status: "invalid" };
    const family = await this.database.prepare(
      `SELECT revoked FROM ${this.familiesTable} WHERE family_id = ?`
    ).bind(latest.family_id).first();
    if (latest.used || family?.revoked) {
      await this.revokeFamily(latest.family_id);
      return { status: "reused" };
    }
    return { status: "invalid" };
  }

  async revoke(tokenHash) {
    const token = await this.database.prepare(
      `SELECT family_id FROM ${this.tokensTable} WHERE token_hash = ?`
    ).bind(tokenHash).first();
    if (!token) return false;
    await this.revokeFamily(token.family_id);
    return true;
  }

  async revokeFamily(familyId) {
    await this.database.batch([
      this.database.prepare(
        `UPDATE ${this.familiesTable} SET revoked = 1 WHERE family_id = ?`
      ).bind(familyId),
      this.database.prepare(
        `DELETE FROM ${this.tokensTable} WHERE family_id = ?`
      ).bind(familyId)
    ]);
  }

  async revokeAll(userId) {
    await this.database.batch([
      this.database.prepare(
        `UPDATE ${this.familiesTable} SET revoked = 1 WHERE user_id = ?`
      ).bind(String(userId)),
      this.database.prepare(
        `DELETE FROM ${this.tokensTable} WHERE user_id = ?`
      ).bind(String(userId))
    ]);
  }

  async isFamilyActive(familyId) {
    const now = Date.now();
    const active = await this.database.prepare(
      `SELECT 1 AS active FROM ${this.familiesTable} f WHERE f.family_id = ? AND f.revoked = 0 ` +
      "AND f.expires_at > ? " +
      `AND EXISTS (SELECT 1 FROM ${this.tokensTable} t WHERE t.family_id = f.family_id AND t.used = 0 AND t.expires_at > ?) LIMIT 1`
    ).bind(familyId, now, now).first();
    return Boolean(active);
  }
}

module.exports = { CloudflareD1RefreshTokenStore };
