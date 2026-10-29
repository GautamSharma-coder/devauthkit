// server/stores/cloudflareD1ApiKeyStore.js

function validateDatabase(database) {
  if (!database || typeof database.prepare !== "function" || typeof database.batch !== "function") {
    throw new TypeError("CloudflareD1ApiKeyStore requires a D1 database with prepare and batch methods");
  }
}

function validatePrefix(value) {
  if (typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new TypeError("CloudflareD1ApiKeyStore tablePrefix must be a valid SQL identifier prefix");
  }
  return value;
}

class CloudflareD1ApiKeyStore {
  constructor(database, options = {}) {
    validateDatabase(database);
    this.database = database;
    this.tablePrefix = validatePrefix(options.tablePrefix ?? "devauthkit_");
  }

  get apiKeysTable() {
    return `${this.tablePrefix}api_keys`;
  }

  async createTables() {
    await this.database.batch([
      this.database.prepare(`
        CREATE TABLE IF NOT EXISTS ${this.apiKeysTable} (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          org_id TEXT,
          name TEXT NOT NULL,
          key_prefix TEXT NOT NULL,
          key_digest TEXT UNIQUE NOT NULL,
          crc32_checksum TEXT NOT NULL,
          masked_key TEXT NOT NULL,
          scopes TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'active',
          last_used_at INTEGER,
          expires_at INTEGER,
          created_at INTEGER NOT NULL
        )
      `),
      this.database.prepare(`CREATE INDEX IF NOT EXISTS idx_${this.tablePrefix}apikeys_digest ON ${this.apiKeysTable}(key_digest)`),
      this.database.prepare(`CREATE INDEX IF NOT EXISTS idx_${this.tablePrefix}apikeys_user ON ${this.apiKeysTable}(user_id)`),
      this.database.prepare(`CREATE INDEX IF NOT EXISTS idx_${this.tablePrefix}apikeys_org ON ${this.apiKeysTable}(org_id)`)
    ]);
  }

  async createKey(keyRecord) {
    if (!keyRecord || !keyRecord.id || !keyRecord.keyDigest) {
      throw new TypeError("keyRecord must contain id and keyDigest");
    }

    const scopesJson = Array.isArray(keyRecord.scopes)
      ? JSON.stringify(keyRecord.scopes)
      : typeof keyRecord.scopes === "string"
        ? keyRecord.scopes
        : "[\"*\"]";

    await this.database.prepare(`
      INSERT INTO ${this.apiKeysTable} (
        id, user_id, org_id, name, key_prefix, key_digest,
        crc32_checksum, masked_key, scopes, status, last_used_at, expires_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      keyRecord.id,
      keyRecord.userId,
      keyRecord.orgId || null,
      keyRecord.name,
      keyRecord.keyPrefix,
      keyRecord.keyDigest,
      keyRecord.crc32Checksum,
      keyRecord.maskedKey || "dak_***",
      scopesJson,
      keyRecord.status || "active",
      keyRecord.lastUsedAt || null,
      keyRecord.expiresAt || null,
      keyRecord.createdAt || Date.now()
    ).run();

    return keyRecord;
  }

  async getById(id) {
    const row = await this.database.prepare(`
      SELECT * FROM ${this.apiKeysTable} WHERE id = ?
    `).bind(id).first();

    if (!row) return null;
    return this._mapRow(row);
  }

  async getByKeyDigest(digest) {
    const row = await this.database.prepare(`
      SELECT * FROM ${this.apiKeysTable} WHERE key_digest = ?
    `).bind(digest).first();

    if (!row) return null;
    return this._mapRow(row);
  }

  async listKeys(filters = {}) {
    const conditions = [];
    const bindings = [];

    if (filters.userId) {
      conditions.push("user_id = ?");
      bindings.push(filters.userId);
    }
    if (filters.orgId) {
      conditions.push("org_id = ?");
      bindings.push(filters.orgId);
    }
    if (filters.status) {
      conditions.push("status = ?");
      bindings.push(filters.status);
    } else {
      conditions.push("status != 'revoked'");
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    const rows = await this.database.prepare(`
      SELECT * FROM ${this.apiKeysTable} ${whereClause}
      ORDER BY created_at DESC
    `).bind(...bindings).all();

    return (rows.results || []).map((row) => {
      const mapped = this._mapRow(row);
      // Strip keyDigest from list response
      const { keyDigest, ...safe } = mapped;
      return safe;
    });
  }

  async updateKey(id, updates = {}) {
    const existing = await this.getById(id);
    if (!existing) return null;

    const newName = updates.name !== undefined ? updates.name : existing.name;
    const newScopes = updates.scopes !== undefined
      ? (Array.isArray(updates.scopes) ? JSON.stringify(updates.scopes) : String(updates.scopes))
      : JSON.stringify(existing.scopes);
    const newStatus = updates.status !== undefined ? updates.status : existing.status;
    const newExpiresAt = updates.expiresAt !== undefined ? updates.expiresAt : existing.expiresAt;

    await this.database.prepare(`
      UPDATE ${this.apiKeysTable}
      SET name = ?, scopes = ?, status = ?, expires_at = ?
      WHERE id = ?
    `).bind(newName, newScopes, newStatus, newExpiresAt, id).run();

    return this.getById(id);
  }

  async revokeKey(id) {
    const res = await this.database.prepare(`
      UPDATE ${this.apiKeysTable}
      SET status = 'revoked'
      WHERE id = ?
    `).bind(id).run();

    return res.success || true;
  }

  async touchLastUsed(id, timestamp = Date.now()) {
    await this.database.prepare(`
      UPDATE ${this.apiKeysTable}
      SET last_used_at = ?
      WHERE id = ?
    `).bind(timestamp, id).run();
  }

  _mapRow(row) {
    let scopes = ["*"];
    if (row.scopes) {
      try {
        scopes = JSON.parse(row.scopes);
      } catch {
        scopes = typeof row.scopes === "string" ? row.scopes.split(",") : ["*"];
      }
    }

    return {
      id: row.id,
      userId: row.user_id,
      orgId: row.org_id,
      name: row.name,
      keyPrefix: row.key_prefix,
      keyDigest: row.key_digest,
      crc32Checksum: row.crc32_checksum,
      maskedKey: row.masked_key,
      scopes,
      status: row.status,
      lastUsedAt: row.last_used_at,
      expiresAt: row.expires_at,
      createdAt: row.created_at
    };
  }
}

module.exports = {
  CloudflareD1ApiKeyStore
};
