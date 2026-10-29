// server/stores/cloudflareD1AuditLogStore.js

function validateDatabase(database) {
  if (!database || typeof database.prepare !== "function" || typeof database.batch !== "function") {
    throw new TypeError("CloudflareD1AuditLogStore requires a D1 database with prepare and batch methods");
  }
}

function validatePrefix(value) {
  if (typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new TypeError("CloudflareD1AuditLogStore tablePrefix must be a valid SQL identifier prefix");
  }
  return value;
}

class CloudflareD1AuditLogStore {
  constructor(database, options = {}) {
    validateDatabase(database);
    this.database = database;
    this.tablePrefix = validatePrefix(options.tablePrefix ?? "devauthkit_");
  }

  get auditLogsTable() {
    return `${this.tablePrefix}audit_logs`;
  }

  async createTables() {
    await this.database.batch([
      this.database.prepare(`
        CREATE TABLE IF NOT EXISTS ${this.auditLogsTable} (
          id TEXT PRIMARY KEY,
          org_id TEXT,
          actor_id TEXT NOT NULL,
          actor_type TEXT NOT NULL,
          target_id TEXT,
          event_type TEXT NOT NULL,
          ip_address TEXT,
          user_agent TEXT,
          prev_hash TEXT NOT NULL,
          entry_hash TEXT NOT NULL,
          metadata TEXT,
          created_at INTEGER NOT NULL
        )
      `),
      this.database.prepare(`CREATE INDEX IF NOT EXISTS idx_${this.tablePrefix}audit_actor ON ${this.auditLogsTable}(actor_id)`),
      this.database.prepare(`CREATE INDEX IF NOT EXISTS idx_${this.tablePrefix}audit_event ON ${this.auditLogsTable}(event_type)`),
      this.database.prepare(`CREATE INDEX IF NOT EXISTS idx_${this.tablePrefix}audit_created ON ${this.auditLogsTable}(created_at)`)
    ]);
  }

  async createEntry(entry) {
    if (!entry || !entry.id) {
      throw new TypeError("Audit entry must contain an id");
    }

    const metadataJson = entry.metadata ? JSON.stringify(entry.metadata) : null;

    await this.database.prepare(`
      INSERT INTO ${this.auditLogsTable} (
        id, org_id, actor_id, actor_type, target_id, event_type,
        ip_address, user_agent, prev_hash, entry_hash, metadata, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      entry.id,
      entry.orgId || null,
      entry.actorId,
      entry.actorType,
      entry.targetId || null,
      entry.eventType,
      entry.ipAddress || null,
      entry.userAgent || null,
      entry.prevHash,
      entry.entryHash,
      metadataJson,
      entry.createdAt || Date.now()
    ).run();

    return entry;
  }

  async getLastHash() {
    const row = await this.database.prepare(`
      SELECT entry_hash FROM ${this.auditLogsTable}
      ORDER BY created_at DESC, id DESC
      LIMIT 1
    `).first();

    return row ? row.entry_hash : null;
  }

  async getById(id) {
    const row = await this.database.prepare(`
      SELECT * FROM ${this.auditLogsTable} WHERE id = ?
    `).bind(id).first();

    if (!row) return null;
    return this._mapRow(row);
  }

  async query(filters = {}) {
    const conditions = [];
    const bindings = [];

    if (filters.actorId) {
      conditions.push("actor_id = ?");
      bindings.push(filters.actorId);
    }
    if (filters.eventType) {
      conditions.push("event_type = ?");
      bindings.push(filters.eventType);
    }
    if (filters.orgId) {
      conditions.push("org_id = ?");
      bindings.push(filters.orgId);
    }
    if (filters.targetId) {
      conditions.push("target_id = ?");
      bindings.push(filters.targetId);
    }
    if (filters.since) {
      conditions.push("created_at >= ?");
      bindings.push(filters.since);
    }
    if (filters.until) {
      conditions.push("created_at <= ?");
      bindings.push(filters.until);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    // Count total matching
    const countRow = await this.database.prepare(`
      SELECT COUNT(*) as total FROM ${this.auditLogsTable} ${whereClause}
    `).bind(...bindings).first();

    const total = countRow ? Number(countRow.total) : 0;
    const offset = Math.max(0, parseInt(filters.offset, 10) || 0);
    const limit = Math.min(1000, Math.max(1, parseInt(filters.limit, 10) || 50));

    const rows = await this.database.prepare(`
      SELECT * FROM ${this.auditLogsTable} ${whereClause}
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `).bind(...bindings, limit, offset).all();

    const entries = (rows.results || []).map((row) => this._mapRow(row));

    return {
      entries,
      total,
      offset,
      limit
    };
  }

  _mapRow(row) {
    let metadata = {};
    if (row.metadata) {
      try {
        metadata = JSON.parse(row.metadata);
      } catch {
        metadata = {};
      }
    }

    return {
      id: row.id,
      orgId: row.org_id,
      actorId: row.actor_id,
      actorType: row.actor_type,
      targetId: row.target_id,
      eventType: row.event_type,
      ipAddress: row.ip_address,
      userAgent: row.user_agent,
      prevHash: row.prev_hash,
      entryHash: row.entry_hash,
      metadata,
      createdAt: row.created_at
    };
  }
}

module.exports = {
  CloudflareD1AuditLogStore
};
