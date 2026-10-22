// server/stores/cloudflareD1WebhookStore.js
const { randomUUID } = require("../utils/webCrypto");
const { generateWebhookSecret } = require("../core/webhookService");

function validateDatabase(database) {
  if (!database || typeof database.prepare !== "function" || typeof database.batch !== "function") {
    throw new TypeError("CloudflareD1WebhookStore requires a D1 database with prepare and batch methods");
  }
}

function validatePrefix(value) {
  if (typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new TypeError("CloudflareD1WebhookStore tablePrefix must be a valid SQL identifier prefix");
  }
  return value;
}

class CloudflareD1WebhookStore {
  constructor(database, options = {}) {
    validateDatabase(database);
    this.database = database;
    this.tablePrefix = validatePrefix(options.tablePrefix ?? "devauthkit_");
  }

  get endpointsTable() {
    return `${this.tablePrefix}webhook_endpoints`;
  }

  get deliveriesTable() {
    return `${this.tablePrefix}webhook_deliveries`;
  }

  async createTables() {
    await this.database.batch([
      this.database.prepare(`
        CREATE TABLE IF NOT EXISTS ${this.endpointsTable} (
          id TEXT PRIMARY KEY,
          url TEXT NOT NULL,
          secret TEXT NOT NULL,
          events TEXT NOT NULL,
          active INTEGER NOT NULL DEFAULT 1,
          metadata TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        )
      `),
      this.database.prepare(`
        CREATE TABLE IF NOT EXISTS ${this.deliveriesTable} (
          id TEXT PRIMARY KEY,
          endpoint_id TEXT NOT NULL,
          event_id TEXT NOT NULL,
          event TEXT NOT NULL,
          url TEXT NOT NULL,
          status_code INTEGER,
          success INTEGER NOT NULL,
          attempt INTEGER NOT NULL,
          error TEXT,
          duration_ms INTEGER NOT NULL,
          delivered_at INTEGER NOT NULL
        )
      `),
      this.database.prepare(`
        CREATE INDEX IF NOT EXISTS idx_${this.tablePrefix}wh_deliveries_ep 
        ON ${this.deliveriesTable} (endpoint_id, delivered_at DESC)
      `)
    ]);
  }

  async createEndpoint({ url, secret = null, events = ["*"], metadata = null }) {
    if (!url || typeof url !== "string") {
      throw new TypeError("Webhook endpoint url is required");
    }

    const id = `whep_${randomUUID()}`;
    const resolvedSecret = secret || generateWebhookSecret();
    const resolvedEvents = Array.isArray(events) && events.length > 0 ? events : ["*"];
    const now = Date.now();

    await this.database
      .prepare(`
        INSERT INTO ${this.endpointsTable} (id, url, secret, events, active, metadata, created_at, updated_at)
        VALUES (?, ?, ?, ?, 1, ?, ?, ?)
      `)
      .bind(
        id,
        url.trim(),
        resolvedSecret,
        JSON.stringify(resolvedEvents),
        metadata ? JSON.stringify(metadata) : null,
        now,
        now
      )
      .run();

    return {
      id,
      url: url.trim(),
      secret: resolvedSecret,
      events: resolvedEvents,
      active: true,
      metadata: metadata || null,
      createdAt: now,
      updatedAt: now
    };
  }

  async getEndpoint(id) {
    if (!id) return null;
    const row = await this.database
      .prepare(`SELECT * FROM ${this.endpointsTable} WHERE id = ?`)
      .bind(String(id))
      .first();

    if (!row) return null;
    return {
      id: row.id,
      url: row.url,
      secret: row.secret,
      events: JSON.parse(row.events),
      active: Boolean(row.active),
      metadata: row.metadata ? JSON.parse(row.metadata) : null,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  async listEndpoints() {
    const rows = await this.database
      .prepare(`SELECT * FROM ${this.endpointsTable} ORDER BY created_at DESC`)
      .all();

    return (rows.results || []).map((row) => ({
      id: row.id,
      url: row.url,
      secret: row.secret,
      events: JSON.parse(row.events),
      active: Boolean(row.active),
      metadata: row.metadata ? JSON.parse(row.metadata) : null,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    }));
  }

  async updateEndpoint(id, updates = {}) {
    const current = await this.getEndpoint(id);
    if (!current) return null;

    const newUrl = updates.url ? updates.url.trim() : current.url;
    const newEvents = Array.isArray(updates.events) ? updates.events : current.events;
    const newActive = typeof updates.active === "boolean" ? updates.active : current.active;
    const newSecret = updates.secret ? updates.secret.trim() : current.secret;
    const newMetadata = updates.metadata !== undefined ? updates.metadata : current.metadata;
    const now = Date.now();

    await this.database
      .prepare(`
        UPDATE ${this.endpointsTable}
        SET url = ?, events = ?, active = ?, secret = ?, metadata = ?, updated_at = ?
        WHERE id = ?
      `)
      .bind(
        newUrl,
        JSON.stringify(newEvents),
        newActive ? 1 : 0,
        newSecret,
        newMetadata ? JSON.stringify(newMetadata) : null,
        now,
        String(id)
      )
      .run();

    return {
      id: current.id,
      url: newUrl,
      secret: newSecret,
      events: newEvents,
      active: newActive,
      metadata: newMetadata,
      createdAt: current.createdAt,
      updatedAt: now
    };
  }

  async deleteEndpoint(id) {
    if (!id) return false;
    const res = await this.database
      .prepare(`DELETE FROM ${this.endpointsTable} WHERE id = ?`)
      .bind(String(id))
      .run();
    return res.meta?.changes > 0 || true;
  }

  async recordDelivery(record) {
    const id = `whdel_${randomUUID()}`;
    const now = record.deliveredAt || Date.now();

    await this.database
      .prepare(`
        INSERT INTO ${this.deliveriesTable} 
        (id, endpoint_id, event_id, event, url, status_code, success, attempt, error, duration_ms, delivered_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        id,
        record.endpointId,
        record.eventId,
        record.event,
        record.url,
        record.statusCode !== undefined ? record.statusCode : null,
        record.success ? 1 : 0,
        record.attempt || 1,
        record.error || null,
        record.durationMs || 0,
        now
      )
      .run();

    return {
      id,
      ...record,
      deliveredAt: now
    };
  }

  async listDeliveries(endpointId = null, limit = 50) {
    const query = endpointId
      ? `SELECT * FROM ${this.deliveriesTable} WHERE endpoint_id = ? ORDER BY delivered_at DESC LIMIT ?`
      : `SELECT * FROM ${this.deliveriesTable} ORDER BY delivered_at DESC LIMIT ?`;

    const stmt = endpointId
      ? this.database.prepare(query).bind(String(endpointId), limit)
      : this.database.prepare(query).bind(limit);

    const rows = await stmt.all();
    return (rows.results || []).map((row) => ({
      id: row.id,
      endpointId: row.endpoint_id,
      eventId: row.event_id,
      event: row.event,
      url: row.url,
      statusCode: row.status_code,
      success: Boolean(row.success),
      attempt: row.attempt,
      error: row.error,
      durationMs: row.duration_ms,
      deliveredAt: row.delivered_at
    }));
  }
}

module.exports = { CloudflareD1WebhookStore };
