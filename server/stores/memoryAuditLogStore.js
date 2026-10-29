// server/stores/memoryAuditLogStore.js

class MemoryAuditLogStore {
  /**
   * @param {Object} [options]
   * @param {number} [options.maxEntries=10000] - Circular buffer ceiling
   */
  constructor(options = {}) {
    this.maxEntries = options.maxEntries || 10000;
    this.entries = [];
    this.entriesById = new Map();
  }

  async createEntry(entry) {
    if (!entry || !entry.id) {
      throw new TypeError("Audit entry must contain an id");
    }

    this.entries.push(entry);
    this.entriesById.set(entry.id, entry);

    // Evict oldest if exceeding max entries
    if (this.entries.length > this.maxEntries) {
      const evicted = this.entries.shift();
      if (evicted) {
        this.entriesById.delete(evicted.id);
      }
    }

    return entry;
  }

  async getLastHash() {
    if (this.entries.length === 0) return null;
    return this.entries[this.entries.length - 1].entryHash;
  }

  async getById(id) {
    return this.entriesById.get(id) || null;
  }

  async query(filters = {}) {
    let result = [...this.entries];

    if (filters.actorId) {
      result = result.filter((e) => e.actorId === filters.actorId);
    }
    if (filters.eventType) {
      result = result.filter((e) => e.eventType === filters.eventType);
    }
    if (filters.orgId) {
      result = result.filter((e) => e.orgId === filters.orgId);
    }
    if (filters.targetId) {
      result = result.filter((e) => e.targetId === filters.targetId);
    }
    if (filters.since) {
      result = result.filter((e) => e.createdAt >= filters.since);
    }
    if (filters.until) {
      result = result.filter((e) => e.createdAt <= filters.until);
    }

    // Default newest first
    result.sort((a, b) => b.createdAt - a.createdAt);

    const total = result.length;
    const offset = Math.max(0, parseInt(filters.offset, 10) || 0);
    const limit = Math.min(1000, Math.max(1, parseInt(filters.limit, 10) || 50));

    const paginated = result.slice(offset, offset + limit);

    return {
      entries: paginated,
      total,
      offset,
      limit
    };
  }

  async clear() {
    this.entries = [];
    this.entriesById.clear();
  }
}

module.exports = {
  MemoryAuditLogStore
};
