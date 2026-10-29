// server/stores/memoryApiKeyStore.js

class MemoryApiKeyStore {
  constructor() {
    this.keys = new Map(); // id -> keyRecord
    this.byDigest = new Map(); // digest -> keyRecord
  }

  async createKey(keyRecord) {
    if (!keyRecord || !keyRecord.id || !keyRecord.keyDigest) {
      throw new TypeError("keyRecord must contain id and keyDigest");
    }

    const cloned = { ...keyRecord };
    this.keys.set(keyRecord.id, cloned);
    this.byDigest.set(keyRecord.keyDigest, cloned);
    return cloned;
  }

  async getById(id) {
    const key = this.keys.get(id);
    return key ? { ...key } : null;
  }

  async getByKeyDigest(digest) {
    const key = this.byDigest.get(digest);
    return key ? { ...key } : null;
  }

  async listKeys(filters = {}) {
    let result = Array.from(this.keys.values());

    if (filters.userId) {
      result = result.filter((k) => k.userId === filters.userId);
    }
    if (filters.orgId) {
      result = result.filter((k) => k.orgId === filters.orgId);
    }
    if (filters.status) {
      result = result.filter((k) => k.status === filters.status);
    } else {
      // Default: don't show permanently revoked unless requested
      result = result.filter((k) => k.status !== "revoked");
    }

    // Sort newest first
    result.sort((a, b) => b.createdAt - a.createdAt);

    return result.map((k) => {
      // Never expose keyDigest in list calls
      const { keyDigest, ...safe } = k;
      return safe;
    });
  }

  async updateKey(id, updates = {}) {
    const existing = this.keys.get(id);
    if (!existing) return null;

    const updated = {
      ...existing,
      name: updates.name !== undefined ? updates.name : existing.name,
      scopes: updates.scopes !== undefined ? updates.scopes : existing.scopes,
      status: updates.status !== undefined ? updates.status : existing.status,
      expiresAt: updates.expiresAt !== undefined ? updates.expiresAt : existing.expiresAt
    };

    this.keys.set(id, updated);
    this.byDigest.set(updated.keyDigest, updated);
    return { ...updated };
  }

  async revokeKey(id) {
    const existing = this.keys.get(id);
    if (!existing) return false;

    existing.status = "revoked";
    this.keys.set(id, existing);
    this.byDigest.set(existing.keyDigest, existing);
    return true;
  }

  async touchLastUsed(id, timestamp = Date.now()) {
    const existing = this.keys.get(id);
    if (existing) {
      existing.lastUsedAt = timestamp;
      this.keys.set(id, existing);
      this.byDigest.set(existing.keyDigest, existing);
    }
  }

  async clear() {
    this.keys.clear();
    this.byDigest.clear();
  }
}

module.exports = {
  MemoryApiKeyStore
};
