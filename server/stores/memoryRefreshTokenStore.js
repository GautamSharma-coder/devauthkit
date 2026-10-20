class MemoryRefreshTokenStore {
  constructor() {
    this.tokens = new Map();
    this.revokedFamilies = new Map();
  }

  prune() {
    const now = Date.now();
    for (const [hash, token] of this.tokens) {
      if (token.expiresAt <= now) this.tokens.delete(hash);
    }
    for (const [familyId, expiresAt] of this.revokedFamilies) {
      if (expiresAt <= now) this.revokedFamilies.delete(familyId);
    }
  }

  async create(tokenHash, record) {
    this.prune();
    this.tokens.set(tokenHash, { ...record, used: false });
  }

  async rotate(tokenHash, replacementHash, replacement) {
    this.prune();
    const current = this.tokens.get(tokenHash);
    if (!current) return { status: "invalid" };
    if (current.used || this.revokedFamilies.has(current.familyId)) {
      this.revokeFamilyNow(current.familyId);
      return { status: "reused" };
    }

    const record = { ...current };
    current.used = true;
    this.tokens.set(replacementHash, { ...current, ...replacement, used: false });
    return { status: "rotated", record };
  }

  revokeFamilyNow(familyId) {
    let expiresAt = 0;
    for (const [hash, token] of this.tokens) {
      if (token.familyId === familyId) {
        expiresAt = Math.max(expiresAt, token.expiresAt);
        this.tokens.delete(hash);
      }
    }
    if (expiresAt > Date.now()) this.revokedFamilies.set(familyId, expiresAt);
  }

  async revokeFamily(familyId) {
    this.prune();
    this.revokeFamilyNow(familyId);
  }

  async revoke(tokenHash) {
    this.prune();
    const token = this.tokens.get(tokenHash);
    if (!token) return false;
    this.revokeFamilyNow(token.familyId);
    return true;
  }

  async revokeAll(userId) {
    this.prune();
    const families = new Set();
    for (const token of this.tokens.values()) {
      if (token.userId === userId) families.add(token.familyId);
    }
    for (const familyId of families) this.revokeFamilyNow(familyId);
  }

  async isFamilyActive(familyId) {
    this.prune();
    if (this.revokedFamilies.has(familyId)) return false;
    for (const token of this.tokens.values()) {
      if (token.familyId === familyId && !token.used) return true;
    }
    return false;
  }
}

module.exports = MemoryRefreshTokenStore;
