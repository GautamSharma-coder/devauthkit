// server/stores/memoryDpopReplayStore.js

class MemoryDpopReplayStore {
  constructor() {
    this.entries = new Map();
  }

  /**
   * Attempt to record a JTI.
   * Returns true if newly recorded (success), false if already seen (replay detected).
   *
   * @param {string} jti - The unique JWT ID of the DPoP proof
   * @param {number} [ttlSeconds=120] - Time-to-live in seconds
   * @returns {Promise<boolean>}
   */
  async record(jti, ttlSeconds = 120) {
    if (typeof jti !== "string" || !jti.trim()) {
      throw new TypeError("DPoP replay store requires a non-empty jti string");
    }
    this.cleanup();
    const now = Date.now();
    const existing = this.entries.get(jti);
    if (existing && existing > now) {
      return false; // Replay detected!
    }
    this.entries.set(jti, now + ttlSeconds * 1000);
    return true;
  }

  /**
   * Check if a JTI has already been used and not yet expired.
   *
   * @param {string} jti
   * @returns {Promise<boolean>}
   */
  async isUsed(jti) {
    if (typeof jti !== "string") return false;
    const expiresAt = this.entries.get(jti);
    return Boolean(expiresAt && expiresAt > Date.now());
  }

  /**
   * Prune expired entries from memory.
   */
  cleanup() {
    const now = Date.now();
    for (const [jti, expiresAt] of this.entries.entries()) {
      if (expiresAt <= now) {
        this.entries.delete(jti);
      }
    }
  }

  /**
   * Clear all entries (for testing).
   */
  clear() {
    this.entries.clear();
  }
}

module.exports = { MemoryDpopReplayStore };
