class MemoryRateLimitStore {
  constructor() {
    this.counters = new Map();
    this.incrementCount = 0;
  }

  async increment(key, windowMs) {
    const now = Date.now();
    let entry = this.counters.get(key);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
      this.counters.set(key, entry);
    }
    entry.count++;
    this.incrementCount++;
    if (this.incrementCount % 100 === 0) {
      for (const [entryKey, value] of this.counters) {
        if (value.resetAt <= now) this.counters.delete(entryKey);
      }
    }
    return entry.count;
  }
}

module.exports = MemoryRateLimitStore;
