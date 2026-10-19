// server/sessionStore.js

/**
 * In-memory OTP session store with automatic TTL expiration
 * and brute-force attempt tracking.
 */
class MemorySessionStore {
  constructor() {
    this.store = {};
    // Periodic garbage collection every 10 minutes to prevent memory leaks
    if (typeof setInterval !== "undefined") {
      this.cleanupTimer = setInterval(() => this.cleanup(), 10 * 60 * 1000);
      if (this.cleanupTimer.unref) this.cleanupTimer.unref();
    }
  }

  set(email, data) {
    this.store[email] = {
      ...data,
      attempts: data.attempts || 0,
      createdAt: data.createdAt || Date.now()
    };
  }

  get(email) {
    const entry = this.store[email];
    if (!entry) return null;
    return entry;
  }

  delete(email) {
    delete this.store[email];
  }

  recordAttempt(email) {
    if (this.store[email]) {
      this.store[email].attempts = (this.store[email].attempts || 0) + 1;
      return this.store[email].attempts;
    }
    return 0;
  }

  cleanup(ttlMs = 15 * 60 * 1000) {
    const now = Date.now();
    for (const email of Object.keys(this.store)) {
      if (now - this.store[email].createdAt > ttlMs) {
        delete this.store[email];
      }
    }
  }
}

const memoryStore = new MemorySessionStore();

// Proxy to allow legacy direct access: sessionStore[email] while supporting store methods
module.exports = new Proxy(memoryStore.store, {
  get(target, prop) {
    if (prop in memoryStore && typeof memoryStore[prop] === "function") {
      return memoryStore[prop].bind(memoryStore);
    }
    return target[prop];
  },
  set(target, prop, value) {
    memoryStore.set(prop, value);
    return true;
  },
  deleteProperty(target, prop) {
    memoryStore.delete(prop);
    return true;
  }
});