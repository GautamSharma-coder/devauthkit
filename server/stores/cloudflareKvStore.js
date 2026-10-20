function requireKvNamespace(namespace, name) {
  if (!namespace || typeof namespace.get !== "function" || typeof namespace.put !== "function" || typeof namespace.delete !== "function") {
    throw new TypeError(`${name} requires a Cloudflare KV namespace`);
  }
}

function expirationTtl(seconds) {
  return Math.max(60, Math.ceil(seconds));
}

function requireAtomicCounterStore(counterStore, name, methods) {
  if (!counterStore || !methods.every((method) => typeof counterStore[method] === "function")) {
    throw new TypeError(`${name} requires an atomic counterStore implementing ${methods.join(", ")}`);
  }
}

class CloudflareKvOtpStore {
  constructor(namespace, options = {}) {
    requireKvNamespace(namespace, "CloudflareKvOtpStore");
    requireAtomicCounterStore(options.counterStore, "CloudflareKvOtpStore", [
      "get", "increment", "delete"
    ]);
    this.namespace = namespace;
    this.counterStore = options.counterStore;
    this.keyPrefix = options.keyPrefix || "devauthkit:otp:";
    this.ttlSeconds = options.ttlSeconds ?? 15 * 60;
    if (!Number.isInteger(this.ttlSeconds) || this.ttlSeconds <= 0) {
      throw new TypeError("CloudflareKvOtpStore ttlSeconds must be a positive integer");
    }
  }

  key(email) {
    return `${this.keyPrefix}${email}`;
  }

  attemptKey(email) {
    return `${this.key(email)}:attempts`;
  }

  async get(email) {
    const value = await this.namespace.get(this.key(email));
    if (value === null) return null;

    const entry = JSON.parse(value);
    if (
      !entry ||
      typeof entry !== "object" ||
      typeof entry.otp !== "string" ||
      !Number.isFinite(entry.createdAt) ||
      typeof entry.attemptKey !== "string"
    ) {
      throw new TypeError("Cloudflare KV contains an invalid OTP record");
    }
    const attempts = await this.counterStore.get(entry.attemptKey);
    if (!Number.isSafeInteger(attempts) || attempts < 0) {
      throw new TypeError("Cloudflare KV contains an invalid OTP attempt count");
    }
    return {
      otp: entry.otp,
      createdAt: entry.createdAt,
      attempts
    };
  }

  async set(email, data) {
    const options = { expirationTtl: this.ttlSeconds };
    await this.namespace.put(this.key(email), JSON.stringify({
      otp: data.otp,
      createdAt: data.createdAt,
      attemptKey: `${this.key(email)}:attempts:${crypto.randomUUID()}`
    }), options);
  }

  async delete(email) {
    const value = await this.namespace.get(this.key(email));
    const entry = value === null ? null : JSON.parse(value);
    await this.namespace.delete(this.key(email));
    if (typeof entry?.attemptKey === "string") {
      await this.counterStore.delete(entry.attemptKey);
    }
  }

  async recordAttempt(email) {
    const value = await this.namespace.get(this.key(email));
    if (value === null) throw new Error("Cannot increment attempts without an active OTP");
    const entry = JSON.parse(value);
    if (typeof entry?.attemptKey !== "string") {
      throw new TypeError("Cloudflare KV OTP record is missing its atomic attempt counter key");
    }
    return this.counterStore.increment(entry.attemptKey, this.ttlSeconds * 1000);
  }
}

class CloudflareKvRateLimitStore {
  constructor(namespace, options = {}) {
    requireKvNamespace(namespace, "CloudflareKvRateLimitStore");
    requireAtomicCounterStore(options.counterStore, "CloudflareKvRateLimitStore", ["increment"]);
    this.namespace = namespace;
    this.counterStore = options.counterStore;
    this.keyPrefix = options.keyPrefix || "devauthkit:rate-limit:";
  }

  async increment(key, windowMs) {
    if (!Number.isSafeInteger(windowMs) || windowMs <= 0) {
      throw new TypeError("CloudflareKvRateLimitStore windowMs must be a positive integer");
    }
    return this.counterStore.increment(
      `${this.keyPrefix}${key}`,
      expirationTtl(windowMs / 1000) * 1000
    );
  }
}

class CloudflareKvMagicLinkStore {
  constructor(namespace, options = {}) {
    requireKvNamespace(namespace, "CloudflareKvMagicLinkStore");
    this.namespace = namespace;
    this.keyPrefix = options.keyPrefix || "devauthkit:magic-link:";
  }

  async set(tokenHash, record) {
    const ttlSeconds = Math.ceil((record.expiresAt - Date.now()) / 1000);
    if (ttlSeconds <= 0) return;
    await this.namespace.put(`${this.keyPrefix}${tokenHash}`, JSON.stringify(record), {
      expirationTtl: expirationTtl(ttlSeconds)
    });
  }

  async get(tokenHash) {
    const value = await this.namespace.get(`${this.keyPrefix}${tokenHash}`);
    if (value === null) return null;
    const entry = JSON.parse(value);
    if (!entry || typeof entry.email !== "string" || !Number.isFinite(entry.expiresAt)) {
      throw new TypeError("Cloudflare KV contains an invalid magic-link record");
    }
    return entry;
  }

  delete(tokenHash) {
    return this.namespace.delete(`${this.keyPrefix}${tokenHash}`);
  }
}

module.exports = {
  CloudflareKvMagicLinkStore,
  CloudflareKvOtpStore,
  CloudflareKvRateLimitStore
};
