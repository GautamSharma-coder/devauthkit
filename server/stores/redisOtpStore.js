const crypto = require("crypto");

class RedisOtpStore {
  constructor(client, options = {}) {
    if (!client || ["get", "set", "del", "incr"].some((method) => typeof client[method] !== "function")) {
      throw new TypeError("RedisOtpStore requires a Redis client with get, set, del, and incr methods");
    }

    this.client = client;
    this.keyPrefix = options.keyPrefix || "devauthkit:otp:";
    this.ttlSeconds = options.ttlSeconds ?? 15 * 60;

    if (!Number.isInteger(this.ttlSeconds) || this.ttlSeconds <= 0) {
      throw new TypeError("RedisOtpStore ttlSeconds must be a positive integer");
    }
  }

  key(email) {
    return `${this.keyPrefix}${email}`;
  }

  attemptKey(email) {
    return `${this.key(email)}:attempts`;
  }

  attemptKeyFor(email, attemptId) {
    return `${this.attemptKey(email)}:${attemptId}`;
  }

  async get(email) {
    const value = await this.client.get(this.key(email));
    if (value === null) return null;

    const entry = JSON.parse(value);
    const attemptId = entry._attemptId;
    delete entry._attemptId;
    if (attemptId) {
      const attempts = await this.client.get(this.attemptKeyFor(email, attemptId));
      entry.attempts = attempts === null ? 0 : Number(attempts);
    } else {
      entry.attempts = entry.attempts || 0;
    }
    return entry;
  }

  async set(email, data) {
    const attemptId = crypto.randomUUID();
    await this.client.set(this.attemptKeyFor(email, attemptId), "0", { EX: this.ttlSeconds });
    await this.client.set(
      this.key(email),
      JSON.stringify({ ...data, attempts: 0, _attemptId: attemptId }),
      { EX: this.ttlSeconds }
    );
  }

  async delete(email) {
    const value = await this.client.get(this.key(email));
    const keys = [this.key(email)];
    if (value !== null) {
      const { _attemptId: attemptId } = JSON.parse(value);
      if (attemptId) keys.push(this.attemptKeyFor(email, attemptId));
    }
    await this.client.del(keys);
  }

  async recordAttempt(email) {
    const value = await this.client.get(this.key(email));
    if (value === null) return 0;

    const entry = JSON.parse(value);
    if (!entry._attemptId) return (entry.attempts || 0) + 1;
    return this.client.incr(this.attemptKeyFor(email, entry._attemptId));
  }
}

module.exports = RedisOtpStore;
