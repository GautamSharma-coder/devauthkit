const { createHash } = require("crypto");

class RedisDpopReplayStore {
  constructor(client, options = {}) {
    if (!client || ["get", "set"].some((method) => typeof client[method] !== "function")) {
      throw new TypeError("RedisDpopReplayStore requires a Redis client with get and set methods");
    }
    if (options.keyPrefix !== undefined && typeof options.keyPrefix !== "string") {
      throw new TypeError("RedisDpopReplayStore keyPrefix must be a string");
    }

    this.client = client;
    this.keyPrefix = options.keyPrefix || "devauthkit:dpop-replay:";
  }

  key(jti) {
    const hash = createHash("sha256").update(jti).digest("hex");
    return `${this.keyPrefix}${hash}`;
  }

  async record(jti, ttlSeconds = 120) {
    if (typeof jti !== "string" || !jti.trim()) {
      throw new TypeError("Redis DPoP replay store requires a non-empty jti string");
    }
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0) {
      throw new TypeError("Redis DPoP replay store ttlSeconds must be a positive integer");
    }

    const result = await this.client.set(this.key(jti), "1", {
      NX: true,
      EX: ttlSeconds
    });
    return result === "OK" || result === true;
  }

  async isUsed(jti) {
    if (typeof jti !== "string" || !jti.trim()) return false;
    return (await this.client.get(this.key(jti))) !== null;
  }
}

module.exports = { RedisDpopReplayStore };
