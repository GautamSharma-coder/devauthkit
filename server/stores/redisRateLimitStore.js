class RedisRateLimitStore {
  constructor(client, options = {}) {
    if (!client || ["incr", "pTTL", "pExpire"].some((method) => typeof client[method] !== "function")) {
      throw new TypeError("RedisRateLimitStore requires a Redis client with incr, pTTL, and pExpire methods");
    }

    this.client = client;
    this.keyPrefix = options.keyPrefix || "devauthkit:rate-limit:";
  }

  async increment(key, windowMs) {
    const redisKey = `${this.keyPrefix}${key}`;
    const count = await this.client.incr(redisKey);
    const ttl = await this.client.pTTL(redisKey);
    if (count === 1 || ttl < 0) {
      await this.client.pExpire(redisKey, windowMs);
    }
    return count;
  }
}

module.exports = RedisRateLimitStore;
