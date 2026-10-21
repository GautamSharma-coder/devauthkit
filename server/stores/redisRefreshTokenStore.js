const { createHash } = require("crypto");

const CREATE_SCRIPT = `-- DEVAUTHKIT_CREATE_REFRESH
local expiresAt = tonumber(ARGV[2])
local ttl = math.max(1, math.ceil((expiresAt - tonumber(ARGV[3])) / 1000))
if redis.call("EXISTS", KEYS[1]) == 1 then return 0 end
local familyRaw = redis.call("GET", KEYS[2])
local family = cjson.decode(ARGV[4])
local familyTtl = ttl
if familyRaw then
  local existingFamily = cjson.decode(familyRaw)
  if existingFamily.revoked or existingFamily.userId ~= family.userId then return 0 end
  existingFamily.expiresAt = math.max(tonumber(existingFamily.expiresAt), expiresAt)
  family = existingFamily
  familyTtl = math.max(1, math.ceil((family.expiresAt - tonumber(ARGV[3])) / 1000))
end
redis.call("SET", KEYS[1], ARGV[1], "EX", ttl)
redis.call("SET", KEYS[2], cjson.encode(family), "EX", familyTtl)
redis.call("SADD", KEYS[3], ARGV[5])
redis.call("SADD", KEYS[4], ARGV[6])
if redis.call("TTL", KEYS[3]) < familyTtl then redis.call("EXPIRE", KEYS[3], familyTtl) end
if redis.call("TTL", KEYS[4]) < familyTtl then redis.call("EXPIRE", KEYS[4], familyTtl) end
return 1`;

const ROTATE_SCRIPT = `-- DEVAUTHKIT_ROTATE_REFRESH
local currentRaw = redis.call("GET", KEYS[1])
if not currentRaw then return { "invalid" } end
local current = cjson.decode(currentRaw)
if current.record.familyId ~= ARGV[4] or current.record.userId ~= ARGV[5] then
  return { "invalid" }
end
local familyRaw = redis.call("GET", KEYS[3])
if not familyRaw then return { "invalid" } end
local family = cjson.decode(familyRaw)
local function revokeFamily()
  local members = redis.call("SMEMBERS", KEYS[4])
  for _, suffix in ipairs(members) do
    redis.call("DEL", ARGV[7] .. "token:" .. suffix)
  end
  redis.call("DEL", KEYS[4])
  family.revoked = true
  local remaining = math.max(1, math.ceil((tonumber(family.expiresAt) - tonumber(ARGV[1])) / 1000))
  redis.call("SET", KEYS[3], cjson.encode(family), "EX", remaining)
  redis.call("SREM", KEYS[5], ARGV[6])
end
if current.status == "used" or family.revoked then
  revokeFamily()
  return { "reused" }
end
if tonumber(current.record.expiresAt) <= tonumber(ARGV[1]) then
  return { "invalid" }
end
if redis.call("EXISTS", KEYS[2]) == 1 then return { "invalid" } end
local record = current.record
current.status = "used"
local currentTtl = math.max(1, math.ceil((tonumber(record.expiresAt) - tonumber(ARGV[1])) / 1000))
redis.call("SET", KEYS[1], cjson.encode(current), "EX", currentTtl)
local replacementTtl = math.max(1, math.ceil((tonumber(ARGV[3]) - tonumber(ARGV[1])) / 1000))
redis.call("SET", KEYS[2], ARGV[2], "EX", replacementTtl)
redis.call("SADD", KEYS[4], ARGV[8])
family.expiresAt = math.max(tonumber(family.expiresAt), tonumber(ARGV[3]))
local familyTtl = math.max(1, math.ceil((family.expiresAt - tonumber(ARGV[1])) / 1000))
redis.call("SET", KEYS[3], cjson.encode(family), "EX", familyTtl)
redis.call("EXPIRE", KEYS[4], familyTtl)
if redis.call("TTL", KEYS[5]) < familyTtl then redis.call("EXPIRE", KEYS[5], familyTtl) end
return { "rotated", cjson.encode(record) }`;

const REVOKE_FAMILY_SCRIPT = `-- DEVAUTHKIT_REVOKE_REFRESH_FAMILY
local familyRaw = redis.call("GET", KEYS[1])
if not familyRaw then return 0 end
local family = cjson.decode(familyRaw)
local members = redis.call("SMEMBERS", KEYS[2])
for _, suffix in ipairs(members) do
  redis.call("DEL", ARGV[1] .. "token:" .. suffix)
end
redis.call("DEL", KEYS[2])
family.revoked = true
local ttl = math.max(1, math.ceil((tonumber(family.expiresAt) - tonumber(ARGV[2])) / 1000))
redis.call("SET", KEYS[1], cjson.encode(family), "EX", ttl)
redis.call("SREM", KEYS[3], ARGV[3])
return 1`;

const REVOKE_ALL_SCRIPT = `-- DEVAUTHKIT_REVOKE_ALL_REFRESH
local families = redis.call("SMEMBERS", KEYS[1])
local revoked = 0
for _, familyHash in ipairs(families) do
  local familyKey = ARGV[1] .. "family:" .. familyHash
  local familyRaw = redis.call("GET", familyKey)
  if familyRaw then
    local family = cjson.decode(familyRaw)
    local tokensKey = ARGV[1] .. "family-tokens:" .. familyHash
    local members = redis.call("SMEMBERS", tokensKey)
    for _, suffix in ipairs(members) do
      redis.call("DEL", ARGV[1] .. "token:" .. suffix)
    end
    redis.call("DEL", tokensKey)
    family.revoked = true
    local ttl = math.max(1, math.ceil((tonumber(family.expiresAt) - tonumber(ARGV[2])) / 1000))
    redis.call("SET", familyKey, cjson.encode(family), "EX", ttl)
    revoked = revoked + 1
  end
end
redis.call("DEL", KEYS[1])
return revoked`;

const FAMILY_ACTIVE_SCRIPT = `-- DEVAUTHKIT_FAMILY_ACTIVE
local familyRaw = redis.call("GET", KEYS[1])
if not familyRaw then return 0 end
local family = cjson.decode(familyRaw)
if family.revoked or tonumber(family.expiresAt) <= tonumber(ARGV[1]) then return 0 end
local members = redis.call("SMEMBERS", KEYS[2])
for _, suffix in ipairs(members) do
  local tokenRaw = redis.call("GET", ARGV[2] .. "token:" .. suffix)
  if tokenRaw then
    local token = cjson.decode(tokenRaw)
    if token.status == "active" and tonumber(token.record.expiresAt) > tonumber(ARGV[1]) then
      return 1
    end
  end
end
return 0`;

class RedisRefreshTokenStore {
  constructor(client, options = {}) {
    if (!client || typeof client.get !== "function" || typeof client.eval !== "function") {
      throw new TypeError("RedisRefreshTokenStore requires a Redis client with get and eval methods");
    }
    if (options.keyPrefix !== undefined && typeof options.keyPrefix !== "string") {
      throw new TypeError("RedisRefreshTokenStore keyPrefix must be a string");
    }
    this.client = client;
    this.keyPrefix = `${options.keyPrefix || "devauthkit:refresh-token:"}{refresh}:`;
  }

  hash(value) {
    return createHash("sha256").update(String(value)).digest("hex");
  }

  tokenKey(tokenHash) {
    return `${this.keyPrefix}token:${this.hash(tokenHash)}`;
  }

  familyHash(familyId) {
    return this.hash(familyId);
  }

  familyKey(familyId) {
    return `${this.keyPrefix}family:${this.familyHash(familyId)}`;
  }

  familyTokensKey(familyId) {
    return `${this.keyPrefix}family-tokens:${this.familyHash(familyId)}`;
  }

  userFamiliesKey(userId) {
    return `${this.keyPrefix}user-families:${this.hash(userId)}`;
  }

  validateRecord(record) {
    if (
      !record || typeof record !== "object" ||
      typeof record.familyId !== "string" || !record.familyId ||
      (typeof record.userId !== "string" && typeof record.userId !== "number") ||
      !record.user || typeof record.user !== "object" || Array.isArray(record.user) ||
      !Number.isSafeInteger(record.expiresAt) || record.expiresAt <= Date.now()
    ) {
      throw new TypeError("RedisRefreshTokenStore requires familyId, userId, and a future expiresAt");
    }
  }

  async create(tokenHash, record) {
    if (typeof tokenHash !== "string" || !tokenHash) {
      throw new TypeError("RedisRefreshTokenStore requires a non-empty token hash");
    }
    this.validateRecord(record);
    const expiresAt = record.expiresAt;
    const userId = String(record.userId);
    const familyHash = this.familyHash(record.familyId);
    const stored = JSON.stringify({ status: "active", record });
    const family = JSON.stringify({ userId, expiresAt, revoked: false });
    const created = await this.client.eval(CREATE_SCRIPT, {
      keys: [
        this.tokenKey(tokenHash),
        this.familyKey(record.familyId),
        this.familyTokensKey(record.familyId),
        this.userFamiliesKey(userId)
      ],
      arguments: [
        stored,
        String(expiresAt),
        String(Date.now()),
        family,
        this.hash(tokenHash),
        familyHash
      ]
    });
    if (Number(created) !== 1) {
      throw new Error("RedisRefreshTokenStore could not create token or token family");
    }
  }

  async rotate(tokenHash, replacementHash, replacement) {
    if (
      typeof tokenHash !== "string" || !tokenHash ||
      typeof replacementHash !== "string" || !replacementHash
    ) {
      throw new TypeError("RedisRefreshTokenStore requires non-empty token hashes");
    }
    if (!replacement || !Number.isSafeInteger(replacement.expiresAt) ||
        replacement.expiresAt <= Date.now()) {
      throw new TypeError("RedisRefreshTokenStore replacement expiresAt must be a future integer timestamp");
    }

    const currentKey = this.tokenKey(tokenHash);
    const currentValue = await this.client.get(currentKey);
    if (currentValue === null) return { status: "invalid" };
    let current;
    try {
      current = JSON.parse(currentValue);
    } catch (error) {
      throw new Error("RedisRefreshTokenStore found an invalid token record", { cause: error });
    }
    const record = current.record;
    if (
      !record || typeof record.familyId !== "string" || !record.familyId ||
      (typeof record.userId !== "string" && typeof record.userId !== "number") ||
      !Number.isSafeInteger(record.expiresAt)
    ) {
      throw new Error("RedisRefreshTokenStore found an invalid token record");
    }
    if (record.expiresAt <= Date.now()) return { status: "invalid" };
    const familyId = record.familyId;
    const userId = String(record.userId);
    const familyHash = this.familyHash(familyId);
    const replacementRecord = { ...record, ...replacement };
    const replacementValue = JSON.stringify({ status: "active", record: replacementRecord });
    const result = await this.client.eval(ROTATE_SCRIPT, {
      keys: [
        currentKey,
        this.tokenKey(replacementHash),
        this.familyKey(familyId),
        this.familyTokensKey(familyId),
        this.userFamiliesKey(userId)
      ],
      arguments: [
        String(Date.now()),
        replacementValue,
        String(replacement.expiresAt),
        familyId,
        userId,
        familyHash,
        this.keyPrefix,
        this.hash(replacementHash)
      ]
    });
    const status = Array.isArray(result) ? String(result[0]) : "";
    if (status === "rotated") {
      return { status, record: JSON.parse(String(result[1])) };
    }
    if (status === "invalid" || status === "reused") return { status };
    throw new Error("RedisRefreshTokenStore received an invalid rotation result");
  }

  async revoke(tokenHash) {
    if (typeof tokenHash !== "string" || !tokenHash) {
      throw new TypeError("RedisRefreshTokenStore requires a non-empty token hash");
    }
    const currentValue = await this.client.get(this.tokenKey(tokenHash));
    if (currentValue === null) return false;
    const current = JSON.parse(currentValue);
    if (!current.record?.familyId) {
      throw new Error("RedisRefreshTokenStore found a token without a family ID");
    }
    await this.revokeFamily(current.record.familyId);
    return true;
  }

  async revokeFamily(familyId) {
    if (typeof familyId !== "string" || !familyId) {
      throw new TypeError("RedisRefreshTokenStore requires a non-empty family ID");
    }
    const familyKey = this.familyKey(familyId);
    const familyValue = await this.client.get(familyKey);
    if (familyValue === null) return;
    const family = JSON.parse(familyValue);
    const familyHash = this.familyHash(familyId);
    await this.client.eval(REVOKE_FAMILY_SCRIPT, {
      keys: [
        familyKey,
        this.familyTokensKey(familyId),
        this.userFamiliesKey(family.userId)
      ],
      arguments: [this.keyPrefix, String(Date.now()), familyHash]
    });
  }

  async revokeAll(userId) {
    if (userId === undefined || userId === null || String(userId) === "") {
      throw new TypeError("RedisRefreshTokenStore requires a non-empty user ID");
    }
    await this.client.eval(REVOKE_ALL_SCRIPT, {
      keys: [this.userFamiliesKey(userId)],
      arguments: [this.keyPrefix, String(Date.now())]
    });
  }

  async isFamilyActive(familyId) {
    if (typeof familyId !== "string" || !familyId) return false;
    const familyHash = this.familyHash(familyId);
    const result = await this.client.eval(FAMILY_ACTIVE_SCRIPT, {
      keys: [this.familyKey(familyId), this.familyTokensKey(familyId)],
      arguments: [String(Date.now()), this.keyPrefix]
    });
    return Number(result) === 1;
  }
}

module.exports = { RedisRefreshTokenStore };
