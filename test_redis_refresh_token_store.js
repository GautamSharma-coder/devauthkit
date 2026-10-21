const assert = require("node:assert/strict");
const { RedisRefreshTokenStore } = require("./server/stores/redisRefreshTokenStore");

function createRedisMock() {
  const values = new Map();
  const sets = new Map();
  const members = (key) => {
    if (!sets.has(key)) sets.set(key, new Set());
    return sets.get(key);
  };
  const revokeFamily = (familyKey, tokenSetKey, userSetKey, prefix, familyHash, now) => {
    const raw = values.get(familyKey);
    if (raw === undefined) return false;
    const family = JSON.parse(raw);
    for (const tokenHash of members(tokenSetKey)) values.delete(`${prefix}token:${tokenHash}`);
    sets.delete(tokenSetKey);
    family.revoked = true;
    values.set(familyKey, JSON.stringify(family));
    members(userSetKey).delete(familyHash);
    return true;
  };

  return {
    values,
    sets,
    async get(key) {
      return values.get(key) ?? null;
    },
    async eval(script, { keys, arguments: args }) {
      if (script.includes("DEVAUTHKIT_CREATE_REFRESH")) {
        if (values.has(keys[0])) return 0;
        const existingFamily = values.get(keys[1]);
        if (existingFamily && JSON.parse(existingFamily).revoked) return 0;
        values.set(keys[0], args[0]);
        values.set(keys[1], args[3]);
        members(keys[2]).add(args[4]);
        members(keys[3]).add(args[5]);
        return 1;
      }
      if (script.includes("DEVAUTHKIT_ROTATE_REFRESH")) {
        const currentRaw = values.get(keys[0]);
        if (!currentRaw) return ["invalid"];
        const current = JSON.parse(currentRaw);
        if (current.record.familyId !== args[3] || current.record.userId !== args[4]) {
          return ["invalid"];
        }
        const family = JSON.parse(values.get(keys[2]) || "null");
        if (!family) return ["invalid"];
        const revoke = () => revokeFamily(
          keys[2], keys[3], keys[4], args[6], args[5], Number(args[0])
        );
        if (current.status === "used" || family.revoked) {
          revoke();
          return ["reused"];
        }
        if (values.has(keys[1])) return ["invalid"];
        current.status = "used";
        values.set(keys[0], JSON.stringify(current));
        values.set(keys[1], args[1]);
        members(keys[3]).add(args[7]);
        family.expiresAt = Math.max(family.expiresAt, Number(args[2]));
        values.set(keys[2], JSON.stringify(family));
        return ["rotated", JSON.stringify(current.record)];
      }
      if (script.includes("DEVAUTHKIT_REVOKE_REFRESH_FAMILY")) {
        return revokeFamily(keys[0], keys[1], keys[2], args[0], args[2], Number(args[1])) ? 1 : 0;
      }
      if (script.includes("DEVAUTHKIT_REVOKE_ALL_REFRESH")) {
        const familyHashes = [...members(keys[0])];
        let revoked = 0;
        for (const familyHash of familyHashes) {
          const familyKey = `${args[0]}family:${familyHash}`;
          const familyRaw = values.get(familyKey);
          if (!familyRaw) continue;
          const family = JSON.parse(familyRaw);
          const tokenSetKey = `${args[0]}family-tokens:${familyHash}`;
          for (const tokenHash of members(tokenSetKey)) values.delete(`${args[0]}token:${tokenHash}`);
          sets.delete(tokenSetKey);
          family.revoked = true;
          values.set(familyKey, JSON.stringify(family));
          revoked++;
        }
        sets.delete(keys[0]);
        return revoked;
      }
      if (script.includes("DEVAUTHKIT_FAMILY_ACTIVE")) {
        const familyRaw = values.get(keys[0]);
        if (!familyRaw) return 0;
        const family = JSON.parse(familyRaw);
        if (family.revoked || family.expiresAt <= Number(args[0])) return 0;
        for (const tokenHash of members(keys[1])) {
          const raw = values.get(`${args[1]}token:${tokenHash}`);
          if (!raw) continue;
          const token = JSON.parse(raw);
          if (token.status === "active" && token.record.expiresAt > Number(args[0])) return 1;
        }
        return 0;
      }
      throw new Error("Unexpected Redis script");
    }
  };
}

async function run() {
  const redis = createRedisMock();
  const store = new RedisRefreshTokenStore(redis, { keyPrefix: "test:refresh:" });
  const now = Date.now();
  const record = {
    familyId: "family-one",
    userId: "user-one",
    user: { id: "user-one", email: "refresh@example.com" },
    expiresAt: now + 60_000
  };

  await store.create("token-one", record);
  assert.equal(await store.isFamilyActive(record.familyId), true);
  const firstRotation = await store.rotate("token-one", "token-two", {
    expiresAt: now + 120_000
  });
  assert.equal(firstRotation.status, "rotated");
  assert.deepEqual(firstRotation.record, record);
  assert.equal(await store.isFamilyActive(record.familyId), true);

  const concurrentRotations = await Promise.all([
    store.rotate("token-two", "token-three-a", { expiresAt: now + 180_000 }),
    store.rotate("token-two", "token-three-b", { expiresAt: now + 180_000 })
  ]);
  assert.equal(concurrentRotations.filter((result) => result.status === "rotated").length, 1);
  assert.equal(concurrentRotations.filter((result) => result.status === "reused").length, 1);
  assert.equal(await store.isFamilyActive(record.familyId), false);
  assert.deepEqual(await store.rotate("absent-token", "replacement", {
    expiresAt: now + 60_000
  }), { status: "invalid" });

  const revokeRecord = { ...record, familyId: "family-revoke" };
  await store.create("token-revoke", revokeRecord);
  assert.equal(await store.revoke("token-revoke"), true);
  assert.equal(await store.isFamilyActive(revokeRecord.familyId), false);
  assert.equal(await store.revoke("missing-token"), false);

  const userFamilyOne = { ...record, familyId: "family-user-a" };
  const userFamilyTwo = { ...record, familyId: "family-user-b" };
  await store.create("token-user-a", userFamilyOne);
  await store.create("token-user-b", userFamilyTwo);
  await store.revokeAll("user-one");
  assert.equal(await store.isFamilyActive(userFamilyOne.familyId), false);
  assert.equal(await store.isFamilyActive(userFamilyTwo.familyId), false);

  assert.throws(() => new RedisRefreshTokenStore({}), /get and eval/);
  console.log("Redis refresh-token store tests passed.");
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
