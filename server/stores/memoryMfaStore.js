class MemoryMfaStore {
  constructor() {
    this.users = new Map();
  }

  async get(userId) {
    const record = this.users.get(String(userId));
    if (!record) return null;
    return {
      ...record,
      recoveryCodeHashes: [...(record.recoveryCodeHashes || [])]
    };
  }

  async setPending(userId, pending) {
    const key = String(userId);
    const current = this.users.get(key);
    if (current?.enabled) return false;
    this.users.set(key, {
      enabled: false,
      pending: { ...pending },
      recoveryCodeHashes: []
    });
    return true;
  }

  async activate(userId, expectedSecret, lastTotpCounter, recoveryCodeHashes) {
    const key = String(userId);
    const current = this.users.get(key);
    if (
      !current?.pending ||
      current.pending.expiresAt <= Date.now() ||
      current.pending.secret !== expectedSecret
    ) return false;

    this.users.set(key, {
      enabled: true,
      secret: expectedSecret,
      lastTotpCounter,
      recoveryCodeHashes: [...recoveryCodeHashes]
    });
    return true;
  }

  async consumeTotpCounter(userId, counter) {
    const record = this.users.get(String(userId));
    if (!record?.enabled || !Number.isSafeInteger(counter) || counter <= record.lastTotpCounter) {
      return false;
    }
    record.lastTotpCounter = counter;
    return true;
  }

  async consumeRecoveryCode(userId, recoveryCodeHash) {
    const record = this.users.get(String(userId));
    if (!record?.enabled) return false;
    const index = record.recoveryCodeHashes.indexOf(recoveryCodeHash);
    if (index === -1) return false;
    record.recoveryCodeHashes.splice(index, 1);
    return true;
  }

  async disable(userId) {
    return this.users.delete(String(userId));
  }
}

module.exports = { MemoryMfaStore };
