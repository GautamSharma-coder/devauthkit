const { randomString, sha256Hex } = require("../utils/webCrypto");

function validateDatabase(database) {
  if (!database || typeof database.prepare !== "function" || typeof database.batch !== "function") {
    throw new TypeError("CloudflareD1PasskeyStore requires a D1 database with prepare and batch methods");
  }
}

function validatePrefix(value) {
  if (typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new TypeError("CloudflareD1PasskeyStore tablePrefix must be a valid SQL identifier prefix");
  }
  return value;
}

function bytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (Array.isArray(value) && value.every(
    (byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255
  )) {
    return Uint8Array.from(value);
  }
  throw new TypeError("D1 passkey record contains an invalid public key");
}

function parseTransports(value) {
  let transports;
  try {
    transports = JSON.parse(value);
  } catch (error) {
    throw new TypeError(`D1 passkey record contains invalid transports JSON: ${error.message}`);
  }
  if (!Array.isArray(transports) || transports.some((item) => typeof item !== "string")) {
    throw new TypeError("D1 passkey record contains invalid transports");
  }
  return transports;
}

function mapCredential(row) {
  if (!row) return null;
  if (
    typeof row.credential_id !== "string" ||
    typeof row.user_id !== "string" ||
    typeof row.user_handle !== "string" ||
    typeof row.email !== "string" ||
    !Number.isSafeInteger(row.counter) ||
    row.counter < 0 ||
    !["singleDevice", "multiDevice"].includes(row.device_type) ||
    ![0, 1].includes(row.backed_up) ||
    !Number.isSafeInteger(row.created_at)
  ) {
    throw new TypeError("D1 passkey record contains invalid credential metadata");
  }
  return {
    id: row.credential_id,
    userId: row.user_id,
    userHandle: row.user_handle,
    email: row.email,
    publicKey: bytes(row.public_key),
    counter: row.counter,
    transports: parseTransports(row.transports),
    deviceType: row.device_type,
    backedUp: Boolean(row.backed_up),
    createdAt: row.created_at
  };
}

class CloudflareD1PasskeyStore {
  constructor(database, options = {}) {
    validateDatabase(database);
    const prefix = validatePrefix(options.tablePrefix || "devauthkit_passkey_");
    this.database = database;
    this.usersTable = `${prefix}users`;
    this.credentialsTable = `${prefix}credentials`;
    this.challengesTable = `${prefix}challenges`;
  }

  async createTables() {
    await this.database.batch([
      this.database.prepare(
        `CREATE TABLE IF NOT EXISTS ${this.usersTable} (` +
        "user_id TEXT PRIMARY KEY, user_handle TEXT NOT NULL UNIQUE)"
      ),
      this.database.prepare(
        `CREATE TABLE IF NOT EXISTS ${this.credentialsTable} (` +
        "credential_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, user_handle TEXT NOT NULL, " +
        "email TEXT NOT NULL, public_key BLOB NOT NULL, counter INTEGER NOT NULL, transports TEXT NOT NULL, " +
        "device_type TEXT NOT NULL, backed_up INTEGER NOT NULL, created_at INTEGER NOT NULL)"
      ),
      this.database.prepare(
        `CREATE INDEX IF NOT EXISTS ${this.credentialsTable}_user_idx ON ${this.credentialsTable}(user_id)`
      ),
      this.database.prepare(
        `CREATE TABLE IF NOT EXISTS ${this.challengesTable} (` +
        "challenge_hash TEXT PRIMARY KEY, purpose TEXT NOT NULL, user_id TEXT, email TEXT, expires_at INTEGER NOT NULL)"
      ),
      this.database.prepare(
        `CREATE INDEX IF NOT EXISTS ${this.challengesTable}_expires_idx ON ${this.challengesTable}(expires_at)`
      )
    ]);
  }

  async getUserHandle(userId) {
    if (typeof userId !== "string" || !userId) {
      throw new TypeError("Passkey user ID must be a non-empty string");
    }
    const candidate = randomString(32);
    await this.database.prepare(
      `INSERT INTO ${this.usersTable} (user_id, user_handle) VALUES (?, ?) ` +
      "ON CONFLICT(user_id) DO NOTHING"
    ).bind(userId, candidate).run();
    const row = await this.database.prepare(
      `SELECT user_handle FROM ${this.usersTable} WHERE user_id = ?`
    ).bind(userId).first();
    if (!row || typeof row.user_handle !== "string" || !row.user_handle) {
      throw new TypeError("D1 passkey store failed to create a stable user handle");
    }
    return row.user_handle;
  }

  async put(challenge, record) {
    if (typeof challenge !== "string" || !challenge) {
      throw new TypeError("Passkey challenge must be a non-empty string");
    }
    if (
      !record ||
      !["registration", "authentication"].includes(record.purpose) ||
      !Number.isSafeInteger(record.expiresAt) ||
      record.expiresAt <= Date.now() ||
      (record.userId !== undefined && (typeof record.userId !== "string" || !record.userId)) ||
      (record.email !== undefined && (typeof record.email !== "string" || !record.email)) ||
      (record.purpose === "registration" && (!record.userId || !record.email))
    ) {
      throw new TypeError("Passkey challenge purpose, expiry, and registration identity are required");
    }
    const challengeHash = await sha256Hex(challenge);
    const now = Date.now();
    await this.database.batch([
      this.database.prepare(`DELETE FROM ${this.challengesTable} WHERE expires_at <= ?`).bind(now),
      this.database.prepare(
        `INSERT INTO ${this.challengesTable} (challenge_hash, purpose, user_id, email, expires_at) ` +
        "VALUES (?, ?, ?, ?, ?)"
      ).bind(challengeHash, record.purpose, record.userId || null, record.email || null, record.expiresAt)
    ]);
  }

  async consume(challenge, purpose) {
    if (
      typeof challenge !== "string" || !challenge ||
      !["registration", "authentication"].includes(purpose)
    ) return null;
    const challengeHash = await sha256Hex(challenge);
    const row = await this.database.prepare(
      `DELETE FROM ${this.challengesTable} WHERE challenge_hash = ? AND purpose = ? AND expires_at > ? ` +
      "RETURNING purpose, user_id, email, expires_at"
    ).bind(challengeHash, purpose, Date.now()).first();
    if (!row) return null;
    return {
      purpose: row.purpose,
      ...(row.user_id ? { userId: row.user_id } : {}),
      ...(row.email ? { email: row.email } : {}),
      expiresAt: row.expires_at
    };
  }

  async create(credential) {
    if (
      !credential ||
      !["id", "userId", "userHandle", "email", "deviceType"].every(
        (key) => typeof credential[key] === "string" && credential[key]
      ) ||
      !(credential.publicKey instanceof Uint8Array) ||
      credential.publicKey.byteLength === 0 ||
      !Number.isSafeInteger(credential.counter) ||
      credential.counter < 0 ||
      !Array.isArray(credential.transports) ||
      credential.transports.some((transport) => typeof transport !== "string") ||
      typeof credential.backedUp !== "boolean" ||
      !Number.isSafeInteger(credential.createdAt)
    ) {
      throw new TypeError("Passkey credential record is invalid");
    }
    await this.database.prepare(
      `INSERT INTO ${this.credentialsTable} ` +
      "(credential_id, user_id, user_handle, email, public_key, counter, transports, device_type, backed_up, created_at) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(
      credential.id,
      credential.userId,
      credential.userHandle,
      credential.email,
      credential.publicKey,
      credential.counter,
      JSON.stringify(credential.transports),
      credential.deviceType,
      credential.backedUp ? 1 : 0,
      credential.createdAt
    ).run();
  }

  async getByCredentialId(credentialId) {
    if (typeof credentialId !== "string" || !credentialId) return null;
    const row = await this.database.prepare(
      `SELECT * FROM ${this.credentialsTable} WHERE credential_id = ?`
    ).bind(credentialId).first();
    return mapCredential(row);
  }

  async listByUserId(userId) {
    if (typeof userId !== "string" || !userId) return [];
    const result = await this.database.prepare(
      `SELECT credential_id, created_at, device_type, backed_up, transports ` +
      `FROM ${this.credentialsTable} WHERE user_id = ? ORDER BY created_at`
    ).bind(userId).all();
    return (result.results || []).map((row) => ({
      id: row.credential_id,
      createdAt: row.created_at,
      deviceType: row.device_type,
      backedUp: Boolean(row.backed_up),
      transports: parseTransports(row.transports)
    }));
  }

  async updateCounter(credentialId, expectedCounter, newCounter, deviceType, backedUp) {
    if (
      typeof credentialId !== "string" ||
      !Number.isSafeInteger(expectedCounter) || expectedCounter < 0 ||
      !Number.isSafeInteger(newCounter) || newCounter < 0 ||
      !["singleDevice", "multiDevice"].includes(deviceType) ||
      typeof backedUp !== "boolean"
    ) {
      throw new TypeError("Passkey signature counter update is invalid");
    }
    const result = await this.database.prepare(
      `UPDATE ${this.credentialsTable} SET counter = ?, device_type = ?, backed_up = ? ` +
      "WHERE credential_id = ? AND counter = ?"
    ).bind(newCounter, deviceType, backedUp ? 1 : 0, credentialId, expectedCounter).run();
    return result.meta?.changes === 1;
  }

  async deleteByCredentialId(credentialId, userId) {
    if (typeof credentialId !== "string" || !credentialId || typeof userId !== "string" || !userId) {
      return false;
    }
    const result = await this.database.prepare(
      `DELETE FROM ${this.credentialsTable} WHERE credential_id = ? AND user_id = ?`
    ).bind(credentialId, userId).run();
    return result.meta?.changes === 1;
  }
}

module.exports = { CloudflareD1PasskeyStore };
