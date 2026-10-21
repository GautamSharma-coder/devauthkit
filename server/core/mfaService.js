const { createHmac, randomBytes, timingSafeEqual } = require("crypto");
const { sha256Hex, signJwt } = require("../utils/webCrypto");

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const TOTP_STEP_SECONDS = 30;
const RECOVERY_CODE_COUNT = 10;

class MfaError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "MfaError";
    this.status = status;
    this.code = code;
  }
}

function encodeBase32(bytes) {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function decodeBase32(value) {
  let bits = 0;
  let buffer = 0;
  const bytes = [];
  for (const character of value.toUpperCase().replace(/=+$/g, "")) {
    const index = BASE32_ALPHABET.indexOf(character);
    if (index === -1) throw new TypeError("Invalid base32 secret");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function totpAtCounter(secret, counter) {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", decodeBase32(secret)).update(message).digest();
  const offset = digest[digest.length - 1] & 15;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, "0");
}

function matchingTotpCounter(secret, code, now = Date.now()) {
  if (typeof code !== "string" || !/^\d{6}$/.test(code)) return null;
  const currentCounter = Math.floor(now / 1000 / TOTP_STEP_SECONDS);
  const candidateCounters = [currentCounter - 1, currentCounter, currentCounter + 1];
  for (const counter of candidateCounters) {
    if (counter < 0) continue;
    const expected = Buffer.from(totpAtCounter(secret, counter));
    const actual = Buffer.from(code);
    if (expected.length === actual.length && timingSafeEqual(expected, actual)) return counter;
  }
  return null;
}

function normalizeRecoveryCode(code) {
  return typeof code === "string" ? code.trim().toUpperCase().replace(/-/g, "") : "";
}

function createMfaService(store, options = {}) {
  if (!store || ![
    "get",
    "setPending",
    "activate",
    "consumeTotpCounter",
    "consumeRecoveryCode",
    "disable"
  ].every((method) => typeof store[method] === "function")) {
    throw new TypeError("mfaStore must implement get, setPending, activate, consumeTotpCounter, consumeRecoveryCode, and disable");
  }
  if (!options.jwtSecret) throw new TypeError("MFA service requires a JWT secret");
  const issuer = options.issuer || "DevAuthKit";
  const stepUpExpiresInSeconds = options.stepUpExpiresInSeconds ?? 300;
  if (!Number.isSafeInteger(stepUpExpiresInSeconds) || stepUpExpiresInSeconds < 30 ||
      stepUpExpiresInSeconds > 3600) {
    throw new TypeError("mfaStepUpExpiresInSeconds must be an integer from 30 through 3600");
  }

  function validateUserId(userId) {
    if ((typeof userId !== "string" && typeof userId !== "number") || !String(userId).trim()) {
      throw new MfaError(400, "invalid_user", "A stable user ID is required for MFA");
    }
    return String(userId);
  }

  async function startEnrollment(userId, accountName) {
    userId = validateUserId(userId);
    const current = await store.get(userId);
    if (current?.enabled) {
      throw new MfaError(409, "mfa_already_enabled", "MFA is already enabled for this account");
    }
    const secret = encodeBase32(randomBytes(20));
    const expiresAt = Date.now() + 10 * 60 * 1000;
    const started = await store.setPending(userId, { secret, expiresAt });
    if (!started) {
      throw new MfaError(409, "mfa_already_enabled", "MFA is already enabled for this account");
    }
    const label = `${issuer}:${accountName || userId}`;
    const otpauthUrl = `otpauth://totp/${encodeURIComponent(label)}?${new URLSearchParams({
      secret,
      issuer,
      algorithm: "SHA1",
      digits: "6",
      period: String(TOTP_STEP_SECONDS)
    })}`;
    return { secret, otpauthUrl, expiresAt };
  }

  async function activate(userId, code) {
    userId = validateUserId(userId);
    const current = await store.get(userId);
    if (!current?.pending || current.pending.expiresAt <= Date.now()) {
      throw new MfaError(400, "mfa_enrollment_expired", "Start a new MFA enrollment before verifying a code");
    }
    const counter = matchingTotpCounter(current.pending.secret, code);
    if (counter === null) {
      throw new MfaError(400, "invalid_mfa_code", "The authenticator code is invalid");
    }
    const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, () =>
      randomBytes(10).toString("hex").toUpperCase().match(/.{1,5}/g).join("-")
    );
    const hashes = await Promise.all(recoveryCodes.map((value) =>
      sha256Hex(normalizeRecoveryCode(value))
    ));
    const activated = await store.activate(
      userId,
      current.pending.secret,
      counter,
      hashes
    );
    if (!activated) {
      throw new MfaError(409, "mfa_enrollment_changed", "MFA enrollment changed; start again");
    }
    return recoveryCodes;
  }

  async function verify(userId, code) {
    userId = validateUserId(userId);
    const current = await store.get(userId);
    if (!current?.enabled) {
      throw new MfaError(409, "mfa_not_enabled", "MFA is not enabled for this account");
    }
    const counter = matchingTotpCounter(current.secret, code);
    let verified = false;
    if (counter !== null) {
      verified = await store.consumeTotpCounter(userId, counter);
    } else {
      const normalized = normalizeRecoveryCode(code);
      if (/^[A-F0-9]{20}$/.test(normalized)) {
        verified = await store.consumeRecoveryCode(userId, await sha256Hex(normalized));
      }
    }
    if (!verified) {
      throw new MfaError(401, "invalid_mfa_code", "The MFA code is invalid or has already been used");
    }
    return signJwt({
      sub: userId,
      amr: ["totp"],
      purpose: "mfa-step-up"
    }, options.jwtSecret, stepUpExpiresInSeconds);
  }

  async function disable(userId) {
    userId = validateUserId(userId);
    await store.disable(userId);
  }

  async function status(userId) {
    userId = validateUserId(userId);
    const current = await store.get(userId);
    return {
      enabled: Boolean(current?.enabled),
      recoveryCodesRemaining: current?.enabled ? current.recoveryCodeHashes.length : 0
    };
  }

  return { startEnrollment, activate, verify, disable, status };
}

module.exports = {
  MfaError,
  createMfaService,
  matchingTotpCounter,
  totpAtCounter
};
