const encoder = new TextEncoder();
const decoder = new TextDecoder();

let cachedCrypto = null;

function cryptoApi() {
  if (cachedCrypto) return cachedCrypto;
  if (globalThis.crypto?.subtle && typeof globalThis.crypto.getRandomValues === "function") {
    cachedCrypto = globalThis.crypto;
    return cachedCrypto;
  }
  try {
    const nodeCrypto = require("node:crypto");
    const webcrypto = nodeCrypto.webcrypto;
    if (webcrypto?.subtle && typeof webcrypto.getRandomValues === "function") {
      cachedCrypto = webcrypto;
      if (!globalThis.crypto) {
        try {
          globalThis.crypto = webcrypto;
        } catch {}
      }
      return cachedCrypto;
    }
  } catch {}
  try {
    const nodeCrypto = require("crypto");
    const webcrypto = nodeCrypto.webcrypto;
    if (webcrypto?.subtle && typeof webcrypto.getRandomValues === "function") {
      cachedCrypto = webcrypto;
      if (!globalThis.crypto) {
        try {
          globalThis.crypto = webcrypto;
        } catch {}
      }
      return cachedCrypto;
    }
  } catch {}
  throw new Error("DevAuthKit requires the Web Crypto API");
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function fromBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  cryptoApi().getRandomValues(bytes);
  return bytes;
}

function randomString(length, encoding = "base64url") {
  const bytes = randomBytes(length);
  if (encoding === "hex") {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  if (encoding === "base64url") return toBase64Url(bytes);
  throw new TypeError(`Unsupported random string encoding: ${encoding}`);
}

function randomUUID() {
  if (typeof cryptoApi().randomUUID === "function") return cryptoApi().randomUUID();
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

async function digest(algorithm, value) {
  return new Uint8Array(await cryptoApi().subtle.digest(algorithm, encoder.encode(value)));
}

async function sha256Hex(value) {
  return Array.from(await digest("SHA-256", value), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Base64Url(value) {
  return toBase64Url(await digest("SHA-256", value));
}

function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index++) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}

function durationSeconds(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  const match = typeof value === "string" && value.match(/^(\d+)(ms|s|m|h|d|w|y)$/);
  if (!match) throw new TypeError("JWT expiration must be a number or a duration such as 15m or 7d");
  return Number(match[1]) * ({
    ms: 0.001,
    s: 1,
    m: 60,
    h: 3600,
    d: 86400,
    w: 604800,
    y: 31536000
  }[match[2]]);
}

async function hmacKey(secret, usages) {
  if (typeof secret !== "string" || !secret) throw new TypeError("JWT secret must be a non-empty string");
  return cryptoApi().subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    usages
  );
}

async function signJwt(payload, secret, expiresIn) {
  const now = Math.floor(Date.now() / 1000);
  const claims = { ...payload };
  if (claims.iat === undefined) claims.iat = now;
  if (expiresIn !== undefined) claims.exp = claims.iat + durationSeconds(expiresIn);
  const header = toBase64Url(encoder.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const body = toBase64Url(encoder.encode(JSON.stringify(claims)));
  const signingInput = `${header}.${body}`;
  const signature = await cryptoApi().subtle.sign(
    "HMAC",
    await hmacKey(secret, ["sign"]),
    encoder.encode(signingInput)
  );
  return `${signingInput}.${toBase64Url(new Uint8Array(signature))}`;
}

async function verifyJwt(token, secret) {
  if (typeof token !== "string") throw new TypeError("JWT must be a string");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT");
  const header = JSON.parse(decoder.decode(fromBase64Url(parts[0])));
  if (header.alg !== "HS256") throw new Error("Unsupported JWT algorithm");
  const valid = await cryptoApi().subtle.verify(
    "HMAC",
    await hmacKey(secret, ["verify"]),
    fromBase64Url(parts[2]),
    encoder.encode(`${parts[0]}.${parts[1]}`)
  );
  if (!valid) throw new Error("Invalid JWT signature");
  const payload = JSON.parse(decoder.decode(fromBase64Url(parts[1])));
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === "number" && now >= payload.exp) throw new Error("JWT expired");
  if (typeof payload.nbf === "number" && now < payload.nbf) throw new Error("JWT not active");
  return payload;
}

module.exports = {
  constantTimeEqual,
  cryptoApi,
  fromBase64Url,
  randomBytes,
  randomString,
  randomUUID,
  sha256Base64Url,
  sha256Hex,
  signJwt,
  toBase64Url,
  verifyJwt
};
