function validatePasskeyConfig(options, passkeyStore, challengeStore) {
  if (options === undefined || options === false) return;
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    throw new TypeError("passkeys must be an options object");
  }
  if (typeof options.rpName !== "string" || !options.rpName.trim() || options.rpName.length > 100) {
    throw new TypeError("passkeys.rpName must be a non-empty string of at most 100 characters");
  }
  if (
    typeof options.rpID !== "string" ||
    !options.rpID ||
    options.rpID !== options.rpID.toLowerCase() ||
    options.rpID.startsWith(".") ||
    options.rpID.endsWith(".")
  ) {
    throw new TypeError("passkeys.rpID must be a lowercase domain name or localhost");
  }
  let rpURL;
  try {
    rpURL = new URL(`https://${options.rpID}`);
  } catch {
    throw new TypeError("passkeys.rpID must be a valid domain name or localhost");
  }
  if (rpURL.hostname !== options.rpID || rpURL.host !== options.rpID || rpURL.pathname !== "/") {
    throw new TypeError("passkeys.rpID must not include a scheme, port, or path");
  }
  if (!Array.isArray(options.origins) || options.origins.length === 0) {
    throw new TypeError("passkeys.origins must be a non-empty allowlist of origins");
  }
  for (const value of options.origins) {
    let origin;
    try {
      origin = new URL(value);
    } catch {
      throw new TypeError("Every passkeys origin must be a valid absolute origin");
    }
    const localHost = ["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname);
    if (
      !["https:", "http:"].includes(origin.protocol) ||
      (origin.protocol === "http:" && !localHost) ||
      origin.origin !== value ||
      (origin.hostname !== options.rpID && !origin.hostname.endsWith(`.${options.rpID}`))
    ) {
      throw new TypeError(
        "Passkey origins must be exact HTTPS origins (HTTP is allowed for localhost) matching rpID"
      );
    }
  }
  if (
    options.challengeTtlSeconds !== undefined &&
    (!Number.isSafeInteger(options.challengeTtlSeconds) ||
      options.challengeTtlSeconds < 30 ||
      options.challengeTtlSeconds > 600)
  ) {
    throw new TypeError("passkeys.challengeTtlSeconds must be an integer from 30 through 600");
  }
  if (!passkeyStore || ![
    "getUserHandle",
    "create",
    "getByCredentialId",
    "listByUserId",
    "updateCounter",
    "deleteByCredentialId"
  ].every((method) => typeof passkeyStore[method] === "function")) {
    throw new TypeError("Passkeys require a passkeyStore implementing the credential and user-handle methods");
  }
  if (!challengeStore || !["put", "consume"].every(
    (method) => typeof challengeStore[method] === "function"
  )) {
    throw new TypeError("Passkeys require a passkeyChallengeStore implementing put and atomic consume");
  }
}

module.exports = validatePasskeyConfig;
