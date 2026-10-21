const validateOAuthProviders = require("./oauthProviderConfig");
const validatePasskeyConfig = require("./passkeyConfig");

const isFunction = (value) => typeof value === "function";

function checkConfig(options = {}, environment = process.env) {
  const issues = [];
  const add = (severity, code, message, fix) => {
    issues.push({ severity, code, message, fix });
  };
  const production = environment.NODE_ENV === "production";
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    add(
      "error",
      "invalid_options",
      "Configuration options must be an object.",
      "Pass the same options object you use to initialize DevAuthKit."
    );
    options = {};
  }
  const jwtSecret = options.jwtSecret || environment.JWT_SECRET ||
    options.sessionSecret || environment.SESSION_SECRET;
  const sessionSecret = options.sessionSecret || environment.SESSION_SECRET;
  const hasStrongSecret = (value) =>
    typeof value === "string" && Buffer.byteLength(value, "utf8") >= 32;
  const dpopEnabled = Boolean(options.dpop) && options.dpop !== "disabled" &&
    options.dpop?.mode !== "disabled";

  if (production && (!hasStrongSecret(jwtSecret) || !hasStrongSecret(sessionSecret))) {
    add(
      "error",
      "production_secrets",
      "Production requires explicit JWT and session secrets of at least 32 bytes.",
      "Set JWT_SECRET and SESSION_SECRET to independently generated secrets, each at least 32 bytes long."
    );
  }
  if (
    options.jwtSecret === "devAuthJwtSecretKey_change_in_production" ||
    options.sessionSecret === "devAuthSecret"
  ) {
    add(
      "error",
      "public_development_secret",
      "A public development secret is configured.",
      "Replace the development secret with a private, randomly generated value."
    );
  }

  if (dpopEnabled && (!options.dpopReplayStore ||
      !isFunction(options.dpopReplayStore.record))) {
    add(
      "error",
      "dpop_replay_store_missing",
      "DPoP is enabled without a replay store that can atomically claim proof IDs.",
      "Configure dpopReplayStore with an atomic record(jti, ttlSeconds) implementation."
    );
  } else if (
    dpopEnabled &&
    options.dpopReplayStore.constructor?.name === "MemoryDpopReplayStore"
  ) {
    add(
      production ? "error" : "warning",
      "dpop_memory_replay_store",
      "The in-memory DPoP replay store does not share replay state across processes or restarts.",
      "Use a shared atomic replay store in production; keep MemoryDpopReplayStore for single-process development."
    );
  }

  const oauthEnabled = Boolean(
    options.google || options.github ||
    (options.oauthProviders && Object.keys(options.oauthProviders).length)
  );
  if (oauthEnabled && !options.oauthStateStore) {
    add(
      production ? "error" : "warning",
      "oauth_state_store_missing",
      "OAuth state is stored in the Express session, which is process-local by default.",
      "Configure a persistent session store and an atomic oauthStateStore shared by all application instances."
    );
  } else if (options.oauthStateStore &&
      !["put", "consume"].every((method) => isFunction(options.oauthStateStore[method]))) {
    add(
      "error",
      "oauth_state_store_invalid",
      "oauthStateStore must implement put(state, expiresAt) and atomic consume(state).",
      "Provide both methods and ensure consume allows only one successful use per state."
    );
  }

  for (const provider of ["google", "github"]) {
    const providerOptions = options[provider];
    if (!providerOptions) continue;
    let callback;
    try {
      callback = new URL(providerOptions.callbackURL);
    } catch {
      add(
        "error",
        `${provider}_callback_url`,
        `${provider}.callbackURL must be an absolute HTTP or HTTPS URL.`,
        `Set ${provider}.callbackURL to the exact callback URL registered with your OAuth provider.`
      );
      continue;
    }
    const localHost = ["localhost", "127.0.0.1", "::1"].includes(callback.hostname);
    if (
      typeof providerOptions.clientId !== "string" || !providerOptions.clientId.trim() ||
      typeof providerOptions.clientSecret !== "string" || !providerOptions.clientSecret.trim() ||
      !["https:", "http:"].includes(callback.protocol) ||
      (callback.protocol !== "https:" && !localHost) ||
      callback.hash
    ) {
      add(
        "error",
        `${provider}_oauth_config`,
        `${provider} needs client credentials and an HTTPS callback URL (HTTP is allowed only on localhost).`,
        `Check ${provider}.clientId, ${provider}.clientSecret, and ${provider}.callbackURL.`
      );
    }
  }

  try {
    validateOAuthProviders(options.oauthProviders);
  } catch (error) {
    add("error", "oauth_provider_config", error.message, "Correct the indicated oauthProviders setting.");
  }

  try {
    validatePasskeyConfig(options.passkeys, options.passkeyStore, options.passkeyChallengeStore);
  } catch (error) {
    add("error", "passkey_config", error.message, "Correct the indicated passkey option or store.");
  }

  const requiredMethods = [
    ["otpStore", ["get", "set", "delete", "recordAttempt"]],
    ["refreshTokenStore", ["create", "rotate", "revoke", "revokeFamily", "revokeAll", "isFamilyActive"]]
  ];
  for (const [name, methods] of requiredMethods) {
    const store = options[name];
    if (store && !methods.every((method) => isFunction(store[method]))) {
      add(
        "error",
        `${name}_invalid`,
        `${name} must implement ${methods.join(", ")}.`,
        `Provide a ${name} implementation with all required methods.`
      );
    }
  }
  if (options.rateLimitStore && !isFunction(options.rateLimitStore.increment)) {
    add(
      "error",
      "rate_limit_store_invalid",
      "rateLimitStore must implement increment(key, windowMs).",
      "Provide a rateLimitStore with an atomic increment method."
    );
  }
  if (options.mfaStore && ![
    "get",
    "setPending",
    "activate",
    "consumeTotpCounter",
    "consumeRecoveryCode",
    "disable"
  ].every((method) => isFunction(options.mfaStore[method]))) {
    add(
      "error",
      "mfa_store_invalid",
      "mfaStore must implement get, setPending, activate, consumeTotpCounter, consumeRecoveryCode, and disable.",
      "Provide an MFA store with atomic TOTP-counter and recovery-code consumption."
    );
  }

  if (production) {
    if (options.mfaStore?.constructor?.name === "MemoryMfaStore") {
      add(
        "error",
        "mfa_store_in_memory",
        "The in-memory MFA store loses enrollment data on restart and is not shared across instances.",
        "Use a persistent MFA store that encrypts TOTP secrets at rest and atomically consumes codes."
      );
    }
    if (!options.otpStore) {
      add(
        "warning",
        "otp_store_in_memory",
        "OTP records use the process-local default store and can be lost on restart or unavailable on another instance.",
        "Configure a persistent otpStore shared by all application instances."
      );
    }
    if (!options.sessionStore) {
      add(
        "warning",
        "session_store_in_memory",
        "Express sessions use the process-local MemoryStore, which is not suitable for production or multiple instances.",
        "Configure a persistent express-session store, such as a Redis-backed store."
      );
    }
    if (options.magicLink && !options.magicLinkStore) {
      add(
        "warning",
        "magic_link_store_in_memory",
        "Magic-link records use process-local memory and are not shared across instances.",
        "Configure a persistent magicLinkStore shared by all application instances."
      );
    }
    if (options.refreshTokens && !options.refreshTokenStore) {
      add(
        "warning",
        "refresh_token_store_in_memory",
        "Refresh-token families use process-local memory and are not shared across instances.",
        "Configure a persistent refreshTokenStore with atomic rotation."
      );
    }
    if (options.rateLimit !== false && !options.rateLimitStore) {
      add(
        "warning",
        "rate_limit_store_in_memory",
        "Rate limits are process-local and can be bypassed by distributing requests across instances.",
        "Configure a shared rateLimitStore, such as the Redis rate-limit adapter."
      );
    }
    if (options.rateLimit === false) {
      add(
        "warning",
        "rate_limiting_disabled",
        "All built-in authentication rate limits are disabled in production.",
        "Enable rate limits or provide compensating protection at your gateway."
      );
    }
  }

  const origins = Array.isArray(options.corsOrigin) ? options.corsOrigin : [options.corsOrigin];
  if (origins.includes("*")) {
    add(
      "error",
      "cors_wildcard_credentials",
      "CORS cannot use a wildcard origin with credentialed authentication requests.",
      "List the exact frontend origins that should be allowed."
    );
  }

  const errors = issues.filter((issue) => issue.severity === "error").length;
  const warnings = issues.filter((issue) => issue.severity === "warning").length;
  return { valid: errors === 0, errors, warnings, issues };
}

module.exports = checkConfig;
