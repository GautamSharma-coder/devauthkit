function isSecureURL(value, allowLocalHttp = false) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  const localHost = ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
  return (
    ["https:", "http:"].includes(url.protocol) &&
    (url.protocol === "https:" || (allowLocalHttp && localHost)) &&
    !url.username &&
    !url.password &&
    !url.hash
  );
}

function validateOAuthProviders(providers) {
  if (providers === undefined) return;
  if (!providers || typeof providers !== "object" || Array.isArray(providers)) {
    throw new TypeError("oauthProviders must be an object keyed by provider name");
  }

  for (const [name, provider] of Object.entries(providers)) {
    if (
      !/^[a-zA-Z0-9_-]{1,50}$/.test(name) ||
      ["google", "github", "__proto__", "prototype", "constructor"].includes(name)
    ) {
      throw new TypeError(`oauthProviders contains an invalid or reserved provider name: ${name}`);
    }
    if (!provider || typeof provider !== "object" || Array.isArray(provider)) {
      throw new TypeError(`oauthProviders.${name} must be an options object`);
    }
    if (
      typeof provider.clientId !== "string" || !provider.clientId.trim() ||
      typeof provider.clientSecret !== "string" || !provider.clientSecret.trim() ||
      typeof provider.mapProfile !== "function"
    ) {
      throw new TypeError(`oauthProviders.${name} requires clientId, clientSecret, and mapProfile`);
    }
    for (const key of ["authorizationURL", "tokenURL", "userInfoURL"]) {
      if (!isSecureURL(provider[key])) {
        throw new TypeError(`oauthProviders.${name}.${key} must be an absolute HTTPS URL`);
      }
    }
    if (!isSecureURL(provider.callbackURL, true)) {
      throw new TypeError(`oauthProviders.${name}.callbackURL must be HTTPS (HTTP is allowed on localhost)`);
    }
    if (provider.scope !== undefined && typeof provider.scope !== "string") {
      throw new TypeError(`oauthProviders.${name}.scope must be a string`);
    }
    if (provider.successRedirectURL !== undefined && !isSecureURL(provider.successRedirectURL, true)) {
      throw new TypeError(`oauthProviders.${name}.successRedirectURL must be HTTPS (HTTP is allowed on localhost)`);
    }
  }
}

module.exports = validateOAuthProviders;
