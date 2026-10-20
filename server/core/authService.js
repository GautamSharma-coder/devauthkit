const { randomString, randomUUID, sha256Hex, signJwt } = require("../utils/webCrypto");

function createAuthService({ config, getRefreshTokenStore }) {
  function refreshOptions() {
    const value = config.get("refreshTokens");
    if (!value) return null;
    const options = typeof value === "object" ? value : {};
    return {
      accessTokenExpiresIn: options.accessTokenExpiresIn || "15m",
      refreshTokenExpiresInDays: options.refreshTokenExpiresInDays ?? 30
    };
  }

  async function resolveUserPayload(email, identity = {}) {
    const userAdapter = config.get("userAdapter");
    if (!userAdapter) {
      return {
        email,
        ...(identity.name ? { name: identity.name } : {}),
        ...(identity.picture ? { picture: identity.picture } : {})
      };
    }

    const dbUser = identity.provider && identity.providerId &&
      typeof userAdapter.findUserByOAuthIdentity === "function"
      ? await userAdapter.findUserByOAuthIdentity({
        provider: identity.provider,
        providerId: identity.providerId
      }) || await userAdapter.findOrCreateUser({ email })
      : await userAdapter.findOrCreateUser({ email });
    if (!dbUser || typeof dbUser !== "object" || dbUser.id === undefined || !dbUser.email) {
      throw new TypeError("userAdapter.findOrCreateUser must return a user with id and email");
    }

    const mappedClaims = config.get("mapUserPayload")
      ? config.get("mapUserPayload")(dbUser, identity)
      : {};
    if (!mappedClaims || typeof mappedClaims !== "object" || Array.isArray(mappedClaims)) {
      throw new TypeError("mapUserPayload must return an object");
    }

    return {
      ...mappedClaims,
      id: dbUser.id,
      email: dbUser.email,
      ...(dbUser.role !== undefined ? { role: dbUser.role } : {})
    };
  }

  async function createAccessToken(userPayload, familyId) {
    if (!familyId) {
      return signJwt(userPayload, config.get("jwtSecret"), config.get("jwtExpiresIn"));
    }
    const options = refreshOptions();
    return signJwt(
      { ...userPayload, sid: familyId, jti: randomUUID() },
      config.get("jwtSecret"),
      options.accessTokenExpiresIn
    );
  }

  async function issueTokens(userPayload, cookies) {
    const refreshConfig = refreshOptions();
    if (!refreshConfig) {
      const token = await createAccessToken(userPayload);
      cookies.setAuthCookie(token);
      return { token, user: userPayload };
    }

    const familyId = randomUUID();
    const refreshToken = randomString(48);
    const expiresAt = Date.now() + refreshConfig.refreshTokenExpiresInDays * 24 * 60 * 60 * 1000;
    await getRefreshTokenStore().create(await sha256Hex(refreshToken), {
      familyId,
      userId: String(userPayload.id ?? userPayload.email),
      user: userPayload,
      expiresAt
    });

    const token = await createAccessToken(userPayload, familyId);
    cookies.setAuthCookie(token);
    cookies.setRefreshCookie(
      refreshToken,
      refreshConfig.refreshTokenExpiresInDays * 24 * 60 * 60 * 1000
    );
    const tokens = {
      token,
      user: userPayload,
      refreshEnabled: true,
      expiresIn: refreshConfig.accessTokenExpiresIn
    };
    Object.defineProperty(tokens, "sessionId", { value: familyId });
    return tokens;
  }

  return {
    createAccessToken,
    hashRefreshToken: sha256Hex,
    issueTokens,
    refreshOptions,
    resolveUserPayload
  };
}

module.exports = { createAuthService };
