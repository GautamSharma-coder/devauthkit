class PasskeyServiceError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "PasskeyServiceError";
    this.status = status;
  }
}

function getWebAuthn() {
  return {
    ...require("@simplewebauthn/server"),
    isoBase64URL: require("@simplewebauthn/server/helpers").isoBase64URL
  };
}

function getStore(config, key) {
  const store = config.get(key);
  if (!store) throw new Error(`${key} is not configured`);
  return store;
}

function validateUser(user) {
  if (
    !user ||
    typeof user.email !== "string" ||
    !user.email.trim() ||
    (user.id !== undefined && !["string", "number"].includes(typeof user.id))
  ) {
    throw new PasskeyServiceError(401, "An authenticated user identity is required");
  }
  return {
    id: String(user.id ?? user.email),
    email: user.email.trim().toLowerCase(),
    displayName: typeof user.name === "string" && user.name.trim()
      ? user.name.trim()
      : user.email.trim()
  };
}

function passkeyOptions(config) {
  const options = config.get("passkeys");
  if (!options) throw new PasskeyServiceError(404, "Passkeys are not configured");
  return options;
}

function createPasskeyService({ config, authService, loadWebAuthn = getWebAuthn }) {
  async function registrationOptions(authenticatedUser) {
    const { generateRegistrationOptions, isoBase64URL } = loadWebAuthn();
    const user = validateUser(authenticatedUser);
    const settings = passkeyOptions(config);
    const passkeyStore = getStore(config, "passkeyStore");
    const challengeStore = getStore(config, "passkeyChallengeStore");
    const userHandle = await passkeyStore.getUserHandle(user.id);
    const existing = await passkeyStore.listByUserId(user.id);
    const options = await generateRegistrationOptions({
      rpName: settings.rpName,
      rpID: settings.rpID,
      userName: user.email,
      userDisplayName: user.displayName,
      userID: isoBase64URL.toBuffer(userHandle),
      attestationType: "none",
      excludeCredentials: existing.map((credential) => ({
        id: credential.id,
        transports: credential.transports
      })),
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required"
      }
    });
    await challengeStore.put(options.challenge, {
      purpose: "registration",
      userId: user.id,
      email: user.email,
      expiresAt: Date.now() + (settings.challengeTtlSeconds ?? 300) * 1000
    });
    return options;
  }

  async function verifyRegistration(authenticatedUser, response) {
    const { verifyRegistrationResponse } = loadWebAuthn();
    const user = validateUser(authenticatedUser);
    const settings = passkeyOptions(config);
    const passkeyStore = getStore(config, "passkeyStore");
    const challengeStore = getStore(config, "passkeyChallengeStore");
    let pending;
    let challengeStoreError;
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: async (challenge) => {
          try {
            pending = await challengeStore.consume(challenge, "registration");
          } catch (error) {
            challengeStoreError = error;
            throw error;
          }
          return Boolean(
            pending &&
            pending.purpose === "registration" &&
            pending.userId === user.id &&
            pending.email === user.email &&
            pending.expiresAt > Date.now()
          );
        },
        expectedOrigin: settings.origins,
        expectedRPID: settings.rpID,
        requireUserVerification: true
      });
    } catch (error) {
      if (challengeStoreError) throw challengeStoreError;
      throw new PasskeyServiceError(400, "Passkey registration response is invalid or expired");
    }
    if (!verification.verified || !verification.registrationInfo) {
      throw new PasskeyServiceError(400, "Passkey registration could not be verified");
    }

    const registered = verification.registrationInfo;
    const credential = registered.credential;
    await passkeyStore.create({
      id: credential.id,
      userId: user.id,
      userHandle: await passkeyStore.getUserHandle(user.id),
      email: user.email,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports || [],
      deviceType: registered.credentialDeviceType,
      backedUp: registered.credentialBackedUp,
      createdAt: Date.now()
    });
    return {
      verified: true,
      credential: {
        id: credential.id,
        deviceType: registered.credentialDeviceType,
        backedUp: registered.credentialBackedUp
      }
    };
  }

  async function authenticationOptions(email) {
    const { generateAuthenticationOptions } = loadWebAuthn();
    const settings = passkeyOptions(config);
    const challengeStore = getStore(config, "passkeyChallengeStore");
    const normalizedEmail = typeof email === "string" && email.trim()
      ? email.trim().toLowerCase()
      : null;
    const options = await generateAuthenticationOptions({
      rpID: settings.rpID,
      userVerification: "required"
    });
    await challengeStore.put(options.challenge, {
      purpose: "authentication",
      ...(normalizedEmail ? { email: normalizedEmail } : {}),
      expiresAt: Date.now() + (settings.challengeTtlSeconds ?? 300) * 1000
    });
    return options;
  }

  async function verifyAuthentication(response) {
    const { verifyAuthenticationResponse } = loadWebAuthn();
    const settings = passkeyOptions(config);
    const passkeyStore = getStore(config, "passkeyStore");
    const challengeStore = getStore(config, "passkeyChallengeStore");
    if (!response || typeof response.id !== "string" || !response.id) {
      throw new PasskeyServiceError(400, "Passkey credential response is required");
    }

    const credential = await passkeyStore.getByCredentialId(response.id);
    if (!credential) throw new PasskeyServiceError(401, "Passkey authentication failed");

    if (
      response.response?.userHandle !== undefined &&
      response.response.userHandle !== null &&
      response.response.userHandle !== credential.userHandle
    ) {
      throw new PasskeyServiceError(401, "Passkey authentication failed");
    }

    let pending;
    let challengeStoreError;
    let verified;
    try {
      verified = await verifyAuthenticationResponse({
        response,
        expectedChallenge: async (challenge) => {
          try {
            pending = await challengeStore.consume(challenge, "authentication");
          } catch (error) {
            challengeStoreError = error;
            throw error;
          }
          return Boolean(
            pending &&
            pending.purpose === "authentication" &&
            pending.expiresAt > Date.now() &&
            (!pending.email || pending.email === credential.email) &&
            (pending.email || response.response?.userHandle === credential.userHandle)
          );
        },
        expectedOrigin: settings.origins,
        expectedRPID: settings.rpID,
        credential: {
          id: credential.id,
          publicKey: credential.publicKey,
          counter: credential.counter,
          transports: credential.transports
        },
        requireUserVerification: true
      });
    } catch (error) {
      if (challengeStoreError) throw challengeStoreError;
      throw new PasskeyServiceError(401, "Passkey authentication failed");
    }
    if (!verified.verified || !pending) {
      throw new PasskeyServiceError(401, "Passkey authentication failed");
    }

    const updated = await passkeyStore.updateCounter(
      credential.id,
      credential.counter,
      verified.authenticationInfo.newCounter,
      verified.authenticationInfo.credentialDeviceType,
      verified.authenticationInfo.credentialBackedUp
    );
    if (!updated) throw new PasskeyServiceError(401, "Passkey authentication failed");

    const user = await authService.resolveUserPayload(credential.email);
    if (String(user.id ?? user.email) !== credential.userId) {
      throw new PasskeyServiceError(401, "Passkey account is no longer available");
    }
    return user;
  }

  async function list(authenticatedUser) {
    const user = validateUser(authenticatedUser);
    return getStore(config, "passkeyStore").listByUserId(user.id);
  }

  async function remove(authenticatedUser, credentialId) {
    const user = validateUser(authenticatedUser);
    if (typeof credentialId !== "string" || !credentialId) {
      throw new PasskeyServiceError(400, "Passkey credential ID is required");
    }
    const removed = await getStore(config, "passkeyStore").deleteByCredentialId(
      credentialId,
      user.id
    );
    if (!removed) throw new PasskeyServiceError(404, "Passkey not found");
  }

  return {
    authenticationOptions,
    list,
    registrationOptions,
    remove,
    verifyAuthentication,
    verifyRegistration
  };
}

module.exports = { createPasskeyService, PasskeyServiceError };
