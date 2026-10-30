const assert = require("node:assert/strict");
const { createPasskeyService, PasskeyServiceError } = require("./server/core/passkeyService");

async function run() {
  const challenges = new Map();
  const credentials = new Map();
  let counterUpdates = 0;
  let registrationOptions;
  let authenticationOptions;
  const passkeyStore = {
    async getUserHandle(userId) {
      return `stable-handle-${userId}`;
    },
    async create(credential) {
      credentials.set(credential.id, credential);
    },
    async getByCredentialId(id) {
      return credentials.get(id) || null;
    },
    async listByUserId() {
      return [];
    },
    async updateCounter(id, expectedCounter, newCounter) {
      const credential = credentials.get(id);
      if (!credential || credential.counter !== expectedCounter) return false;
      credential.counter = newCounter;
      counterUpdates++;
      return true;
    },
    async deleteByCredentialId() {
      return false;
    }
  };
  const passkeyChallengeStore = {
    async put(challenge, record) {
      challenges.set(challenge, record);
    },
    async consume(challenge, purpose) {
      const record = challenges.get(challenge);
      if (!record || record.purpose !== purpose || record.expiresAt <= Date.now()) return null;
      challenges.delete(challenge);
      return record;
    }
  };
  const webAuthn = {
    isoBase64URL: {
      toBuffer: (value) => new TextEncoder().encode(value)
    },
    async generateRegistrationOptions(options) {
      registrationOptions = options;
      return { challenge: "registration-challenge", ...options };
    },
    async verifyRegistrationResponse({ expectedChallenge }) {
      const valid = await expectedChallenge("registration-challenge");
      return valid ? {
        verified: true,
        registrationInfo: {
          credential: {
            id: "test-credential",
            publicKey: new Uint8Array([1, 2, 3]),
            counter: 4,
            transports: ["internal"]
          },
          credentialDeviceType: "singleDevice",
          credentialBackedUp: false
        }
      } : { verified: false };
    },
    async generateAuthenticationOptions(options) {
      authenticationOptions = options;
      return { challenge: "authentication-challenge", ...options };
    },
    async verifyAuthenticationResponse({ expectedChallenge }) {
      const valid = await expectedChallenge("authentication-challenge");
      return valid ? {
        verified: true,
        authenticationInfo: {
          newCounter: 5,
          credentialDeviceType: "singleDevice",
          credentialBackedUp: false
        }
      } : { verified: false };
    }
  };
  const configValues = {
    passkeys: {
      rpName: "DevAuthKit test",
      rpID: "example.com",
      origins: ["https://example.com"]
    },
    passkeyStore,
    passkeyChallengeStore
  };
  const service = createPasskeyService({
    config: { get: (key) => configValues[key] },
    authService: {
      async resolveUserPayload(email) {
        return { id: "user-1", email };
      }
    },
    loadWebAuthn: () => webAuthn
  });
  const user = { id: "user-1", email: "user@example.com", name: "Test User" };

  const registration = await service.registrationOptions(user);
  assert.equal(registration.challenge, "registration-challenge");
  assert.equal(registrationOptions.authenticatorSelection.residentKey, "required");
  assert.equal(registrationOptions.authenticatorSelection.userVerification, "required");
  assert.deepEqual(
    Array.from(registrationOptions.userID),
    Array.from(new TextEncoder().encode("stable-handle-user-1"))
  );

  const registrationResult = await service.verifyRegistration(user, { id: "registration-response" });
  assert.equal(registrationResult.verified, true);
  assert.equal(credentials.get("test-credential").email, "user@example.com");
  assert.equal(await service.verifyRegistration(user, { id: "registration-response" }).then(
    () => false,
    (error) => error instanceof PasskeyServiceError && error.status === 400
  ), true);

  const loginOptions = await service.authenticationOptions("user@example.com");
  assert.equal(loginOptions.challenge, "authentication-challenge");
  assert.equal(authenticationOptions.allowCredentials, undefined);
  assert.equal((await passkeyChallengeStore.consume("authentication-challenge", "authentication")).email,
    "user@example.com");

  const loginOptionsAgain = await service.authenticationOptions();
  assert.equal(loginOptionsAgain.challenge, "authentication-challenge");
  const credential = credentials.get("test-credential");
  credential.userHandle = "stable-handle-user-1";
  credential.userId = "user-1";
  const authenticatedUser = await service.verifyAuthentication({
    id: "test-credential",
    response: { userHandle: "stable-handle-user-1" }
  });
  assert.deepEqual(authenticatedUser, { id: "user-1", email: "user@example.com" });
  assert.equal(counterUpdates, 1);
  assert.equal(credential.counter, 5);
  assert.equal(await service.verifyAuthentication({
    id: "test-credential",
    response: { userHandle: "stable-handle-user-1" }
  }).then(
    () => false,
    (error) => error instanceof PasskeyServiceError && error.status === 401
  ), true);

  console.log("Passkey service tests passed");
}

run().then(() => process.exit(0)).catch((err) => { console.error(err); process.exit(1); });
