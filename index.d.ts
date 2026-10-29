import type { Application, Request, Response, NextFunction } from "express";
import type { Store } from "express-session";

export interface OtpStore {
  get(email: string): { otp: string; attempts: number; createdAt: number } | null | Promise<{ otp: string; attempts: number; createdAt: number } | null>;
  set(email: string, data: { otp: string; attempts: number; createdAt: number }): void | Promise<void>;
  delete(email: string): void | Promise<void>;
  /** Increment attempts atomically; implementations must not use read-modify-write counters. */
  recordAttempt(email: string): number | Promise<number>;
}

export interface MagicLinkRecord {
  email: string;
  expiresAt: number;
}

export interface MagicLinkStore {
  get(tokenHash: string): MagicLinkRecord | null | Promise<MagicLinkRecord | null>;
  set(tokenHash: string, record: MagicLinkRecord): void | Promise<void>;
  delete(tokenHash: string): void | Promise<void>;
}

export interface RedisClientLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, options: { EX: number }): Promise<unknown>;
  del(keys: string | string[]): Promise<number>;
  incr(key: string): Promise<number>;
}

export interface RateLimitStore {
  /** Atomically increment a counter for the supplied window. */
  increment(key: string, windowMs: number): number | Promise<number>;
}

export interface RedisRateLimitClient {
  incr(key: string): Promise<number>;
  pTTL(key: string): Promise<number>;
  pExpire(key: string, milliseconds: number): Promise<number | boolean>;
}

export interface RedisDpopReplayClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, options: { NX: true; EX: number }): Promise<string | null | boolean>;
}

export interface RedisRefreshTokenClient {
  get(key: string): Promise<string | null>;
  eval(script: string, options: { keys: string[]; arguments: string[] }): Promise<unknown>;
}

export interface RateLimitRule {
  /** Fixed-window duration in milliseconds. */
  windowMs?: number;
  /** Fallback request limit for enabled identity dimensions. */
  max?: number;
  perIp?: boolean;
  perEmail?: boolean;
  perSession?: boolean;
  perIpMax?: number;
  perEmailMax?: number;
  perSessionMax?: number;
}

export type RateLimitRoute =
  | "requestOtp"
  | "verifyOtp"
  | "verifyMagicLink"
  | "mfaEnroll"
  | "mfaEnable"
  | "mfaVerify"
  | "mfaDisable"
  | "refresh"
  | "revokeSession"
  | "revokeAllSessions"
  | "logout"
  | "oauthStart"
  | "oauthCallback"
  | "oauthLink"
  | "googleStart"
  | "googleCallback"
  | "githubStart"
  | "githubCallback"
  | "passkeyRegisterOptions"
  | "passkeyRegisterVerify"
  | "passkeyAuthenticationOptions"
  | "passkeyAuthenticationVerify"
  | "passkeyList"
  | "passkeyDelete";

export type RateLimitConfig = false | Partial<Record<RateLimitRoute, RateLimitRule | false>>;

export interface AdapterUser {
  id: string | number;
  email: string;
  role?: string;
  [key: string]: unknown;
}

export interface UserAdapter {
  findOrCreateUser(data: { email: string }): AdapterUser | Promise<AdapterUser>;
  findUserByOAuthIdentity?(identity: { provider: string; providerId: string }): AdapterUser | null | Promise<AdapterUser | null>;
  /**
   * Persist an identity for this user. Implementations must enforce uniqueness for
   * (provider, providerId) atomically and reject identities owned by another user.
   */
  linkOAuthIdentity?(identity: {
    userId: string;
    provider: string;
    providerId: string;
    email: string;
    name?: string;
    picture?: string;
    username?: string;
  }): void | Promise<void>;
}

export interface AuthIdentityContext {
  provider?: string;
  providerId?: string;
  name?: string;
  picture?: string;
}

export type UserPayloadMapper = (
  user: AdapterUser,
  identity?: AuthIdentityContext
) => Record<string, unknown>;

export interface RefreshTokenRecord {
  familyId: string;
  userId: string;
  user: AuthenticatedUser;
  expiresAt: number;
}

export interface RefreshTokenStore {
  create(tokenHash: string, record: RefreshTokenRecord): void | Promise<void>;
  /**
   * Atomically consume the current token and persist its replacement. If an already-used
   * token is presented, revoke every token in its family and return `reused`.
   */
  rotate(
    tokenHash: string,
    replacementHash: string,
    replacement: { expiresAt: number }
  ): Promise<RefreshTokenRotationResult>;
  revoke(tokenHash: string): boolean | Promise<boolean>;
  revokeFamily(familyId: string): void | Promise<void>;
  revokeAll(userId: string): void | Promise<void>;
  isFamilyActive(familyId: string): boolean | Promise<boolean>;
}

export type RefreshTokenRotationResult =
  | { status: "rotated"; record: RefreshTokenRecord }
  | { status: "invalid" | "reused" };

export interface RefreshTokenOptions {
  /** @default "15m" */
  accessTokenExpiresIn?: string;
  /** @default 30 */
  refreshTokenExpiresInDays?: number;
}

export class MemoryRefreshTokenStore implements RefreshTokenStore {
  create(tokenHash: string, record: RefreshTokenRecord): Promise<void>;
  rotate(
    tokenHash: string,
    replacementHash: string,
    replacement: { expiresAt: number }
  ): Promise<RefreshTokenRotationResult>;
  revoke(tokenHash: string): Promise<boolean>;
  revokeFamily(familyId: string): Promise<void>;
  revokeAll(userId: string): Promise<void>;
  isFamilyActive(familyId: string): Promise<boolean>;
}

export interface GoogleOAuthOptions {
  clientId: string;
  clientSecret: string;
  callbackURL: string;
  /** Optional application URL to redirect to after setting the auth cookie. */
  successRedirectURL?: string;
}

export interface GitHubOAuthOptions {
  clientId: string;
  clientSecret: string;
  callbackURL: string;
  /** Optional OAuth scope @default "read:user user:email" */
  scope?: string;
  /** Optional application URL to redirect to after setting the auth cookie. */
  successRedirectURL?: string;
}

export interface OAuthProviderOptions {
  clientId: string;
  clientSecret: string;
  callbackURL: string;
  authorizationURL: string;
  tokenURL: string;
  userInfoURL: string;
  scope?: string;
  successRedirectURL?: string;
  /**
   * Map the user-info JSON to { id, email, emailVerified, name?, picture?, username? }.
   * The callback must set emailVerified only when the provider verified the address.
   */
  mapProfile(profile: Record<string, unknown>, context: {
    accessToken: string;
  }): {
    id: string | number;
    email: string;
    emailVerified: boolean;
    name?: string;
    picture?: string;
    username?: string;
  } | Promise<{
    id: string | number;
    email: string;
    emailVerified: boolean;
    name?: string;
    picture?: string;
    username?: string;
  }>;
}

export interface OAuthStateStore {
  put(state: string, expiresAt: number): void | Promise<void>;
  /** Atomically return true once for an existing, unexpired state and consume it. */
  consume(state: string): boolean | Promise<boolean>;
}

export interface PasskeyChallengeRecord {
  purpose: "registration" | "authentication";
  userId?: string;
  email?: string;
  expiresAt: number;
}

export interface PasskeyChallengeStore {
  put(challenge: string, record: PasskeyChallengeRecord): void | Promise<void>;
  /** Atomically consume a matching, unexpired challenge once. */
  consume(
    challenge: string,
    purpose: PasskeyChallengeRecord["purpose"]
  ): PasskeyChallengeRecord | null | Promise<PasskeyChallengeRecord | null>;
}

export interface PasskeyCredentialRecord {
  id: string;
  userId: string;
  userHandle: string;
  email: string;
  publicKey: Uint8Array;
  counter: number;
  transports: string[];
  deviceType: string;
  backedUp: boolean;
  createdAt: number;
}

export interface PasskeySummary {
  id: string;
  createdAt: number;
  deviceType: string;
  backedUp: boolean;
  transports: string[];
}

export interface PasskeyStore {
  getUserHandle(userId: string): string | Promise<string>;
  create(credential: PasskeyCredentialRecord): void | Promise<void>;
  getByCredentialId(credentialId: string): PasskeyCredentialRecord | null | Promise<PasskeyCredentialRecord | null>;
  listByUserId(userId: string): PasskeySummary[] | Promise<PasskeySummary[]>;
  updateCounter(
    credentialId: string,
    expectedCounter: number,
    newCounter: number,
    deviceType: string,
    backedUp: boolean
  ): boolean | Promise<boolean>;
  deleteByCredentialId(credentialId: string, userId: string): boolean | Promise<boolean>;
}

export interface PasskeyOptions {
  /** Human-readable relying-party name displayed by the authenticator. */
  rpName: string;
  /** Relying-party domain, such as "example.com" or "localhost". */
  rpID: string;
  /** Exact allowed application origins, such as ["https://example.com"]. */
  origins: string[];
  /** Challenge expiry in seconds. Must be between 30 and 600. @default 300 */
  challengeTtlSeconds?: number;
}

export interface MfaRecord {
  enabled: boolean;
  pending?: { secret: string; expiresAt: number };
  secret?: string;
  lastTotpCounter?: number;
  recoveryCodeHashes: string[];
}

export interface MfaStore {
  get(userId: string): MfaRecord | null | Promise<MfaRecord | null>;
  setPending(userId: string, pending: { secret: string; expiresAt: number }): boolean | Promise<boolean>;
  activate(userId: string, expectedSecret: string, lastTotpCounter: number, recoveryCodeHashes: string[]): boolean | Promise<boolean>;
  /** Atomically accept the TOTP counter only if it exceeds the stored counter. */
  consumeTotpCounter(userId: string, counter: number): boolean | Promise<boolean>;
  /** Atomically remove and accept a recovery-code hash at most once. */
  consumeRecoveryCode(userId: string, recoveryCodeHash: string): boolean | Promise<boolean>;
  disable(userId: string): boolean | void | Promise<boolean | void>;
}

export class MemoryMfaStore implements MfaStore {
  get(userId: string): Promise<MfaRecord | null>;
  setPending(userId: string, pending: { secret: string; expiresAt: number }): Promise<boolean>;
  activate(userId: string, expectedSecret: string, lastTotpCounter: number, recoveryCodeHashes: string[]): Promise<boolean>;
  consumeTotpCounter(userId: string, counter: number): Promise<boolean>;
  consumeRecoveryCode(userId: string, recoveryCodeHash: string): Promise<boolean>;
  disable(userId: string): Promise<boolean>;
}

export function prismaAdapter<T extends object>(
  prisma: T,
  options?: {
    model?: string;
    fields?: { id?: string; email?: string; role?: string };
  }
): UserAdapter;

export function drizzleAdapter<TDb extends object, TTable extends object>(
  db: TDb,
  options: {
    table: TTable;
    eq?: (column: any, value: any) => any;
    fields?: { id?: string; email?: string; role?: string };
  }
): UserAdapter;

export function mongooseAdapter<TModel extends object>(
  model: TModel,
  options?: {
    fields?: { id?: string; email?: string; role?: string };
  }
): UserAdapter;

export class RedisOtpStore implements OtpStore {
  constructor(client: RedisClientLike, options?: { keyPrefix?: string; ttlSeconds?: number });
  get(email: string): Promise<{ otp: string; attempts: number; createdAt: number } | null>;
  set(email: string, data: { otp: string; attempts: number; createdAt: number }): Promise<void>;
  delete(email: string): Promise<void>;
  recordAttempt(email: string): Promise<number>;
}

export class MemoryRateLimitStore implements RateLimitStore {
  increment(key: string, windowMs: number): Promise<number>;
}

export class RedisRateLimitStore implements RateLimitStore {
  constructor(client: RedisRateLimitClient, options?: { keyPrefix?: string });
  increment(key: string, windowMs: number): Promise<number>;
}

export class RedisDpopReplayStore implements DpopReplayStore {
  constructor(client: RedisDpopReplayClient, options?: { keyPrefix?: string });
  record(jti: string, ttlSeconds?: number): Promise<boolean>;
  isUsed(jti: string): Promise<boolean>;
}

export class RedisRefreshTokenStore implements RefreshTokenStore {
  constructor(client: RedisRefreshTokenClient, options?: { keyPrefix?: string });
  create(tokenHash: string, record: RefreshTokenRecord): Promise<void>;
  rotate(
    tokenHash: string,
    replacementHash: string,
    replacement: { expiresAt: number }
  ): Promise<RefreshTokenRotationResult>;
  revoke(tokenHash: string): Promise<boolean>;
  revokeFamily(familyId: string): Promise<void>;
  revokeAll(userId: string): Promise<void>;
  isFamilyActive(familyId: string): Promise<boolean>;
}

export interface DevAuthConfigOptions {
  /**
   * Allowed CORS origin(s). E.g. "http://localhost:3000" or ["http://localhost:3000", "http://localhost:3001"]
   * @default "http://localhost:3001"
   */
  corsOrigin?: string | string[];

  /**
   * Secret key used for signing session cookies
   * Defaults to a random process-local secret for development. Production requires
   * an explicit secret of at least 32 bytes.
   */
  sessionSecret?: string;

  /**
   * Secret key used for signing JWT Bearer tokens
   * Uses JWT_SECRET or sessionSecret when configured; otherwise a random process-local
   * secret is generated for development. Production requires explicit secrets of at
   * least 32 bytes.
   */
  jwtSecret?: string;

  /**
   * Expiration time for JWT tokens (e.g. "1h", "7d", "30d")
   * @default "7d"
   */
  jwtExpiresIn?: string;

  /**
   * Time in minutes before a generated OTP expires
   * @default 5
   */
  otpExpiryMinutes?: number;

  /**
   * Maximum failed verification attempts before the OTP is invalidated
   * @default 5
   */
  maxAttempts?: number;

  /**
   * If true, prints generated OTPs cleanly to the terminal console instead of sending email.
   * Defaults to true in non-production environments when EMAIL_USER is not configured.
   */
  devMode?: boolean;

  /**
   * Route prefix under which auth endpoints are mounted
   * @default "/auth"
   */
  apiPrefix?: string;

  /**
   * Email delivery provider. Supports "smtp" (nodemailer default) or "resend"
   * @default "smtp"
   */
  emailProvider?: "smtp" | "resend";

  /**
   * Resend API Key if using Resend for email delivery
   */
  resendApiKey?: string;

  /**
   * The "From" address for sent emails (e.g. "noreply@myapp.com" or "Acme Auth <auth@myapp.com>")
   */
  fromEmail?: string;

  /**
   * Custom nodemailer transporter instance or custom transporter options
   */
  transporter?: any;

  /**
   * Custom email delivery function: async ({ email, otp }) => void
   */
  mailer?: (params: { email: string; otp: string }) => Promise<void> | void;

  /**
   * Enable set-cookie for JWT token in httpOnly mode on successful verification
   * @default true
   */
  setHttpOnlyCookie?: boolean;

  /**
   * Cookie name for httpOnly auth token
   * @default "devauth_token"
   */
  cookieName?: string;

  /**
   * Enable verbose internal debug logs
   * @default false
   */
  debug?: boolean;

  /**
   * Custom OTP storage adapter. Must implement get, set, delete, and atomic recordAttempt.
   * Defaults to the built-in in-memory store.
   */
  otpStore?: OtpStore;

  /**
   * Custom express-session store, such as connect-redis.
   * Defaults to express-session's in-memory store.
   */
  sessionStore?: Store;

  /**
   * Optional persistent user lookup/create adapter. When omitted, users remain email-only.
   */
  userAdapter?: UserAdapter;

  /**
   * Map an adapter user to additional safe JWT and req.user claims.
   * The mapped id, email, and role (when present) remain authoritative.
   */
  mapUserPayload?: UserPayloadMapper;

  /**
   * Enable Google OAuth with a registered callback URL. When omitted, Google routes return 404.
   */
  google?: GoogleOAuthOptions;

  /**
   * Enable GitHub OAuth 2.0 with PKCE and profile identity mapping. When omitted, GitHub routes return 404.
   */
  github?: GitHubOAuthOptions;

  /**
   * Add OAuth 2.0 providers using authorization-code + PKCE and a profile mapper.
   * Routes are /auth/oauth/:provider and /auth/oauth/:provider/callback.
   */
  oauthProviders?: Record<string, OAuthProviderOptions>;

  /**
   * Optional atomic one-time OAuth state storage. Required by the Hono adapter;
   * Express sessions already provide server-side state persistence.
   */
  oauthStateStore?: OAuthStateStore;

  /**
   * Enable WebAuthn passkey registration and authentication. Requires explicit,
   * durable passkeyStore and passkeyChallengeStore implementations.
   */
  passkeys?: false | PasskeyOptions;

  /** Persistent passkey credential and user-handle store. */
  passkeyStore?: PasskeyStore;

  /** Persistent store that atomically consumes each passkey challenge once. */
  passkeyChallengeStore?: PasskeyChallengeStore;

  /**
   * Enable Magic Link click-to-login authentication alongside 6-digit OTPs.
   * @default false
   */
  magicLink?: boolean;

  /**
   * Optional persistent magic-link storage. Defaults to process memory.
   */
  magicLinkStore?: MagicLinkStore;

  /**
   * Expiration time in minutes for magic link tokens.
   * @default 15
   */
  magicLinkExpiryMinutes?: number;

  /**
   * Optional custom base URL for magic link generation (e.g. "https://myapp.com/auth")
   */
  magicLinkBaseURL?: string;

  /**
   * Optional application redirect URL after successful magic link verification
   */
  magicLinkSuccessURL?: string;

  /**
   * Optional rotating refresh-token lifecycle. Disabled unless set to true or configured.
   * Requires the httpOnly auth cookie to remain enabled.
   */
  refreshTokens?: boolean | RefreshTokenOptions;

  /**
   * Persistent refresh token store. Rotation must be atomic. Defaults to process memory,
   * which is not shared across server instances and is cleared by restarts.
   */
  refreshTokenStore?: RefreshTokenStore;

  /**
   * Per-route fixed-window limits. Set a route to false to disable its limiter,
   * or set the entire option to false to disable all rate limiting.
   */
  rateLimit?: RateLimitConfig;

  /**
   * Shared rate-limit counter store. Defaults to process memory; use Redis when
   * running multiple application instances.
   */
  rateLimitStore?: RateLimitStore;

  /**
   * DPoP (RFC 9449 Demonstrating Proof-of-Possession) token binding configuration.
   * Enables cryptographic binding of access tokens to client ECDSA P-256 keys.
   */
  dpop?: boolean | "optional" | "required" | {
    mode?: "optional" | "required" | "disabled";
    maxClockSkewSeconds?: number;
    enforceNonce?: boolean;
  };

  /**
   * Atomic replay protection store for single-use DPoP proof JTIs.
   * Required when DPoP is enabled. Use shared storage across server instances.
   */
  dpopReplayStore?: DpopReplayStore;

  /** Server nonce for freshness enforcement */
  dpopNonce?: string;

  /** Maximum allowable clock skew in seconds (default: 60) */
  dpopMaxClockSkewSeconds?: number;
  /** Store MFA enrollments; persistent adapters must encrypt TOTP secrets at rest. */
  mfaStore?: MfaStore;
  /** Issuer displayed by authenticator apps. @default "DevAuthKit" */
  mfaIssuer?: string;
  /** Step-up token lifetime in seconds. @default 300 */
  mfaStepUpExpiresInSeconds?: number;

  /**
   * Enable multi-tenant organizations & workspaces.
   * Auto-provisions in-memory organization store in devMode unless organizationStore is provided.
   * @default false
   */
  organizations?: boolean;

  /**
   * Persistent store for organizations, memberships, and invitations.
   * Required in production when organizations is true.
   */
  organizationStore?: OrganizationStore;

  /** Custom role permission map overrides */
  orgRoles?: Record<string, string[]>;

  /**
   * Enable cryptographically signed outbound webhooks (HMAC-SHA256, Svix/Stripe standard).
   * Auto-provisions MemoryWebhookStore unless webhookStore is provided.
   * @default false
   */
  webhooks?: boolean;

  /**
   * Persistent store for webhook endpoints and delivery logs.
   * Required in production when webhooks is true.
   */
  webhookStore?: WebhookStore;

  /** Custom webhook dispatcher instance */
  webhookDispatcher?: any;

  /**
   * Enable Enterprise SSO (SAML 2.0 & OIDC).
   * Auto-provisions MemorySsoStore unless ssoStore is provided.
   * @default false
   */
  sso?: boolean | { store?: any; maxClockSkewSeconds?: number; signingCert?: string };

  /**
   * Persistent store for Enterprise SSO connections, anti-replay assertion tracking, and SCIM mappings.
   */
  ssoStore?: any;

  /**
   * Enable SCIM 2.0 Directory Sync protocol engine (RFC 7643 & RFC 7644).
   * Auto-provisions MemorySsoStore unless ssoStore is provided.
   * @default false
   */
  scim?: boolean;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  logoUrl?: string | null;
  metadata?: Record<string, any>;
  createdAt: number;
  updatedAt: number;
}

export interface OrganizationMember {
  id: string;
  orgId: string;
  userId: string;
  role: "owner" | "admin" | "member" | "viewer" | string;
  email?: string;
  joinedAt: number;
}

export interface OrganizationInvitation {
  id: string;
  orgId: string;
  email: string;
  role: string;
  inviterId: string;
  tokenHash: string;
  expiresAt: number;
  createdAt: number;
}

export interface OrganizationStore {
  createOrg(params: { name: string; slug?: string; logoUrl?: string; metadata?: Record<string, any>; ownerUserId: string; ownerEmail?: string }): Promise<{ organization: Organization; member: OrganizationMember }>;
  getOrgById(id: string): Promise<Organization | null>;
  getOrgBySlug(slug: string): Promise<Organization | null>;
  listUserOrgs(userId: string): Promise<Array<Organization & { role: string; joinedAt: number }>>;
  updateOrg(id: string, updates: Partial<Pick<Organization, "name" | "slug" | "logoUrl" | "metadata">>): Promise<Organization>;
  deleteOrg(id: string): Promise<boolean>;
  getMember(orgId: string, userId: string): Promise<OrganizationMember | null>;
  listMembers(orgId: string): Promise<OrganizationMember[]>;
  addMember(orgId: string, userId: string, role: string, email?: string): Promise<OrganizationMember>;
  updateMemberRole(orgId: string, userId: string, role: string): Promise<OrganizationMember>;
  removeMember(orgId: string, userId: string): Promise<boolean>;
  createInvitation(params: { orgId: string; email: string; role: string; inviterId: string; tokenHash: string; expiresAt: number }): Promise<OrganizationInvitation>;
  getInvitationByTokenHash(tokenHash: string): Promise<OrganizationInvitation | null>;
  listInvitations(orgId: string): Promise<Array<Omit<OrganizationInvitation, "tokenHash">>>;
  deleteInvitation(id: string): Promise<boolean>;
}

export class MemoryOrganizationStore implements OrganizationStore {
  createOrg(params: { name: string; slug?: string; logoUrl?: string; metadata?: Record<string, any>; ownerUserId: string; ownerEmail?: string }): Promise<{ organization: Organization; member: OrganizationMember }>;
  getOrgById(id: string): Promise<Organization | null>;
  getOrgBySlug(slug: string): Promise<Organization | null>;
  listUserOrgs(userId: string): Promise<Array<Organization & { role: string; joinedAt: number }>>;
  updateOrg(id: string, updates: Partial<Pick<Organization, "name" | "slug" | "logoUrl" | "metadata">>): Promise<Organization>;
  deleteOrg(id: string): Promise<boolean>;
  getMember(orgId: string, userId: string): Promise<OrganizationMember | null>;
  listMembers(orgId: string): Promise<OrganizationMember[]>;
  addMember(orgId: string, userId: string, role: string, email?: string): Promise<OrganizationMember>;
  updateMemberRole(orgId: string, userId: string, role: string): Promise<OrganizationMember>;
  removeMember(orgId: string, userId: string): Promise<boolean>;
  createInvitation(params: { orgId: string; email: string; role: string; inviterId: string; tokenHash: string; expiresAt: number }): Promise<OrganizationInvitation>;
  getInvitationByTokenHash(tokenHash: string): Promise<OrganizationInvitation | null>;
  listInvitations(orgId: string): Promise<Array<Omit<OrganizationInvitation, "tokenHash">>>;
  deleteInvitation(id: string): Promise<boolean>;
  clear(): void;
}

export interface WebhookEndpoint {
  id: string;
  url: string;
  secret: string;
  events: string[];
  active: boolean;
  metadata?: Record<string, any>;
  createdAt: number;
  updatedAt: number;
}

export interface WebhookDelivery {
  id: string;
  endpointId: string;
  eventId: string;
  event: string;
  payload: string;
  statusCode: number | null;
  success: boolean;
  error?: string | null;
  attempt: number;
  durationMs: number;
  timestamp: number;
}

export interface WebhookStore {
  createEndpoint(data: {
    url: string;
    secret?: string;
    events?: string | string[];
    metadata?: Record<string, any>;
  }): Promise<WebhookEndpoint>;
  getEndpoint(id: string): Promise<WebhookEndpoint | null>;
  listEndpoints(): Promise<WebhookEndpoint[]>;
  updateEndpoint(
    id: string,
    updates: Partial<{
      url: string;
      secret: string;
      events: string[];
      active: boolean;
      metadata: Record<string, any>;
    }>
  ): Promise<WebhookEndpoint | null>;
  deleteEndpoint(id: string): Promise<boolean>;
  recordDelivery(data: Omit<WebhookDelivery, "id">): Promise<WebhookDelivery>;
  listDeliveries(endpointId: string, limit?: number): Promise<WebhookDelivery[]>;
}

export class MemoryWebhookStore implements WebhookStore {
  createEndpoint(data: {
    url: string;
    secret?: string;
    events?: string | string[];
    metadata?: Record<string, any>;
  }): Promise<WebhookEndpoint>;
  getEndpoint(id: string): Promise<WebhookEndpoint | null>;
  listEndpoints(): Promise<WebhookEndpoint[]>;
  updateEndpoint(
    id: string,
    updates: Partial<{
      url: string;
      secret: string;
      events: string[];
      active: boolean;
      metadata: Record<string, any>;
    }>
  ): Promise<WebhookEndpoint | null>;
  deleteEndpoint(id: string): Promise<boolean>;
  recordDelivery(data: Omit<WebhookDelivery, "id">): Promise<WebhookDelivery>;
  listDeliveries(endpointId: string, limit?: number): Promise<WebhookDelivery[]>;
}

export interface DpopReplayStore {
  /** Atomically claim a proof JTI; return false if it is already active. */
  record(jti: string, ttlSeconds?: number): boolean | Promise<boolean>;
  isUsed(jti: string): boolean | Promise<boolean>;
  cleanup?(): void | Promise<void>;
}

export class MemoryDpopReplayStore implements DpopReplayStore {
  record(jti: string, ttlSeconds?: number): Promise<boolean>;
  isUsed(jti: string): Promise<boolean>;
  cleanup(): void;
  clear(): void;
}

export interface AuthenticatedUser {
  email: string;
  id?: string | number;
  cnf?: { jkt: string };
  [key: string]: any;
}

export interface AuthenticatedRequest extends Request {
  user?: AuthenticatedUser;
  org?: Organization;
  organization?: Organization;
  orgMember?: OrganizationMember;
  dpop?: {
    jkt: string;
    payload: Record<string, any>;
  };
}

export type AuthMiddleware = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => void;

export interface RequireRoleOptions {
  /** Field name on req.user representing the user role @default "role" */
  roleKey?: string;
  /** Custom 403 error message */
  errorMessage?: string;
}

export function requireRole(
  allowedRoles: string | string[],
  options?: RequireRoleOptions
): AuthMiddleware;

export const requireAuth: AuthMiddleware;
/** Require an authenticated request with a valid short-lived MFA step-up token. */
export const requireMfa: AuthMiddleware;
export const requireDPoP: AuthMiddleware;
export const requireOrg: AuthMiddleware;
export function requireOrgRole(
  allowedRoles: string | string[],
  options?: { errorMessage?: string }
): AuthMiddleware;
export function requireOrgPermission(
  requiredPermission: string,
  options?: { errorMessage?: string }
): AuthMiddleware;
export const checkConfig: (options?: DevAuthConfigOptions) => ConfigCheckResult;

export interface DevAuthKitInstance {
  (app: Application, options?: DevAuthConfigOptions): Application;
  checkConfig(options?: DevAuthConfigOptions): ConfigCheckResult;
  requireAuth: AuthMiddleware;
  requireMfa: AuthMiddleware;
  requireDPoP: AuthMiddleware;
  requireRole: typeof requireRole;
  requireOrg: AuthMiddleware;
  requireOrgRole: typeof requireOrgRole;
  requireOrgPermission: typeof requireOrgPermission;
  devAuthKit: DevAuthKitInstance;
  config: {
    set: (options?: DevAuthConfigOptions) => DevAuthConfigOptions;
    get: (key?: keyof DevAuthConfigOptions) => any;
  };
  RedisOtpStore: typeof RedisOtpStore;
  prismaAdapter: typeof prismaAdapter;
  drizzleAdapter: typeof drizzleAdapter;
  mongooseAdapter: typeof mongooseAdapter;
  MemoryRefreshTokenStore: typeof MemoryRefreshTokenStore;
  MemoryMfaStore: typeof MemoryMfaStore;
  RedisRefreshTokenStore: typeof RedisRefreshTokenStore;
  MemoryRateLimitStore: typeof MemoryRateLimitStore;
  RedisRateLimitStore: typeof RedisRateLimitStore;
  RedisDpopReplayStore: typeof RedisDpopReplayStore;
  MemoryDpopReplayStore: typeof MemoryDpopReplayStore;
  MemoryOrganizationStore: typeof MemoryOrganizationStore;
  MemoryWebhookStore: typeof MemoryWebhookStore;
  CloudflareD1WebhookStore: any;
  WebhookDispatcher: any;
  emitWebhookEvent: (event: string, data: any) => Promise<string | null>;
  webhooks: any;
  organizations: any;
  dpop: any;
  sso: any;
  scim: any;
  MemorySsoStore: any;
  CloudflareD1SsoStore: any;
  // v2 Next-Gen Exports
  requireApiKey: (requiredScopes?: string[] | string) => AuthMiddleware;
  AuditLogService: any;
  emitAuditLog: (event: any) => Promise<any>;
  MemoryAuditLogStore: any;
  CloudflareD1AuditLogStore: any;
  ApiKeyService: any;
  matchesScopes: (granted: string[] | string, required: string[] | string) => boolean;
  verifyKeyChecksum: (rawKey: string) => boolean;
  MemoryApiKeyStore: any;
  CloudflareD1ApiKeyStore: any;
  SessionService: any;
  sessionService: any;
  blockUser: (req: any, res: any) => Promise<any>;
  unblockUser: (req: any, res: any) => Promise<any>;
  isUserBlocked: (userId: string) => boolean;
  getUserEpoch: (userId: string) => number;
}

export interface ConfigCheckIssue {
  severity: "error" | "warning";
  code: string;
  message: string;
  fix: string;
}

export interface ConfigCheckResult {
  valid: boolean;
  errors: number;
  warnings: number;
  issues: ConfigCheckIssue[];
}

declare const devAuthKit: DevAuthKitInstance;

export default devAuthKit;
export {
  devAuthKit,
  MemoryDpopReplayStore,
  MemoryOrganizationStore,
  MemoryWebhookStore,
  MemorySsoStore,
  checkConfig,
  requireOrg,
  requireOrgRole,
  requireOrgPermission
};

