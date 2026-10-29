export interface DevAuthClientOptions {
  /**
   * Base backend URL (e.g. "http://localhost:3000" or empty string if same-origin)
   * @default ""
   */
  apiUrl?: string;

  /**
   * Auth route mount prefix
   * @default "/auth"
   */
  apiPrefix?: string;

  /**
   * Key name used for token storage in localStorage
   * @default "devauth_token"
   */
  tokenKey?: string;

  /**
   * Key name used for user metadata in localStorage
   * @default "devauth_user"
   */
  userKey?: string;

  /**
   * Key name used for organization metadata in localStorage
   * @default "devauth_org"
   */
  orgKey?: string;

  /**
   * Callback invoked when any authenticated request returns a 401 Unauthorized status
   */
  onTokenExpired?: () => void;

  /**
   * Custom fetch implementation (e.g. isomorphic-fetch or node-fetch)
   */
  customFetch?: typeof fetch;

  /**
   * If true, enables RFC 9449 Demonstrating Proof-of-Possession (DPoP) token binding.
   * Cryptographically binds access tokens to client ECDSA P-256 keys to neutralize token theft.
   * @default false
   */
  dpop?: boolean;

  /**
   * If true, sends cookies with all fetch requests (credentials: "include")
   * @default true
   */
  useCookies?: boolean;
}

export interface ClientOrg {
  id: string;
  name: string;
  slug: string;
  logoUrl?: string | null;
  metadata?: Record<string, any>;
  role?: string;
  joinedAt?: number;
}

export interface ClientOrgMember {
  id: string;
  orgId: string;
  userId: string;
  role: string;
  email?: string;
  joinedAt: number;
}

export interface AuthUser {
  email: string;
  id?: string | number;
  [key: string]: any;
}

export interface SendOTPResponse {
  success: boolean;
  message: string;
  devMode?: boolean;
  expiresInMinutes?: number;
}

export interface VerifyOTPResponse {
  success: boolean;
  message: string;
  token?: string;
  tokenType?: "DPoP" | "Bearer";
  user: AuthUser;
  refreshEnabled?: boolean;
  expiresIn?: string;
}

export interface RefreshResponse {
  message: string;
  token: string;
  tokenType?: "DPoP" | "Bearer";
  user: AuthUser;
  refreshEnabled: true;
  expiresIn: string;
}

export class DevAuthClient {
  constructor(options?: DevAuthClientOptions);

  apiUrl: string;
  apiPrefix: string;
  tokenKey: string;
  userKey: string;
  orgKey: string;
  tokenTypeKey: string;
  refreshEnabledKey: string;
  useCookies: boolean;
  dpop: boolean;
  refreshPromise: Promise<RefreshResponse> | null;

  /**
   * Get or create client-side ECDSA P-256 key pair for DPoP proof generation
   */
  getDPoPKeyPair(): Promise<{
    keyPair: CryptoKeyPair;
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    jwk: { kty: string; crv: string; x: string; y: string };
  }>;

  /**
   * Create an RFC 9449 DPoP proof JWT for an outgoing HTTP request
   */
  createDPoPProof(method: string, uri: string, accessToken?: string): Promise<string>;

  /**
   * Check if the client or active session is DPoP bound
   */
  isDPoPBound(): boolean;

  /**
   * Request a one-time login code sent to the specified email
   */
  sendOTP(email: string): Promise<SendOTPResponse>;

  /**
   * Verify OTP and complete authentication.
   * Automatically stores the received JWT token and user profile.
   */
  verifyOTP(email: string, otp: string | number): Promise<VerifyOTPResponse>;

  /**
   * Verify a Magic Link token and complete authentication.
   */
  verifyMagicLink(token: string, email?: string): Promise<VerifyOTPResponse>;

  /**
   * Rotate the httpOnly refresh cookie and store the newly issued access token.
   */
  refresh(): Promise<RefreshResponse>;

  /**
   * Wrapper around native fetch that automatically injects the Bearer token
   * into Authorization headers and forwards cookies.
   */
  fetch(endpoint: string, init?: RequestInit): Promise<Response>;

  /**
   * Fetch authenticated user profile from backend `/auth/me`
   */
  getProfile(): Promise<{ user: AuthUser }>;

  /**
   * Clear session, purge stored credentials, and trigger state change listeners
   */
  logout(): Promise<void>;

  /**
   * Get cached user object from local storage
   */
  getUser(): AuthUser | null;

  /**
   * Get stored JWT token
   */
  getToken(): string | null;

  /**
   * Check if a valid token or user exists locally
   */
  isAuthenticated(): boolean;

  /**
   * Subscribe to authentication state changes (login, logout)
   * @returns An unsubscribe function
   */
  onAuthStateChanged(callback: (user: AuthUser | null) => void): () => void;

  /**
   * Get active organization from local storage
   */
  getActiveOrg(): ClientOrg | null;

  /**
   * List all organizations current user belongs to
   */
  listOrgs(): Promise<ClientOrg[]>;

  /**
   * Create a new organization
   */
  createOrg(params: {
    name: string;
    slug?: string;
    logoUrl?: string;
    metadata?: Record<string, any>;
  }): Promise<{ success: boolean; organization: ClientOrg; member: ClientOrgMember }>;

  /**
   * Get organization details and members
   */
  getOrg(orgId: string): Promise<{
    success: boolean;
    organization: ClientOrg;
    member: ClientOrgMember;
    members: ClientOrgMember[];
  }>;

  /**
   * Switch active workspace and receive a new tenant-scoped token
   */
  switchOrg(orgId: string): Promise<{
    success: boolean;
    token: string;
    organization: ClientOrg;
    member: ClientOrgMember;
  }>;

  /**
   * Send an invitation to join the organization
   */
  inviteMember(
    orgId: string,
    params: { email: string; role?: string }
  ): Promise<{ success: boolean; invitation: any; devModeInviteToken?: string }>;

  /**
   * Accept an invitation token and join an organization
   */
  joinOrg(token: string): Promise<{
    success: boolean;
    token: string;
    organization: ClientOrg;
    member: ClientOrgMember;
  }>;

  /**
   * List pending invitations for an organization
   */
  listInvitations(orgId: string): Promise<any[]>;

  /**
   * Revoke a pending invitation
   */
  revokeInvitation(orgId: string, inviteId: string): Promise<{ success: boolean }>;

  /**
   * Update member role
   */
  updateMemberRole(
    orgId: string,
    userId: string,
    role: string
  ): Promise<{ success: boolean; member: ClientOrgMember }>;

  /**
   * Remove member from organization
   */
  removeMember(orgId: string, userId: string): Promise<{ success: boolean }>;

  /**
   * Resolve Enterprise SSO connection by user email or corporate domain
   */
  resolveSso(
    emailOrDomain: string,
    relayState?: string
  ): Promise<{ success: boolean; type: "SAML" | "OIDC"; redirectUrl: string; connectionId: string }>;

  /**
   * Redirect user to corporate IdP for Single Sign-On
   */
  loginWithSso(
    emailOrDomain: string,
    relayState?: string
  ): Promise<{ success: boolean; type: "SAML" | "OIDC"; redirectUrl: string; connectionId: string }>;

  /**
   * Start an impersonation session (Admin only)
   */
  impersonate(userId: string, reason?: string): Promise<{ token: string; targetUser: any; actor: any }>;

  /**
   * End active impersonation session and restore admin identity
   */
  endImpersonation(): Promise<{ success: boolean }>;

  /**
   * Whether the client is currently in an impersonated session
   */
  isImpersonating(): boolean;

  /**
   * Get the administrator actor who initiated the current impersonation session
   */
  getActorUser(): any | null;

  /**
   * List all active sessions across devices
   */
  listSessions(): Promise<any[]>;

  /**
   * Revoke a specific session by ID
   */
  revokeSession(sessionId: string): Promise<{ success: boolean }>;

  /**
   * Revoke all other active sessions except the current one
   */
  revokeOtherSessions(): Promise<{ success: boolean; revokedCount: number }>;

  /**
   * List API keys for the current user or organization
   */
  listApiKeys(): Promise<any[]>;

  /**
   * Create a new scoped API key
   */
  createApiKey(options: {
    name: string;
    scopes?: string[] | string;
    expiresInDays?: number;
    env?: "live" | "test";
  }): Promise<{ key: any; rawKey: string }>;

  /**
   * Revoke an API key
   */
  revokeApiKey(keyId: string): Promise<{ success: boolean }>;

  /**
   * Roll (rotate) an API key
   */
  rollApiKey(keyId: string): Promise<{ key: any; rawKey: string }>;

  /**
   * Query audit logs (Admin/Org Owner only)
   */
  listAuditLogs(filters?: Record<string, any>): Promise<{ entries: any[]; total: number }>;

  /**
   * Verify cryptographic Merkle hash chain of audit logs
   */
  verifyAuditTrail(): Promise<{ valid: boolean; message: string }>;
}

export function createDevAuthClient(options?: DevAuthClientOptions): DevAuthClient;

