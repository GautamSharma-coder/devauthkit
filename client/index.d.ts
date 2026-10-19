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
   * Callback invoked when any authenticated request returns a 401 Unauthorized status
   */
  onTokenExpired?: () => void;

  /**
   * Custom fetch implementation (e.g. isomorphic-fetch or node-fetch)
   */
  customFetch?: typeof fetch;

  /**
   * If true, sends cookies with all fetch requests (credentials: "include")
   * @default true
   */
  useCookies?: boolean;
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
  user: AuthUser;
}

export class DevAuthClient {
  constructor(options?: DevAuthClientOptions);

  apiUrl: string;
  apiPrefix: string;
  tokenKey: string;
  userKey: string;
  useCookies: boolean;

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
}

export function createDevAuthClient(options?: DevAuthClientOptions): DevAuthClient;
