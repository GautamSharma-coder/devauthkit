import type { Application, Request, Response, NextFunction } from "express";
import type { Store } from "express-session";

export interface OtpStore {
  get(email: string): { otp: string; attempts: number; createdAt: number } | null | Promise<{ otp: string; attempts: number; createdAt: number } | null>;
  set(email: string, data: { otp: string; attempts: number; createdAt: number }): void | Promise<void>;
  delete(email: string): void | Promise<void>;
  recordAttempt(email: string): number | Promise<number>;
}

export interface RedisClientLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, options: { EX: number }): Promise<unknown>;
  del(keys: string | string[]): Promise<number>;
  incr(key: string): Promise<number>;
}

export interface AdapterUser {
  id: string | number;
  email: string;
  role?: string;
  [key: string]: unknown;
}

export interface UserAdapter {
  findOrCreateUser(data: { email: string }): AdapterUser | Promise<AdapterUser>;
}

export interface AuthIdentityContext {
  provider?: "google";
  providerId?: string;
  name?: string;
  picture?: string;
}

export type UserPayloadMapper = (
  user: AdapterUser,
  identity?: AuthIdentityContext
) => Record<string, unknown>;

export interface GoogleOAuthOptions {
  clientId: string;
  clientSecret: string;
  callbackURL: string;
  /** Optional application URL to redirect to after setting the auth cookie. */
  successRedirectURL?: string;
}

export function prismaAdapter<T extends object>(
  prisma: T,
  options?: {
    model?: string;
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

export interface DevAuthConfigOptions {
  /**
   * Allowed CORS origin(s). E.g. "http://localhost:3000" or ["http://localhost:3000", "http://localhost:3001"]
   * @default "http://localhost:3001"
   */
  corsOrigin?: string | string[];

  /**
   * Secret key used for signing session cookies
   * @default process.env.SESSION_SECRET || "devAuthSecret"
   */
  sessionSecret?: string;

  /**
   * Secret key used for signing JWT Bearer tokens
   * @default process.env.JWT_SECRET || sessionSecret
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
}

export interface AuthenticatedUser {
  email: string;
  id?: string | number;
  [key: string]: any;
}

export interface AuthenticatedRequest extends Request {
  user?: AuthenticatedUser;
}

export type AuthMiddleware = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => void;

export interface DevAuthKitInstance {
  (app: Application, options?: DevAuthConfigOptions): Application;
  requireAuth: AuthMiddleware;
  devAuthKit: DevAuthKitInstance;
  config: {
    set: (options?: DevAuthConfigOptions) => DevAuthConfigOptions;
    get: (key?: keyof DevAuthConfigOptions) => any;
  };
  RedisOtpStore: typeof RedisOtpStore;
  prismaAdapter: typeof prismaAdapter;
}

declare const devAuthKit: DevAuthKitInstance;

export default devAuthKit;
export { devAuthKit };
export { prismaAdapter };
