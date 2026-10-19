import type { Application, Request, Response, NextFunction } from "express";

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
}

declare const devAuthKit: DevAuthKitInstance;

export default devAuthKit;
export { devAuthKit };
