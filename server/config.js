// server/config.js

const environment = typeof process === "undefined" ? {} : process.env;
const { randomString } = require("./utils/webCrypto");

const defaultConfig = {
  corsOrigin: "http://localhost:3001",
  sessionSecret: environment.SESSION_SECRET || randomString(32),
  jwtSecret: environment.JWT_SECRET || environment.SESSION_SECRET,
  jwtExpiresIn: "7d",
  otpExpiryMinutes: 5,
  maxAttempts: 5,
  devMode: false,
  debug: false,
  apiPrefix: "/auth",
  setHttpOnlyCookie: true,
  cookieName: "devauth_token",
  otpStore: undefined,
  sessionStore: undefined,
  userAdapter: undefined,
  mapUserPayload: undefined,
  google: undefined,
  github: undefined,
  oauthProviders: undefined,
  oauthStateStore: undefined,
  magicLink: false,
  magicLinkStore: undefined,
  magicLinkExpiryMinutes: 15,
  magicLinkBaseURL: undefined,
  magicLinkSuccessURL: undefined,
  refreshTokens: false,
  refreshTokenStore: undefined,
  rateLimit: {
    requestOtp: { windowMs: 60_000, max: 20, perIp: true, perEmail: true, perIpMax: 20, perEmailMax: 3 },
    verifyOtp: { windowMs: 15 * 60_000, max: 30, perIp: true, perEmail: true, perIpMax: 30, perEmailMax: 10 },
    verifyMagicLink: { windowMs: 15 * 60_000, max: 20, perIp: true, perEmail: true, perIpMax: 20, perEmailMax: 10 },
    refresh: { windowMs: 15 * 60_000, max: 30, perIp: true },
    revokeSession: { windowMs: 15 * 60_000, max: 30, perIp: true },
    revokeAllSessions: { windowMs: 15 * 60_000, max: 10, perIp: true },
    logout: { windowMs: 15 * 60_000, max: 30, perIp: true },
    oauthStart: { windowMs: 15 * 60_000, max: 20, perIp: true },
    oauthCallback: { windowMs: 15 * 60_000, max: 30, perIp: true },
    oauthLink: { windowMs: 15 * 60_000, max: 20, perIp: true },
    googleStart: { windowMs: 15 * 60_000, max: 20, perIp: true },
    googleCallback: { windowMs: 15 * 60_000, max: 30, perIp: true },
    githubStart: { windowMs: 15 * 60_000, max: 20, perIp: true },
    githubCallback: { windowMs: 15 * 60_000, max: 30, perIp: true }
  },
  rateLimitStore: undefined,
  emailProvider: environment.RESEND_API_KEY ? "resend" : "smtp",
  resendApiKey: environment.RESEND_API_KEY || "",
  fromEmail: environment.FROM_EMAIL || environment.EMAIL_USER || "onboarding@resend.dev"
};

let currentConfig = { ...defaultConfig };

function mergeRateLimitRules(rateLimit) {
  if (rateLimit === undefined) return { ...defaultConfig.rateLimit };
  if (rateLimit === false) return false;
  if (!rateLimit || typeof rateLimit !== "object" || Array.isArray(rateLimit)) return rateLimit;

  return {
    ...defaultConfig.rateLimit,
    ...Object.fromEntries(
      Object.entries(rateLimit).map(([name, rule]) => [
        name,
        rule === false
          ? false
          : rule && typeof rule === "object" && !Array.isArray(rule)
            ? { ...(defaultConfig.rateLimit[name] || {}), ...rule }
            : rule
      ])
    )
  };
}

module.exports = {
  set(options = {}) {
    const hasResend = Boolean(options.resendApiKey || environment.RESEND_API_KEY);
    const hasSmtp = Boolean(environment.EMAIL_USER && environment.EMAIL_USER !== "your-email@example.com" && environment.EMAIL_PASS);
    const hasCustomMailer = typeof options.mailer === "function";

    const isDevModeAuto = Boolean(
      options.devMode ?? 
      (environment.DEV_MODE === "true" ||
       (!hasResend && !hasSmtp && !hasCustomMailer))
    );

    currentConfig = {
      ...defaultConfig,
      ...options,
      userAdapter: options.userAdapter,
      mapUserPayload: options.mapUserPayload,
      google: options.google,
      github: options.github,
      oauthProviders: options.oauthProviders,
      oauthStateStore: options.oauthStateStore,
      magicLink: options.magicLink ?? defaultConfig.magicLink,
      magicLinkExpiryMinutes: options.magicLinkExpiryMinutes || defaultConfig.magicLinkExpiryMinutes,
      magicLinkBaseURL: options.magicLinkBaseURL || defaultConfig.magicLinkBaseURL,
      magicLinkSuccessURL: options.magicLinkSuccessURL || defaultConfig.magicLinkSuccessURL,
      refreshTokens: options.refreshTokens ?? defaultConfig.refreshTokens,
      refreshTokenStore: options.refreshTokenStore,
      rateLimit: mergeRateLimitRules(options.rateLimit),
      rateLimitStore: options.rateLimitStore,
      sessionSecret: options.sessionSecret || environment.SESSION_SECRET || defaultConfig.sessionSecret,
      jwtSecret: options.jwtSecret || environment.JWT_SECRET || options.sessionSecret || environment.SESSION_SECRET || defaultConfig.jwtSecret,
      devMode: options.devMode !== undefined ? Boolean(options.devMode) : isDevModeAuto,
      setHttpOnlyCookie: options.setHttpOnlyCookie !== undefined ? Boolean(options.setHttpOnlyCookie) : defaultConfig.setHttpOnlyCookie,
      cookieName: options.cookieName || defaultConfig.cookieName,
      emailProvider: options.emailProvider || (hasResend ? "resend" : defaultConfig.emailProvider),
      resendApiKey: options.resendApiKey || environment.RESEND_API_KEY || "",
      fromEmail: options.fromEmail || environment.FROM_EMAIL || defaultConfig.fromEmail
    };
    return currentConfig;
  },

  get(key) {
    if (key) return currentConfig[key];
    return currentConfig;
  }
};
