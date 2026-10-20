// server/config.js

const defaultConfig = {
  corsOrigin: "http://localhost:3001",
  sessionSecret: process.env.SESSION_SECRET || "devAuthSecret",
  jwtSecret: process.env.JWT_SECRET || process.env.SESSION_SECRET || "devAuthJwtSecretKey_change_in_production",
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
  emailProvider: process.env.RESEND_API_KEY ? "resend" : "smtp",
  resendApiKey: process.env.RESEND_API_KEY || "",
  fromEmail: process.env.FROM_EMAIL || process.env.EMAIL_USER || "onboarding@resend.dev"
};

let currentConfig = { ...defaultConfig };

module.exports = {
  set(options = {}) {
    const hasResend = Boolean(options.resendApiKey || process.env.RESEND_API_KEY);
    const hasSmtp = Boolean(process.env.EMAIL_USER && process.env.EMAIL_USER !== "your-email@example.com" && process.env.EMAIL_PASS);
    const hasCustomMailer = typeof options.mailer === "function";

    const isDevModeAuto = Boolean(
      options.devMode ?? 
      (process.env.DEV_MODE === "true" ||
       (!hasResend && !hasSmtp && !hasCustomMailer))
    );

    currentConfig = {
      ...defaultConfig,
      ...options,
      userAdapter: options.userAdapter,
      mapUserPayload: options.mapUserPayload,
      google: options.google,
      sessionSecret: options.sessionSecret || process.env.SESSION_SECRET || defaultConfig.sessionSecret,
      jwtSecret: options.jwtSecret || process.env.JWT_SECRET || options.sessionSecret || defaultConfig.jwtSecret,
      devMode: options.devMode !== undefined ? Boolean(options.devMode) : isDevModeAuto,
      setHttpOnlyCookie: options.setHttpOnlyCookie !== undefined ? Boolean(options.setHttpOnlyCookie) : defaultConfig.setHttpOnlyCookie,
      cookieName: options.cookieName || defaultConfig.cookieName,
      emailProvider: options.emailProvider || (hasResend ? "resend" : defaultConfig.emailProvider),
      resendApiKey: options.resendApiKey || process.env.RESEND_API_KEY || "",
      fromEmail: options.fromEmail || process.env.FROM_EMAIL || defaultConfig.fromEmail
    };
    return currentConfig;
  },

  get(key) {
    if (key) return currentConfig[key];
    return currentConfig;
  }
};
