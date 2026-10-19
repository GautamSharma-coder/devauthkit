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
  apiPrefix: "/auth"
};

let currentConfig = { ...defaultConfig };

module.exports = {
  set(options = {}) {
    const isDevModeAuto = Boolean(
      options.devMode ?? 
      (process.env.DEV_MODE === "true" ||
       !process.env.EMAIL_USER ||
       process.env.EMAIL_USER === "your-email@example.com" ||
       process.env.NODE_ENV !== "production")
    );

    currentConfig = {
      ...defaultConfig,
      ...options,
      sessionSecret: options.sessionSecret || process.env.SESSION_SECRET || defaultConfig.sessionSecret,
      jwtSecret: options.jwtSecret || process.env.JWT_SECRET || options.sessionSecret || defaultConfig.jwtSecret,
      devMode: options.devMode !== undefined ? Boolean(options.devMode) : isDevModeAuto
    };
    return currentConfig;
  },

  get(key) {
    if (key) return currentConfig[key];
    return currentConfig;
  }
};
