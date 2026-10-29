// server/config.js

const environment = typeof process === "undefined" ? {} : process.env;
const { randomString } = require("./utils/webCrypto");
const { MemoryOrganizationStore } = require("./stores/memoryOrganizationStore");
const { MemoryWebhookStore } = require("./stores/memoryWebhookStore");
const { MemorySsoStore } = require("./stores/memorySsoStore");
const { WebhookDispatcher } = require("./core/webhookDispatcher");
const { MemoryAuditLogStore } = require("./stores/memoryAuditLogStore");
const { AuditLogService } = require("./core/auditLogService");
const { MemoryApiKeyStore } = require("./stores/memoryApiKeyStore");
const { ApiKeyService } = require("./core/apiKeyService");
const { defaultSessionService } = require("./core/sessionService");

const defaultConfig = {
  corsOrigin: "http://localhost:3001",
  sessionSecret: environment.SESSION_SECRET,
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
  passkeys: undefined,
  passkeyStore: undefined,
  passkeyChallengeStore: undefined,
  mfaStore: undefined,
  mfaIssuer: "DevAuthKit",
  mfaStepUpExpiresInSeconds: 300,
  magicLink: false,
  magicLinkStore: undefined,
  magicLinkExpiryMinutes: 15,
  magicLinkBaseURL: undefined,
  magicLinkSuccessURL: undefined,
  refreshTokens: false,
  refreshTokenStore: undefined,
  organizations: false,
  organizationStore: undefined,
  orgRoles: undefined,
  webhooks: false,
  webhookStore: undefined,
  webhookDispatcher: undefined,
  sso: false,
  ssoStore: undefined,
  scim: false,
  dpop: false,
  dpopReplayStore: undefined,
  dpopNonce: undefined,
  dpopMaxClockSkewSeconds: 60,
  // v2 Next-Gen Features
  audit: true,
  auditStore: undefined,
  auditService: undefined,
  apiKeys: true,
  apiKeyStore: undefined,
  apiKeyService: undefined,
  impersonation: { enabled: true, maxTtlSeconds: 3600 },
  sessionService: undefined,
  rateLimit: {
    requestOtp: { windowMs: 60_000, max: 20, perIp: true, perEmail: true, perIpMax: 20, perEmailMax: 3 },
    verifyOtp: { windowMs: 15 * 60_000, max: 30, perIp: true, perEmail: true, perIpMax: 30, perEmailMax: 10 },
    verifyMagicLink: { windowMs: 15 * 60_000, max: 20, perIp: true, perEmail: true, perIpMax: 20, perEmailMax: 10 },
    mfaEnroll: { windowMs: 15 * 60_000, max: 10, perIp: true },
    mfaEnable: { windowMs: 15 * 60_000, max: 10, perIp: true },
    mfaVerify: { windowMs: 15 * 60_000, max: 10, perIp: true },
    mfaDisable: { windowMs: 15 * 60_000, max: 5, perIp: true },
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
    githubCallback: { windowMs: 15 * 60_000, max: 30, perIp: true },
    passkeyRegisterOptions: { windowMs: 15 * 60_000, max: 10, perIp: true },
    passkeyRegisterVerify: { windowMs: 15 * 60_000, max: 10, perIp: true },
    passkeyAuthenticationOptions: { windowMs: 15 * 60_000, max: 30, perIp: true, perEmail: true, perEmailMax: 10 },
    passkeyAuthenticationVerify: { windowMs: 15 * 60_000, max: 20, perIp: true },
    passkeyList: { windowMs: 15 * 60_000, max: 60, perIp: true },
    passkeyDelete: { windowMs: 15 * 60_000, max: 10, perIp: true },
    // v2 Rate Limit Rules
    createApiKey: { windowMs: 15 * 60_000, max: 20, perIp: true },
    listApiKeys: { windowMs: 15 * 60_000, max: 60, perIp: true },
    impersonate: { windowMs: 15 * 60_000, max: 20, perIp: true },
    blockUser: { windowMs: 15 * 60_000, max: 20, perIp: true },
    listSessions: { windowMs: 15 * 60_000, max: 60, perIp: true }
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

    const auditStore = options.auditStore || (options.audit !== false ? new MemoryAuditLogStore() : undefined);
    const auditService = options.auditService || (options.audit !== false ? new AuditLogService({ store: auditStore }) : undefined);

    const apiKeyStore = options.apiKeyStore || (options.apiKeys !== false ? new MemoryApiKeyStore() : undefined);
    const apiKeyService = options.apiKeyService || (options.apiKeys !== false ? new ApiKeyService({ store: apiKeyStore }) : undefined);

    const sessionService = options.sessionService || defaultSessionService;

    currentConfig = {
      ...defaultConfig,
      ...options,
      userAdapter: options.userAdapter,
      mapUserPayload: options.mapUserPayload,
      google: options.google,
      github: options.github,
      oauthProviders: options.oauthProviders,
      oauthStateStore: options.oauthStateStore,
      passkeys: options.passkeys,
      passkeyStore: options.passkeyStore,
      passkeyChallengeStore: options.passkeyChallengeStore,
      mfaStore: options.mfaStore,
      mfaIssuer: options.mfaIssuer || defaultConfig.mfaIssuer,
      mfaStepUpExpiresInSeconds: options.mfaStepUpExpiresInSeconds ?? defaultConfig.mfaStepUpExpiresInSeconds,
      magicLink: options.magicLink ?? defaultConfig.magicLink,
      magicLinkExpiryMinutes: options.magicLinkExpiryMinutes || defaultConfig.magicLinkExpiryMinutes,
      magicLinkBaseURL: options.magicLinkBaseURL || defaultConfig.magicLinkBaseURL,
      magicLinkSuccessURL: options.magicLinkSuccessURL || defaultConfig.magicLinkSuccessURL,
      refreshTokens: options.refreshTokens ?? defaultConfig.refreshTokens,
      refreshTokenStore: options.refreshTokenStore,
      organizations: Boolean(options.organizations || options.organizationStore),
      organizationStore: options.organizationStore || (options.organizations ? new MemoryOrganizationStore() : undefined),
      orgRoles: options.orgRoles || defaultConfig.orgRoles,
      webhooks: Boolean(options.webhooks || options.webhookStore),
      webhookStore: options.webhookStore || (options.webhooks ? new MemoryWebhookStore() : undefined),
      sso: Boolean(options.sso || options.ssoStore),
      ssoStore: options.ssoStore || options.sso?.store || ((options.sso || options.scim) ? new MemorySsoStore() : undefined),
      scim: Boolean(options.scim || options.ssoStore),
      // v2 Next-Gen Injections
      audit: options.audit !== false,
      auditStore,
      auditService,
      apiKeys: options.apiKeys !== false,
      apiKeyStore,
      apiKeyService,
      impersonation: { ...defaultConfig.impersonation, ...(options.impersonation || {}) },
      sessionService,
      rateLimit: mergeRateLimitRules(options.rateLimit),
      rateLimitStore: options.rateLimitStore,
      sessionSecret: options.sessionSecret || environment.SESSION_SECRET || defaultConfig.sessionSecret || randomString(32),
      jwtSecret: options.jwtSecret || environment.JWT_SECRET || options.sessionSecret || environment.SESSION_SECRET || defaultConfig.jwtSecret,
      devMode: options.devMode !== undefined ? Boolean(options.devMode) : isDevModeAuto,
      setHttpOnlyCookie: options.setHttpOnlyCookie !== undefined ? Boolean(options.setHttpOnlyCookie) : defaultConfig.setHttpOnlyCookie,
      cookieName: options.cookieName || defaultConfig.cookieName,
      emailProvider: options.emailProvider || (hasResend ? "resend" : defaultConfig.emailProvider),
      resendApiKey: options.resendApiKey || environment.RESEND_API_KEY || "",
      fromEmail: options.fromEmail || environment.FROM_EMAIL || defaultConfig.fromEmail
    };

    if (currentConfig.webhooks && currentConfig.webhookStore) {
      currentConfig.webhookDispatcher = options.webhookDispatcher || new WebhookDispatcher({
        store: currentConfig.webhookStore,
        fetchImpl: options.customFetch
      });

      if (Array.isArray(options.webhooks?.endpoints)) {
        for (const ep of options.webhooks.endpoints) {
          if (ep && ep.url) {
            currentConfig.webhookStore.createEndpoint(ep).catch?.(() => {});
          }
        }
      }
    }

    return currentConfig;
  },

  get(key) {
    if (key) return currentConfig[key];
    return currentConfig;
  }
};
