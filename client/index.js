/**
 * DevAuthKit Client SDK
 * Lightweight, universal client for DevAuthKit authentication
 */

(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    // CommonJS
    module.exports = factory();
  } else if (typeof define === "function" && define.amd) {
    // AMD
    define([], factory);
  } else {
    // Browser Global
    root.DevAuthClient = factory().DevAuthClient;
    root.createDevAuthClient = factory().createDevAuthClient;
  }
})(typeof globalThis !== "undefined" ? globalThis : typeof window !== "undefined" ? window : this, function () {
  
  // Memory storage fallback when localStorage is unavailable (e.g. SSR, Node, React Native)
  class MemoryStorage {
    constructor() {
      this.items = {};
    }
    getItem(key) {
      return this.items[key] || null;
    }
    setItem(key, value) {
      this.items[key] = String(value);
    }
    removeItem(key) {
      delete this.items[key];
    }
  }

  function getStorage() {
    try {
      if (typeof window !== "undefined" && window.localStorage) {
        return window.localStorage;
      }
    } catch (e) {
      // In private browsing or sandboxed iframes, accessing localStorage might throw
    }
    return new MemoryStorage();
  }

  function getSubtleCrypto() {
    if (typeof globalThis !== "undefined" && globalThis.crypto?.subtle) {
      return globalThis.crypto.subtle;
    }
    if (typeof window !== "undefined" && window.crypto?.subtle) {
      return window.crypto.subtle;
    }
    try {
      const nodeCrypto = require("crypto");
      if (nodeCrypto.webcrypto?.subtle) {
        return nodeCrypto.webcrypto.subtle;
      }
    } catch (e) {}
    return null;
  }

  function bytesToBase64Url(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  }

  async function sha256Base64Url(str, subtle) {
    const encoder = new TextEncoder();
    const digest = await subtle.digest("SHA-256", encoder.encode(str));
    return bytesToBase64Url(new Uint8Array(digest));
  }

  async function createClientDPoPProof({ privateKey, jwk, method, uri, accessToken, nonce, subtle }) {
    const encoder = new TextEncoder();
    const now = Math.floor(Date.now() / 1000);
    const header = {
      typ: "dpop+jwt",
      alg: "ES256",
      jwk: {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y
      }
    };
    const htu = uri.split("?")[0].split("#")[0];
    const payload = {
      jti: (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function")
        ? crypto.randomUUID()
        : ("dpop_" + Math.random().toString(36).slice(2) + Date.now().toString(36)),
      htm: method.toUpperCase(),
      htu,
      iat: now
    };
    if (accessToken) {
      payload.ath = await sha256Base64Url(accessToken, subtle);
    }
    if (nonce) {
      payload.nonce = nonce;
    }

    const encodedHeader = bytesToBase64Url(encoder.encode(JSON.stringify(header)));
    const encodedPayload = bytesToBase64Url(encoder.encode(JSON.stringify(payload)));
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    const signatureBuf = await subtle.sign(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      privateKey,
      encoder.encode(signingInput)
    );
    return `${signingInput}.${bytesToBase64Url(new Uint8Array(signatureBuf))}`;
  }

  class DevAuthClient {
    /**
     * @param {Object} options
     * @param {string} [options.apiUrl=""] - Base backend URL (e.g. "http://localhost:3000" or empty if same-origin)
     * @param {string} [options.apiPrefix="/auth"] - Auth route prefix (default: "/auth")
     * @param {string} [options.tokenKey="devauth_token"] - Key name used in localStorage
     * @param {string} [options.userKey="devauth_user"] - Key name for user data in localStorage
     * @param {Function} [options.onTokenExpired] - Callback when an authenticated request returns 401
     * @param {Object} [options.customFetch] - Optional custom fetch implementation
     */
    constructor(options = {}) {
      this.apiUrl = (options.apiUrl || "").replace(/\/+$/, "");
      this.apiPrefix = options.apiPrefix || "/auth";
      this.tokenKey = options.tokenKey || "devauth_token";
      this.userKey = options.userKey || "devauth_user";
      this.tokenTypeKey = `${this.tokenKey}_type`;
      this.refreshEnabledKey = `${this.tokenKey}_refresh_enabled`;
      this.dpop = Boolean(options.dpop);
      this.dpopKey = null;
      this.dpopNonce = null;
      this.onTokenExpired = options.onTokenExpired || null;
      this.fetchImpl = options.customFetch || (typeof fetch !== "undefined" ? fetch.bind(globalThis) : null);
      this.storage = getStorage();
      this.listeners = [];
      this.refreshPromise = null;
    }

    /**
     * Get or create client-side ECDSA P-256 key pair for DPoP proof generation
     * @returns {Promise<{ keyPair: CryptoKeyPair, privateKey: CryptoKey, publicKey: CryptoKey, jwk: Object }>}
     */
    async getDPoPKeyPair() {
      if (this.dpopKey) return this.dpopKey;
      const subtle = getSubtleCrypto();
      if (!subtle) {
        throw new Error("[DevAuthKit] Web Crypto API is required for DPoP proof generation");
      }
      const keyPair = await subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );
      const exportedPub = await subtle.exportKey("jwk", keyPair.publicKey);
      const publicJwk = {
        kty: exportedPub.kty,
        crv: exportedPub.crv,
        x: exportedPub.x,
        y: exportedPub.y
      };
      this.dpopKey = {
        keyPair,
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        jwk: publicJwk
      };
      return this.dpopKey;
    }

    /**
     * Create an RFC 9449 DPoP proof JWT for an outgoing HTTP request
     * @param {string} method - HTTP method ("GET", "POST", etc.)
     * @param {string} uri - Target URI
     * @param {string} [accessToken] - Access token to bind via ath claim
     * @returns {Promise<string>}
     */
    async createDPoPProof(method, uri, accessToken) {
      const keyObj = await this.getDPoPKeyPair();
      const subtle = getSubtleCrypto();
      return createClientDPoPProof({
        privateKey: keyObj.privateKey,
        jwk: keyObj.jwk,
        method,
        uri,
        accessToken,
        nonce: this.dpopNonce,
        subtle
      });
    }

    /**
     * Check if the client or active session is DPoP bound
     * @returns {boolean}
     */
    isDPoPBound() {
      return this.dpop || this.storage.getItem(this.tokenTypeKey) === "DPoP";
    }

    /**
     * Subscribe to authentication state changes (login / logout)
     * @param {Function} callback - Function receiving (user | null)
     * @returns {Function} unsubscribe function
     */
    onAuthStateChanged(callback) {
      if (typeof callback === "function") {
        this.listeners.push(callback);
        // Immediately invoke with current state
        callback(this.getUser());
      }
      return () => {
        this.listeners = this.listeners.filter(l => l !== callback);
      };
    }

    _notifyAuthChange(user) {
      this.listeners.forEach(fn => {
        try {
          fn(user);
        } catch (err) {
          console.error("[DevAuthKit] Listener error:", err);
        }
      });
    }

    /**
     * Request a one-time login code sent to the specified email
     * @param {string} email
     * @returns {Promise<{ success: boolean, message: string, devMode?: boolean }>}
     */
    async sendOTP(email) {
      if (!email) throw new Error("Email is required");

      const res = await this._rawFetch(`${this.apiUrl}${this.apiPrefix}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim() }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to send OTP");
      }
      return data;
    }

    // Alias for sendOTP
    async requestOTP(email) {
      return this.sendOTP(email);
    }

    // Alias for sendOTP
    async login(email) {
      return this.sendOTP(email);
    }

    /**
     * Verify the OTP code and establish authentication session & JWT token
     * @param {string} email
     * @param {string} otp
     * @returns {Promise<{ success: boolean, token: string, user: Object }>}
     */
    async verifyOTP(email, otp) {
      if (!email || !otp) throw new Error("Email and OTP are required");

      const url = `${this.apiUrl}${this.apiPrefix}/verify`;
      const headers = { "Content-Type": "application/json" };
      if (this.dpop) {
        try {
          headers["DPoP"] = await this.createDPoPProof("POST", url);
        } catch (e) {
          console.warn("[DevAuthKit] Failed to generate DPoP proof for verifyOTP:", e);
        }
      }

      const res = await this._rawFetch(url, {
        method: "POST",
        headers,
        credentials: "include",
        body: JSON.stringify({ email: email.trim(), otp: otp.toString().trim() }),
      });

      const dpopNonceHeader = res.headers?.get ? res.headers.get("DPoP-Nonce") : res.headers?.["dpop-nonce"];
      if (dpopNonceHeader) this.dpopNonce = dpopNonceHeader;

      const data = await res.json();
      if (!res.ok) {
        const error = new Error(data.error || "Verification failed");
        error.attemptsRemaining = data.attemptsRemaining;
        throw error;
      }

      if (data.token) {
        this.storage.setItem(this.tokenKey, data.token);
      }
      if (data.tokenType === "DPoP") {
        this.storage.setItem(this.tokenTypeKey, "DPoP");
      } else {
        this.storage.removeItem(this.tokenTypeKey);
      }
      if (data.user) {
        this.storage.setItem(this.userKey, JSON.stringify(data.user));
      }
      if (data.refreshEnabled) {
        this.storage.setItem(this.refreshEnabledKey, "true");
      } else {
        this.storage.removeItem(this.refreshEnabledKey);
      }

      this._notifyAuthChange(data.user);
      return data;
    }

    // Alias for verifyOTP
    async verify(email, otp) {
      return this.verifyOTP(email, otp);
    }

    /**
     * Verify Magic Link token and authenticate
     * @param {string} token
     * @param {string} [email]
     * @returns {Promise<{ success: boolean, token: string, user: Object }>}
     */
    async verifyMagicLink(token, email) {
      if (!token) throw new Error("Magic link token is required");

      const url = `${this.apiUrl}${this.apiPrefix}/verify-magic`;
      const headers = { "Content-Type": "application/json" };
      if (this.dpop) {
        try {
          headers["DPoP"] = await this.createDPoPProof("POST", url);
        } catch (e) {
          console.warn("[DevAuthKit] Failed to generate DPoP proof for verifyMagicLink:", e);
        }
      }

      const res = await this._rawFetch(url, {
        method: "POST",
        headers,
        credentials: "include",
        body: JSON.stringify({ token: String(token).trim(), ...(email ? { email: String(email).trim() } : {}) }),
      });

      const dpopNonceHeader = res.headers?.get ? res.headers.get("DPoP-Nonce") : res.headers?.["dpop-nonce"];
      if (dpopNonceHeader) this.dpopNonce = dpopNonceHeader;

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Magic link verification failed");
      }

      if (data.token) {
        this.storage.setItem(this.tokenKey, data.token);
      }
      if (data.tokenType === "DPoP") {
        this.storage.setItem(this.tokenTypeKey, "DPoP");
      } else {
        this.storage.removeItem(this.tokenTypeKey);
      }
      if (data.user) {
        this.storage.setItem(this.userKey, JSON.stringify(data.user));
      }
      if (data.refreshEnabled) {
        this.storage.setItem(this.refreshEnabledKey, "true");
      } else {
        this.storage.removeItem(this.refreshEnabledKey);
      }

      this._notifyAuthChange(data.user);
      return data;
    }

    /**
     * Check if user is currently authenticated
     * @returns {boolean}
     */
    isAuthenticated() {
      return Boolean(this.getToken());
    }

    /**
     * Get stored JWT token
     * @returns {string | null}
     */
    getToken() {
      return this.storage.getItem(this.tokenKey) || null;
    }

    /**
     * Get current authenticated user details
     * @returns {Object | null}
     */
    getUser() {
      const stored = this.storage.getItem(this.userKey);
      if (!stored) return null;
      try {
        return JSON.parse(stored);
      } catch (e) {
        return { email: stored };
      }
    }

    /**
     * Fetch user profile from the server
     * @returns {Promise<Object>}
     */
    async getProfile() {
      const res = await this.fetch(`${this.apiUrl}${this.apiPrefix}/me`);
      if (!res.ok) {
        throw new Error("Failed to fetch user profile");
      }
      const data = await res.json();
      if (data.user) {
        this.storage.setItem(this.userKey, JSON.stringify(data.user));
      }
      return data.user || data;
    }

    async refresh() {
      if (!this.refreshPromise) {
        this.refreshPromise = (async () => {
          const url = `${this.apiUrl}${this.apiPrefix}/refresh`;
          const headers = {};
          if (this.isDPoPBound()) {
            try {
              headers["DPoP"] = await this.createDPoPProof("POST", url);
            } catch (e) {
              console.warn("[DevAuthKit] Failed to generate DPoP proof for refresh:", e);
            }
          }

          const res = await this._rawFetch(url, {
            method: "POST",
            headers,
            credentials: "include"
          });

          const dpopNonceHeader = res.headers?.get ? res.headers.get("DPoP-Nonce") : res.headers?.["dpop-nonce"];
          if (dpopNonceHeader) this.dpopNonce = dpopNonceHeader;

          const data = await res.json();
          if (!res.ok) {
            throw new Error(data.error || "Failed to refresh authentication");
          }
          this.storage.setItem(this.tokenKey, data.token);
          if (data.tokenType === "DPoP") {
            this.storage.setItem(this.tokenTypeKey, "DPoP");
          }
          if (data.user) this.storage.setItem(this.userKey, JSON.stringify(data.user));
          this.storage.setItem(this.refreshEnabledKey, "true");
          return data;
        })().finally(() => {
          this.refreshPromise = null;
        });
      }
      return this.refreshPromise;
    }

    /**
     * Make an authenticated HTTP request with Bearer token & session credentials
     * @param {string} endpoint - Path (e.g. "/api/todos") or full URL
     * @param {RequestInit} [options] - Standard fetch options
     * @returns {Promise<Response>}
     */
    async fetch(endpoint, options = {}) {
      let url = endpoint;
      if (!url.startsWith("http://") && !url.startsWith("https://")) {
        url = `${this.apiUrl}${url.startsWith("/") ? "" : "/"}${url}`;
      }

      const headers = new Headers(options.headers || {});
      const token = this.getToken();
      const isDPoP = this.isDPoPBound();
      const method = (options.method || "GET").toUpperCase();

      if (token && !headers.has("Authorization")) {
        headers.set("Authorization", isDPoP ? `DPoP ${token}` : `Bearer ${token}`);
      }

      if (isDPoP && !headers.has("DPoP")) {
        try {
          headers.set("DPoP", await this.createDPoPProof(method, url, token || undefined));
        } catch (e) {
          console.warn("[DevAuthKit] Failed to generate DPoP proof for fetch:", e);
        }
      }

      const requestOptions = {
        ...options,
        headers,
        credentials: options.credentials || "include",
      };

      let res = await this._rawFetch(url, requestOptions);

      // Capture DPoP-Nonce if provided
      const dpopNonceHeader = res.headers?.get ? res.headers.get("DPoP-Nonce") : res.headers?.["dpop-nonce"];
      if (dpopNonceHeader) {
        this.dpopNonce = dpopNonceHeader;
      }

      // If server returned 401 with use_dpop_nonce challenge, auto-retry once with fresh nonce
      if (res.status === 401 && dpopNonceHeader && isDPoP) {
        try {
          const retryHeaders = new Headers(options.headers || {});
          if (token && !retryHeaders.has("Authorization")) {
            retryHeaders.set("Authorization", `DPoP ${token}`);
          }
          retryHeaders.set("DPoP", await this.createDPoPProof(method, url, token || undefined));
          res = await this._rawFetch(url, { ...requestOptions, headers: retryHeaders });
        } catch (e) {
          // ignore retry error
        }
      }

      if (res.status === 401 && this.storage.getItem(this.refreshEnabledKey) === "true") {
        try {
          await this.refresh();
          const refreshedHeaders = new Headers(options.headers || {});
          const refreshedToken = this.getToken();
          const refreshedIsDPoP = this.isDPoPBound();
          if (refreshedToken && !refreshedHeaders.has("Authorization")) {
            refreshedHeaders.set("Authorization", refreshedIsDPoP ? `DPoP ${refreshedToken}` : `Bearer ${refreshedToken}`);
          }
          if (refreshedIsDPoP && !refreshedHeaders.has("DPoP")) {
            refreshedHeaders.set("DPoP", await this.createDPoPProof(method, url, refreshedToken || undefined));
          }
          res = await this._rawFetch(url, { ...requestOptions, headers: refreshedHeaders });
        } catch {
          this.storage.removeItem(this.tokenKey);
          this.storage.removeItem(this.tokenTypeKey);
          this.storage.removeItem(this.userKey);
          this.storage.removeItem(this.refreshEnabledKey);
          this._notifyAuthChange(null);
          if (this.onTokenExpired) this.onTokenExpired();
          return res;
        }
      }

      if (res.status === 401 && this.onTokenExpired) {
        this.onTokenExpired();
      }

      return res;
    }

    /**
     * Logout and clear local tokens & server session
     * @returns {Promise<{ success: boolean }>}
     */
    async logout() {
      try {
        await this._rawFetch(`${this.apiUrl}${this.apiPrefix}/logout`, {
          method: "POST",
          credentials: "include"
        });
      } catch (e) {
        // Continue clearing client state even if network fails
      }

      this.storage.removeItem(this.tokenKey);
      this.storage.removeItem(this.tokenTypeKey);
      this.storage.removeItem(this.userKey);
      this.storage.removeItem(this.refreshEnabledKey);
      this.dpopKey = null;
      this.dpopNonce = null;
      this._notifyAuthChange(null);
      return { success: true };
    }

    _rawFetch(url, options) {
      if (!this.fetchImpl) {
        throw new Error("[DevAuthKit] No fetch implementation found. Pass customFetch in options.");
      }
      return this.fetchImpl(url, options);
    }
  }

  function createDevAuthClient(options) {
    return new DevAuthClient(options);
  }

  return {
    DevAuthClient,
    createDevAuthClient,
    default: DevAuthClient
  };
});
