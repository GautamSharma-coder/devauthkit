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
      this.onTokenExpired = options.onTokenExpired || null;
      this.fetchImpl = options.customFetch || (typeof fetch !== "undefined" ? fetch.bind(globalThis) : null);
      this.storage = getStorage();
      this.listeners = [];
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

      const res = await this._rawFetch(`${this.apiUrl}${this.apiPrefix}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email: email.trim(), otp: otp.trim() }),
      });

      const data = await res.json();
      if (!res.ok) {
        const error = new Error(data.error || "Verification failed");
        error.attemptsRemaining = data.attemptsRemaining;
        throw error;
      }

      if (data.token) {
        this.storage.setItem(this.tokenKey, data.token);
      }
      if (data.user) {
        this.storage.setItem(this.userKey, JSON.stringify(data.user));
      }

      this._notifyAuthChange(data.user);
      return data;
    }

    // Alias for verifyOTP
    async verify(email, otp) {
      return this.verifyOTP(email, otp);
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

      if (token && !headers.has("Authorization")) {
        headers.set("Authorization", `Bearer ${token}`);
      }

      const requestOptions = {
        ...options,
        headers,
        credentials: options.credentials || "include",
      };

      const res = await this._rawFetch(url, requestOptions);

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
      this.storage.removeItem(this.userKey);
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
