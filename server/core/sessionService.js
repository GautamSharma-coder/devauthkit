// server/core/sessionService.js
const { randomUUID } = require("../utils/webCrypto");

/**
 * Lightweight heuristic User-Agent parser without external dependencies
 * @param {string} uaString
 * @returns {{ deviceType: string, os: string, browser: string }}
 */
function parseUserAgent(uaString = "") {
  const ua = uaString || "";

  // Device Type
  let deviceType = "desktop";
  if (/mobile/i.test(ua)) deviceType = "mobile";
  if (/tablet|ipad/i.test(ua)) deviceType = "tablet";
  if (/bot|crawler|spider/i.test(ua)) deviceType = "bot";

  // Operating System
  let os = "Unknown";
  if (/windows/i.test(ua)) os = "Windows";
  else if (/iphone|ipad|ipod/i.test(ua)) os = "iOS";
  else if (/android/i.test(ua)) os = "Android";
  else if (/macintosh|mac os x/i.test(ua)) os = "macOS";
  else if (/linux/i.test(ua)) os = "Linux";

  // Browser
  let browser = "Unknown";
  if (/edg/i.test(ua)) browser = "Edge";
  else if (/chrome|crios/i.test(ua)) browser = "Chrome";
  else if (/safari/i.test(ua) && !/chrome/i.test(ua)) browser = "Safari";
  else if (/firefox|fxios/i.test(ua)) browser = "Firefox";
  else if (/opera|opr/i.test(ua)) browser = "Opera";

  return { deviceType, os, browser };
}

class SessionService {
  constructor(options = {}) {
    this.sessions = new Map(); // sessionId -> sessionRecord
    this.userSessions = new Map(); // userId -> Set<sessionId>
  }

  /**
   * Registers or updates an active session
   * @param {Object} params
   * @param {string} params.sessionId
   * @param {string} params.userId
   * @param {string} [params.ipAddress]
   * @param {string} [params.userAgent]
   * @returns {Object} Session record
   */
  registerSession(params) {
    const { sessionId, userId, ipAddress, userAgent } = params;
    if (!sessionId || !userId) return null;

    const { deviceType, os, browser } = parseUserAgent(userAgent);
    const now = Date.now();

    const existing = this.sessions.get(sessionId);
    if (existing) {
      existing.lastActiveAt = now;
      existing.ipAddress = ipAddress || existing.ipAddress;
      existing.userAgent = userAgent || existing.userAgent;
      return existing;
    }

    const sessionRecord = {
      id: sessionId,
      userId,
      ipAddress: ipAddress || "127.0.0.1",
      userAgent: userAgent || "Unknown",
      deviceType,
      operatingSystem: os,
      browser,
      sessionEpoch: 1,
      status: "active",
      createdAt: now,
      lastActiveAt: now
    };

    this.sessions.set(sessionId, sessionRecord);

    if (!this.userSessions.has(userId)) {
      this.userSessions.set(userId, new Set());
    }
    this.userSessions.get(userId).add(sessionId);

    return sessionRecord;
  }

  /**
   * Lists all active sessions for a user
   * @param {string} userId
   * @param {string} [currentSessionId]
   * @returns {Array<Object>}
   */
  listUserSessions(userId, currentSessionId) {
    const sessionIds = this.userSessions.get(userId);
    if (!sessionIds) return [];

    const result = [];
    for (const sid of sessionIds) {
      const s = this.sessions.get(sid);
      if (s && s.status === "active") {
        result.push({
          ...s,
          isCurrent: Boolean(currentSessionId && sid === currentSessionId)
        });
      }
    }

    // Sort most recently active first
    result.sort((a, b) => b.lastActiveAt - a.lastActiveAt);
    return result;
  }

  /**
   * Revokes a specific session
   * @param {string} sessionId
   * @param {string} [userId]
   * @returns {boolean}
   */
  revokeSession(sessionId, userId) {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    if (userId && session.userId !== userId) return false;

    session.status = "revoked";
    this.sessions.delete(sessionId);

    const userSet = this.userSessions.get(session.userId);
    if (userSet) {
      userSet.delete(sessionId);
    }

    return true;
  }

  /**
   * Revokes all active sessions for a user except the current one
   * @param {string} userId
   * @param {string} currentSessionId
   * @returns {number} Count of revoked sessions
   */
  revokeOtherSessions(userId, currentSessionId) {
    const sessionIds = this.userSessions.get(userId);
    if (!sessionIds) return 0;

    let count = 0;
    for (const sid of Array.from(sessionIds)) {
      if (sid !== currentSessionId) {
        this.revokeSession(sid, userId);
        count++;
      }
    }

    return count;
  }

  /**
   * Revokes all active sessions for a user
   * @param {string} userId
   * @returns {number}
   */
  revokeAllUserSessions(userId) {
    const sessionIds = this.userSessions.get(userId);
    if (!sessionIds) return 0;

    let count = 0;
    for (const sid of Array.from(sessionIds)) {
      this.revokeSession(sid, userId);
      count++;
    }

    return count;
  }
}

// Global default session service instance
const defaultSessionService = new SessionService();

module.exports = {
  SessionService,
  parseUserAgent,
  defaultSessionService
};
