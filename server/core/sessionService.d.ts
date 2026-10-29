export interface DeviceInfo {
  deviceType: "desktop" | "mobile" | "tablet" | "bot" | string;
  os: string;
  browser: string;
}

export interface SessionRecord {
  sessionId: string;
  userId: string;
  deviceType: string;
  os: string;
  browser: string;
  ipAddress?: string | null;
  userAgent?: string | null;
  createdAt: number;
  lastActiveAt: number;
  expiresAt: number;
  revokedAt?: number | null;
}

export declare function parseUserAgent(uaString?: string): DeviceInfo;

export declare class SessionService {
  constructor(options?: any);
  registerSession(params: {
    sessionId: string;
    userId: string;
    ipAddress?: string;
    userAgent?: string;
  }): SessionRecord | null;
  touchSession(sessionId: string): SessionRecord | null;
  listSessions(userId: string): SessionRecord[];
  revokeSession(sessionId: string, userId: string): boolean;
  revokeOtherSessions(userId: string, currentSessionId: string): number;
  revokeAllUserSessions(userId: string): number;
}

export declare const defaultSessionService: SessionService;
