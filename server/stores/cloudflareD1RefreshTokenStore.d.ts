import type { RefreshTokenStore, RefreshTokenRecord, RefreshTokenRotationResult } from "../../index";

export interface D1PreparedStatementLike {
  bind(...values: unknown[]): D1PreparedStatementLike;
  first<T = Record<string, unknown>>(): Promise<T | null>;
}

export interface D1DatabaseLike {
  prepare(query: string): D1PreparedStatementLike;
  batch<T = unknown>(statements: D1PreparedStatementLike[]): Promise<Array<{
    results?: T[];
    success?: boolean;
    meta?: { changes?: number };
  }>>;
}

export class CloudflareD1RefreshTokenStore implements RefreshTokenStore {
  constructor(database: D1DatabaseLike, options?: { tablePrefix?: string });
  createTables(): Promise<void>;
  create(tokenHash: string, record: RefreshTokenRecord): Promise<void>;
  rotate(
    tokenHash: string,
    replacementHash: string,
    replacement: { expiresAt: number }
  ): Promise<RefreshTokenRotationResult>;
  revoke(tokenHash: string): Promise<boolean>;
  revokeFamily(familyId: string): Promise<void>;
  revokeAll(userId: string): Promise<void>;
  isFamilyActive(familyId: string): Promise<boolean>;
}
