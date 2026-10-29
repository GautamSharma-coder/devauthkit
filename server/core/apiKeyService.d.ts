export interface ApiKeyRecord {
  id: string;
  name: string;
  keyDigest: string;
  maskedKey: string;
  userId: string;
  orgId?: string | null;
  scopes: string[];
  rateLimitPerMinute: number;
  expiresAt: number | null;
  lastUsedAt: number | null;
  status: "active" | "revoked" | string;
  createdAt: number;
  revokedAt?: number | null;
}

export interface ApiKeyStore {
  createKey(record: ApiKeyRecord): Promise<ApiKeyRecord>;
  getById(keyId: string): Promise<ApiKeyRecord | null>;
  getByDigest(digest: string): Promise<ApiKeyRecord | null>;
  listKeys(filter: { userId?: string; orgId?: string | null }): Promise<ApiKeyRecord[]>;
  revokeKey(keyId: string): Promise<ApiKeyRecord | null>;
  updateKey(keyId: string, updates: Partial<ApiKeyRecord>): Promise<ApiKeyRecord | null>;
  recordUsage(keyId: string, timestamp?: number): Promise<void>;
}

export declare function crc32Hex(str: string): string;

export declare function verifyKeyChecksum(rawKey: string): boolean;

export declare function hashApiKey(rawKey: string, salt?: string): Promise<string>;

export declare function matchesScopes(
  grantedScopes: string[] | string,
  requiredScopes: string[] | string
): boolean;

export declare function maskApiKey(rawKey: string): string;

export declare class ApiKeyService {
  store: ApiKeyStore | null;
  constructor(options?: { store?: ApiKeyStore; cacheTtlMs?: number });
  setStore(store: ApiKeyStore): void;
  createKey(params: {
    name: string;
    userId: string;
    orgId?: string | null;
    scopes?: string[];
    rateLimitPerMinute?: number;
    expiresInDays?: number | null;
    environment?: "live" | "test";
  }): Promise<{ key: ApiKeyRecord; rawKey: string }>;
  verifyKey(rawKey: string, requiredScopes?: string[] | string): Promise<{
    valid: boolean;
    key?: ApiKeyRecord;
    error?: string;
  }>;
  rollKey(keyId: string, userId: string, params?: { expiresInDays?: number | null }): Promise<{
    key: ApiKeyRecord;
    rawKey: string;
    oldKeyId: string;
  }>;
  revokeKey(keyId: string, userId: string): Promise<ApiKeyRecord | null>;
  listKeys(userId: string, orgId?: string | null): Promise<ApiKeyRecord[]>;
  getById(keyId: string): Promise<ApiKeyRecord | null>;
  updateKey(keyId: string, userId: string, updates: Partial<ApiKeyRecord>): Promise<ApiKeyRecord | null>;
}
