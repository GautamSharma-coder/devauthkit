export interface ApiKeyRecord {
  id: string;
  userId: string;
  orgId?: string | null;
  name: string;
  keyPrefix: string;
  keyDigest: string;
  crc32Checksum: string;
  maskedKey: string;
  scopes: string[];
  status: "active" | "suspended" | "revoked";
  lastUsedAt?: number | null;
  expiresAt?: number | null;
  createdAt: number;
}

export type SafeApiKey = Omit<ApiKeyRecord, "keyDigest">;

export interface ApiKeyListFilters {
  userId?: string;
  orgId?: string;
  status?: "active" | "suspended" | "revoked";
}

export interface ApiKeyStore {
  createKey(keyRecord: ApiKeyRecord): Promise<ApiKeyRecord>;
  getById(id: string): Promise<ApiKeyRecord | null>;
  getByKeyDigest(digest: string): Promise<ApiKeyRecord | null>;
  listKeys(filters?: ApiKeyListFilters): Promise<SafeApiKey[]>;
  updateKey(id: string, updates: Partial<ApiKeyRecord>): Promise<ApiKeyRecord | null>;
  revokeKey(id: string): Promise<boolean>;
  touchLastUsed?(id: string, timestamp?: number): Promise<void>;
  clear?(): Promise<void>;
}

export declare class MemoryApiKeyStore implements ApiKeyStore {
  createKey(keyRecord: ApiKeyRecord): Promise<ApiKeyRecord>;
  getById(id: string): Promise<ApiKeyRecord | null>;
  getByKeyDigest(digest: string): Promise<ApiKeyRecord | null>;
  listKeys(filters?: ApiKeyListFilters): Promise<SafeApiKey[]>;
  updateKey(id: string, updates: Partial<ApiKeyRecord>): Promise<ApiKeyRecord | null>;
  revokeKey(id: string): Promise<boolean>;
  touchLastUsed(id: string, timestamp?: number): Promise<void>;
  clear(): Promise<void>;
}
