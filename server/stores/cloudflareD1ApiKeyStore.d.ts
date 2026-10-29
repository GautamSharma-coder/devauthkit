import { ApiKeyRecord, SafeApiKey, ApiKeyListFilters, ApiKeyStore } from "./memoryApiKeyStore";

export interface CloudflareD1ApiKeyStoreOptions {
  tablePrefix?: string;
}

export declare class CloudflareD1ApiKeyStore implements ApiKeyStore {
  constructor(database: any, options?: CloudflareD1ApiKeyStoreOptions);
  createTables(): Promise<void>;
  createKey(keyRecord: ApiKeyRecord): Promise<ApiKeyRecord>;
  getById(id: string): Promise<ApiKeyRecord | null>;
  getByKeyDigest(digest: string): Promise<ApiKeyRecord | null>;
  listKeys(filters?: ApiKeyListFilters): Promise<SafeApiKey[]>;
  updateKey(id: string, updates: Partial<ApiKeyRecord>): Promise<ApiKeyRecord | null>;
  revokeKey(id: string): Promise<boolean>;
  touchLastUsed(id: string, timestamp?: number): Promise<void>;
}
