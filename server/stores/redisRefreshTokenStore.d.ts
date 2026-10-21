import type { RefreshTokenStore } from "../../index";

export interface RedisRefreshTokenClient {
  get(key: string): Promise<string | null>;
  eval(
    script: string,
    options: { keys: string[]; arguments: string[] }
  ): Promise<unknown>;
}

export interface RedisRefreshTokenStoreOptions {
  keyPrefix?: string;
}

export class RedisRefreshTokenStore implements RefreshTokenStore {
  constructor(client: RedisRefreshTokenClient, options?: RedisRefreshTokenStoreOptions);
  create(tokenHash: string, record: {
    familyId: string;
    userId: string;
    user: Record<string, unknown>;
    expiresAt: number;
  }): Promise<void>;
  rotate(
    tokenHash: string,
    replacementHash: string,
    replacement: { expiresAt: number }
  ): ReturnType<RefreshTokenStore["rotate"]>;
  revoke(tokenHash: string): Promise<boolean>;
  revokeFamily(familyId: string): Promise<void>;
  revokeAll(userId: string): Promise<void>;
  isFamilyActive(familyId: string): Promise<boolean>;
}
