export interface RedisDpopReplayClient {
  get(key: string): Promise<string | null>;
  set(
    key: string,
    value: string,
    options: { NX: true; EX: number }
  ): Promise<string | null | boolean>;
}

export interface RedisDpopReplayStoreOptions {
  keyPrefix?: string;
}

export class RedisDpopReplayStore {
  constructor(client: RedisDpopReplayClient, options?: RedisDpopReplayStoreOptions);
  record(jti: string, ttlSeconds?: number): Promise<boolean>;
  isUsed(jti: string): Promise<boolean>;
}
