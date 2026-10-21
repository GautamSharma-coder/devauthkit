export interface CloudflareD1Database {
  prepare(query: string): {
    bind(...values: any[]): {
      first<T = any>(): Promise<T | null>;
      all<T = any>(): Promise<{ results: T[] }>;
      run(): Promise<{ success: boolean }>;
    };
  };
  batch(statements: any[]): Promise<any[]>;
}

export interface CloudflareD1DpopReplayStoreOptions {
  tablePrefix?: string;
}

export class CloudflareD1DpopReplayStore {
  constructor(database: CloudflareD1Database, options?: CloudflareD1DpopReplayStoreOptions);
  createTables(): Promise<void>;
  record(jti: string, ttlSeconds?: number): Promise<boolean>;
  isUsed(jti: string): Promise<boolean>;
  cleanup(): Promise<void>;
}
