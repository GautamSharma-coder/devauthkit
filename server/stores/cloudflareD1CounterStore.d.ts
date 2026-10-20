export interface D1CounterPreparedStatement {
  bind(...values: unknown[]): D1CounterPreparedStatement;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  run(): Promise<unknown>;
}

export interface D1CounterDatabase {
  prepare(query: string): D1CounterPreparedStatement;
  batch(statements: D1CounterPreparedStatement[]): Promise<unknown[]>;
}

export class CloudflareD1CounterStore {
  constructor(database: D1CounterDatabase, options?: { tablePrefix?: string });
  createTables(): Promise<void>;
  get(key: string): Promise<number>;
  /** Atomically increment a count, expiring ttlMs after its first increment. */
  increment(key: string, ttlMs: number): Promise<number>;
  delete(key: string): Promise<void>;
}
