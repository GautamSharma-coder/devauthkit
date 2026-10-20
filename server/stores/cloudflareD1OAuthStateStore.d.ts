export interface D1OAuthStatePreparedStatement {
  bind(...values: unknown[]): D1OAuthStatePreparedStatement;
  first<T = Record<string, unknown>>(): Promise<T | null>;
}

export interface D1OAuthStateDatabase {
  prepare(query: string): D1OAuthStatePreparedStatement;
  batch(statements: D1OAuthStatePreparedStatement[]): Promise<unknown[]>;
}

export class CloudflareD1OAuthStateStore {
  constructor(database: D1OAuthStateDatabase, options?: { tablePrefix?: string });
  createTables(): Promise<void>;
  put(state: string, expiresAt: number): Promise<void>;
  /** Atomically consume a state token once. */
  consume(state: string): Promise<boolean>;
}
