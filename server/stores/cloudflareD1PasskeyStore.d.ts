import type {
  PasskeyChallengeRecord,
  PasskeyCredentialRecord,
  PasskeyStore
} from "../../index";

export interface D1PasskeyPreparedStatement {
  bind(...values: unknown[]): D1PasskeyPreparedStatement;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<{ results?: T[] }>;
  run(): Promise<{ meta?: { changes?: number } }>;
}

export interface D1PasskeyDatabase {
  prepare(query: string): D1PasskeyPreparedStatement;
  batch(statements: D1PasskeyPreparedStatement[]): Promise<unknown[]>;
}

export class CloudflareD1PasskeyStore implements PasskeyStore {
  constructor(database: D1PasskeyDatabase, options?: { tablePrefix?: string });
  createTables(): Promise<void>;
  getUserHandle(userId: string): Promise<string>;
  put(challenge: string, record: PasskeyChallengeRecord): Promise<void>;
  consume(
    challenge: string,
    purpose: PasskeyChallengeRecord["purpose"]
  ): Promise<PasskeyChallengeRecord | null>;
  create(credential: PasskeyCredentialRecord): Promise<void>;
  getByCredentialId(credentialId: string): Promise<PasskeyCredentialRecord | null>;
  listByUserId(userId: string): Promise<Array<{
    id: string;
    createdAt: number;
    deviceType: string;
    backedUp: boolean;
    transports: string[];
  }>>;
  updateCounter(
    credentialId: string,
    expectedCounter: number,
    newCounter: number,
    deviceType: string,
    backedUp: boolean
  ): Promise<boolean>;
  deleteByCredentialId(credentialId: string, userId: string): Promise<boolean>;
}
