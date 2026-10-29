import { AuditLogEntry, AuditLogQueryFilters, AuditLogQueryResult, AuditLogStore } from "./memoryAuditLogStore";

export interface CloudflareD1AuditLogStoreOptions {
  tablePrefix?: string;
}

export declare class CloudflareD1AuditLogStore implements AuditLogStore {
  constructor(database: any, options?: CloudflareD1AuditLogStoreOptions);
  createTables(): Promise<void>;
  createEntry(entry: AuditLogEntry): Promise<AuditLogEntry>;
  getLastHash(): Promise<string | null>;
  getById(id: string): Promise<AuditLogEntry | null>;
  query(filters?: AuditLogQueryFilters): Promise<AuditLogQueryResult>;
}
