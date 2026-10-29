export interface AuditLogEntry {
  id: string;
  orgId?: string | null;
  actorId: string;
  actorType: "user" | "apikey" | "system" | "impersonator";
  targetId?: string | null;
  eventType: string;
  ipAddress?: string | null;
  userAgent?: string | null;
  prevHash: string;
  entryHash: string;
  metadata?: Record<string, any>;
  createdAt: number;
}

export interface AuditLogQueryFilters {
  actorId?: string;
  eventType?: string;
  orgId?: string;
  targetId?: string;
  since?: number;
  until?: number;
  limit?: number;
  offset?: number;
}

export interface AuditLogQueryResult {
  entries: AuditLogEntry[];
  total: number;
  offset: number;
  limit: number;
}

export interface AuditLogStore {
  createEntry(entry: AuditLogEntry): Promise<AuditLogEntry>;
  getLastHash(): Promise<string | null>;
  getById(id: string): Promise<AuditLogEntry | null>;
  query(filters?: AuditLogQueryFilters): Promise<AuditLogQueryResult>;
  clear?(): Promise<void>;
}

export declare class MemoryAuditLogStore implements AuditLogStore {
  constructor(options?: { maxEntries?: number });
  createEntry(entry: AuditLogEntry): Promise<AuditLogEntry>;
  getLastHash(): Promise<string | null>;
  getById(id: string): Promise<AuditLogEntry | null>;
  query(filters?: AuditLogQueryFilters): Promise<AuditLogQueryResult>;
  clear(): Promise<void>;
}
