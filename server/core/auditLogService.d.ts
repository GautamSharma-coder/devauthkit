export interface AuditLogEntry {
  id: string;
  timestamp: number;
  actorId: string;
  actorType: "user" | "apikey" | "system" | "impersonator" | string;
  eventType: string;
  targetId?: string | null;
  orgId?: string | null;
  ipAddress?: string | null;
  metadata?: Record<string, any>;
  prevHash: string;
  entryHash: string;
  createdAt: number;
}

export interface AuditLogStore {
  append(entry: AuditLogEntry): Promise<AuditLogEntry>;
  getLatest(orgId?: string | null): Promise<AuditLogEntry | null>;
  query(filter?: {
    actorId?: string;
    orgId?: string;
    eventType?: string;
    startDate?: number;
    endDate?: number;
    limit?: number;
    offset?: number;
  }): Promise<{ entries: AuditLogEntry[]; total: number }>;
}

export declare const GENESIS_HASH: string;

export declare function computeEntryHash(prevHash: string, entry: Partial<AuditLogEntry>): Promise<string>;

export declare class AuditLogService {
  store: AuditLogStore | null;
  enabled: boolean;
  lastHash: string;
  constructor(options?: { store?: AuditLogStore; enabled?: boolean });
  setStore(store: AuditLogStore): void;
  record(event: Partial<AuditLogEntry>): Promise<AuditLogEntry>;
  query(filter?: any): Promise<{ entries: AuditLogEntry[]; total: number }>;
  exportNdjson(filter?: any): Promise<string>;
  static verifyChain(entries: AuditLogEntry[]): Promise<{ valid: boolean; brokenIndex: number | null; message: string }>;
}

export declare function emitAuditLog(event: Partial<AuditLogEntry>): Promise<AuditLogEntry | null>;
