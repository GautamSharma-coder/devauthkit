import type { D1Database } from "@cloudflare/workers-types";
import type { WebhookEndpoint, WebhookDeliveryRecord, WebhookStore } from "../../index";

export interface CloudflareD1WebhookStoreOptions {
  tablePrefix?: string;
}

export class CloudflareD1WebhookStore implements WebhookStore {
  constructor(database: D1Database, options?: CloudflareD1WebhookStoreOptions);
  database: D1Database;
  tablePrefix: string;
  endpointsTable: string;
  deliveriesTable: string;

  createTables(): Promise<void>;
  createEndpoint(params: {
    url: string;
    secret?: string;
    events?: string[];
    metadata?: Record<string, any>;
  }): Promise<WebhookEndpoint>;
  getEndpoint(id: string): Promise<WebhookEndpoint | null>;
  listEndpoints(): Promise<WebhookEndpoint[]>;
  updateEndpoint(
    id: string,
    updates: Partial<Pick<WebhookEndpoint, "url" | "events" | "active" | "secret" | "metadata">>
  ): Promise<WebhookEndpoint | null>;
  deleteEndpoint(id: string): Promise<boolean>;
  recordDelivery(record: Omit<WebhookDeliveryRecord, "id">): Promise<WebhookDeliveryRecord>;
  listDeliveries(endpointId?: string | null, limit?: number): Promise<WebhookDeliveryRecord[]>;
}
