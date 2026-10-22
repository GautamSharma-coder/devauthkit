export interface WebhookEndpoint {
  id: string;
  url: string;
  secret: string;
  events: string[];
  active: boolean;
  metadata?: Record<string, any>;
  createdAt: number;
  updatedAt: number;
}

export interface WebhookDelivery {
  id: string;
  endpointId: string;
  eventId: string;
  event: string;
  payload: string;
  statusCode: number | null;
  success: boolean;
  error?: string | null;
  attempt: number;
  durationMs: number;
  timestamp: number;
}

export class MemoryWebhookStore {
  createEndpoint(data: {
    url: string;
    secret?: string;
    events?: string | string[];
    metadata?: Record<string, any>;
  }): Promise<WebhookEndpoint>;

  getEndpoint(id: string): Promise<WebhookEndpoint | null>;

  listEndpoints(): Promise<WebhookEndpoint[]>;

  updateEndpoint(
    id: string,
    updates: Partial<{
      url: string;
      secret: string;
      events: string[];
      active: boolean;
      metadata: Record<string, any>;
    }>
  ): Promise<WebhookEndpoint | null>;

  deleteEndpoint(id: string): Promise<boolean>;

  recordDelivery(data: Omit<WebhookDelivery, "id">): Promise<WebhookDelivery>;

  listDeliveries(endpointId: string, limit?: number): Promise<WebhookDelivery[]>;
}
