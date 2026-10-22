// server/stores/memoryWebhookStore.js
const { randomUUID } = require("../utils/webCrypto");
const { generateWebhookSecret } = require("../core/webhookService");

class MemoryWebhookStore {
  constructor() {
    this.endpoints = new Map();
    this.deliveries = [];
    this.maxDeliveries = 1000;
  }

  async createEndpoint({ url, secret = null, events = ["*"], metadata = null }) {
    if (!url || typeof url !== "string") {
      throw new TypeError("Webhook endpoint url is required");
    }

    const id = `whep_${randomUUID()}`;
    const now = Date.now();
    const endpoint = {
      id,
      url: url.trim(),
      secret: secret || generateWebhookSecret(),
      events: Array.isArray(events) && events.length > 0 ? events : ["*"],
      active: true,
      metadata: metadata || null,
      createdAt: now,
      updatedAt: now
    };

    this.endpoints.set(id, endpoint);
    return { ...endpoint };
  }

  async getEndpoint(id) {
    if (!id) return null;
    const ep = this.endpoints.get(String(id));
    return ep ? { ...ep } : null;
  }

  async listEndpoints() {
    return Array.from(this.endpoints.values()).map((ep) => ({ ...ep }));
  }

  async updateEndpoint(id, updates = {}) {
    const ep = this.endpoints.get(String(id));
    if (!ep) return null;

    if (updates.url && typeof updates.url === "string") {
      ep.url = updates.url.trim();
    }
    if (Array.isArray(updates.events)) {
      ep.events = updates.events.length > 0 ? updates.events : ["*"];
    }
    if (typeof updates.active === "boolean") {
      ep.active = updates.active;
    }
    if (updates.secret && typeof updates.secret === "string") {
      ep.secret = updates.secret.trim();
    }
    if (updates.metadata !== undefined) {
      ep.metadata = updates.metadata;
    }
    ep.updatedAt = Date.now();
    return { ...ep };
  }

  async deleteEndpoint(id) {
    return this.endpoints.delete(String(id));
  }

  async recordDelivery(record) {
    const id = `whdel_${randomUUID()}`;
    const delivery = {
      id,
      ...record,
      deliveredAt: record.deliveredAt || Date.now()
    };
    this.deliveries.unshift(delivery);
    if (this.deliveries.length > this.maxDeliveries) {
      this.deliveries.length = this.maxDeliveries;
    }
    return { ...delivery };
  }

  async listDeliveries(endpointId = null, limit = 50) {
    let filtered = this.deliveries;
    if (endpointId) {
      filtered = filtered.filter((d) => d.endpointId === String(endpointId));
    }
    return filtered.slice(0, limit).map((d) => ({ ...d }));
  }

  clear() {
    this.endpoints.clear();
    this.deliveries = [];
  }
}

module.exports = { MemoryWebhookStore };
