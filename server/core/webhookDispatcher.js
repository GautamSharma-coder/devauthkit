// server/core/webhookDispatcher.js
const { randomUUID } = require("../utils/webCrypto");
const {
  computeWebhookSignature,
  buildSignatureHeader,
  matchesEvent
} = require("./webhookService");

class WebhookDispatcher {
  /**
   * @param {Object} options
   * @param {Object} options.store - WebhookStore implementation
   * @param {Function} [options.fetchImpl] - Fetch implementation
   * @param {number} [options.timeoutMs=5000] - Request timeout in milliseconds
   * @param {number} [options.maxRetries=3] - Maximum retry attempts on 5xx/network failure
   */
  constructor(options = {}) {
    this.store = options.store || null;
    this.fetchImpl = options.fetchImpl || (typeof fetch !== "undefined" ? fetch.bind(globalThis) : null);
    this.timeoutMs = options.timeoutMs || 5000;
    this.maxRetries = options.maxRetries !== undefined ? options.maxRetries : 3;
    this.retryDelays = [1000, 3000, 8000];
  }

  setStore(store) {
    this.store = store;
  }

  /**
   * Asynchronously emit an event to all matching subscribed webhook endpoints
   * Non-blocking: returns immediately while delivery proceeds in the background.
   * @param {string} event - Event name e.g. "user.created", "org.member_added"
   * @param {Object} data - Event payload data
   * @param {Object} [options]
   * @returns {Promise<string>} Generated eventId
   */
  async emit(event, data, options = {}) {
    const eventId = `evt_${randomUUID()}`;
    const timestamp = Math.floor(Date.now() / 1000);
    const payloadObject = {
      id: eventId,
      event,
      timestamp,
      data: data || {}
    };
    const payloadString = JSON.stringify(payloadObject);

    // Dispatch in background without blocking calling thread
    const dispatchTask = async () => {
      if (!this.store || typeof this.store.listEndpoints !== "function") return;
      try {
        const endpoints = await this.store.listEndpoints();
        const activeEndpoints = endpoints.filter(
          (ep) => ep.active && matchesEvent(ep.events, event)
        );

        await Promise.all(
          activeEndpoints.map((ep) =>
            this._deliverToEndpoint(ep, eventId, event, payloadString, timestamp)
          )
        );
      } catch (err) {
        console.error(`[DevAuthKit Webhooks] Error in event dispatch for ${event}:`, err);
      }
    };

    if (typeof queueMicrotask === "function") {
      queueMicrotask(dispatchTask);
    } else {
      setTimeout(dispatchTask, 0);
    }

    return eventId;
  }

  /**
   * Internal delivery helper with timeout and exponential backoff retry
   */
  async _deliverToEndpoint(endpoint, eventId, event, payloadString, timestamp) {
    if (!this.fetchImpl) return;

    let attempt = 1;
    const maxAttempts = Math.max(1, this.maxRetries + 1);

    while (attempt <= maxAttempts) {
      const startTime = Date.now();
      let statusCode = null;
      let error = null;
      let success = false;

      try {
        const signature = await computeWebhookSignature(payloadString, endpoint.secret, timestamp);
        const signatureHeader = buildSignatureHeader(signature, timestamp);

        const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
        const timer = controller ? setTimeout(() => controller.abort(), this.timeoutMs) : null;

        try {
          const res = await this.fetchImpl(endpoint.url, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "User-Agent": "DevAuthKit-Webhooks/1.7.0",
              "DevAuth-Signature": signatureHeader,
              "x-devauth-signature": signatureHeader,
              "DevAuth-Event-Id": eventId,
              "DevAuth-Event": event
            },
            body: payloadString,
            signal: controller ? controller.signal : undefined
          });
          statusCode = res.status;
          success = res.ok;
          if (!res.ok) {
            error = `Endpoint returned HTTP ${res.status}`;
          }
        } finally {
          if (timer) clearTimeout(timer);
        }
      } catch (err) {
        error = err.message || "Network request failed";
      }

      const durationMs = Date.now() - startTime;

      // Record this delivery attempt
      if (this.store && typeof this.store.recordDelivery === "function") {
        try {
          await this.store.recordDelivery({
            endpointId: endpoint.id,
            eventId,
            event,
            url: endpoint.url,
            statusCode,
            success,
            attempt,
            error: success ? null : error,
            durationMs,
            deliveredAt: Date.now()
          });
        } catch (logErr) {
          console.error("[DevAuthKit Webhooks] Failed to record delivery log:", logErr);
        }
      }

      // If successful or client error (4xx), do not retry
      if (success || (statusCode && statusCode >= 400 && statusCode < 500)) {
        break;
      }

      // If attempts exhausted, stop
      if (attempt >= maxAttempts) {
        break;
      }

      // Exponential backoff delay
      const delay = this.retryDelays[attempt - 1] || 5000;
      await new Promise((resolve) => setTimeout(resolve, delay));
      attempt++;
    }
  }
}

/**
 * Global helper to dispatch a webhook event if webhooks are configured
 * @param {string} event - Event name
 * @param {Object} data - Event payload
 * @returns {Promise<string|null>} Event ID or null
 */
function emitWebhookEvent(event, data) {
  try {
    const config = require("../config");
    const dispatcher = config.get("webhookDispatcher");
    if (dispatcher && typeof dispatcher.emit === "function") {
      return dispatcher.emit(event, data);
    }
  } catch (err) {
    // Non-blocking catch
  }
  return Promise.resolve(null);
}

module.exports = {
  WebhookDispatcher,
  emitWebhookEvent
};
