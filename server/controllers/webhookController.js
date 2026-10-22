// server/controllers/webhookController.js
const config = require("../config");

function getWebhookStore() {
  const store = config.get("webhookStore");
  if (!store) {
    throw new Error("Webhooks feature is not enabled; please configure a webhookStore in devAuthKit options.");
  }
  return store;
}

function getWebhookDispatcher() {
  return config.get("webhookDispatcher");
}

/**
 * POST /auth/webhooks - Register new webhook endpoint
 */
async function createEndpoint(req, res) {
  try {
    const store = getWebhookStore();
    const { url, secret, events, metadata } = req.body || {};

    if (!url || typeof url !== "string" || (!url.startsWith("http://") && !url.startsWith("https://"))) {
      return res.status(400).json({ error: "A valid http:// or https:// URL is required" });
    }

    const endpoint = await store.createEndpoint({
      url,
      secret,
      events,
      metadata
    });

    return res.status(201).json({
      success: true,
      endpoint
    });
  } catch (err) {
    return res.status(400).json({ error: err.message || "Failed to create webhook endpoint" });
  }
}

/**
 * GET /auth/webhooks - List all registered webhook endpoints
 */
async function listEndpoints(req, res) {
  try {
    const store = getWebhookStore();
    const endpoints = await store.listEndpoints();
    return res.json({ success: true, endpoints });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to list webhook endpoints" });
  }
}

/**
 * GET /auth/webhooks/:id - Get specific webhook endpoint
 */
async function getEndpoint(req, res) {
  try {
    const store = getWebhookStore();
    const endpoint = await store.getEndpoint(req.params.id);
    if (!endpoint) {
      return res.status(404).json({ error: "Webhook endpoint not found" });
    }
    return res.json({ success: true, endpoint });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to get webhook endpoint" });
  }
}

/**
 * PATCH /auth/webhooks/:id - Update webhook endpoint
 */
async function updateEndpoint(req, res) {
  try {
    const store = getWebhookStore();
    const updates = req.body || {};
    const updated = await store.updateEndpoint(req.params.id, updates);
    if (!updated) {
      return res.status(404).json({ error: "Webhook endpoint not found" });
    }
    return res.json({ success: true, endpoint: updated });
  } catch (err) {
    return res.status(400).json({ error: err.message || "Failed to update webhook endpoint" });
  }
}

/**
 * DELETE /auth/webhooks/:id - Delete webhook endpoint
 */
async function deleteEndpoint(req, res) {
  try {
    const store = getWebhookStore();
    const deleted = await store.deleteEndpoint(req.params.id);
    if (!deleted) {
      return res.status(404).json({ error: "Webhook endpoint not found" });
    }
    return res.json({ success: true, message: "Webhook endpoint deleted successfully" });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to delete webhook endpoint" });
  }
}

/**
 * GET /auth/webhooks/:id/deliveries - List recent delivery logs
 */
async function listDeliveries(req, res) {
  try {
    const store = getWebhookStore();
    const limit = parseInt(req.query.limit, 10) || 50;
    const deliveries = await store.listDeliveries(req.params.id, limit);
    return res.json({ success: true, deliveries });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to list deliveries" });
  }
}

/**
 * POST /auth/webhooks/:id/test - Send a test ping event to the endpoint
 */
async function testEndpoint(req, res) {
  try {
    const store = getWebhookStore();
    const dispatcher = getWebhookDispatcher();
    const endpoint = await store.getEndpoint(req.params.id);
    if (!endpoint) {
      return res.status(404).json({ error: "Webhook endpoint not found" });
    }

    if (!dispatcher) {
      return res.status(500).json({ error: "Webhook dispatcher is not configured" });
    }

    const eventId = await dispatcher.emit("webhook.test", {
      message: "Test webhook from DevAuthKit",
      timestamp: Date.now()
    });

    return res.json({
      success: true,
      message: "Test event dispatched",
      eventId
    });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to send test webhook" });
  }
}

module.exports = {
  createEndpoint,
  listEndpoints,
  getEndpoint,
  updateEndpoint,
  deleteEndpoint,
  listDeliveries,
  testEndpoint
};
