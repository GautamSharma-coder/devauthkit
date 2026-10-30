// index.js
if (typeof globalThis.SubtleCrypto === "undefined") {
  try {
    const nodeCrypto = require("node:crypto");
    globalThis.SubtleCrypto = nodeCrypto.webcrypto?.SubtleCrypto || class SubtleCrypto {};
  } catch {
    globalThis.SubtleCrypto = class SubtleCrypto {};
  }
}
if (typeof globalThis.File === "undefined") {
  try {
    const { File } = require("node:buffer");
    if (File) globalThis.File = File;
  } catch {}
}

const devAuthKit = require("./server/server.js");

module.exports = devAuthKit;
