// example.js
const express = require("express");
const devAuthKit = require("./server/server.js"); // local import for testing

const app = express();

devAuthKit(app, {
  corsOrigin: "http://localhost:3001",
  sessionSecret: "my-secret",
  debug: true
});

app.listen(3000, () => {
  console.log("Example app using DevAuthKit running on http://localhost:3000");
});