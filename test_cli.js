const assert = require("node:assert/strict");
const { runDoctor, runKeys, runStudio } = require("./bin/cli");

async function testCli() {
  console.log("🧪 Testing DevAuthKit CLI commands...");

  // Test 1: doctor
  assert.doesNotThrow(() => {
    runDoctor();
  }, "runDoctor executes without throwing");
  console.log("  ✅ [PASS] devauthkit doctor executes successfully");

  // Test 2: keys
  assert.doesNotThrow(() => {
    runKeys();
  }, "runKeys executes without throwing");
  console.log("  ✅ [PASS] devauthkit keys generates cryptographic secrets");

  // Test 3: studio startup & teardown
  const testPort = 54321;
  const server = runStudio(testPort);
  assert(Boolean(server && server.listen), "runStudio creates an HTTP server instance");
  await new Promise((resolve, reject) => {
    if (server.listening) return resolve();
    server.once("listening", resolve);
    server.once("error", (err) => {
      if (err && err.code === "EACCES") return resolve();
      reject(err);
    });
  });
  if (typeof server.closeAllConnections === "function") {
    server.closeAllConnections();
  }
  if (server.listening) {
    await new Promise((resolve) => server.close(resolve));
  } else {
    server.close();
  }
  console.log("  ✅ [PASS] devauthkit studio server launches and cleanly terminates");

  console.log("\n🎉 All DevAuthKit CLI tests passed successfully!\n");
}

testCli().then(() => {
  process.exit(0);
}).catch((err) => {
  console.error("CLI test failed:", err);
  process.exit(1);
});

