#!/usr/bin/env node

/**
 * DevAuthKit CLI — Command-line interface for DevAuthKit.
 *
 * Commands:
 *   init     - Scaffold DevAuthKit into an existing project (Next.js, Express, Hono)
 *   studio   - Start the local visual Admin Dashboard (port 4321)
 *   doctor   - Run pre-flight configuration and security diagnostics
 *   keys     - Generate cryptographically secure keys & secrets
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const readline = require("node:readline");
const { runStudio: startStudioServer } = require("./studio");

const CWD = process.cwd();

function printBanner() {
  console.log(`
\x1b[35m  ____             _         _   _     _  ___ _   
 |  _ \\  _____   _/ \\  _   _| |_| |__ | |/ (_) |_ 
 | | | |/ _ \\ \\ / / _ \\| | | | __| '_ \\| ' /| | __|
 | |_| |  __/\\ V / ___ \\ |_| | |_| | | | . \\| | |_ 
 |____/ \\___| \\_/_/   \\_\\__,_|\\__|_| |_|_|\\_\\_|\\__|\x1b[0m
 \x1b[2mThe definitive self-hosted authentication platform for modern apps.\x1b[0m
`);
}

function prompt(question, defaultValue = "") {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  return new Promise((resolve) => {
    const q = defaultValue ? `${question} \x1b[2m(${defaultValue})\x1b[0m: ` : `${question}: `;
    rl.question(q, (answer) => {
      rl.close();
      resolve(answer.trim() || defaultValue);
    });
  });
}

/**
 * COMMAND: keys
 * Generates cryptographic secrets for .env
 */
function runKeys() {
  printBanner();
  console.log("\x1b[36m🔑 Generating Cryptographically Secure Secrets...\x1b[0m\n");

  const jwtSecret = crypto.randomBytes(32).toString("hex");
  const sessionSecret = crypto.randomBytes(32).toString("hex");
  const webhookSecret = "whsec_" + crypto.randomBytes(24).toString("hex");
  const apiKey = "dak_live_" + crypto.randomBytes(20).toString("hex");

  console.log(`\x1b[32mJWT_SECRET\x1b[0m=${jwtSecret}`);
  console.log(`\x1b[32mSESSION_SECRET\x1b[0m=${sessionSecret}`);
  console.log(`\x1b[32mDEVAUTHKIT_WEBHOOK_SECRET\x1b[0m=${webhookSecret}`);
  console.log(`\x1b[32mDEVAUTHKIT_ADMIN_KEY\x1b[0m=${apiKey}\n`);
  console.log("\x1b[2mPaste these into your .env or production secret store.\x1b[0m\n");
}

function readEnvFileKeys(filePath) {
  if (!fs.existsSync(filePath)) return {};
  const out = {};
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;
    const k = trimmed.slice(0, eqIdx).trim();
    const v = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, "");
    if (k) out[k] = v;
  }
  return out;
}

/**
 * COMMAND: doctor
 * Pre-flight diagnostic check
 */
function runDoctor() {
  printBanner();
  console.log("\x1b[36m🩺 Running DevAuthKit Configuration Doctor...\x1b[0m\n");

  const issues = [];
  const warnings = [];
  const checks = [];

  // Check 1: Node.js version
  const nodeVersion = process.versions.node;
  const major = parseInt(nodeVersion.split(".")[0], 10);
  if (major >= 18) {
    checks.push({ name: "Node.js Runtime", status: "PASS", detail: `v${nodeVersion} (>= 18.0.0)` });
  } else {
    issues.push(`Node.js v${nodeVersion} is outdated. Node.js >= 18 is required for native WebCrypto.`);
  }

  // Check 2: .env exists & secrets
  const envPath = path.join(CWD, ".env");
  const envLocalPath = path.join(CWD, ".env.local");
  const hasEnv = fs.existsSync(envPath) || fs.existsSync(envLocalPath);
  const fileEnv = { ...readEnvFileKeys(envPath), ...readEnvFileKeys(envLocalPath) };
  if (hasEnv) {
    checks.push({ name: "Environment File", status: "PASS", detail: "Found .env or .env.local" });
  } else {
    issues.push("No .env or .env.local file detected. Run 'npx devauthkit init' to generate one.");
  }

  const jwtSecret = process.env.JWT_SECRET || fileEnv.JWT_SECRET;
  const sessionSecret = process.env.SESSION_SECRET || fileEnv.SESSION_SECRET;
  if (jwtSecret && Buffer.byteLength(jwtSecret, "utf8") >= 32) {
    checks.push({ name: "JWT_SECRET", status: "PASS", detail: "Configured (>= 32 bytes)" });
  } else {
    warnings.push("JWT_SECRET is missing or shorter than 32 bytes. Run 'npx devauthkit keys' to generate one.");
  }

  if (sessionSecret && Buffer.byteLength(sessionSecret, "utf8") >= 32) {
    checks.push({ name: "SESSION_SECRET", status: "PASS", detail: "Configured (>= 32 bytes)" });
  } else {
    warnings.push("SESSION_SECRET is missing or shorter than 32 bytes. Production requires an explicit session secret.");
  }

  // Check 3: WebCrypto availability
  if (typeof crypto.subtle !== "undefined") {
    checks.push({ name: "SubtleCrypto (Web Crypto API)", status: "PASS", detail: "Native hardware acceleration active" });
  } else {
    issues.push("SubtleCrypto not detected. RFC 9449 DPoP and Merkle audit chains require SubtleCrypto.");
  }

  checks.forEach((c) => {
    console.log(`  \x1b[32m✓\x1b[0m \x1b[1m${c.name}\x1b[0m: ${c.detail}`);
  });

  if (warnings.length > 0) {
    console.log(`\n\x1b[33m⚠ ${warnings.length} recommendation(s):\x1b[0m`);
    warnings.forEach((w) => console.log(`  - ${w}`));
  }

  if (issues.length === 0) {
    console.log(`\n\x1b[32m✅ All core diagnostic checks passed.\x1b[0m\n`);
  } else {
    console.log(`\n\x1b[31m⚠️ Found ${issues.length} potential issue(s):\x1b[0m`);
    issues.forEach((iss) => console.log(`  - ${iss}`));
    console.log();
  }
}

/**
 * COMMAND: init
 * Interactive Scaffolding
 */
async function runInit() {
  printBanner();
  console.log("\x1b[36m🚀 Welcome to DevAuthKit Scaffolder!\x1b[0m\n");

  const framework = await prompt("Select your backend framework [express/nextjs/hono]", "express");
  const db = await prompt("Select database adapter [prisma/drizzle/mongoose/memory]", "prisma");
  const jwtSecret = crypto.randomBytes(32).toString("hex");
  const sessionSecret = crypto.randomBytes(32).toString("hex");

  console.log(`\n\x1b[32mScaffolding DevAuthKit for ${framework.toUpperCase()} with ${db}...\x1b[0m`);

  // 1. Create or append to .env / .env.local
  const envFile = framework.toLowerCase().includes("next") ? ".env.local" : ".env";
  const targetEnv = path.join(CWD, envFile);
  const envContent = `
# DevAuthKit Configuration (Generated)
JWT_SECRET="${jwtSecret}"
SESSION_SECRET="${sessionSecret}"
`;
  if (!fs.existsSync(targetEnv)) {
    fs.writeFileSync(targetEnv, envContent.trim() + "\n", "utf8");
    console.log(`  \x1b[32m✓\x1b[0m Created ${envFile}`);
  } else {
    fs.appendFileSync(targetEnv, "\n" + envContent.trim() + "\n", "utf8");
    console.log(`  \x1b[32m✓\x1b[0m Appended secrets to ${envFile}`);
  }

  // 2. Generate accurate scaffold snippet
  if (framework.toLowerCase().includes("next")) {
    console.log("\n\x1b[33m[Next.js React UI Setup]\x1b[0m");
    console.log("Wrap your app with <AuthProvider> and drop in <SignIn />:");
    console.log(`
\x1b[2m// app/page.tsx\x1b[0m
import { AuthProvider, SignIn, UserButton } from "devauthkit/react";

export default function Home() {
  return (
    <AuthProvider>
      <header className="p-4 flex justify-between">
        <h1>My App</h1>
        <UserButton showName />
      </header>
      <main className="flex justify-center mt-12">
        <SignIn redirectUrl="/dashboard" showPasskey showSocial />
      </main>
    </AuthProvider>
  );
}
`);
  } else if (framework.toLowerCase().includes("hono")) {
    console.log("\n\x1b[33m[Cloudflare Hono Setup]\x1b[0m");
    console.log(`
import { Hono } from "hono";
import { createAuthRouter, requireAuth } from "devauthkit/hono";

const app = new Hono();
app.route("/auth", createAuthRouter({ jwtSecret: process.env.JWT_SECRET! }));
app.get("/api/me", requireAuth(), (c) => c.json({ user: c.get("user") }));
export default app;
`);
  } else {
    console.log("\n\x1b[33m[Express Setup]\x1b[0m");
    console.log(`
const express = require("express");
const devAuthKit = require("devauthkit");

const app = express();
devAuthKit(app, {
  jwtSecret: process.env.JWT_SECRET,
  sessionSecret: process.env.SESSION_SECRET
});

app.get("/api/me", devAuthKit.requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000, () => console.log("DevAuthKit running on port 3000"));
`);
  }

  console.log("\x1b[32m✨ Setup complete! Run 'npx devauthkit studio' to open the local inspector.\x1b[0m\n");
}

function parseStudioArgs(args) {
  let port = 4321;
  let apiUrl = "";
  let token = "";

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--port" || arg === "-p") {
      const val = parseInt(args[++i], 10);
      if (!Number.isNaN(val)) port = val;
    } else if (arg === "--url" || arg === "--api") {
      apiUrl = args[++i] || "";
    } else if (arg === "--token" || arg === "-t") {
      token = args[++i] || "";
    } else if (/^\d+$/.test(arg)) {
      port = parseInt(arg, 10);
    }
  }

  return { port, apiUrl, token };
}

/**
 * COMMAND: studio
 * Embedded Visual Admin Dashboard Server
 */
function runStudio(port = 4321, options = {}) {
  return startStudioServer(port, { cwd: CWD, printBanner, ...options });
}

// CLI Dispatcher
async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || "help";

  switch (command) {
    case "init":
      await runInit();
      break;
    case "doctor":
      runDoctor();
      break;
    case "keys":
      runKeys();
      break;
    case "studio": {
      const parsed = parseStudioArgs(args.slice(1));
      runStudio(parsed.port, { apiUrl: parsed.apiUrl, token: parsed.token });
      break;
    }
    case "help":
    default:
      printBanner();
      console.log(`Usage:
  npx devauthkit init     \x1b[2mScaffold auth into Express, Next.js, or Hono\x1b[0m
  npx devauthkit studio   \x1b[2mLaunch local visual Admin Dashboard (http://localhost:4321)\x1b[0m
                          \x1b[2mOptions: [port] [--url http://localhost:3000/auth] [--token <jwt>]\x1b[0m
  npx devauthkit doctor   \x1b[2mRun configuration and security diagnostics\x1b[0m
  npx devauthkit keys     \x1b[2mGenerate cryptographically secure secrets\x1b[0m
`);
      break;
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
  });
}

module.exports = {
  runDoctor,
  runKeys,
  runStudio
};

