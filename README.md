<p align="center">
  <img src="logo.png" alt="DevAuthKit Security Logo" width="320" />
</p>

# DevAuthKit 🔐

<a href="https://www.producthunt.com/products/devauthkit?embed=true&amp;utm_source=badge-featured&amp;utm_medium=badge&amp;utm_campaign=badge-devauthkit" target="_blank" rel="noopener noreferrer"><img alt="devauthkit - Plug-and-play passwordless auth &amp; JWT for Express.js | Product Hunt" width="250" height="54" src="https://api.producthunt.com/widgets/embed-image/v1/featured.svg?post_id=1286171&amp;theme=light&amp;t=1792469701608"></a>

[![npm version](https://img.shields.io/npm/v/devauthkit.svg)](https://www.npmjs.com/package/devauthkit)
[![Documentation](https://img.shields.io/badge/Documentation-Live%20Docs-0ea5e9.svg)](https://gautamsharma-coder.github.io/devauthkit/docs.html)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![CI](https://github.com/GautamSharma-coder/devauthkit/actions/workflows/ci.yml/badge.svg)](https://github.com/GautamSharma-coder/devauthkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**DevAuthKit** is a lightweight, zero-config self-hosted authentication toolkit for Node.js & Express with a universal companion Client SDK. Built for developers who want plug-and-play passwordless email OTP authentication, JWT Bearer tokens, and secure `httpOnly` sessions without paying exorbitant SaaS pricing (Clerk/Auth0) or wrestling with complex configuration (NextAuth/Passport).

📚 **[Read the Full Documentation & API Reference →](https://gautamsharma-coder.github.io/devauthkit/docs.html)**  
🌐 **[Live Demo & Interactive Sandbox →](https://gautamsharma-coder.github.io/devauthkit/)**

---

### ⚡ Why DevAuthKit? (Comparison)

| Feature | **DevAuthKit** | Clerk / Auth0 | NextAuth / Auth.js | Passport.js |
| :--- | :---: | :---: | :---: | :---: |
| **Pricing** | **100% Free / Self-Hosted** | $$$ / MAU Tier Limits | Free | Free |
| **Setup Time** | **< 3 minutes** | 5 minutes | 30+ minutes | 2+ hours |
| **TypeScript Support** | ✅ **Native (`.d.ts`)** | ✅ | Complex Typings | ⚠️ `@types/passport` |
| **Passwordless Email OTP** | ✅ **Built-in** | ✅ | Manual Config | ❌ Manual |
| **1-Click Magic Links** | ✅ **Built-in** | ✅ | Manual Config | ❌ Manual |
| **Social Login (OAuth 2.0)** | ✅ **Google + GitHub (PKCE)** | Vendor Cloud | Plugins required | Manual strategies |
| **Zero-Setup Dev Mode** | ✅ **Console OTPs** | ❌ Requires Cloud Account | ❌ | ❌ |
| **Email Providers** | **Resend + SMTP + Custom** | Vendor Cloud | Nodemailer / Custom | Manual |
| **Dual/Triple Strategy** | **Bearer + httpOnly Cookie + Session** | Proprietary SDK | Session / JWT | Strategy plugins |
| **Token Theft Defense (DPoP)** | 🛡️ **RFC 9449 Key Binding** | ❌ Bearer only | ❌ Bearer only | ❌ Bearer only |
| **Database Adapters** | **Prisma + Drizzle + Mongoose** | Vendor Cloud | Adapters required | Manual DB glue |
| **Frontend Integration** | ✅ **Client SDK + React Hooks** | Proprietary Components | Next.js / React only | ❌ None |

---

## ✨ Features

- 🛡️ **DPoP Token Theft Defense (RFC 9449)**: Cryptographically binds access tokens to client ECDSA P-256 public keys via `cnf.jkt` thumbprints, instantly neutralizing malware/XSS token theft, replay attacks, and session hijacking.
- 🔑 **Passwordless Email OTP**: Secure 6-digit codes generated with Node's native `crypto.randomInt`.
- 🔗 **1-Click Magic Links**: Secure email verification links alongside 6-digit OTPs with single-use token invalidation.
- 📘 **100% TypeScript Native**: Full type definitions included (`index.d.ts`, `client/index.d.ts`, and adapter `.d.ts` files).
- 🛡️ **Triple-Strategy Auth**: Supports **JWT Bearer Tokens**, secure **`httpOnly` Cookies**, and **Session Cookies** in a single `requireAuth` middleware.
- 🛡️ **Role-Based Access Control (RBAC)**: Built-in `requireRole(["admin"])` middleware for granular route authorization.
- ⚡ **Zero-Setup Dev Mode**: Test locally with zero configuration. If email credentials are not configured, OTPs and magic links are cleanly printed to your terminal.
- 📬 **Modern Email Support**: First-class support for **[Resend](https://resend.com)** (`RESEND_API_KEY`) and standard SMTP (Nodemailer, Gmail, SendGrid).
- 📦 **Built-in Client SDK & React Hooks**: Import `DevAuthClient` from `devauthkit/client` or `useAuth()` / `<AuthProvider>` from `devauthkit/react`.
- 🚫 **Brute-Force & Replay Shield**: Automatic lockout after 5 failed attempts, OTP invalidation on verification, and cooldown throttling.
- 🚦 **Configurable Rate Limits**: Per-IP and per-email protection for auth endpoints, with a shared Redis counter adapter for multi-instance deployments.
- 🕒 **In-Memory TTL Store**: Auto-pruning memory store to prevent leaks without requiring a database for rapid prototypes.
- 🗄️ **Multi-Database Support**: First-class user adapters for **Prisma**, **Drizzle ORM**, and **Mongoose (MongoDB)**.
- 🌐 **Social OAuth 2.0**: Built-in **Google** and **GitHub** login with PKCE (`S256`), CSRF protection, verified email enforcement, and seamless user adapter mapping.
- 🔄 **Rotating Refresh Tokens**: Optional short-lived access tokens (15m), rotating httpOnly refresh cookies (30d), reuse detection, and session revocation.
- 🚪 **Complete Auth Lifecycle**: Built-in `/auth/me` profile inspection and `/auth/logout` session destruction.
- 🔄 **Reactive State Management**: `auth.onAuthStateChanged()` listener for instant frontend UI re-renders on login/logout.

---

## 📦 Installation

```bash
npm install devauthkit
```

---

## 🚀 Quick Start (Backend)

```javascript
const express = require("express");
const devAuthKit = require("devauthkit");

const app = express();

// Initialize DevAuthKit with options
devAuthKit(app, {
  corsOrigin: ["http://localhost:3000", "http://localhost:3001"],
  jwtSecret: process.env.JWT_SECRET,
  sessionSecret: process.env.SESSION_SECRET,
  devMode: process.env.NODE_ENV !== "production", // prints OTP to console if true
  debug: true
});

// Protect custom routes using requireAuth middleware
const { requireAuth } = devAuthKit;

app.get("/api/dashboard", requireAuth, (req, res) => {
  res.json({
    message: "Access granted to protected dashboard!",
    user: req.user // Decoded from JWT or session
  });
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
```

### Diagnose configuration issues

Run the configuration doctor before starting the server. It reports setup errors and production-readiness warnings with suggested fixes, without changing the active configuration or exposing secret values:

```javascript
const report = devAuthKit.checkConfig({
  jwtSecret: process.env.JWT_SECRET,
  sessionSecret: process.env.SESSION_SECRET,
  dpop: true,
  dpopReplayStore
});

for (const issue of report.issues) {
  console.log(`[${issue.severity}] ${issue.code}: ${issue.message}\n  Fix: ${issue.fix}`);
}
if (!report.valid) process.exitCode = 1;
```

Call `checkConfig()` without options to inspect the currently configured options. A valid report can still contain warnings; address them before deploying if they apply to your setup.

### TOTP MFA and step-up protection

Configure an MFA store and use the authenticated enrollment endpoints. The development memory store is not durable; production adapters must encrypt TOTP secrets at rest and atomically consume TOTP counters and recovery-code hashes:

```javascript
const devAuthKit = require("devauthkit");

devAuthKit(app, {
  jwtSecret: process.env.JWT_SECRET,
  sessionSecret: process.env.SESSION_SECRET,
  mfaIssuer: "Example App",
  mfaStore: new devAuthKit.MemoryMfaStore() // Development only
});

app.post("/api/billing/change", devAuthKit.requireMfa, changeBillingDetails);
```

After authenticating, call `POST /auth/mfa/enroll` to receive an `otpauth://` URL and secret, add it to an authenticator app, then call `POST /auth/mfa/enable` with `{ "code": "123456" }`. Save the returned recovery codes securely; they are shown only once. To step up for a protected action, call `POST /auth/mfa/verify` with an authenticator or recovery code, then send the returned `mfaToken` in the `X-MFA-Token` header to routes using `requireMfa`. Step-up tokens expire after five minutes by default. Disable MFA with `POST /auth/mfa/disable` while sending that header.

MFA is opt-in and applies to routes where you add `requireMfa`; it does not change the passwordless login flow. `GET /auth/mfa` reports enrollment status. Enrollment and disable requests require a configured same-origin `Origin` when using cookie authentication.

### Persistent users with Prisma

Provide a `userAdapter` to resolve a stable user record when an OTP is verified. The included Prisma adapter uses Prisma's `upsert`, so the email field must be unique in your model. Prisma remains an optional dependency owned by your application.

```bash
npm install @prisma/client
```

```javascript
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const devAuthKit = require("devauthkit");
const prismaAdapter = require("devauthkit/adapters/prisma");

const prisma = new PrismaClient();
const app = express();

devAuthKit(app, {
  userAdapter: prismaAdapter(prisma),
  mapUserPayload: (user) => ({ role: user.role, plan: user.plan }),
  jwtSecret: process.env.JWT_SECRET,
  sessionSecret: process.env.SESSION_SECRET
});

app.get("/api/dashboard", devAuthKit.requireAuth, (req, res) => {
  res.json({ userId: req.user.id, role: req.user.role });
});
```

By default, the adapter uses `prisma.user` and the `id`, `email`, and optional `role` fields. Customize the model delegate or field names when needed:

```javascript
const prismaAdapter = require("devauthkit/adapters/prisma");
const userAdapter = prismaAdapter(prisma, {
  model: "account",
  fields: { id: "userId", email: "emailAddress", role: "accessLevel" }
});
```

The verified user ID, email, optional role, and values returned by `mapUserPayload` are placed in the JWT and `req.user`; protected requests do not query Prisma. Only add safe claims to tokens. Without `userAdapter`, the existing email-only user behavior is unchanged. Custom adapters implement `findOrCreateUser({ email })` and return a user object containing `id` and `email`.

### Google sign-in

Create an OAuth 2.0 Web application credential in Google Cloud, add the exact callback URL to its authorized redirect URIs, and configure the optional `google` object:

```javascript
devAuthKit(app, {
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback",
    successRedirectURL: "http://localhost:3001/"
  },
  userAdapter: prismaAdapter(prisma),
  jwtSecret: process.env.JWT_SECRET,
  sessionSecret: process.env.SESSION_SECRET
});
```

Start the sign-in by navigating the browser to `GET /auth/google`. Google returns to `GET /auth/google/callback`. The flow validates a one-time session-bound `state`, uses PKCE, retrieves the profile from Google's userinfo endpoint, and requires a verified email. It resolves that email through `userAdapter` when configured. The callback sets the normal httpOnly auth cookie and redirects to `successRedirectURL` when provided and cookies are enabled; otherwise it responds with the same token/user JSON shape as OTP verification. Use HTTPS callback and success URLs outside localhost, and keep the Google client secret on the server. Google routes return 404 when Google OAuth is not configured.

### GitHub OAuth 2.0

Enable 1-click developer sign-in with native PKCE (`S256`) and GitHub verified email mapping:

```javascript
devAuthKit(app, {
  github: {
    clientId: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/github/callback",
    successRedirectURL: "http://localhost:3001/"
  },
  jwtSecret: process.env.JWT_SECRET,
  sessionSecret: process.env.SESSION_SECRET
});
```

Start the sign-in by navigating the browser to `GET /auth/github`. The flow validates timing-safe CSRF state, exchanges the authorization code using PKCE, retrieves the primary verified email from GitHub, resolves persistent user identity via `userAdapter`, and issues JWT/session credentials.

### Custom OAuth providers and account linking

Google and GitHub share the same PKCE-based OAuth flow. Add another OAuth 2.0 provider by supplying its endpoints and a mapper that only marks an email verified when the provider explicitly confirms it:

```javascript
devAuthKit(app, {
  oauthProviders: {
    acme: {
      clientId: process.env.ACME_CLIENT_ID,
      clientSecret: process.env.ACME_CLIENT_SECRET,
      callbackURL: "https://api.example.com/auth/oauth/acme/callback",
      authorizationURL: "https://identity.example.com/authorize",
      tokenURL: "https://identity.example.com/token",
      userInfoURL: "https://identity.example.com/userinfo",
      scope: "openid email profile",
      mapProfile: (profile) => ({
        id: profile.sub,
        email: profile.email,
        emailVerified: profile.email_verified === true,
        name: profile.name
      })
    }
  }
});
```

Navigate to `GET /auth/oauth/acme` to sign in. OAuth provider names may contain letters, digits, `_`, and `-`; `google` and `github` are reserved for the built-in providers. The provider endpoints must use HTTPS, and the callback must use HTTPS outside localhost.

To link a provider to an already-authenticated account, send a same-origin `POST` to `/auth/oauth/acme/link` with the user's existing authenticated cookie or bearer token. The request's `Origin` must match a configured `corsOrigin`; use a top-level form POST for cookie-based browser login, or a JSON fetch with a bearer token and navigate to the returned `authorizationURL`. Link callbacks use the same configured callback URL. Account linking is enabled only when the configured `userAdapter` implements both optional identity methods:

- `findUserByOAuthIdentity({ provider, providerId })` looks up logins by stable provider identity before falling back to verified email.
- `linkOAuthIdentity({ userId, provider, providerId, email, ...profile })` must atomically enforce uniqueness on `(provider, providerId)` and reject identities already owned by another user.

The built-in Prisma, Drizzle, and Mongoose adapters do not assume an identity-table schema; add these methods with your application's own schema before enabling linking. Never link accounts based only on a client-supplied email.

### Magic Link Authentication

Enable 1-click login links sent alongside 6-digit OTPs:

```javascript
devAuthKit(app, {
  magicLink: true, // or request with { email, magicLink: true }
  magicLinkExpiryMinutes: 15,
  magicLinkSuccessURL: "http://localhost:3001/dashboard"
});
```

When users request a login code, their email includes both the 6-digit OTP and a direct click-to-sign-in Magic Link. Verification is handled at `GET /auth/verify-magic?token=...&email=...` (for browser navigation) and `POST /auth/verify-magic` (for API clients).

### Role-Based Access Control (RBAC)

Protect sensitive routes using the built-in `requireRole` middleware. It automatically enforces authentication if `req.user` is not yet attached:

```javascript
const { requireRole, requireAuth } = devAuthKit;

// Single role restriction
app.get("/api/admin", requireRole("admin"), (req, res) => {
  res.json({ message: "Admin console", user: req.user });
});

// Multi-role permissions
app.delete("/api/posts/:id", requireRole(["admin", "moderator"]), (req, res) => {
  res.json({ message: "Post deleted" });
});
```

### Database Adapters: Drizzle ORM & Mongoose

In addition to Prisma, DevAuthKit provides first-class adapters for **Drizzle ORM** and **Mongoose (MongoDB)**:

```javascript
// Drizzle ORM
const drizzleAdapter = require("devauthkit/adapters/drizzle");
devAuthKit(app, {
  userAdapter: drizzleAdapter(db, { table: usersTable })
});

// Mongoose (MongoDB)
const mongooseAdapter = require("devauthkit/adapters/mongoose");
devAuthKit(app, {
  userAdapter: mongooseAdapter(UserModel)
});
```

### React & Next.js Hooks (`devauthkit/react`)

Use the official `AuthProvider` and `useAuth()` hook for instant state management in React, Next.js (App & Pages router), and Vite:

```jsx
import { AuthProvider, useAuth } from "devauthkit/react";

function App() {
  return (
    <AuthProvider>
      <UserProfile />
    </AuthProvider>
  );
}

function UserProfile() {
  const { user, isAuthenticated, isLoading, sendOTP, verifyOTP, logout, loginWithGitHub, loginWithGoogle } = useAuth();

  if (isLoading) return <div>Loading auth...</div>;
  if (!isAuthenticated) return <button onClick={() => loginWithGitHub()}>Login with GitHub</button>;

  return (
    <div>
      <h2>Welcome, {user.email}</h2>
      <button onClick={logout}>Sign Out</button>
    </div>
  );
}
```

### Refresh tokens and session revocation

Enable rotating refresh tokens to use 15-minute access tokens and a 30-day httpOnly refresh cookie by default:

```javascript
devAuthKit(app, {
  refreshTokens: {
    accessTokenExpiresIn: "15m",
    refreshTokenExpiresInDays: 30
  },
  jwtSecret: process.env.JWT_SECRET,
  sessionSecret: process.env.SESSION_SECRET
});
```

The browser sends the refresh cookie to `POST /auth/refresh`; the endpoint consumes it and issues a replacement. Refresh tokens are stored as SHA-256 hashes, and reuse of an already-rotated token revokes the whole token family. The access-token middleware checks session-family revocation, so revocation takes effect immediately for JWTs issued with this feature. `POST /auth/sessions/revoke` revokes the current token family, while `POST /auth/sessions/revoke-all` revokes all refresh sessions for the authenticated user. Logout also revokes the presented refresh-token family.

For convenience, the client SDK automatically calls the refresh endpoint once after an authenticated request gets a 401 (after OTP login has indicated refresh support). The refresh token itself is never returned in JSON or exposed to JavaScript. Refresh-token rotation and access-token revocation require the store's `rotate` operation to be atomic.

Refresh storage defaults to process memory for local development. This is not suitable for multiple app instances and is cleared on restart. For production, pass a persistent `refreshTokenStore` implementing `create`, atomic `rotate`, `revoke`, `revokeFamily`, `revokeAll`, and `isFamilyActive`; the last method is checked on each request using a refresh-enabled JWT. Use `RedisRefreshTokenStore` or `CloudflareD1RefreshTokenStore` to share refresh state across application instances.

### Authentication rate limits

Auth endpoints use fixed-window limits by default. OTP requests are limited to 20 per IP and 3 per email per minute; OTP verification is limited to 30 per IP and 10 per email per 15 minutes. Magic-link verification, OAuth, refresh, logout, and session-revocation endpoints also receive per-IP limits. Responses include `RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset`; blocked requests return `429` with `Retry-After`. The existing OTP cooldown remains in place as an additional per-email safeguard.

Customize or disable individual route rules. Unspecified route rules retain their defaults:

```javascript
devAuthKit(app, {
  rateLimit: {
    requestOtp: {
      perEmailMax: 5,
      perIpMax: 40
    },
    googleStart: false
  }
});
```

Set `rateLimit: false` to disable all built-in auth limits. Limits are process-local by default and therefore are not shared between server instances. For a shared Redis store, pass a connected Redis client:

```javascript
devAuthKit(app, {
  rateLimitStore: new devAuthKit.RedisRateLimitStore(redis, {
    keyPrefix: "myapp:auth-rate-limit:"
  })
});
```

The Redis adapter uses atomic `INCR` and expiring keys. Configure Express `trust proxy` correctly before mounting DevAuthKit when deployed behind a reverse proxy; the package uses Express's `req.ip` and does not trust forwarded headers on its own.

### Cloudflare Workers with Hono, D1, and KV

The `devauthkit/hono` entry point uses Web Crypto and Hono's Web Request/Response APIs; it does not load Express, `jsonwebtoken`, or Nodemailer. Install Hono and Drizzle in your Worker project:

```bash
npm install hono drizzle-orm
```

Create a SQLite-compatible Drizzle users table (for example, in `src/schema.ts`):

```typescript
import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const users = sqliteTable("users", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  email: text("email").notNull().unique(),
  role: text("role")
});
```

Bind a D1 database and KV namespace in your Wrangler configuration. Run your user-table migration and create the refresh-token, OAuth-state, atomic-counter, and (if enabled) passkey tables once as part of deployment, not from a request handler:

```typescript
import { CloudflareD1RefreshTokenStore } from "devauthkit/stores/cloudflare-d1";
import { CloudflareD1OAuthStateStore } from "devauthkit/stores/cloudflare-d1-oauth-state";
import { CloudflareD1CounterStore } from "devauthkit/stores/cloudflare-d1-counter";
import { CloudflareD1PasskeyStore } from "devauthkit/stores/cloudflare-d1-passkeys";

await new CloudflareD1RefreshTokenStore(env.DB).createTables();
await new CloudflareD1OAuthStateStore(env.DB).createTables();
await new CloudflareD1CounterStore(env.DB).createTables();
await new CloudflareD1PasskeyStore(env.DB).createTables();
```

Mount the Hono router and construct its stores from Worker bindings:

```typescript
import { Hono } from "hono";
import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/d1";
import { createAuthRouter } from "devauthkit/hono";
import { drizzleAdapter } from "devauthkit/adapters/drizzle";
import {
  CloudflareKvMagicLinkStore,
  CloudflareKvOtpStore,
  CloudflareKvRateLimitStore
} from "devauthkit/stores/cloudflare-kv";
import { CloudflareD1RefreshTokenStore } from "devauthkit/stores/cloudflare-d1";
import { CloudflareD1CounterStore } from "devauthkit/stores/cloudflare-d1-counter";
import { CloudflareD1OAuthStateStore } from "devauthkit/stores/cloudflare-d1-oauth-state";
import { CloudflareD1PasskeyStore } from "devauthkit/stores/cloudflare-d1-passkeys";
import { users } from "./schema";

let workerApp;

export default {
  fetch(request, env, executionCtx) {
    if (!workerApp) {
      const app = new Hono();
      const counterStore = new CloudflareD1CounterStore(env.DB);
      const passkeyStore = new CloudflareD1PasskeyStore(env.DB);
      app.route("/", createAuthRouter({
        jwtSecret: env.JWT_SECRET,
        sessionSecret: env.JWT_SECRET,
        apiPrefix: "/auth",
        devMode: false,
        emailProvider: "resend",
        resendApiKey: env.RESEND_API_KEY,
        fromEmail: "login@example.com",
        otpStore: new CloudflareKvOtpStore(env.AUTH_KV, { counterStore }),
        magicLinkStore: new CloudflareKvMagicLinkStore(env.AUTH_KV),
        rateLimitStore: new CloudflareKvRateLimitStore(env.AUTH_KV, { counterStore }),
        userAdapter: drizzleAdapter(drizzle(env.DB), { table: users, eq }),
        refreshTokens: true,
        refreshTokenStore: new CloudflareD1RefreshTokenStore(env.DB),
        oauthStateStore: new CloudflareD1OAuthStateStore(env.DB),
        passkeys: {
          rpName: "Example App",
          rpID: env.WEBAUTHN_RP_ID,
          origins: [env.WEBAUTHN_ORIGIN]
        },
        passkeyStore,
        passkeyChallengeStore: passkeyStore
      }));
      workerApp = app;
    }
    return workerApp.fetch(request, env, executionCtx);
  }
};
```

This mounts OTP, magic-link, OAuth, refresh, profile, and passkey endpoints under `/auth`. Passkeys are enabled only when `passkeys`, `passkeyStore`, and `passkeyChallengeStore` are explicitly configured. Set `WEBAUTHN_RP_ID` to the relying-party domain (for example, `example.com`) and `WEBAUTHN_ORIGIN` to an exact allowed origin (for example, `https://example.com`). The D1 passkey store may implement both store interfaces; its tables must be created as part of deployment, not from a request handler. Passkey challenges are hashed and consumed atomically, credentials are scoped to a stable user handle, and signature counters use conditional D1 updates. Do not use process-memory stores for production passkey state.

Passkey enrollment requires an authenticated user. The client posts the returned options to `navigator.credentials.create()` (after decoding WebAuthn base64url fields into buffers), then posts the serialized credential to the verification endpoint. Login uses the public authentication-options and verification endpoints with `navigator.credentials.get()`. Verification requires user verification and checks the configured origins and RP ID using `@simplewebauthn/server`.

**Storage consistency matters:** Cloudflare KV is eventually consistent and does not provide atomic counters. `CloudflareKvOtpStore` and `CloudflareKvRateLimitStore` therefore require a strongly consistent `counterStore` such as `CloudflareD1CounterStore`; counter-store failures return an error instead of allowing authentication attempts or rate-limited requests. Refresh-token rotation uses D1 `batch()` transactions and conditional updates, rather than KV, to preserve the package's atomic rotation and replay-detection contract. Do not use the in-memory stores in a production Worker.

---

## 🛡️ DPoP: Proof-of-Possession Token Binding (RFC 9449)

In standard OAuth 2.0 / JWT architectures, access tokens are **Bearer tokens**: anyone who intercepts or extracts the token (via infostealer malware, malicious browser extensions, XSS, man-in-the-middle, or server access logs) can impersonate the user until expiry.

**DPoP (Demonstrating Proof-of-Possession at the Application Layer — [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449))** eliminates token theft. 

### How it works:
1. **Client Key Generation**: The client SDK generates a private ECDSA P-256 (`ES256`) keypair stored in client memory. The private key never leaves the client device.
2. **Cryptographic Binding**: During login (`verifyOTP`, `verifyMagicLink`, or `refresh`), the client creates a signed DPoP proof containing its public JWK. The server embeds the RFC 7638 SHA-256 thumbprint of that key into the JWT (`cnf.jkt`).
3. **Proof Verification**: On every API request, the client computes an ephemeral single-use signature containing the HTTP method (`htm`), target URI (`htu`), timestamp (`iat`), and the SHA-256 hash of the access token (`ath`).
4. **Zero-Trust Enforcement**: The server's `requireAuth` or `requireDPoP` middleware rejects any request where:
   - The token is presented without a matching DPoP signature.
   - An attacker attempts to sign with their own keypair (key binding mismatch).
   - A previous proof is replayed (single-use `jti` replay store).
   - The proof has expired or target URI/method mismatches.

### 1. Backend Setup (Express.js)

```javascript
const express = require("express");
const devAuthKit = require("devauthkit");

const app = express();
const dpopReplayStore = new devAuthKit.MemoryDpopReplayStore(); // Single-process development only

// In production, configure an atomic shared replay store accessible to every instance.
devAuthKit(app, {
  jwtSecret: process.env.JWT_SECRET,
  sessionSecret: process.env.SESSION_SECRET,
  dpop: true, // Enables RFC 9449 DPoP verification and token binding
  dpopReplayStore
});

const { requireAuth, requireDPoP } = devAuthKit;

// requireAuth supports both standard tokens and cryptographically enforces DPoP when bound:
app.get("/api/dashboard", requireAuth, (req, res) => {
  res.json({
    user: req.user,
    dpopBound: Boolean(req.dpop) // { jkt: "..." }
  });
});

// requireDPoP strictly mandates a valid DPoP proof (ideal for financial transfers or settings changes):
app.post("/api/sensitive-transfer", requireDPoP, (req, res) => {
  res.json({ success: true });
});
```

### 2. Backend Setup (Cloudflare Workers & Hono)

```javascript
import { Hono } from "hono";
import { createAuthRouter, requireAuth, requireDPoP } from "devauthkit/hono";
import { CloudflareD1DpopReplayStore } from "devauthkit/stores/cloudflare-d1-dpop-replay";

export default {
  async fetch(request, env) {
    const app = new Hono();
    const dpopReplayStore = new CloudflareD1DpopReplayStore(env.DB);

    app.route("/", createAuthRouter({
      jwtSecret: env.JWT_SECRET,
      dpop: true,
      dpopReplayStore
    }));

    app.get("/api/edge-data", requireAuth({ dpopReplayStore }), (c) => {
      return c.json({ user: c.get("user"), dpop: c.get("dpop") });
    });

    return app.fetch(request, env);
  }
};
```

### 3. Frontend Client SDK (`DevAuthClient`)

Enable DPoP with a single flag (`dpop: true`). The SDK transparently manages ECDSA P-256 keys, computes DPoP proofs, attaches `Authorization: DPoP <token>` and `DPoP: <proof>` headers, and handles server nonce challenges:

```javascript
import { DevAuthClient } from "devauthkit/client";

const auth = new DevAuthClient({
  apiUrl: "http://localhost:3000",
  dpop: true // ✨ Activates RFC 9449 hardware-bound token protection
});

// 1. Send OTP
await auth.sendOTP("user@example.com");

// 2. Verify OTP - automatically signs DPoP proof and receives a cnf.jkt-bound token!
await auth.verifyOTP("user@example.com", "123456");

// 3. Authenticated calls automatically compute ath hash and single-use signature!
const res = await auth.fetch("/api/dashboard");
const data = await res.json();

console.log("Is DPoP Bound?", auth.isDPoPBound()); // true
```

### 4. React & Next.js Hooks

```jsx
import { AuthProvider, useAuth } from "devauthkit/react";
import { DevAuthClient } from "devauthkit/client";

const client = new DevAuthClient({ dpop: true });

function App() {
  return (
    <AuthProvider client={client}>
      <Dashboard />
    </AuthProvider>
  );
}

function Dashboard() {
  const { user, isDPoPBound } = useAuth();
  return (
    <div>
      <h1>Welcome, {user?.email}</h1>
      {isDPoPBound && <span className="badge">🛡️ Protected by DPoP Token Binding</span>}
    </div>
  );
}
```

---

## 💻 Client SDK (`devauthkit/client`)

DevAuthKit includes a universal frontend client SDK that handles token storage, authentication state, and automatically injects Bearer tokens into your API requests.

### Usage in React, Vue, Next.js, or Vite

```javascript
import { DevAuthClient } from "devauthkit/client";

// Initialize client
const auth = new DevAuthClient({
  apiUrl: "http://localhost:3000" // or omit if running on the same domain
});

// 1. Request OTP Code
await auth.sendOTP("user@example.com");

// 2. Verify OTP & Automatically Store JWT Token
await auth.verifyOTP("user@example.com", "123456");

// 3. Make Authenticated API Calls (Bearer Token is attached automatically!)
const res = await auth.fetch("/api/dashboard");
const data = await res.json();

// 4. Check Authentication State
if (auth.isAuthenticated()) {
  console.log("Current user:", auth.getUser());
}

// 5. Reactive State Listener (Great for React useEffect or Vue watchers)
const unsubscribe = auth.onAuthStateChanged((user) => {
  if (user) {
    console.log("User logged in:", user.email);
  } else {
    console.log("User logged out");
  }
});

// 6. Log Out
await auth.logout();
```

### Usage in Plain HTML (Browser Script Tag)

```html
<script src="node_modules/devauthkit/client/index.js"></script>
<!-- Or via CDN: https://unpkg.com/devauthkit/client/index.js -->

<script>
  const auth = new DevAuthClient({ apiUrl: "http://localhost:3000" });
  
  // Use auth.sendOTP(), auth.verifyOTP(), auth.fetch(), etc.
</script>
```

---

## 🧪 Available Endpoints

> 📖 **Complete API Reference & Guides:** Detailed request/response payloads, code snippets, and error tables are documented at **[https://gautamsharma-coder.github.io/devauthkit/docs.html](https://gautamsharma-coder.github.io/devauthkit/docs.html)**.

By default, routes are mounted under `/auth`:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/auth/login` *(or `/auth/request-otp`)* | Request an OTP (and optional Magic Link) sent to email. |
| `POST` | `/auth/verify` *(or `/auth/verify-otp`)* | Verify the OTP; returns JWT token & starts session. |
| `GET` / `POST` | `/auth/verify-magic` | Verify 1-click Magic Link token. |
| `POST` | `/auth/refresh` | Rotate the httpOnly refresh cookie and issue a new access token (when enabled). |
| `POST` | `/auth/sessions/revoke` | Revoke the authenticated token family immediately. |
| `POST` | `/auth/sessions/revoke-all` | Revoke all refresh sessions for the authenticated user. |
| `POST` | `/auth/passkeys/register/options` | Generate passkey enrollment options (requires authentication; passkeys enabled). |
| `POST` | `/auth/passkeys/register/verify` | Verify and save an enrollment credential (requires authentication; body: `{ "credential": ... }`). |
| `POST` | `/auth/passkeys/authenticate/options` | Generate login options; optional body: `{ "email": "..." }`. |
| `POST` | `/auth/passkeys/authenticate/verify` | Verify a passkey assertion and issue a login token (body: `{ "credential": ... }`). |
| `GET` | `/auth/passkeys` | List passkeys for the authenticated user. |
| `DELETE` | `/auth/passkeys/:credentialId` | Delete an owned passkey (requires authentication). |
| `GET` | `/auth/google` | Start Google OAuth sign-in (when configured). |
| `GET` | `/auth/google/callback` | Complete Google OAuth sign-in (when configured). |
| `GET` | `/auth/github` | Start GitHub OAuth sign-in (when configured). |
| `GET` | `/auth/github/callback` | Complete GitHub OAuth sign-in (when configured). |
| `GET` | `/auth/me` | Return authenticated user's info (requires Bearer token or session). |
| `POST` | `/auth/logout` | Destroy session and clear session cookies. |
| `GET` | `/profile` | Built-in test route verifying authentication status. |

---

## ⚙️ Configuration Options

Pass configuration options to `devAuthKit(app, options)`:

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `corsOrigin` | `string \| string[]` | `"http://localhost:3001"` | Allowed CORS origin(s). |
| `sessionSecret` | `string` | Random per-process development secret | Secret key for `express-session`; production requires an explicit secret of at least 32 bytes. |
| `jwtSecret` | `string` | Random per-process development secret | Secret key for signing JWT tokens; production requires an explicit secret of at least 32 bytes. |
| `jwtExpiresIn` | `string` | `"7d"` | JWT expiration timeframe (e.g. `"1h"`, `"7d"`). |
| `otpExpiryMinutes`| `number` | `5` | Validity window of OTP codes in minutes. |
| `maxAttempts` | `number` | `5` | Maximum failed verification attempts before invalidating OTP. |
| `devMode` | `boolean` | `true` in non-prod | When enabled, logs OTPs to terminal console for zero-config testing. |
| `apiPrefix` | `string` | `"/auth"` | Route mount prefix. |
| `setHttpOnlyCookie` | `boolean` | `true` | Automatically set secure `httpOnly` cookie with JWT on verification. |
| `cookieName` | `string` | `"devauth_token"` | Name of the authentication cookie. |
| `emailProvider` | `string` | `"smtp"` or `"resend"` | Email delivery service. Defaults to `"resend"` if `RESEND_API_KEY` is present. |
| `resendApiKey` | `string` | `process.env.RESEND_API_KEY` | API Key for transactional delivery via Resend. |
| `fromEmail` | `string` | `process.env.FROM_EMAIL` | Sender address (e.g. `"auth@myapp.com"`). |
| `mailer` | `function` | `undefined` | Custom async mailer function `async ({ email, otp }) => {}`. |
| `otpStore` | `OtpStore` | In-memory store | Storage adapter for OTP records; must implement `get`, `set`, `delete`, and atomic `recordAttempt`. |
| `sessionStore` | `express-session` store | In-memory store | Optional persistent session store, such as `connect-redis`. |
| `userAdapter` | `UserAdapter` | Email-only user | Optional adapter that finds or creates a persistent user after OTP verification. |
| `mapUserPayload` | `function` | Core user claims | Maps an adapter user to additional safe claims included in the JWT and `req.user`. |
| `google` | `GoogleOAuthOptions` | Disabled | Optional Google OAuth credentials, callback URL, and post-login redirect. |
| `github` | `GitHubOAuthOptions` | Disabled | Optional GitHub OAuth credentials, callback URL, and post-login redirect. |
| `magicLink` | `boolean` | `false` | Enable 1-click Magic Link email verification links alongside OTP. |
| `magicLinkExpiryMinutes` | `number` | `15` | Magic link token validity in minutes. |
| `magicLinkSuccessURL` | `string` | `undefined` | Optional browser redirect URL on successful magic link verification. |
| `passkeys` | `PasskeyOptions` | Disabled | Enable WebAuthn with `rpName`, lowercase `rpID`, and exact allowed `origins`; challenge TTL defaults to 300 seconds. |
| `passkeyStore` | `PasskeyStore` | None | Required durable credential and user-handle storage when passkeys are enabled. |
| `passkeyChallengeStore` | `PasskeyChallengeStore` | None | Required durable store with atomic single-use challenge consumption. |
| `refreshTokens` | `boolean \| RefreshTokenOptions` | `false` | Enable rotating httpOnly refresh cookies; access tokens default to 15 minutes and refresh tokens to 30 days. |
| `refreshTokenStore` | `RefreshTokenStore` | In-memory store | Persistent token-family store. Its rotation must be atomic; use `RedisRefreshTokenStore` or `CloudflareD1RefreshTokenStore` for shared production storage. |
| `rateLimit` | `RateLimitConfig` | Built-in route limits | Customize individual route windows/identity limits, disable one route with `false`, or disable all limits with `false`. |
| `rateLimitStore` | `RateLimitStore` | In-memory store | Optional shared counter store; use `new devAuthKit.RedisRateLimitStore(redis)` for multiple instances. |
| `dpop` | `boolean` | `false` | Enable RFC 9449 Demonstrating Proof-of-Possession (DPoP) key-binding and verification. |
| `dpopReplayStore` | `DpopReplayStore` | None | Required when DPoP is enabled; `record` must atomically claim a single-use `jti`. Use `RedisDpopReplayStore` or another shared store across production instances; `MemoryDpopReplayStore` is single-process only. |
| `dpopMaxSkewSeconds` | `number` | `60` | Maximum allowable clock skew (in seconds) for DPoP proof timestamps (`iat`). |
| `debug` | `boolean` | `false` | Enable verbose internal logging. |

### Persistent storage with Redis

Install the Redis client and the Express session adapter:

```bash
npm install redis connect-redis
```

Pass the same connected Redis client to DevAuthKit's OTP adapter and the session adapter. OTP storage and Express session storage are separate: configure both to persist both kinds of state across restarts and application instances.

```javascript
const express = require("express");
const { createClient } = require("redis");
const { RedisStore: ExpressRedisStore } = require("connect-redis");
const devAuthKit = require("devauthkit");

async function start() {
  const app = express();
  const redis = createClient({ url: process.env.REDIS_URL });

  redis.on("error", (error) => console.error("Redis error:", error));
  await redis.connect();

  devAuthKit(app, {
    otpStore: new devAuthKit.RedisOtpStore(redis),
    refreshTokens: true,
    refreshTokenStore: new devAuthKit.RedisRefreshTokenStore(redis),
    dpop: true,
    dpopReplayStore: new devAuthKit.RedisDpopReplayStore(redis),
    sessionStore: new ExpressRedisStore({ client: redis }),
    sessionSecret: process.env.SESSION_SECRET,
    jwtSecret: process.env.JWT_SECRET
  });

  app.listen(3000);
}

start().catch((error) => {
  console.error("Failed to start DevAuthKit:", error);
  process.exitCode = 1;
});
```

`RedisOtpStore` uses Redis' `get`, `set`, `del`, and atomic `incr` commands (compatible with the `redis` Node.js client). It stores OTP records and a separate attempt counter for 15 minutes by default. Customize its namespace or TTL with `new devAuthKit.RedisOtpStore(redis, { keyPrefix: "myapp:otp:", ttlSeconds: 900 })`. Custom OTP adapters must implement all four adapter methods; `recordAttempt` must increment attempts atomically when shared across multiple application instances.

`RedisDpopReplayStore` uses Redis `SET` with `NX` and `EX` options to atomically accept each proof `jti` once until its TTL expires. It is compatible with the `redis` Node.js client and hashes JTIs before using them as Redis keys. Customize its namespace with `new devAuthKit.RedisDpopReplayStore(redis, { keyPrefix: "myapp:dpop:" })`.

`RedisRefreshTokenStore` runs refresh creation, rotation, reuse detection, and family revocation in atomic Redis Lua scripts. It requires a Redis client with `get` and `eval` methods (compatible with node-redis v4+). All keys for one adapter use a shared Redis Cluster hash slot so multi-key scripts remain atomic; this adapter is best suited to a dedicated Redis instance or deployments where the refresh-store key-slot throughput is sufficient. Customize the namespace with `new devAuthKit.RedisRefreshTokenStore(redis, { keyPrefix: "myapp:refresh:" })`.

---

## 📁 .env Configuration (Production Ready)

Create a `.env` file in your root project:

```env
SESSION_SECRET=super_secret_session_key_12345
JWT_SECRET=super_secret_jwt_key_12345

# Option A: Modern Delivery via Resend (Recommended)
RESEND_API_KEY=re_123456789
FROM_EMAIL=auth@yourdomain.com

# Option B: Standard SMTP (e.g. Gmail App Password, SendGrid, Postmark)
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-16-character-app-password

# Optional: Google OAuth (configure callback URL in Google Cloud)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Optional: GitHub OAuth (configure callback URL in GitHub Developer settings)
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

> **Note:** If both `RESEND_API_KEY` and `EMAIL_USER` are omitted, DevAuthKit automatically activates **Zero-Setup Dev Mode** and prints OTPs directly to your console!

---

## 🔖 Version Changelog

- **v1.6.0 (Latest)**:
  - **DPoP (RFC 9449) Proof-of-Possession**: Built-in zero-trust application-layer key binding preventing token theft, infostealer exploits, and replay attacks across Express and Hono.
  - Added `requireDPoP` middleware and DPoP-aware `requireAuth` (`cnf.jkt` validation).
  - Added `CloudflareD1DpopReplayStore` and `RedisDpopReplayStore` replay protection caches.
  - Added client-side ECDSA P-256 key management, automatic DPoP proof generation, and nonce challenge retry to `DevAuthClient({ dpop: true })`.
  - Added `isDPoPBound` reactive session indicator in `devauthkit/react` `useAuth()`.
  - Added WebAuthn passkey registration, email-bound and discoverable authentication, credential management, and D1 adapter (`CloudflareD1PasskeyStore`).
  - Added Multi-Factor Authentication (MFA / TOTP) with recovery codes and step-up auth middleware (`requireMfa`).
  - Added Configuration Doctor (`devAuthKit.checkConfig()`) for pre-flight diagnosis of environment and production security issues.
- **v1.5.0**:
  - **Cloudflare Workers & Hono**: Added a Web Crypto-compatible Hono adapter and Worker-safe JWT, OTP, OAuth PKCE, and rate-limit hashing.
  - **Cloudflare KV stores**: Added OTP, magic-link, and rate-limit adapters with expiration support and documented eventual-consistency limitations.
  - **Cloudflare D1 refresh-token store**: Added atomic D1 rotation, replay detection, session revocation, and TypeScript D1 typing.
  - **Extensible OAuth 2.0**: Unified Google/GitHub PKCE flows, added configurable custom providers, and added origin-checked account linking through user-adapter identity methods.
  - Added Miniflare integration tests for KV, D1, and Hono while preserving Express authentication behavior.
- **Next (Roadmap)**:
  - 🔑 **Passkeys & WebAuthn**: Native biometric passwordless authentication (TouchID, FaceID, Windows Hello, YubiKey).
  - 🛡️ **Two-Factor Authentication (2FA / TOTP)**: Authenticator app integration (Google Authenticator, 1Password) with QR codes and backup recovery keys.
  - 📱 **SMS OTP Authentication**: Pluggable SMS OTP delivery adapters (Twilio, AWS SNS, MessageBird).
  - 🏢 **Multi-Tenancy & Organizations**: Built-in support for team accounts, organization workspaces, and member invitations.
  - 🌐 **Discord & Apple OAuth 2.0**: 1-click social sign-in with PKCE for Discord and Sign in with Apple.
  - 🪝 **Signed Webhooks**: Cryptographically signed webhook events (`user.created`, `user.login`, `session.revoked`, `security.lockout`).
  - 💚 **Vue 3 & Svelte Composables**: Official `@devauthkit/vue` and `@devauthkit/svelte` companion packages.
- **v1.4.0 (Latest)**:
  - **Rate Limiting (Advanced)**: Implemented granular per-route rate limiting (request OTP, verification, OAuth, magic links, refresh, logout, and session revocation) with Redis support for multi-instance deployments, and Express `trust proxy` awareness.
  -  **Revocable Sessions & Refresh-Token Rotation**: Implemented opt-in short-lived access tokens (15m), rotating httpOnly refresh cookies (30d), refresh-token reuse detection, and current/all-session revocation (`POST /auth/sessions/revoke`, `POST /auth/sessions/revoke-all`).
  -  **GitHub OAuth 2.0**: Native 1-click developer login with PKCE (`S256`), CSRF protection, and profile identity mapping.
  -  **Magic Link Authentication**: Click-to-login secure email verification links alongside 6-digit OTPs (`GET/POST /auth/verify-magic`).
  -  **Drizzle ORM & Mongoose Adapters**: First-class database adapters for Drizzle (`devauthkit/adapters/drizzle`) and MongoDB users (`devauthkit/adapters/mongoose`).
  -  **Role-Based Access Control (RBAC)**: Built-in `requireRole(["admin"])` middleware for granular route permissions.
  -  **React & Next.js Hooks**: Official `AuthProvider` and `useAuth()` hook (`devauthkit/react`) for effortless frontend integration.
- **v1.3.0**:
  - **Google OAuth 2.0**: Built-in social login with native PKCE (`S256`), timing-safe CSRF state validation, and automatic session regeneration.
  - **Persistent Database Identity (Prisma Adapter)**: Pluggable `userAdapter` interface with first-class Prisma adapter (`devauthkit/adapters/prisma`) and configurable JWT payload mapping.
  - **Distributed OTP Caching (Redis Store)**: High-concurrency `RedisOtpStore` with atomic attempt rate-limiting.
  - **Pluggable Session Store**: Support for persistent `express-session` stores (e.g. `connect-redis`).
  - Comprehensive automated test suite expanded to 40/40 passing tests.
- **v1.2.0**:
  - **100% Native TypeScript Support**: Added first-class `.d.ts` declaration files for both backend and client SDK.
  - **Triple-Strategy Auth**: Added secure `httpOnly` cookie issuance and verification in `requireAuth` middleware.
  - **Resend Email Integration**: Direct zero-dependency integration with Resend API via `RESEND_API_KEY`.
  - Upgraded test suite with automated cookie verification tests (19/19 passing).
- **v1.1.1**:
  - Added universal companion **Client SDK** (`devauthkit/client`).
  - Added `DevAuthClient` with `sendOTP()`, `verifyOTP()`, `fetch()`, `getProfile()`, `onAuthStateChanged()`, and `logout()`.
  - Configured package `"exports"` for clean import resolution (`import { DevAuthClient } from "devauthkit/client"`).
  - Packaged client files into npm tarball.
- **v1.1.0**:
  - Full JWT token support (sign, verify, refresh payloads).
  - Dual-strategy `requireAuth` middleware (Bearer header + session cookie).
  - Cryptographically secure `crypto.randomInt` OTP generation.
  - Zero-setup Dev Mode with stylish console OTP logging.
  - Brute-force protection (5 attempt limit) & request cooldown.
  - Added `/auth/me` and `/auth/logout` endpoints.
  - Replay protection (OTP cleared on verification).
  - Interactive browser demo with dark mode UI.
- **v1.0.2**: CORS/session configurable via options.
- **v1.0.1**: Reusable module support.
- **v1.0.0**: Initial release.

---

## 🙌 Contributing

Contributions, feature requests, and bug reports are welcome! Please check out our [Contributing Guide](CONTRIBUTING.md) to learn how to set up the project locally and submit PRs.

---

## 👨‍💻 Author

**Gautam Sharma**  
GitHub: [@GautamSharma-coder](https://github.com/GautamSharma-coder)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
