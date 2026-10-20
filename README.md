<p align="center">
  <img src="logo.png" alt="DevAuthKit Security Logo" width="320" />
</p>

# DevAuthKit 🔐

<a href="https://www.producthunt.com/products/devauthkit?embed=true&amp;utm_source=badge-featured&amp;utm_medium=badge&amp;utm_campaign=badge-devauthkit" target="_blank" rel="noopener noreferrer"><img alt="devauthkit - Plug-and-play passwordless auth &amp; JWT for Express.js | Product Hunt" width="250" height="54" src="https://api.producthunt.com/widgets/embed-image/v1/featured.svg?post_id=1286171&amp;theme=light&amp;t=1792469701608"></a>

[![npm version](https://img.shields.io/npm/v/devauthkit.svg)](https://www.npmjs.com/package/devauthkit)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![CI](https://github.com/GautamSharma-coder/devauthkit/actions/workflows/ci.yml/badge.svg)](https://github.com/GautamSharma-coder/devauthkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**DevAuthKit** is a lightweight, zero-config self-hosted authentication toolkit for Node.js & Express with a universal companion Client SDK. Built for developers who want plug-and-play passwordless email OTP authentication, JWT Bearer tokens, and secure `httpOnly` sessions without paying exorbitant SaaS pricing (Clerk/Auth0) or wrestling with complex configuration (NextAuth/Passport).

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
| **Database Adapters** | **Prisma + Drizzle + Mongoose** | Vendor Cloud | Adapters required | Manual DB glue |
| **Frontend Integration** | ✅ **Client SDK + React Hooks** | Proprietary Components | Next.js / React only | ❌ None |

---

## ✨ Features

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
  jwtSecret: process.env.JWT_SECRET || "your-jwt-secret-key",
  sessionSecret: process.env.SESSION_SECRET || "your-session-secret-key",
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

Refresh storage defaults to process memory for local development. This is not suitable for multiple app instances and is cleared on restart. For production, pass a persistent `refreshTokenStore` implementing `create`, atomic `rotate`, `revoke`, `revokeFamily`, `revokeAll`, and `isFamilyActive`; the last method is checked on each request using a refresh-enabled JWT. Keep this store shared across application instances.

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

By default, routes are mounted under `/auth`:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/auth/login` *(or `/auth/request-otp`)* | Request an OTP (and optional Magic Link) sent to email. |
| `POST` | `/auth/verify` *(or `/auth/verify-otp`)* | Verify the OTP; returns JWT token & starts session. |
| `GET` / `POST` | `/auth/verify-magic` | Verify 1-click Magic Link token. |
| `POST` | `/auth/refresh` | Rotate the httpOnly refresh cookie and issue a new access token (when enabled). |
| `POST` | `/auth/sessions/revoke` | Revoke the authenticated token family immediately. |
| `POST` | `/auth/sessions/revoke-all` | Revoke all refresh sessions for the authenticated user. |
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
| `sessionSecret` | `string` | `process.env.SESSION_SECRET` | Secret key for `express-session`. |
| `jwtSecret` | `string` | `process.env.JWT_SECRET` | Secret key for signing JWT tokens. |
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
| `refreshTokens` | `boolean \| RefreshTokenOptions` | `false` | Enable rotating httpOnly refresh cookies; access tokens default to 15 minutes and refresh tokens to 30 days. |
| `refreshTokenStore` | `RefreshTokenStore` | In-memory store | Optional persistent token-family store. Its rotation must be atomic for replay protection. |
| `rateLimit` | `RateLimitConfig` | Built-in route limits | Customize individual route windows/identity limits, disable one route with `false`, or disable all limits with `false`. |
| `rateLimitStore` | `RateLimitStore` | In-memory store | Optional shared counter store; use `new devAuthKit.RedisRateLimitStore(redis)` for multiple instances. |
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

- **Next (v1.5.0 — In Development / Roadmap)**:
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
