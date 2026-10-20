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
| **Zero-Setup Dev Mode** | ✅ **Console OTPs** | ❌ Requires Cloud Account | ❌ | ❌ |
| **Email Providers** | **Resend + SMTP + Custom** | Vendor Cloud | Nodemailer / Custom | Manual |
| **Dual/Triple Strategy** | **Bearer + httpOnly Cookie + Session** | Proprietary SDK | Session / JWT | Strategy plugins |
| **Database Lock-in** | ❌ **None (Zero Lock-in)** | Yes (Proprietary Cloud) | Adapters required | Manual DB glue |

---

## ✨ Features

- 🔑 **Passwordless Email OTP**: Secure 6-digit codes generated with Node's native `crypto.randomInt`.
- 📘 **100% TypeScript Native**: Full type definitions included (`index.d.ts` & `client/index.d.ts`) with zero external `@types` installs required.
- 🛡️ **Triple-Strategy Auth**: Supports **JWT Bearer Tokens**, secure **`httpOnly` Cookies**, and **Session Cookies** in a single `requireAuth` middleware.
- ⚡ **Zero-Setup Dev Mode**: Test locally with zero configuration. If email credentials are not configured, OTPs are cleanly printed to your terminal.
- 📬 **Modern Email Support**: First-class support for **[Resend](https://resend.com)** (`RESEND_API_KEY`) and standard SMTP (Nodemailer, Gmail, SendGrid).
- 📦 **Built-in Client SDK**: Import `DevAuthClient` from `devauthkit/client` for 3-line frontend auth in React, Vue, Next.js, or Vanilla JS.
- 🚫 **Brute-Force & Replay Shield**: Automatic lockout after 5 failed attempts, OTP invalidation on verification, and cooldown throttling.
- 🕒 **In-Memory TTL Store**: Auto-pruning memory store to prevent leaks without requiring a database for rapid prototypes.
- 🗄️ **Pluggable Storage**: Keep OTP state in memory by default, or use the Redis OTP adapter and a persistent `express-session` store for multi-instance deployments.
- 👤 **Persistent User Identity**: Optionally create or load a database user at login with a pluggable user adapter and included Prisma adapter.
- 🌐 **Google OAuth 2.0**: Built-in social login with PKCE (`S256`), CSRF protection, verified email enforcement, and seamless user adapter mapping.
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
| `POST` | `/auth/login` *(or `/auth/request-otp`)* | Request an OTP sent to the user's email. |
| `POST` | `/auth/verify` *(or `/auth/verify-otp`)* | Verify the OTP; returns JWT token & starts session. |
| `GET` | `/auth/google` | Start Google OAuth sign-in (when configured). |
| `GET` | `/auth/google/callback` | Complete Google OAuth sign-in (when configured). |
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

# Optional: Google OAuth (configure the matching callback URL in Google Cloud)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
```

> **Note:** If both `RESEND_API_KEY` and `EMAIL_USER` are omitted, DevAuthKit automatically activates **Zero-Setup Dev Mode** and prints OTPs directly to your console!

---

## 🔖 Version Changelog

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
