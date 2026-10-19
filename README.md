# DevAuthKit 🔐

[![npm version](https://img.shields.io/npm/v/devauthkit.svg)](https://www.npmjs.com/package/devauthkit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**DevAuthKit** is a plug-and-play authentication framework for Express.js. Designed for developers who want to integrate secure passwordless email OTP authentication, JWT Bearer tokens, and session handling into their apps in minutes—with zero boilerplate.

---

## ✨ Features

- 🔑 **Passwordless Email OTP**: Secure 6-digit codes generated with Node's native `crypto.randomInt`.
- 🛡️ **Dual-Strategy Auth**: Supports both **JWT Bearer Tokens** (`Authorization: Bearer <token>`) and **Session Cookies** (`express-session`).
- ⚡ **Zero-Setup Dev Mode**: Test locally out of the box! If email credentials are not configured, OTPs are cleanly printed to your terminal.
- 🚫 **Brute-Force & Replay Shield**: Automatic lockout after 5 failed attempts, OTP invalidation on verification, and cooldown throttling.
- 🕒 **In-Memory TTL Store**: Auto-pruning memory store to prevent leaks without requiring a database for rapid prototypes.
- 🚪 **Complete Auth Lifecycle**: Built-in `/auth/me` profile inspection and `/auth/logout` session destruction.
- 📦 **Pluggable & Customizable**: Configurable JWT secret, expiry, CORS origins, and custom mailers.

---

## 📦 Installation

```bash
npm install devauthkit
```

---

## 🚀 Quick Start

### 1. Integrate with your Express App

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

---

## 🧪 Available Endpoints

By default, routes are mounted under `/auth`:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/auth/login` *(or `/auth/request-otp`)* | Request an OTP sent to the user's email. |
| `POST` | `/auth/verify` *(or `/auth/verify-otp`)* | Verify the OTP; returns JWT token & starts session. |
| `GET` | `/auth/me` | Return authenticated user's info (requires Bearer token or session). |
| `POST` | `/auth/logout` | Destroy session and clear session cookies. |
| `GET` | `/profile` | Built-in test route verifying authentication status. |

---

## 💻 Frontend Client Example

### 1. Request OTP
```javascript
const res = await fetch("http://localhost:3000/auth/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email: "user@example.com" })
});
const data = await res.json();
```

### 2. Verify OTP & Store JWT
```javascript
const res = await fetch("http://localhost:3000/auth/verify", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  credentials: "include", // For session cookies
  body: JSON.stringify({ email: "user@example.com", otp: "123456" })
});
const { token, user } = await res.json();

// Save token for API calls
localStorage.setItem("auth_token", token);
```

### 3. Make Protected Requests
```javascript
const token = localStorage.getItem("auth_token");

const res = await fetch("http://localhost:3000/api/dashboard", {
  headers: {
    "Authorization": `Bearer ${token}`
  },
  credentials: "include"
});
const data = await res.json();
```

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
| `mailer` | `function` | `undefined` | Custom async mailer function `async ({ email, otp }) => {}`. |
| `debug` | `boolean` | `false` | Enable verbose internal logging. |

---

## 📁 .env Configuration (Optional for Production SMTP)

Create a `.env` file in your root project:

```env
SESSION_SECRET=super_secret_session_key_12345
JWT_SECRET=super_secret_jwt_key_12345

# SMTP credentials (e.g. Gmail App Password, Resend, or SendGrid)
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-16-character-app-password
```

> **Note:** If `EMAIL_USER` is omitted, DevAuthKit automatically activates **Dev Mode** and prints OTPs directly to your console!

---

## 🔖 Version Changelog

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

## 👨‍💻 Author

**Gautam Sharma**  
GitHub: [@GautamSharma-coder](https://github.com/GautamSharma-coder)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
