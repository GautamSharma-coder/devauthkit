# DevAuthKit — One-Page Email OTP & Resend Rate Limiting Example

> **The production-ready reference setup for passwordless Email OTP with zero-trust resend rate limiting.**

OTP authentication flows are the single most common authentication mechanism that developers get stuck wiring up — and the **#1 place where authentication gets abused** if resend rate limiting is not properly configured.

This runnable one-page example app shows you how to wire up the entire lifecycle with **DevAuthKit** in minutes:
1. Requesting an OTP verification code
2. Enforcing a reactive 60-second client-side cooldown timer on the resend button
3. Defending against OTP spam and email bombing via DevAuthKit's server-side sliding window rate limiter
4. Catching `HTTP 429 Too Many Requests` and syncing lockouts using `retryAfterSeconds`
5. Verifying the 6-digit OTP and establishing a dual JWT & session cookie state
6. Accessing protected Express API routes with `auth.fetch()` and clean logout

---

## ⚡ Quick Start

From the root of the `devauthkit` repository, run:

```bash
npm run example:otp
```

*(or `node examples/email-otp-flow/server.js`)*

Then open your browser at:
👉 **[http://localhost:3000](http://localhost:3000)**

> **Note for Local Testing:** In `devMode: true`, DevAuthKit prints the 6-digit OTP directly into your terminal console so you don't need real SMTP credentials to test!

---

## 🛡️ Why Rate Limiting on Resend Matters

If an OTP resend button has no rate limit:
- **Email Bombing / Influx:** Attackers can script hundreds of requests against a victim's email address in seconds.
- **Provider API Quota Depletion:** Exhausts your email service provider quota (Resend, SendGrid, Postmark) within minutes.
- **Brute-Force Widening:** Excessive active OTP generations make timing attacks and code guessing easier.

### Two-Tier Protection in this Example

1. **Client Tier (UI Cooldown):**
   - The resend button is immediately disabled upon clicking.
   - A reactive 60-second countdown informs the user when they can next request a code.
2. **Server Tier (DevAuthKit Middleware):**
   - DevAuthKit enforces a sliding-window rate limiter per email (`perEmailMax: 3` per 60s) and per IP (`perIpMax: 10` per 60s).
   - If an automated script or malicious user bypasses the client UI, the server rejects the request with `HTTP 429 Too Many Requests`, returning `retryAfterSeconds` and a standard RFC `Retry-After` header.
   - The client SDK exposes `err.retryAfterSeconds`, allowing the UI to instantly lock and display the exact remaining server cooldown.

---

## 💻 Server Code Walkthrough (`server.js`)

```javascript
const express = require("express");
const devAuthKit = require("devauthkit");

const app = express();

// Initialize DevAuthKit with OTP and Resend Rate Limiting
devAuthKit(app, {
  jwtSecret: process.env.JWT_SECRET || "super-secret-jwt-key",
  devMode: true, // prints OTP in console for local testing
  rateLimit: {
    requestOtp: {
      windowMs: 60 * 1000, // 1 minute sliding window
      perEmail: true,
      perEmailMax: 3,       // Max 3 OTP requests / minute per email
      perIp: true,
      perIpMax: 10         // Max 10 requests / minute per IP
    }
  }
});

// Protect your custom API routes
const { requireAuth } = devAuthKit;
app.get("/api/dashboard", requireAuth, (req, res) => {
  res.json({ message: "Welcome to the secret dashboard!", user: req.user });
});

app.listen(3000);
```

---

## 📱 Client Resend Handler with Rate Limit Protection

```javascript
import { DevAuthClient } from "devauthkit/client";

const auth = new DevAuthClient();

async function handleResendOTP(email) {
  try {
    const res = await auth.sendOTP(email);
    console.log("OTP sent!", res.message);
    startCooldown(60); // 60s countdown
  } catch (err) {
    if (err.status === 429 || err.retryAfterSeconds) {
      console.warn(`Server rate limit active: wait ${err.retryAfterSeconds}s`);
      startCooldown(err.retryAfterSeconds);
    } else {
      console.error(err.message);
    }
  }
}
```

---

## 📁 Directory Structure

```
examples/email-otp-flow/
├── public/
│   └── index.html      # Responsive one-page UI with cooldown & 429 handling
├── server.js           # Express + DevAuthKit server with rateLimit config
└── README.md           # This guide
```

