# DevAuthKit 🔐

A plug-and-play authentication service built with Express.js — designed for developers who want to easily integrate secure login, JWT, session handling, and email-based OTP into their apps.

---

## 🚀 Features

- ✅ Session & Token-based Auth
- 📧 Email-based OTP login (via Nodemailer)
- 🔐 JWT support
- 🕒 Session management with `express-session`
- 🌍 CORS ready
- 📦 Easily pluggable into any Express backend

---



## 📦 Installation

```bash
npm install devauthkit
```
---
## 🛠️ Usage

1. Basic Setup (in your Express app)
```js
// index.js or server.js
const express = require("express");
const devAuthKit = require("devauthkit");

const app = express();

devAuthKit(app, {
  corsOrigin: "http://localhost:3001",   // frontend URL
  sessionSecret: process.env.SESSION_SECRET || "mySecret",
  debug: true
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
```
---
## 🧪 Available Routes

Method	Endpoint	Description

POST	/auth/register	Register user with email
POST	/auth/login	Send OTP to email
POST	/auth/verify	Verify OTP and log in
GET	/profile	Protected route (requires session)


> Note: These routes are defined under /auth by default.

---
## 📁 .env Configuration

Create a .env file in your root project (not in DevAuthKit):

SESSION_SECRET=yourSecretSessionKey
EMAIL_USER=your@gmail.com
EMAIL_PASS=yourEmailAppPassword

Make sure to use an app password for Gmail or secure SMTP credentials.

---
## 🔖 Versioning
# Current Version

[![npm version](https://img.shields.io/npm/v/devauthkit.svg)](https://www.npmjs.com/package/devauthkit)

1.0.0: Initial release

1.0.1: Reusable module support

1.0.2: CORS/session configurable via options

---
👨‍💻 Author

Gautam Sharma
GitHub: @GautamSharma-coder


---

📄 License

This project is licensed under the MIT License.


---

🙌 Contribute

PRs and issues are welcome! Open a feature request or report a bug in GitHub Issues.

---

