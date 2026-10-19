# Contributing to DevAuthKit 🔐

First off, thank you for considering contributing to **DevAuthKit**! 🎉 

DevAuthKit is an open-source project designed to make authentication in Node.js and Express painless, secure, and developer-friendly. Contributions of all kinds—whether reporting bugs, improving documentation, submitting feature proposals, or writing code—are warmly welcomed.

---

## 📑 Table of Contents

- [Code of Conduct](#-code-of-conduct)
- [How Can I Contribute?](#-how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Working on Good First Issues](#working-on-good-first-issues)
- [Development Setup](#-development-setup)
  - [Prerequisites](#prerequisites)
  - [Installation & Local Run](#installation--local-run)
  - [Running the Test Suite](#running-the-test-suite)
- [Project Architecture](#-project-architecture)
- [Git Commit & Branch Conventions](#-git-commit--branch-conventions)
- [Pull Request Checklist](#-pull-request-checklist)
- [Community & Support](#-community--support)

---

## 📜 Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free experience for everyone. Please review our full [Code of Conduct](CODE_OF_CONDUCT.md) before participating. Respect, empathy, and kindness are required in all interactions.

---

## 💡 How Can I Contribute?

### Reporting Bugs
If you encounter unexpected behavior or security issues:
1. Check the [GitHub Issues](https://github.com/GautamSharma-coder/devauthkit/issues) to ensure it hasn't already been reported.
2. If it is new, open an issue with:
   - A clear and descriptive title.
   - Steps to reproduce the problem.
   - Expected vs. actual behavior.
   - Your Node.js version and operating system.

### Suggesting Enhancements
Have an idea for a feature or improvement? Open an issue with the label `enhancement` and describe:
- The problem your idea solves.
- Proposed solution or API design.
- Any alternative solutions you've considered.

### Working on Good First Issues
Looking for inspiration? Here are high-impact areas currently open for contribution:
- 🛡️ **Rate Limiting**: Add IP/email request throttling to prevent OTP flooding.
- ✉️ **HTML Email Templates**: Add customizable, responsive HTML email layouts for production SMTP.
- 📘 **TypeScript Support**: Add `.d.ts` declaration files for backend and client SDK.
- 🔌 **Storage Adapters**: Add Redis or database adapters (MongoDB / Prisma) to complement the in-memory store.
- 🌐 **Social Providers**: Add Google / GitHub OAuth integrations.

---

## 🛠️ Development Setup

### Prerequisites
- [Node.js](https://nodejs.org/) (v16.0.0 or higher recommended)
- `npm` (v8 or higher)
- `git`

### Installation & Local Run

1. **Fork the repository** on GitHub.
2. **Clone your fork locally**:
   ```bash
   git clone https://github.com/<your-username>/devauthkit.git
   cd devauthkit
   ```
3. **Install dependencies**:
   ```bash
   npm install
   ```
4. **Start the local example server**:
   ```bash
   node example.js
   # or with live reload:
   npm run dev
   ```
5. **Open the interactive test demo**:
   Navigate to [http://localhost:3000/demo/index.html](http://localhost:3000/demo/index.html) in your browser.
   
   > ⚡ **Dev Mode Tip**: You do not need to configure real email credentials! In Dev Mode, generated OTP codes are printed directly to your terminal console for instant testing.

---

### 🧪 Running the Test Suite

We maintain automated tests to prevent regressions. Always run tests before submitting your changes:

```bash
npm test
```

All new features and bug fixes should include corresponding test coverage in [test_auth.js](test_auth.js).

---

## 🏛️ Project Architecture

Here is how the codebase is structured:

```text
devauthkit/
├── index.js                  # Main CommonJS entry point
├── package.json              # Package metadata, dependencies, scripts, & exports
├── test_auth.js              # Automated integration & unit test suite
├── example.js                # Local sandbox server demonstrating setup
│
├── server/                   # Backend Express Authentication Core
│   ├── server.js             # devAuthKit() initialization & mounting logic
│   ├── config.js             # Configuration manager with defaults & devMode detection
│   ├── sessionStore.js       # In-memory session store with TTL auto-cleanup
│   ├── controllers/
│   │   └── authController.js # requestOTP, verifyOTP, getMe, logout logic
│   ├── middleware/
│   │   └── requireAuth.js    # Dual auth middleware (Bearer JWT + Session cookie)
│   ├── routes/
│   │   └── authRoutes.js     # Route definitions & aliases (/login, /verify, /me, /logout)
│   └── utils/
│       ├── generateOTP.js    # Cryptographically secure randomInt generator
│       └── mailer.js         # Transporter setup & devMode console logger
│
└── client/                   # Frontend Client SDK & Demo
    ├── index.js              # Universal DevAuthClient SDK (CommonJS, ESM, Browser)
    └── frontend/
        └── index.html        # Interactive dark-mode demo webpage
```

---

## 🌿 Git Commit & Branch Conventions

### Branch Naming
Create a dedicated branch for your work:
- `feat/feature-name` (e.g. `feat/rate-limiting`)
- `fix/bug-description` (e.g. `fix/jwt-expiration-check`)
- `docs/doc-update` (e.g. `docs/client-sdk-guide`)

```bash
git checkout -b feat/my-new-feature
```

### Commit Messages
We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` A new feature (e.g., `feat: add redis session store adapter`)
- `fix:` A bug fix (e.g., `fix: prevent timing attack on otp comparison`)
- `docs:` Documentation changes only
- `test:` Adding or updating tests
- `refactor:` Code change that neither fixes a bug nor adds a feature
- `chore:` Maintenance tasks, dependency updates

---

## ✅ Pull Request Checklist

Before opening your pull request, please make sure:

- [ ] Your code adheres to existing code styles and patterns.
- [ ] You have run `npm test` and all tests pass (0 failures).
- [ ] You have added tests covering your new feature or bug fix.
- [ ] You have updated the documentation in [README.md](README.md) if you added or changed an API.
- [ ] Your branch is rebased onto the latest `main` branch.
- [ ] You have written a descriptive PR title and summary explaining *why* the change is needed.

---

## 💬 Community & Support

- **Repository**: [https://github.com/GautamSharma-coder/devauthkit](https://github.com/GautamSharma-coder/devauthkit)
- **Issues**: [https://github.com/GautamSharma-coder/devauthkit/issues](https://github.com/GautamSharma-coder/devauthkit/issues)
- **Author**: [@GautamSharma-coder](https://github.com/GautamSharma-coder)

Thank you for helping make **DevAuthKit** better for developers everywhere! 🚀
