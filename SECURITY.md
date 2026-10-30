# 🔐 Security Policy & Vulnerability Disclosure

At **DevAuthKit**, security is foundational. Because this toolkit orchestrates authentication credentials, session lifecycles, cryptographic tokens, and compliance audit trails, we maintain an uncompromising posture toward security assurance and vulnerability remediation.

We actively collaborate with security researchers, bug bounty hunters, and developers worldwide to safeguard the open-source ecosystem.

---

## 🛡️ Supported Versions

We provide security updates and patches according to the following support matrix:

| Release Line | Status | Security Patches |
| :--- | :--- | :--- |
| **`v1.10.x`** | **Active / Current** | ✅ **Full Support (Immediate Hotfixes)** |
| `v1.9.x` | Maintenance | ⚠️ Critical Security Fixes Only |
| `< v1.9.0` | End of Life (EOL) | ❌ Unsupported — Please upgrade immediately |

> [!IMPORTANT]
> We strongly advise all production deployments to run the latest patch release on the current minor branch to benefit from the latest cryptographic primitives and security mitigations.

---

## 🚨 Reporting a Security Vulnerability

**Please do NOT disclose security vulnerabilities through public GitHub issues, pull requests, or public forums.** Public disclosure puts production systems using DevAuthKit at immediate risk.

### Method 1: GitHub Private Security Advisory (Recommended)
DevAuthKit uses GitHub's native Private Vulnerability Reporting. This provides an encrypted, private channel between researchers and the core maintainer:

👉 **[Submit a Private Security Advisory](https://github.com/GautamSharma-coder/devauthkit/security/advisories/new)**

### Method 2: Direct Security Contact
If GitHub Private Reporting is unavailable or you prefer encrypted direct communication:
- **Security Lead:** Gautam Sharma ([@GautamSharma-coder](https://github.com/GautamSharma-coder))
- **Email:** [gautamksharma45@gmail.com](mailto:gautamksharma45@gmail.com)
- **Subject Line:** `[SECURITY] DevAuthKit Vulnerability Report - <Brief Description>`

---

## 📋 What to Include in Your Report

To help us validate, triage, and patch the issue swiftly, please include as much of the following details as possible:

1. **Vulnerability Type**: (e.g., Authentication Bypass, Token Forgery, Replay Attack, Timing Leak, SSRF, Merkle Chain Tampering, Privilege Escalation).
2. **Affected Component**: Specify the relevant file, function, or route (e.g., `server/dpop.js`, `server/audit.js`, or adapter modules).
3. **Proof of Concept (PoC)**: Minimal, reproducible Node.js test script, cURL command, or request trace demonstrating the exploit.
4. **Environment**: Exact `devauthkit` package version, Node.js runtime version, database adapter (Prisma, Drizzle, Mongoose), and OS.
5. **Impact Assessment**: Estimated CVSS score and description of potential real-world harm.
6. **Suggested Remediation**: If you have identified a potential patch or mitigation, please feel free to share.

---

## ⏱️ Response Timelines & SLA

We adhere to a standard **Coordinated Vulnerability Disclosure (CVD)** process:

| Milestone | Target Response Time | Action |
| :--- | :--- | :--- |
| **Initial Acknowledgment** | **< 24 hours** | Receipt confirmed; assigned an internal triage ticket. |
| **Triage & Validation** | **< 72 hours** | Vulnerability reproduced; severity and CVSS rating determined. |
| **Remediation & Testing** | **< 7–14 days** | Patch engineered and validated against test suites and edge cases. |
| **Patch Release** | Immediate upon verification | New release published to npm and GitHub Releases. |
| **Public Advisory** | Coordinated | CVE assigned (if applicable) and credited advisory published. |

We respect a standard **90-day embargo** policy before public disclosure, allowing sufficient time for developers to upgrade their installations.

---

## 🎯 In-Scope vs. Out-of-Scope

### In-Scope Vulnerabilities
- Flaws in cryptographic primitives, token parsing, or signature validation.
- RFC 9449 DPoP key-binding bypasses or proof validation flaws.
- Session fixation, session hijacking, or revocation epoch bypasses.
- SHA-256 Merkle chain audit log tampering or verification bypasses.
- Authentication / authorization bypasses in `auth.protect()` or middleware guards.
- Timing attack vulnerabilities in secret or signature comparisons.
- Injection flaws (SQLi, NoSQLi) within database adapters.
- Server-Side Request Forgery (SSRF) in webhook dispatchers or OAuth discovery endpoints.

### Out-of-Scope Issues
- Attacks requiring physical access to a developer's workstation or server host.
- Weak JWT / session secrets explicitly set by the end user (e.g., `JWT_SECRET="12345"`).
- Missing rate limits when explicitly disabled via user configuration.
- Denial of Service (DoS) attacks on non-production test endpoints.
- Social engineering, phishing, or credential stuffing attacks against end-user deployments.

---

## 🛡️ Safe Harbor Policy

We consider security research conducted under this policy to be:
- **Authorized**: We will not pursue legal action against security researchers who report vulnerabilities in good faith and adhere to these guidelines.
- **Coordinated**: We will work with you to understand and address the issue, recognizing your contribution.

If at any point you are unsure whether your testing is safe or authorized, please reach out to our security contact prior to conducting testing.

---

## 🏅 Security Acknowledgments & Hall of Fame

We believe in giving credit where credit is due. Upon successful validation and release of a patch, we will:
1. Publicly credit your name/handle in the GitHub Security Advisory.
2. List your contribution in our official Release Notes and CHANGELOG.
3. Feature you in the DevAuthKit Security Hall of Fame.

---

## 🔐 Production Hardening Recommendations

If you are using DevAuthKit in production, we strongly recommend enforcing the following baseline practices:

- [ ] **Enforce TLS/HTTPS**: Never run authentication endpoints over unencrypted HTTP.
- [ ] **Cryptographic Secret Entropy**: Use high-entropy, cryptographically random keys for `JWT_SECRET` (minimum 32+ bytes generated via `crypto.randomBytes(32).toString('hex')`).
- [ ] **Strict CORS Whitelisting**: Explicitly declare authorized origin domains. Never use `corsOrigin: "*"` in production.
- [ ] **Secure Cookie Flags**: Ensure `cookie.secure: true`, `cookie.httpOnly: true`, and `cookie.sameSite: "lax" | "strict"`.
- [ ] **DPoP Token Protection**: Enable RFC 9449 DPoP enforcement on critical API routes to prevent stolen bearer token reuse.
- [ ] **Audit Trail Archival**: Periodically export and cold-store immutable audit logs via `GET /auth/audit-logs/export` for regulatory compliance.
- [ ] **Dependency Audits**: Run `npm audit` regularly to catch CVEs in upstream dependencies.

---

*Thank you for contributing to the security, reliability, and resilience of DevAuthKit!*
