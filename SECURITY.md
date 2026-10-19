# Security Policy 🔐

At **DevAuthKit**, security is our top priority. Because this library handles sensitive authentication credentials, tokens, and sessions, we take all vulnerability reports with the highest level of urgency.

---

## 🛡️ Supported Versions

Only the latest minor releases receive active security updates and patches:

| Version | Supported          |
| :------ | :----------------- |
| `1.1.x` | :white_check_mark: |
| `1.0.x` | :x:                |
| `< 1.0` | :x:                |

We strongly encourage all users to upgrade to the latest version of `devauthkit` to ensure they have the latest security patches and features.

---

## 🚨 Reporting a Vulnerability

**Please do NOT file public GitHub Issues for security vulnerabilities.** Publicly disclosing vulnerabilities puts applications using DevAuthKit at risk.

### Preferred Method: GitHub Private Vulnerability Reporting
You can report security vulnerabilities privately via GitHub:
👉 **[Report a Security Vulnerability](https://github.com/GautamSharma-coder/devauthkit/security/advisories/new)**

### Alternative Method
If GitHub Private Reporting is unavailable, you can reach out directly to the maintainer via GitHub: **[@GautamSharma-coder](https://github.com/GautamSharma-coder)**.

### What to Include in Your Report
To help us triage and resolve the issue quickly, please provide:
1. **Description**: Clear description of the vulnerability and its potential impact.
2. **Steps to Reproduce**: Minimal reproduction script, curl command, or step-by-step instructions.
3. **Proof of Concept (PoC)**: If applicable, code demonstrating the exploit.
4. **Environment**: Version of `devauthkit`, Node.js version, and OS.
5. **Mitigation**: Any proposed fix or workaround (if known).

---

## ⏱️ Response Timeline

When a security vulnerability is reported, our process is:

1. **Acknowledgment**: We will acknowledge receipt of your report within **48 hours**.
2. **Investigation & Triage**: We will confirm the vulnerability and assess its severity.
3. **Patch Development**: We will work on a patch in a private security branch.
4. **Release & Advisory**: We will release a patched version (e.g. patch release `v1.1.x`) and publish a public Security Advisory detailing the issue and credit the reporter.

---

## 🔒 Security Best Practices for DevAuthKit Users

When deploying applications with DevAuthKit in production, please adhere to these guidelines:

- 🔑 **Cryptographic Secrets**: Always set strong, random, and unique keys for `JWT_SECRET` and `SESSION_SECRET` (at least 32 characters long). Never commit secrets to version control.
- 🌐 **Always Use HTTPS**: DevAuthKit automatically sets cookie `secure: true` when `NODE_ENV=production`. Ensure your production server runs behind TLS/SSL.
- 🛡️ **Tight CORS Configuration**: Avoid `corsOrigin: "*"` in production. Always specify your exact frontend domains (e.g., `corsOrigin: ["https://myapp.com"]`).
- 📧 **Production SMTP**: Never use personal email accounts for high-volume production auth. Use verified transactional email services (Resend, SendGrid, AWS SES, or Postmark) with SPF, DKIM, and DMARC configured.
- 📦 **Keep Dependencies Updated**: Regularly run `npm audit` to check for security advisories across all sub-dependencies.

---

Thank you for helping us keep DevAuthKit and its users safe! 🚀
