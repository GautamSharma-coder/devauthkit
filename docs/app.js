/**
 * DevAuthKit Documentation & Live Interactive Sandbox
 * High-performance, zero-dependency browser script
 */

document.addEventListener("DOMContentLoaded", () => {
  initClipboardButtons();
  initCodeTabSwitchers();
  initScrollSpy();
  initMobileMenu();
  initQuickSearch();
  initSandbox();
  initLandingAnimations();
});

/* ==========================================================================
   Landing Page Motion
   ========================================================================== */
function initLandingAnimations() {
  const landingPage = document.querySelector(".landing-page");
  const gsap = window.gsap;
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  if (!landingPage || !gsap || reduceMotion) return;

  const hero = gsap.timeline({ defaults: { ease: "power3.out" } });
  hero
    .from(".site-header", { y: -18, autoAlpha: 0, duration: 0.7 })
    .from(".hero-pill-badge", { y: 18, autoAlpha: 0, duration: 0.6 }, "-=0.32")
    .from(".landing-headline", { y: 28, autoAlpha: 0, duration: 0.75 }, "-=0.34")
    .from(".landing-subtitle", { y: 18, autoAlpha: 0, duration: 0.6 }, "-=0.42")
    .from(".landing-hero-actions", { y: 14, autoAlpha: 0, duration: 0.55 }, "-=0.34")
    .from(".stats-strip .stat-card", {
      y: 18,
      autoAlpha: 0,
      duration: 0.5,
      stagger: 0.1
    }, "-=0.25");

  const revealTargets = document.querySelectorAll(
    ".landing-section .section-header-center, .sandbox-card, .bento-card, .code-window, " +
      ".table-wrapper, .grand-cta-box"
  );
  if (!revealTargets.length || !("IntersectionObserver" in window)) return;

  const revealObserver = new IntersectionObserver((entries, observer) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;

      gsap.fromTo(
        entry.target,
        { y: 24, autoAlpha: 0 },
        { y: 0, autoAlpha: 1, duration: 0.65, ease: "power2.out", clearProps: "transform,opacity,visibility" }
      );
      observer.unobserve(entry.target);
    });
  }, { threshold: 0.12 });

  revealTargets.forEach((target) => revealObserver.observe(target));
}

/* ==========================================================================
   1. Clipboard Functionality
   ========================================================================== */
function initClipboardButtons() {
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const textToCopy = btn.getAttribute("data-copy");
      try {
        await navigator.clipboard.writeText(textToCopy);
        const originalContent = btn.innerHTML;
        btn.innerHTML = `✓ Copied!`;
        btn.style.color = "#ffffff";
        setTimeout(() => {
          btn.innerHTML = originalContent;
          btn.style.color = "";
        }, 2000);
      } catch (err) {
        console.error("Failed to copy text:", err);
      }
    });
  });

  document.querySelectorAll(".code-copy-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const codeBlock = btn.closest(".code-window")?.querySelector("pre.code-block");
      if (!codeBlock) return;
      try {
        await navigator.clipboard.writeText(codeBlock.innerText);
        const originalText = btn.innerText;
        btn.innerText = "✓ Copied!";
        btn.style.color = "#ffffff";
        setTimeout(() => {
          btn.innerText = originalText;
          btn.style.color = "";
        }, 2000);
      } catch (err) {
        console.error("Copy failed:", err);
      }
    });
  });
}

/* ==========================================================================
   2. Code Snippet Tab Switchers
   ========================================================================== */
function initCodeTabSwitchers() {
  document.querySelectorAll(".code-window").forEach((windowEl) => {
    const tabs = windowEl.querySelectorAll(".code-tab");
    const blocks = windowEl.querySelectorAll(".code-block-item");

    tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        const targetTab = tab.getAttribute("data-tab");

        tabs.forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");

        blocks.forEach((block) => {
          if (block.getAttribute("data-tab-content") === targetTab) {
            block.style.display = "block";
          } else {
            block.style.display = "none";
          }
        });
      });
    });
  });
}

/* ==========================================================================
   3. ScrollSpy & Table of Contents
   ========================================================================== */
function initScrollSpy() {
  const headings = document.querySelectorAll(".docs-content h2, .docs-content h3");
  const tocLinks = document.querySelectorAll(".toc-link");
  if (!headings.length || !tocLinks.length) return;

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const id = entry.target.getAttribute("id");
          if (!id) return;

          tocLinks.forEach((link) => {
            if (link.getAttribute("href") === `#${id}`) {
              link.classList.add("active");
            } else {
              link.classList.remove("active");
            }
          });
        }
      });
    },
    { rootMargin: "-80px 0px -70% 0px", threshold: 0 }
  );

  headings.forEach((heading) => observer.observe(heading));
}

/* ==========================================================================
   4. Mobile Menu Toggle
   ========================================================================== */
function initMobileMenu() {
  const menuBtn = document.getElementById("mobileMenuBtn");
  const sidebar = document.getElementById("docsSidebar");

  if (!menuBtn || !sidebar) return;

  menuBtn.addEventListener("click", () => {
    sidebar.classList.toggle("open");
  });

  // Close sidebar on link click
  sidebar.querySelectorAll(".sidebar-link").forEach((link) => {
    link.addEventListener("click", () => {
      sidebar.classList.remove("open");
    });
  });
}

/* ==========================================================================
   5. Quick Search / Filter
   ========================================================================== */
function initQuickSearch() {
  const searchInput = document.getElementById("docSearchInput");
  const sections = document.querySelectorAll(".doc-section");

  if (!searchInput) return;

  // Shortcut Ctrl+K or Cmd+K
  window.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "k") {
      e.preventDefault();
      searchInput.focus();
      searchInput.select();
    }
  });

  searchInput.addEventListener("input", (e) => {
    const q = e.target.value.toLowerCase().trim();
    if (!q) {
      sections.forEach((sec) => (sec.style.display = "block"));
      return;
    }

    sections.forEach((sec) => {
      const text = sec.innerText.toLowerCase();
      if (text.includes(q)) {
        sec.style.display = "block";
      } else {
        sec.style.display = "none";
      }
    });
  });
}

/* ==========================================================================
   6. Interactive Security & Auth Sandbox
   ========================================================================== */
function initSandbox() {
  // Sandbox Tab Switching
  const tabBtns = document.querySelectorAll(".sandbox-tab-btn");
  const views = document.querySelectorAll(".sandbox-view");

  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.getAttribute("data-sandbox-target");
      tabBtns.forEach((b) => b.classList.remove("active"));
      views.forEach((v) => v.classList.remove("active"));

      btn.classList.add("active");
      const targetView = document.getElementById(target);
      if (targetView) targetView.classList.add("active");
    });
  });

  // --- Sandbox 1: Passwordless OTP Simulator ---
  const otpEmailInput = document.getElementById("simOtpEmail");
  const sendOtpBtn = document.getElementById("simSendOtpBtn");
  const otpCodeInput = document.getElementById("simOtpCode");
  const verifyOtpBtn = document.getElementById("simVerifyOtpBtn");
  const otpConsole = document.getElementById("simOtpConsole");

  let currentGeneratedOtp = null;

  sendOtpBtn?.addEventListener("click", () => {
    const email = otpEmailInput.value.trim() || "developer@example.com";
    currentGeneratedOtp = Math.floor(100000 + Math.random() * 900000).toString();

    otpConsole.innerHTML = `<span style="color:#64748b">[DevAuthKit DevMode] Zero-config email fallback active:</span>
<span style="color:#3f3f46">--------------------------------------------------</span>
<span style="color:#38bdf8">[TARGET] Email to:</span> <span style="color:#f4f4f5">${email}</span>
<span style="color:#fbbf24; font-weight:600;">[OTP CODE] DevAuthKit Code: [ ${currentGeneratedOtp} ]</span>
<span style="color:#a1a1aa">[POLICY] Validity: 10 minutes | Attempts allowed: 5</span>
<span style="color:#3f3f46">--------------------------------------------------</span>
<span style="color:#4ade80; font-weight:600;">HTTP/1.1 200 OK</span>
{
  <span style="color:#93c5fd">"success"</span>: <span style="color:#fbbf24">true</span>,
  <span style="color:#93c5fd">"message"</span>: <span style="color:#4ade80">"OTP sent successfully to ${email}"</span>,
  <span style="color:#93c5fd">"cooldownSeconds"</span>: <span style="color:#fbbf24">60</span>
}`;
    otpCodeInput.value = currentGeneratedOtp;
    otpCodeInput.focus();
  });

  verifyOtpBtn?.addEventListener("click", () => {
    const code = otpCodeInput.value.trim();
    const email = otpEmailInput.value.trim() || "developer@example.com";

    if (!code) {
      otpConsole.innerHTML = `<span style="color:#fbbf24">[ERROR] Please enter or generate an OTP code first.</span>`;
      return;
    }

    if (code !== currentGeneratedOtp) {
      otpConsole.innerHTML = `<span style="color:#f43f5e; font-weight:600;">HTTP/1.1 401 Unauthorized</span>
{
  <span style="color:#93c5fd">"error"</span>: <span style="color:#f43f5e">"invalid_otp"</span>,
  <span style="color:#93c5fd">"message"</span>: <span style="color:#f43f5e">"The verification code is invalid or has expired."</span>,
  <span style="color:#93c5fd">"attemptsRemaining"</span>: <span style="color:#fbbf24">4</span>
}`;
      return;
    }

    // Success! Generate simulated JWT
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const payload = btoa(
      JSON.stringify({
        sub: "usr_77a49f92",
        email: email,
        role: "admin",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900
      })
    );
    const mockToken = `${header}.${payload}.c89a0f443b2792...`;

    otpConsole.innerHTML = `<span style="color:#4ade80; font-weight:600;">HTTP/1.1 200 OK (Verification Successful)</span>
<span style="color:#a1a1aa">Set-Cookie:</span> <span style="color:#4ade80">devauthkit_refresh=hash_9a87...; HttpOnly; Secure; SameSite=Lax</span>

{
  <span style="color:#93c5fd">"success"</span>: <span style="color:#fbbf24">true</span>,
  <span style="color:#93c5fd">"user"</span>: {
    <span style="color:#93c5fd">"id"</span>: <span style="color:#4ade80">"usr_77a49f92"</span>,
    <span style="color:#93c5fd">"email"</span>: <span style="color:#4ade80">"${email}"</span>,
    <span style="color:#93c5fd">"role"</span>: <span style="color:#4ade80">"admin"</span>
  },
  <span style="color:#93c5fd">"token"</span>: <span style="color:#38bdf8">"${mockToken}"</span>,
  <span style="color:#93c5fd">"expiresIn"</span>: <span style="color:#fbbf24">900</span>
}

<span style="color:#4ade80">[STATUS] Verification completed. Session established and Bearer token ready for API calls.</span>`;
  });

  // --- Sandbox 2: RFC 9449 DPoP Cryptographic Token Binding ---
  const dpopGenBtn = document.getElementById("simDpopGenBtn");
  const dpopConsole = document.getElementById("simDpopConsole");

  dpopGenBtn?.addEventListener("click", async () => {
    dpopConsole.innerText = `[RUNNING] Generating ECDSA P-256 (ES256) keypair using browser Web Crypto API...`;

    try {
      // 1. Generate real Web Crypto P-256 Keypair in browser
      const keyPair = await window.crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      );

      // 2. Export Public JWK
      const publicJwk = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);

      // 3. Compute RFC 7638 SHA-256 JWK Thumbprint (jkt)
      const canonicalJwk = JSON.stringify({
        crv: publicJwk.crv,
        kty: publicJwk.kty,
        x: publicJwk.x,
        y: publicJwk.y
      });
      const hashBuffer = await window.crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(canonicalJwk)
      );
      const jkt = base64UrlEncode(new Uint8Array(hashBuffer));

      // 4. Compute mock access token bound to jkt
      const mockDpopJwt = {
        header: { alg: "HS256", typ: "dpop+jwt" },
        payload: {
          sub: "usr_dpop_secure_44",
          email: "security-lead@enterprise.com",
          cnf: {
            jkt: jkt // RFC 9449 Key Thumbprint Binding!
          },
          exp: Math.floor(Date.now() / 1000) + 900
        }
      };

      dpopConsole.innerHTML = `<span style="color:#38bdf8; font-weight:600;">[RFC 9449] DPoP Key Pair Generated in Browser Memory</span>
<span style="color:#3f3f46">----------------------------------------------------------------------</span>
<span style="color:#fbbf24">[JWK] Client Public Key:</span>
  <span style="color:#93c5fd">kty:</span> <span style="color:#4ade80">"${publicJwk.kty}"</span>
  <span style="color:#93c5fd">crv:</span> <span style="color:#4ade80">"${publicJwk.crv}"</span>
  <span style="color:#93c5fd">x:</span>   <span style="color:#f4f4f5">"${publicJwk.x.slice(0, 16)}..."</span>
  <span style="color:#93c5fd">y:</span>   <span style="color:#f4f4f5">"${publicJwk.y.slice(0, 16)}..."</span>

<span style="color:#fbbf24; font-weight:600;">[THUMBPRINT] RFC 7638 SHA-256 (cnf.jkt):</span>
  <span style="color:#38bdf8; font-weight:600;">"${jkt}"</span>

<span style="color:#c084fc; font-weight:600;">[PAYLOAD] DPoP-Bound Access Token:</span>
<span style="color:#e4e4e7">${JSON.stringify(mockDpopJwt.payload, null, 2)}</span>

<span style="color:#4ade80; font-weight:600;">[SECURITY GUARANTEE]:</span>
<span style="color:#a1a1aa">Even if an attacker steals this token from network traffic, they DO NOT possess
the private key held in this browser's memory. Any request without a matching
live signature will be rejected with 401 Unauthorized!</span>`;
    } catch (err) {
      dpopConsole.innerText = `DPoP simulation fallback: ${err.message}`;
    }
  });

  // --- Sandbox 3: Passkeys / WebAuthn Biometrics ---
  const passkeyTestBtn = document.getElementById("simPasskeyTestBtn");
  const passkeyConsole = document.getElementById("simPasskeyConsole");

  passkeyTestBtn?.addEventListener("click", () => {
    const isAvailable = !!(
      window.PublicKeyCredential &&
      navigator.credentials &&
      navigator.credentials.create
    );

    passkeyConsole.innerHTML = `[WEBAUTHN] Platform Authenticator Check:
---------------------------------------------------------
- WebAuthn API Available: ${isAvailable ? "[PASS] Yes" : "[FAIL] No"}
- Platform Authenticator (TouchID / FaceID / Windows Hello): ${isAvailable ? "[PASS] Supported" : "[INFO] Emulated"}

[Simulated Passkey Registration with DevAuthKit]
1. Server issues registration challenge (TTL: 300s):
   challenge: "b64_ch_99e8210bf..."
   rp: { name: "DevAuthKit App", id: "${window.location.hostname || "localhost"}" }
   pubKeyCredParams: [{ alg: -7, type: "public-key" }]

2. Biometric scan prompt triggered via navigator.credentials.create()...
3. Public key stored securely in durable Cloudflare D1 / database.
4. Future logins require ZERO passwords, ZERO OTP emails — instant 1-touch auth!`;
  });
}

function base64UrlEncode(uint8Array) {
  let binary = "";
  for (let i = 0; i < uint8Array.byteLength; i++) {
    binary += String.fromCharCode(uint8Array[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
