"use client";

// client/react/ui.js
let React = null;
try {
  React = require("react");
} catch {
  // React is an optional peer dependency
}

function assertReact() {
  if (!React) {
    throw new Error(
      "[DevAuthKit] React is not installed. To use DevAuthKit UI components, please install react: npm install react"
    );
  }
}

// SVG Icons
const Icons = {
  Google: () =>
    React.createElement(
      "svg",
      { width: 18, height: 18, viewBox: "0 0 24 24", style: { display: "inline-block", verticalAlign: "middle" } },
      React.createElement("path", {
        fill: "#4285F4",
        d: "M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.8-2.4 3.66v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.15z"
      }),
      React.createElement("path", {
        fill: "#34A853",
        d: "M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.26v3.15C3.25 21.36 7.33 24 12 24z"
      }),
      React.createElement("path", {
        fill: "#FBBC05",
        d: "M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.26C.46 8.17 0 9.99 0 12s.46 3.83 1.26 5.42l4.02-3.15z"
      }),
      React.createElement("path", {
        fill: "#EA4335",
        d: "M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.33 0 3.25 2.64 1.26 6.58l4.02 3.15c.95-2.83 3.6-4.98 6.72-4.98z"
      })
    ),
  GitHub: () =>
    React.createElement(
      "svg",
      { width: 18, height: 18, viewBox: "0 0 24 24", fill: "currentColor", style: { display: "inline-block", verticalAlign: "middle" } },
      React.createElement("path", {
        fillRule: "evenodd",
        clipRule: "evenodd",
        d: "M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
      })
    ),
  Passkey: () =>
    React.createElement(
      "svg",
      { width: 18, height: 18, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 2, strokeLinecap: "round", strokeLinejoin: "round", style: { display: "inline-block", verticalAlign: "middle" } },
      React.createElement("path", { d: "M12 2a10 10 0 0 0-7.38 16.75" }),
      React.createElement("path", { d: "M12 6a6 6 0 0 0-4.43 10.05" }),
      React.createElement("path", { d: "M12 10a2 2 0 0 0-1.47 3.35" }),
      React.createElement("path", { d: "M19.07 4.93A10 10 0 0 1 22 12c0 2.76-1.12 5.26-2.93 7.07" }),
      React.createElement("path", { d: "M16.24 7.76A6 6 0 0 1 18 12c0 1.66-.67 3.16-1.76 4.24" }),
      React.createElement("path", { d: "M13.41 10.59A2 2 0 0 1 14 12c0 .55-.22 1.05-.59 1.41" })
    ),
  Shield: () =>
    React.createElement(
      "svg",
      { width: 16, height: 16, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 2, strokeLinecap: "round", strokeLinejoin: "round" },
      React.createElement("path", { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" })
    ),
  Spinner: () =>
    React.createElement(
      "svg",
      {
        width: 18,
        height: 18,
        viewBox: "0 0 24 24",
        fill: "none",
        stroke: "currentColor",
        strokeWidth: 2.5,
        style: {
          display: "inline-block",
          animation: "dak-spin 1s linear infinite",
          verticalAlign: "middle"
        }
      },
      React.createElement("circle", { cx: 12, cy: 12, r: 10, strokeOpacity: 0.25 }),
      React.createElement("path", { d: "M12 2a10 10 0 0 1 10 10" })
    ),
  Check: () =>
    React.createElement(
      "svg",
      { width: 14, height: 14, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 3, strokeLinecap: "round", strokeLinejoin: "round" },
      React.createElement("polyline", { points: "20 6 9 17 4 12" })
    ),
  Building: () =>
    React.createElement(
      "svg",
      { width: 16, height: 16, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 2, strokeLinecap: "round", strokeLinejoin: "round" },
      React.createElement("rect", { x: 4, y: 2, width: 16, height: 20, rx: 2, ry: 2 }),
      React.createElement("path", { d: "M9 22v-4h6v4" }),
      React.createElement("path", { d: "M8 6h.01" }),
      React.createElement("path", { d: "M16 6h.01" }),
      React.createElement("path", { d: "M8 10h.01" }),
      React.createElement("path", { d: "M16 10h.01" }),
      React.createElement("path", { d: "M8 14h.01" }),
      React.createElement("path", { d: "M16 14h.01" })
    ),
  ChevronDown: () =>
    React.createElement(
      "svg",
      { width: 14, height: 14, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 2, strokeLinecap: "round", strokeLinejoin: "round" },
      React.createElement("polyline", { points: "6 9 12 15 18 9" })
    )
};

// CSS Stylesheet injector
const STYLE_ID = "devauthkit-ui-styles";
function injectStylesOnce() {
  if (typeof document === "undefined") return;
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement("style");
  style.id = STYLE_ID;
  style.textContent = `
    @keyframes dak-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
    .dak-card {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      border-radius: 12px;
      padding: 28px;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.2), 0 8px 10px -6px rgba(0, 0, 0, 0.1);
      width: 100%;
      max-width: 420px;
      margin: 0 auto;
      box-sizing: border-box;
      transition: all 0.2s ease;
    }
    .dak-theme-dark {
      background: #0f172a;
      border: 1px solid #334155;
      color: #f8fafc;
    }
    .dak-theme-light {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      color: #0f172a;
    }
    .dak-title { font-size: 20px; font-weight: 700; margin: 0 0 6px 0; text-align: center; }
    .dak-subtitle { font-size: 13px; color: #94a3b8; margin: 0 0 20px 0; text-align: center; line-height: 1.4; }
    .dak-input {
      width: 100%;
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 14px;
      margin-bottom: 12px;
      box-sizing: border-box;
      outline: none;
      transition: border-color 0.15s ease;
    }
    .dak-theme-dark .dak-input {
      background: #1e293b;
      border: 1px solid #475569;
      color: #f8fafc;
    }
    .dak-theme-dark .dak-input:focus { border-color: #6366f1; }
    .dak-theme-light .dak-input {
      background: #f8fafc;
      border: 1px solid #cbd5e1;
      color: #0f172a;
    }
    .dak-theme-light .dak-input:focus { border-color: #4f46e5; }
    .dak-btn-primary {
      width: 100%;
      padding: 11px 16px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      border: none;
      cursor: pointer;
      background: #6366f1;
      color: #ffffff;
      transition: background 0.15s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }
    .dak-btn-primary:hover:not(:disabled) { background: #4f46e5; }
    .dak-btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }
    .dak-btn-outline {
      width: 100%;
      padding: 9px 14px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      margin-bottom: 8px;
      transition: all 0.15s ease;
      box-sizing: border-box;
    }
    .dak-theme-dark .dak-btn-outline {
      background: #1e293b;
      border: 1px solid #334155;
      color: #f8fafc;
    }
    .dak-theme-dark .dak-btn-outline:hover { background: #334155; }
    .dak-theme-light .dak-btn-outline {
      background: #ffffff;
      border: 1px solid #cbd5e1;
      color: #334155;
    }
    .dak-theme-light .dak-btn-outline:hover { background: #f1f5f9; }
    .dak-divider {
      display: flex;
      align-items: center;
      text-align: center;
      margin: 18px 0;
      font-size: 12px;
      color: #94a3b8;
    }
    .dak-divider::before, .dak-divider::after {
      content: '';
      flex: 1;
      border-bottom: 1px solid #334155;
    }
    .dak-theme-light .dak-divider::before, .dak-theme-light .dak-divider::after {
      border-bottom: 1px solid #e2e8f0;
    }
    .dak-divider:not(:empty)::before { margin-right: .75em; }
    .dak-divider:not(:empty)::after { margin-left: .75em; }
    .dak-alert {
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 13px;
      margin-bottom: 14px;
      line-height: 1.4;
    }
    .dak-alert-error {
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: #f87171;
    }
    .dak-alert-success {
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: #34d399;
    }
    .dak-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 2px 8px;
      border-radius: 9999px;
      font-size: 11px;
      font-weight: 600;
    }
    .dak-badge-dpop {
      background: rgba(99, 102, 241, 0.15);
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.3);
    }
    .dak-avatar {
      width: 34px;
      height: 34px;
      border-radius: 50%;
      background: linear-gradient(135deg, #6366f1, #a855f7);
      color: #ffffff;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 13px;
      cursor: pointer;
      user-select: none;
      border: 2px solid rgba(255, 255, 255, 0.1);
    }
    .dak-popover {
      position: absolute;
      right: 0;
      top: calc(100% + 8px);
      width: 280px;
      border-radius: 10px;
      padding: 12px;
      z-index: 9999;
      box-shadow: 0 12px 28px rgba(0, 0, 0, 0.35);
    }
  `;
  document.head.appendChild(style);
}

/**
 * Drop-in <SignIn /> authentication component.
 *
 * Supports Email OTP, Magic Link, Passkeys, Google, GitHub, and Enterprise SSO.
 */
function SignIn(props = {}) {
  assertReact();
  injectStylesOnce();

  const {
    appearance = {},
    redirectUrl = "/",
    onSuccess,
    onError,
    showSocial = true,
    showPasskey = true,
    showSSO = true,
    initialStep = "email"
  } = props;

  const { useAuth } = require("./index");
  const auth = useAuth();

  const themeClass = appearance.theme === "light" ? "dak-theme-light" : "dak-theme-dark";

  const [step, setStep] = React.useState(initialStep); // 'email' | 'otp' | 'sso'
  const [email, setEmail] = React.useState("");
  const [otp, setOtp] = React.useState("");
  const [ssoDomain, setSsoDomain] = React.useState("");
  const [isLoading, setIsLoading] = React.useState(false);
  const [error, setError] = React.useState(null);
  const [message, setMessage] = React.useState(null);
  const [countdown, setCountdown] = React.useState(0);

  React.useEffect(() => {
    if (countdown > 0) {
      const timer = setTimeout(() => setCountdown(countdown - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [countdown]);

  const handleSendOTP = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (!email || !email.includes("@")) {
      setError("Please enter a valid email address.");
      return;
    }
    try {
      setIsLoading(true);
      setError(null);
      await auth.sendOTP(email);
      setStep("otp");
      setCountdown(60);
      setMessage(`A 6-digit verification code has been sent to ${email}`);
    } catch (err) {
      const msg = err.message || "Failed to send verification code.";
      if (err.retryAfterSeconds) {
        setCountdown(err.retryAfterSeconds);
      }
      setError(msg);
      if (onError) onError(err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerifyOTP = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (!otp || otp.length < 6) {
      setError("Please enter the 6-digit code.");
      return;
    }
    try {
      setIsLoading(true);
      setError(null);
      const res = await auth.verifyOTP(email, otp);
      if (onSuccess) onSuccess(res.user);
      if (redirectUrl && typeof window !== "undefined") {
        window.location.href = redirectUrl;
      }
    } catch (err) {
      const msg = err.message || "Invalid or expired verification code.";
      setError(msg);
      if (onError) onError(err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSSORedirect = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (!ssoDomain) {
      setError("Please enter your organization work domain (e.g. acme.com).");
      return;
    }
    try {
      setIsLoading(true);
      setError(null);
      if (auth.client.loginWithSso) {
        await auth.client.loginWithSso(ssoDomain, redirectUrl);
      } else {
        throw new Error("Enterprise SSO is not supported in the current client.");
      }
    } catch (err) {
      setError(err.message || "Failed to initiate Enterprise SSO.");
      if (onError) onError(err);
      setIsLoading(false);
    }
  };

  return React.createElement(
    "div",
    { className: `dak-card ${themeClass} ${appearance.className || ""}` },
    React.createElement("h2", { className: "dak-title" }, step === "otp" ? "Verify your code" : "Sign in to DevAuthKit"),
    React.createElement(
      "p",
      { className: "dak-subtitle" },
      step === "otp"
        ? `Enter the code sent to ${email}`
        : "Enterprise-grade security with zero vendor lock-in."
    ),

    error && React.createElement("div", { className: "dak-alert dak-alert-error" }, error),
    message && React.createElement("div", { className: "dak-alert dak-alert-success" }, message),

    step === "email" &&
      React.createElement(
        "form",
        { onSubmit: handleSendOTP },
        React.createElement("input", {
          type: "email",
          required: true,
          placeholder: "name@company.com",
          value: email,
          onChange: (e) => setEmail(e.target.value),
          className: "dak-input"
        }),
        React.createElement(
          "button",
          { type: "submit", disabled: isLoading, className: "dak-btn-primary" },
          isLoading ? React.createElement(Icons.Spinner) : "Continue with Email"
        )
      ),

    step === "otp" &&
      React.createElement(
        "form",
        { onSubmit: handleVerifyOTP },
        React.createElement("input", {
          type: "text",
          required: true,
          maxLength: 6,
          autoFocus: true,
          placeholder: "6-digit OTP code",
          value: otp,
          onChange: (e) => setOtp(e.target.value.trim()),
          className: "dak-input",
          style: { textAlign: "center", letterSpacing: "6px", fontSize: "18px", fontWeight: "700" }
        }),
        React.createElement(
          "button",
          { type: "submit", disabled: isLoading, className: "dak-btn-primary" },
          isLoading ? React.createElement(Icons.Spinner) : "Verify & Sign In"
        ),
        React.createElement(
          "div",
          { style: { display: "flex", justifyContent: "space-between", marginTop: 14, fontSize: 12, color: "#94a3b8" } },
          React.createElement(
            "button",
            {
              type: "button",
              onClick: () => setStep("email"),
              style: { background: "none", border: "none", color: "#818cf8", cursor: "pointer", padding: 0 }
            },
            "← Use another email"
          ),
          React.createElement(
            "button",
            {
              type: "button",
              disabled: countdown > 0 || isLoading,
              onClick: handleSendOTP,
              style: {
                background: "none",
                border: "none",
                color: countdown > 0 ? "#64748b" : "#818cf8",
                cursor: countdown > 0 ? "default" : "pointer",
                padding: 0
              }
            },
            countdown > 0 ? `Resend code in ${countdown}s` : "Resend code"
          )
        )
      ),

    step === "sso" &&
      React.createElement(
        "form",
        { onSubmit: handleSSORedirect },
        React.createElement("input", {
          type: "text",
          required: true,
          autoFocus: true,
          placeholder: "company.com",
          value: ssoDomain,
          onChange: (e) => setSsoDomain(e.target.value.trim()),
          className: "dak-input"
        }),
        React.createElement(
          "button",
          { type: "submit", disabled: isLoading, className: "dak-btn-primary" },
          isLoading ? React.createElement(Icons.Spinner) : "Continue with SSO"
        ),
        React.createElement(
          "div",
          { style: { marginTop: 12, textAlign: "center" } },
          React.createElement(
            "button",
            {
              type: "button",
              onClick: () => setStep("email"),
              style: { background: "none", border: "none", color: "#818cf8", cursor: "pointer", fontSize: 12 }
            },
            "← Back to all options"
          )
        )
      ),

    step === "email" &&
      (showSocial || showPasskey || showSSO) &&
      React.createElement("div", { className: "dak-divider" }, "OR"),

    step === "email" &&
      showPasskey &&
      React.createElement(
        "button",
        {
          type: "button",
          onClick: async () => {
            try {
              setIsLoading(true);
              setError(null);
              // Trigger discoverable passkey login
              if (auth.client.loginWithPasskey) {
                const res = await auth.client.loginWithPasskey();
                if (onSuccess) onSuccess(res.user);
                if (redirectUrl && typeof window !== "undefined") window.location.href = redirectUrl;
              } else {
                setError("Passkey login is supported via your WebAuthn backend configuration.");
              }
            } catch (err) {
              setError(err.message || "Passkey authentication was cancelled or failed.");
            } finally {
              setIsLoading(false);
            }
          },
          className: "dak-btn-outline"
        },
        React.createElement(Icons.Passkey),
        "Sign in with Passkey / Biometrics"
      ),

    step === "email" &&
      showSocial &&
      React.createElement(
        React.Fragment,
        null,
        React.createElement(
          "button",
          {
            type: "button",
            onClick: () => auth.loginWithGoogle({ successRedirectURL: redirectUrl }),
            className: "dak-btn-outline"
          },
          React.createElement(Icons.Google),
          "Continue with Google"
        ),
        React.createElement(
          "button",
          {
            type: "button",
            onClick: () => auth.loginWithGitHub({ successRedirectURL: redirectUrl }),
            className: "dak-btn-outline"
          },
          React.createElement(Icons.GitHub),
          "Continue with GitHub"
        )
      ),

    step === "email" &&
      showSSO &&
      React.createElement(
        "button",
        {
          type: "button",
          onClick: () => setStep("sso"),
          className: "dak-btn-outline"
        },
        React.createElement(Icons.Building),
        "Single Sign-On (SAML / OIDC)"
      )
  );
}

/**
 * Drop-in <SignUp /> component — alias to SignIn with signup branding.
 */
function SignUp(props = {}) {
  return React.createElement(SignIn, { ...props, initialStep: "email" });
}

/**
 * Drop-in <UserButton /> avatar & profile popover menu.
 */
function UserButton(props = {}) {
  assertReact();
  injectStylesOnce();

  const {
    appearance = {},
    showName = false,
    afterSignOutUrl = "/"
  } = props;

  const { useAuth } = require("./index");
  const auth = useAuth();

  const [isOpen, setIsOpen] = React.useState(false);
  const containerRef = React.useRef(null);

  const themeClass = appearance.theme === "light" ? "dak-theme-light" : "dak-theme-dark";

  // Close on outside click
  React.useEffect(() => {
    function handleClickOutside(event) {
      if (containerRef.current && !containerRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    }
    if (isOpen) {
      document.addEventListener("mousedown", handleClickOutside);
      return () => document.removeEventListener("mousedown", handleClickOutside);
    }
  }, [isOpen]);

  if (!auth.isAuthenticated || !auth.user) {
    return null;
  }

  const email = auth.user.email || "user@devauthkit.com";
  const initials = email.substring(0, 2).toUpperCase();

  const handleSignOut = async () => {
    await auth.logout();
    setIsOpen(false);
    if (afterSignOutUrl && typeof window !== "undefined") {
      window.location.href = afterSignOutUrl;
    }
  };

  return React.createElement(
    "div",
    {
      ref: containerRef,
      style: { position: "relative", display: "inline-flex", alignItems: "center", gap: 8 }
    },
    React.createElement(
      "div",
      {
        onClick: () => setIsOpen(!isOpen),
        className: "dak-avatar",
        title: email
      },
      initials
    ),
    showName &&
      React.createElement(
        "span",
        { style: { fontSize: 13, fontWeight: 500, cursor: "pointer" }, onClick: () => setIsOpen(!isOpen) },
        email
      ),
    isOpen &&
      React.createElement(
        "div",
        { className: `dak-popover ${themeClass}` },
        React.createElement(
          "div",
          { style: { display: "flex", alignItems: "center", gap: 10, paddingBottom: 10, borderBottom: "1px solid #334155" } },
          React.createElement("div", { className: "dak-avatar" }, initials),
          React.createElement(
            "div",
            { style: { overflow: "hidden" } },
            React.createElement("div", { style: { fontSize: 13, fontWeight: 600, textOverflow: "ellipsis", overflow: "hidden", whiteSpace: "nowrap" } }, email),
            auth.isDPoPBound &&
              React.createElement(
                "span",
                { className: "dak-badge dak-badge-dpop", style: { marginTop: 4 } },
                React.createElement(Icons.Shield),
                "DPoP Protected"
              )
          )
        ),
        React.createElement(
          "div",
          { style: { marginTop: 8 } },
          React.createElement(
            "button",
            {
              onClick: handleSignOut,
              className: "dak-btn-outline",
              style: { width: "100%", justifyContent: "flex-start", marginBottom: 0, color: "#f87171" }
            },
            "Sign Out"
          )
        )
      )
  );
}

/**
 * Drop-in <OrganizationSwitcher /> workspace dropdown component.
 */
function OrganizationSwitcher(props = {}) {
  assertReact();
  injectStylesOnce();

  const { appearance = {} } = props;
  const { useAuth, useOrg } = require("./index");
  const auth = useAuth();
  const orgContext = useOrg();

  const [isOpen, setIsOpen] = React.useState(false);
  const [showCreateModal, setShowCreateModal] = React.useState(false);
  const [newOrgName, setNewOrgName] = React.useState("");
  const [isLoading, setIsLoading] = React.useState(false);

  const containerRef = React.useRef(null);
  const themeClass = appearance.theme === "light" ? "dak-theme-light" : "dak-theme-dark";

  React.useEffect(() => {
    function handleClickOutside(event) {
      if (containerRef.current && !containerRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    }
    if (isOpen) {
      document.addEventListener("mousedown", handleClickOutside);
      return () => document.removeEventListener("mousedown", handleClickOutside);
    }
  }, [isOpen]);

  if (!auth.isAuthenticated) return null;

  const currentOrg = orgContext.activeOrg;
  const orgName = currentOrg ? currentOrg.name : "Personal Workspace";

  const handleCreateOrg = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (!newOrgName) return;
    try {
      setIsLoading(true);
      await orgContext.createOrg({ name: newOrgName });
      setNewOrgName("");
      setShowCreateModal(false);
      setIsOpen(false);
    } catch (err) {
      alert(err.message || "Failed to create organization");
    } finally {
      setIsLoading(false);
    }
  };

  return React.createElement(
    "div",
    { ref: containerRef, style: { position: "relative", display: "inline-block" } },
    React.createElement(
      "button",
      {
        onClick: () => setIsOpen(!isOpen),
        className: "dak-btn-outline",
        style: { width: "auto", padding: "6px 12px", borderRadius: 8, gap: 8 }
      },
      React.createElement(Icons.Building),
      React.createElement("span", { style: { fontWeight: 600 } }, orgName),
      React.createElement(Icons.ChevronDown)
    ),

    isOpen &&
      React.createElement(
        "div",
        { className: `dak-popover ${themeClass}`, style: { width: 240, left: 0, right: "auto" } },
        React.createElement("div", { style: { fontSize: 11, fontWeight: 700, color: "#94a3b8", textTransform: "uppercase", padding: "4px 8px" } }, "Organizations"),
        (orgContext.organizations || []).map((org) =>
          React.createElement(
            "div",
            {
              key: org.id,
              onClick: async () => {
                await orgContext.switchOrg(org.id);
                setIsOpen(false);
              },
              style: {
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "8px 10px",
                borderRadius: 6,
                cursor: "pointer",
                fontSize: 13,
                fontWeight: currentOrg?.id === org.id ? 600 : 400,
                background: currentOrg?.id === org.id ? "rgba(99, 102, 241, 0.15)" : "transparent"
              }
            },
            React.createElement("span", null, org.name),
            currentOrg?.id === org.id && React.createElement(Icons.Check)
          )
        ),
        React.createElement("div", { style: { borderTop: "1px solid #334155", margin: "8px 0" } }),
        React.createElement(
          "button",
          {
            onClick: () => setShowCreateModal(true),
            className: "dak-btn-outline",
            style: { width: "100%", justifyContent: "flex-start", marginBottom: 0 }
          },
          "+ Create Organization"
        )
      ),

    showCreateModal &&
      React.createElement(
        "div",
        {
          style: {
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0, 0, 0, 0.6)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 10000
          }
        },
        React.createElement(
          "div",
          { className: `dak-card ${themeClass}`, style: { maxWidth: 360 } },
          React.createElement("h3", { className: "dak-title" }, "Create Organization"),
          React.createElement("p", { className: "dak-subtitle" }, "Create a shared multi-tenant workspace for your team."),
          React.createElement(
            "form",
            { onSubmit: handleCreateOrg },
            React.createElement("input", {
              type: "text",
              required: true,
              placeholder: "Acme Corp",
              value: newOrgName,
              onChange: (e) => setNewOrgName(e.target.value),
              className: "dak-input"
            }),
            React.createElement(
              "div",
              { style: { display: "flex", gap: 8, marginTop: 12 } },
              React.createElement(
                "button",
                {
                  type: "button",
                  onClick: () => setShowCreateModal(false),
                  className: "dak-btn-outline",
                  style: { flex: 1, marginBottom: 0 }
                },
                "Cancel"
              ),
              React.createElement(
                "button",
                {
                  type: "submit",
                  disabled: isLoading,
                  className: "dak-btn-primary",
                  style: { flex: 1 }
                },
                isLoading ? React.createElement(Icons.Spinner) : "Create"
              )
            )
          )
        )
      )
  );
}

/**
 * Drop-in <UserProfile /> comprehensive account settings modal/card.
 */
function UserProfile(props = {}) {
  assertReact();
  injectStylesOnce();

  const { appearance = {} } = props;
  const { useAuth, useSessions, useApiKeys } = require("./index");
  const auth = useAuth();
  const sessionManager = useSessions();
  const apiKeyManager = useApiKeys();

  const [activeTab, setActiveTab] = React.useState("general"); // 'general' | 'sessions' | 'keys'
  const [newKeyName, setNewKeyName] = React.useState("");
  const [newKeyResult, setNewKeyResult] = React.useState(null);

  const themeClass = appearance.theme === "light" ? "dak-theme-light" : "dak-theme-dark";

  if (!auth.isAuthenticated || !auth.user) return null;

  const handleCreateApiKey = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (!newKeyName) return;
    try {
      const res = await apiKeyManager.createApiKey({ name: newKeyName, scopes: ["*"] });
      const createdSecret = res.rawKey || (typeof res.key === "string" ? res.key : res.key?.maskedKey || res.key?.id);
      setNewKeyResult(createdSecret || null);
      setNewKeyName("");
    } catch (err) {
      alert(err.message || "Failed to create API key");
    }
  };

  return React.createElement(
    "div",
    { className: `dak-card ${themeClass} ${appearance.className || ""}`, style: { maxWidth: 540 } },
    React.createElement(
      "div",
      { style: { display: "flex", gap: 12, borderBottom: "1px solid #334155", paddingBottom: 12, marginBottom: 16 } },
      ["general", "sessions", "keys"].map((tab) =>
        React.createElement(
          "button",
          {
            key: tab,
            onClick: () => setActiveTab(tab),
            style: {
              background: "none",
              border: "none",
              cursor: "pointer",
              fontWeight: 600,
              fontSize: 13,
              textTransform: "capitalize",
              color: activeTab === tab ? "#6366f1" : "#94a3b8",
              borderBottom: activeTab === tab ? "2px solid #6366f1" : "2px solid transparent",
              paddingBottom: 6
            }
          },
          tab === "general" ? "Account" : tab === "sessions" ? "Security & Devices" : "API Keys"
        )
      )
    ),

    activeTab === "general" &&
      React.createElement(
        "div",
        null,
        React.createElement("h3", { style: { fontSize: 16, marginBottom: 12 } }, "User Details"),
        React.createElement("p", { style: { fontSize: 13, color: "#94a3b8", marginBottom: 6 } }, `Email: ${auth.user.email}`),
        React.createElement("p", { style: { fontSize: 13, color: "#94a3b8", marginBottom: 6 } }, `User ID: ${auth.user.id}`),
        React.createElement(
          "div",
          { style: { marginTop: 14 } },
          React.createElement(
            "span",
            { className: "dak-badge dak-badge-dpop" },
            React.createElement(Icons.Shield),
            auth.isDPoPBound ? "DPoP Hardware Cryptographically Bound" : "Standard Bearer Mode"
          )
        )
      ),

    activeTab === "sessions" &&
      React.createElement(
        "div",
        null,
        React.createElement("h3", { style: { fontSize: 16, marginBottom: 12 } }, "Active Sessions"),
        React.createElement(
          "button",
          {
            onClick: () => sessionManager.revokeOtherSessions(),
            className: "dak-btn-outline",
            style: { color: "#f87171", marginBottom: 14 }
          },
          "Revoke All Other Devices"
        ),
        (sessionManager.sessions || []).map((sess) =>
          React.createElement(
            "div",
            {
              key: sess.id,
              style: {
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                padding: "10px 12px",
                border: "1px solid #334155",
                borderRadius: 8,
                marginBottom: 8,
                fontSize: 13
              }
            },
            React.createElement(
              "div",
              null,
              React.createElement("div", { style: { fontWeight: 600 } }, `${sess.device?.os || sess.operatingSystem || "Device"} • ${sess.device?.browser || sess.browser || "Browser"}`),
              React.createElement("div", { style: { fontSize: 11, color: "#94a3b8" } }, `IP: ${sess.ip || sess.ipAddress || "Unknown"} | ${sess.isCurrent ? "Current Session" : "Active"}`)
            ),
            !sess.isCurrent &&
              React.createElement(
                "button",
                {
                  onClick: () => sessionManager.revokeSession(sess.id),
                  style: { background: "none", border: "none", color: "#f87171", cursor: "pointer", fontSize: 12 }
                },
                "Revoke"
              )
          )
        )
      ),

    activeTab === "keys" &&
      React.createElement(
        "div",
        null,
        React.createElement("h3", { style: { fontSize: 16, marginBottom: 12 } }, "Machine API Keys"),
        React.createElement(
          "form",
          { onSubmit: handleCreateApiKey, style: { display: "flex", gap: 8, marginBottom: 16 } },
          React.createElement("input", {
            type: "text",
            required: true,
            placeholder: "Key Name (e.g. CI/CD)",
            value: newKeyName,
            onChange: (e) => setNewKeyName(e.target.value),
            className: "dak-input",
            style: { marginBottom: 0 }
          }),
          React.createElement(
            "button",
            { type: "submit", className: "dak-btn-primary", style: { width: "auto", whiteSpace: "nowrap" } },
            "Generate Key"
          )
        ),
        newKeyResult &&
          React.createElement(
            "div",
            { className: "dak-alert dak-alert-success", style: { wordBreak: "break-all" } },
            React.createElement("div", { style: { fontWeight: 700 } }, "Key Created (Save this now):"),
            newKeyResult
          ),
        (apiKeyManager.apiKeys || []).map((k) =>
          React.createElement(
            "div",
            {
              key: k.id,
              style: {
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                padding: "8px 12px",
                border: "1px solid #334155",
                borderRadius: 8,
                marginBottom: 6,
                fontSize: 13
              }
            },
            React.createElement(
              "div",
              null,
              React.createElement("div", { style: { fontWeight: 600 } }, k.name || "API Key"),
              React.createElement("div", { style: { fontSize: 11, color: "#94a3b8" } }, `Prefix: ${k.prefix || k.maskedKey || k.keyPrefix || "dak_"}...`)
            ),
            React.createElement(
              "button",
              {
                onClick: () => apiKeyManager.revokeApiKey(k.id),
                style: { background: "none", border: "none", color: "#f87171", cursor: "pointer", fontSize: 12 }
              },
              "Revoke"
            )
          )
        )
      )
  );
}

module.exports = {
  SignIn,
  SignUp,
  UserButton,
  OrganizationSwitcher,
  UserProfile,
  Icons
};

