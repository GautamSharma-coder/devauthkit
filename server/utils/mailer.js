// server/utils/mailer.js
const config = require("../config");

/**
 * Send email using Resend HTTP API (zero external SDK required)
 */
async function sendViaResend({ email, otp, magicLinkUrl }) {
  const apiKey = config.get("resendApiKey");
  const fromEmail = config.get("fromEmail") || "onboarding@resend.dev";
  const otpExpiryMinutes = config.get("otpExpiryMinutes");

  const magicLinkButton = magicLinkUrl
    ? `
      <div style="margin: 24px 0; text-align: center;">
        <a href="${magicLinkUrl}" style="background-color: #0f172a; color: #ffffff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 600; display: inline-block;">Sign in with Magic Link</a>
      </div>
      <p style="text-align: center; color: #64748b; font-size: 13px;">Or use the one-time password below:</p>
    `
    : `<p style="color: #475569; font-size: 15px;">Use the following one-time password (OTP) to complete your sign-in:</p>`;

  const html = `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px; border: 1px solid #e2e8f0; border-radius: 8px;">
      <h2 style="color: #1e293b; margin-top: 0;">DevAuthKit 🔐</h2>
      ${magicLinkButton}
      <div style="background-color: #f1f5f9; padding: 16px; border-radius: 6px; text-align: center; margin: 24px 0;">
        <span style="font-size: 32px; font-weight: 700; letter-spacing: 6px; color: #0f172a;">${otp}</span>
      </div>
      <p style="color: #64748b; font-size: 13px;">This code expires in ${otpExpiryMinutes} minutes. If you did not request this code, you can safely ignore this email.</p>
    </div>
  `;

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: fromEmail,
      to: [email],
      subject: "Your DevAuthKit Verification Code",
      text: magicLinkUrl
        ? `Sign in with Magic Link: ${magicLinkUrl}\n\nOr use your OTP: ${otp}. It will expire in ${otpExpiryMinutes} minutes.`
        : `Your OTP is: ${otp}. It will expire in ${otpExpiryMinutes} minutes.`,
      html
    })
  });

  if (!res.ok) {
    const errorBody = await res.text();
    throw new Error(`Resend API error (${res.status}): ${errorBody}`);
  }
}

/**
 * Send OTP via email or print to console if in devMode.
 * @param {Object} params - { email, otp, magicLinkUrl }
 * @returns {Promise<{ success: boolean, devMode?: boolean }>}
 */
async function sendOTP({ email, otp, magicLinkUrl }) {
  const isDevMode = config.get("devMode");
  const customMailer = config.get("mailer");
  const emailProvider = config.get("emailProvider");
  const resendApiKey = config.get("resendApiKey");
  const smtpMailerAvailable = typeof config.get("smtpMailer") === "function" &&
    config.get("smtpMailerAvailable") !== false;

  // 1. If developer passed a custom mailer function: e.g. async ({ email, otp, magicLinkUrl }) => ...
  if (typeof customMailer === "function") {
    await customMailer({ email, otp, magicLinkUrl });
    return { success: true };
  }

  const hasResend = Boolean(emailProvider === "resend" && resendApiKey);
  const smtpMailer = config.get("smtpMailer");

  // 2. Log credentials only when development logging was explicitly enabled
  if (isDevMode) {
    console.log("\n" + "=".repeat(52));
    console.log("  [DevAuthKit] 🔑 DEV MODE OTP NOTIFICATION");
    console.log("=".repeat(52));
    console.log(`  To:         ${email}`);
    console.log(`  OTP:        ${otp}`);
    if (magicLinkUrl) {
      console.log(`  Magic Link: ${magicLinkUrl}`);
    }
    console.log(`  Expires:    ${config.get("otpExpiryMinutes")} minutes`);
    console.log("=".repeat(52) + "\n");
    return { success: true, devMode: true };
  }

  // 3. Resend email provider delivery
  if (hasResend) {
    await sendViaResend({ email, otp, magicLinkUrl });
    return { success: true, devMode: false, provider: "resend" };
  }

  if (typeof smtpMailer !== "function") {
    throw new Error("OTP delivery is unavailable; configure a mailer, SMTP, or Resend");
  }
  await smtpMailer({ email, otp, magicLinkUrl });

  return { success: true, devMode: false, provider: "smtp" };
}

module.exports = {
  sendOTP
};