// server/utils/mailer.js
const nodemailer = require("nodemailer");
const config = require("../config");

let transporter = null;

function getTransporter() {
  const customTransporter = config.get("transporter");
  if (customTransporter) return customTransporter;

  const emailUser = process.env.EMAIL_USER;
  const emailPass = process.env.EMAIL_PASS;

  if (emailUser && emailPass && emailUser !== "your-email@example.com") {
    if (!transporter) {
      transporter = nodemailer.createTransport({
        service: config.get("emailService") || "gmail",
        auth: {
          user: emailUser,
          pass: emailPass,
        },
      });
    }
    return transporter;
  }
  return null;
}

/**
 * Send OTP via email or print to console if in devMode.
 * @param {Object} params - { email, otp }
 * @returns {Promise<{ success: boolean, devMode?: boolean }>}
 */
async function sendOTP({ email, otp }) {
  const isDevMode = config.get("devMode");
  const customMailer = config.get("mailer");

  // If developer passed a custom mailer function: e.g. async ({ email, otp }) => ...
  if (typeof customMailer === "function") {
    await customMailer({ email, otp });
    return { success: true };
  }

  const activeTransporter = getTransporter();

  // If in Dev Mode or no valid SMTP credentials provided, log to console
  if (isDevMode || !activeTransporter) {
    console.log("\n" + "=".repeat(52));
    console.log("  [DevAuthKit] 🔑 DEV MODE OTP NOTIFICATION");
    console.log("=".repeat(52));
    console.log(`  To:      ${email}`);
    console.log(`  OTP:     ${otp}`);
    console.log(`  Expires: ${config.get("otpExpiryMinutes")} minutes`);
    console.log("=".repeat(52) + "\n");
    return { success: true, devMode: true };
  }

  // Real SMTP delivery
  await activeTransporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your DevAuthKit Verification Code",
    text: `Your OTP is: ${otp}. It will expire in ${config.get("otpExpiryMinutes")} minutes.`,
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px; border: 1px solid #e2e8f0; border-radius: 8px;">
        <h2 style="color: #1e293b; margin-top: 0;">DevAuthKit 🔐</h2>
        <p style="color: #475569; font-size: 15px;">Use the following one-time password (OTP) to complete your sign-in:</p>
        <div style="background-color: #f1f5f9; padding: 16px; border-radius: 6px; text-align: center; margin: 24px 0;">
          <span style="font-size: 32px; font-weight: 700; letter-spacing: 6px; color: #0f172a;">${otp}</span>
        </div>
        <p style="color: #64748b; font-size: 13px;">This code expires in ${config.get("otpExpiryMinutes")} minutes. If you did not request this code, you can safely ignore this email.</p>
      </div>
    `
  });

  return { success: true, devMode: false };
}

module.exports = {
  sendOTP,
  getTransporter
};