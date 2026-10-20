const nodemailer = require("nodemailer");
const config = require("../config");

let transporter = null;

function getTransporter() {
  const customTransporter = config.get("transporter");
  if (customTransporter) return customTransporter;

  const emailUser = process.env.EMAIL_USER;
  const emailPass = process.env.EMAIL_PASS;
  if (!emailUser || !emailPass || emailUser === "your-email@example.com") return null;

  if (!transporter) {
    transporter = nodemailer.createTransport({
      service: config.get("emailService") || "gmail",
      auth: { user: emailUser, pass: emailPass }
    });
  }
  return transporter;
}

async function sendSMTPOTP({ email, otp, magicLinkUrl }) {
  const activeTransporter = getTransporter();
  if (!activeTransporter) throw new Error("SMTP credentials are not configured");

  const magicLinkContent = magicLinkUrl
    ? `<p><a href="${magicLinkUrl}">Sign in with Magic Link</a></p>`
    : "<p>Use the following one-time password to complete your sign-in:</p>";

  await activeTransporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your DevAuthKit Verification Code",
    text: magicLinkUrl
      ? `Sign in with Magic Link: ${magicLinkUrl}\n\nOr use OTP: ${otp}. It will expire in ${config.get("otpExpiryMinutes")} minutes.`
      : `Your OTP is: ${otp}. It will expire in ${config.get("otpExpiryMinutes")} minutes.`,
    html: `<div><h2>DevAuthKit</h2>${magicLinkContent}<p style="font-size:32px;letter-spacing:6px">${otp}</p><p>This code expires in ${config.get("otpExpiryMinutes")} minutes.</p></div>`
  });
}

sendSMTPOTP.isConfigured = () => Boolean(
  config.get("transporter") ||
  (process.env.EMAIL_USER && process.env.EMAIL_USER !== "your-email@example.com" && process.env.EMAIL_PASS)
);

module.exports = sendSMTPOTP;
