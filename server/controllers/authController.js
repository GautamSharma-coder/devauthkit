// server/controllers/authController.js
const transporter = require("../utils/mailer");
const generateOTP = require("../utils/generateOTP");
const sessionStore = require("../sessionStore");

exports.requestOTP = async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  const otp = generateOTP();
  sessionStore[email] = { otp, verified: false, createdAt: Date.now() };

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your DevAuthKit OTP",
    text: `Your OTP is ${otp}`,
  });

  res.json({ message: "OTP sent" });
};

exports.verifyOTP = (req, res) => {
  const { email, otp } = req.body;
  const user = sessionStore[email];

  if (!user || user.otp !== otp) return res.status(401).json({ error: "Invalid OTP" });
  if (Date.now() - user.createdAt > 5 * 60 * 1000) return res.status(401).json({ error: "OTP expired" });

  req.session.user = { email };
  user.verified = true;
  res.json({ message: "Logged in" });
};