// server/utils/generateOTP.js
const crypto = require("crypto");

/**
 * Generate a cryptographically secure numeric OTP of specified length.
 * @param {number} length - Default is 6 digits
 * @returns {string} - The generated OTP as string
 */
module.exports = function generateOTP(length = 6) {
  const min = Math.pow(10, length - 1);
  const max = Math.pow(10, length) - 1;
  return crypto.randomInt(min, max + 1).toString();
};
