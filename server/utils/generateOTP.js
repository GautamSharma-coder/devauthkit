// server/utils/generateOTP.js
const { randomBytes } = require("./webCrypto");

/**
 * Generate a cryptographically secure numeric OTP of specified length.
 * @param {number} length - Default is 6 digits
 * @returns {string} - The generated OTP as string
 */
module.exports = function generateOTP(length = 6) {
  if (!Number.isInteger(length) || length < 1 || length > 9) {
    throw new TypeError("OTP length must be an integer between 1 and 9");
  }
  const min = Math.pow(10, length - 1);
  const range = Math.pow(10, length) - min;
  const limit = Math.floor(0x100000000 / range) * range;
  let value;
  do {
    const bytes = randomBytes(4);
    value = new DataView(bytes.buffer).getUint32(0);
  } while (value >= limit);
  return (min + (value % range)).toString();
};
