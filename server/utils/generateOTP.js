// server/utils/generateOTP.js
const { randomBytes } = require("./webCrypto");

/**
 * Generate a cryptographically secure numeric OTP of the specified length.
 * Uses rejection sampling over 32-bit random values to avoid modulo bias.
 *
 * @param {number} [length=6] - Number of digits in the generated OTP. Must be an integer between 1 and 9 (inclusive).
 * @returns {string} A numeric OTP string of the requested length (digits `0`-`9`, with values in `[10^(length - 1), 10^length - 1]`).
 * @throws {TypeError} Throws if `length` is not an integer between 1 and 9.
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
