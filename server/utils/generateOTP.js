// server/utils/generateOTP.js
module.exports = function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
};
