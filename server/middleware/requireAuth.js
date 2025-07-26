// server/middleware/requireAuth.js
const sessionStore = require("../sessionStore");

module.exports = (req, res, next) => {
  const user = req.session.user;
  if (user && sessionStore[user.email]?.verified) {
    return next();
  }
  res.status(401).json({ error: "Unauthorized" });
};