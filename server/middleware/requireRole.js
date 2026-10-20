// server/middleware/requireRole.js
const requireAuth = require("./requireAuth");

/**
 * Role-Based Access Control (RBAC) middleware for route authorization.
 * Can be used standalone (automatically enforces requireAuth if user is not already attached)
 * or chained after requireAuth.
 *
 * @param {string|string[]} allowedRoles - Role name or array of allowed roles (e.g. "admin", ["admin", "moderator"])
 * @param {Object} [options]
 * @param {string} [options.roleKey="role"] - Field name on req.user representing the user role
 * @param {string} [options.errorMessage="Forbidden: Insufficient permissions"] - Custom 403 error message
 */
function requireRole(allowedRoles, options = {}) {
  const roles = Array.isArray(allowedRoles)
    ? allowedRoles
    : typeof allowedRoles === "string"
      ? [allowedRoles]
      : [];

  if (roles.length === 0) {
    throw new TypeError("requireRole requires at least one allowed role (string or array of strings)");
  }

  const roleKey = options.roleKey || "role";
  const errorMessage = options.errorMessage || "Forbidden: Insufficient permissions";

  return async function roleMiddleware(req, res, next) {
    const checkRole = (user) => {
      const userRole = user[roleKey];
      const userRoles = Array.isArray(user.roles)
        ? user.roles
        : Array.isArray(user[roleKey])
          ? user[roleKey]
          : (userRole ? [userRole] : []);

      const hasAccess = roles.some((role) => userRoles.includes(role) || userRole === role);
      if (!hasAccess) {
        return res.status(403).json({ error: errorMessage });
      }
      return next();
    };

    if (!req.user) {
      return requireAuth(req, res, (err) => {
        if (err) return next(err);
        if (!req.user) {
          return res.status(401).json({ error: "Unauthorized: Authentication required" });
        }
        return checkRole(req.user);
      });
    }

    return checkRole(req.user);
  };
}

module.exports = requireRole;
