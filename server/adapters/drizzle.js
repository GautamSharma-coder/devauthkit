const DEFAULT_FIELDS = {
  id: "id",
  email: "email",
  role: "role"
};

/**
 * Creates a DevAuthKit user adapter for Drizzle ORM.
 *
 * @param {Object} db - Drizzle database client instance
 * @param {Object} options
 * @param {Object} options.table - Drizzle table schema object
 * @param {Function} [options.eq] - Optional Drizzle eq operator function
 * @param {Object} [options.fields] - Custom field mappings { id, email, role }
 */
function drizzleAdapter(db, options = {}) {
  if (!db || typeof db !== "object") {
    throw new TypeError("drizzleAdapter requires a Drizzle database instance");
  }

  const table = options.table;
  if (!table || typeof table !== "object") {
    throw new TypeError("drizzleAdapter requires a valid Drizzle table schema in options.table");
  }

  const fields = { ...DEFAULT_FIELDS, ...options.fields };
  if (Object.values(fields).some((field) => typeof field !== "string" || !field.trim())) {
    throw new TypeError("drizzleAdapter field mappings must be non-empty strings");
  }

  return {
    async findOrCreateUser({ email }) {
      const normalizedEmail = email.trim().toLowerCase();

      // 1. Try finding existing user
      if (typeof db.select === "function") {
        let query = db.select().from(table);
        if (typeof options.eq === "function" && table[fields.email]) {
          query = query.where(options.eq(table[fields.email], normalizedEmail));
        }
        const rows = await query;
        const existing = Array.isArray(rows)
          ? rows.find((r) => String(r[fields.email]).toLowerCase() === normalizedEmail) || (rows.length === 1 && String(rows[0][fields.email]).toLowerCase() === normalizedEmail ? rows[0] : null)
          : null;

        if (existing && existing[fields.id] !== undefined) {
          return {
            ...existing,
            id: existing[fields.id],
            email: existing[fields.email],
            ...(existing[fields.role] !== undefined ? { role: existing[fields.role] } : {})
          };
        }
      }

      // 2. Insert new user
      if (typeof db.insert === "function") {
        let insertBuilder = db.insert(table).values({ [fields.email]: normalizedEmail });
        if (typeof insertBuilder.returning === "function") {
          insertBuilder = insertBuilder.returning();
        }
        const result = await insertBuilder;
        let created = Array.isArray(result) ? result[0] : result;

        if (!created || created[fields.id] === undefined) {
          if (typeof db.select === "function") {
            const rows = await db.select().from(table);
            created = Array.isArray(rows) ? rows.find((r) => String(r[fields.email]).toLowerCase() === normalizedEmail) : null;
          }
        }

        if (!created || created[fields.id] === undefined) {
          throw new TypeError(`Drizzle table must return the configured "${fields.id}" and "${fields.email}" fields`);
        }

        return {
          ...created,
          id: created[fields.id],
          email: created[fields.email],
          ...(created[fields.role] !== undefined ? { role: created[fields.role] } : {})
        };
      }

      throw new TypeError("Drizzle database instance must support select and insert operations");
    }
  };
}

module.exports = drizzleAdapter;
module.exports.drizzleAdapter = drizzleAdapter;
