const DEFAULT_FIELDS = {
  id: "_id",
  email: "email",
  role: "role"
};

/**
 * Creates a DevAuthKit user adapter for Mongoose (MongoDB).
 *
 * @param {Object} model - Mongoose Model instance
 * @param {Object} [options]
 * @param {Object} [options.fields] - Custom field mappings { id, email, role }
 */
function mongooseAdapter(model, options = {}) {
  if (!model || (typeof model.findOneAndUpdate !== "function" && typeof model.findOne !== "function")) {
    throw new TypeError("mongooseAdapter requires a valid Mongoose model instance");
  }

  const fields = { ...DEFAULT_FIELDS, ...options.fields };
  if (Object.values(fields).some((field) => typeof field !== "string" || !field.trim())) {
    throw new TypeError("mongooseAdapter field mappings must be non-empty strings");
  }

  return {
    async findOrCreateUser({ email }) {
      const normalizedEmail = email.trim().toLowerCase();

      let record;
      if (typeof model.findOneAndUpdate === "function") {
        const query = model.findOneAndUpdate(
          { [fields.email]: normalizedEmail },
          { $setOnInsert: { [fields.email]: normalizedEmail } },
          { new: true, upsert: true, setDefaultsOnInsert: true }
        );
        record = typeof query.lean === "function" ? await query.lean() : await query;
      } else {
        record = await model.findOne({ [fields.email]: normalizedEmail });
        if (!record && typeof model.create === "function") {
          record = await model.create({ [fields.email]: normalizedEmail });
        }
      }

      if (record && typeof record.toObject === "function") {
        record = record.toObject();
      }

      const idVal = record ? (record[fields.id] !== undefined ? record[fields.id] : record.id || record._id) : undefined;
      const emailVal = record ? record[fields.email] : undefined;

      if (!record || idVal === undefined || !emailVal) {
        throw new TypeError(
          `Mongoose model must return configured "${fields.id}" and "${fields.email}" fields`
        );
      }

      return {
        ...record,
        id: String(idVal),
        email: emailVal,
        ...(record[fields.role] !== undefined ? { role: record[fields.role] } : {})
      };
    }
  };
}

module.exports = mongooseAdapter;
module.exports.mongooseAdapter = mongooseAdapter;
