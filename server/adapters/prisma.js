const DEFAULT_FIELDS = {
  id: "id",
  email: "email",
  role: "role"
};

function prismaAdapter(prisma, options = {}) {
  if (!prisma || typeof prisma !== "object") {
    throw new TypeError("prismaAdapter requires a Prisma client instance");
  }

  const modelName = options.model || "user";
  const fields = { ...DEFAULT_FIELDS, ...options.fields };
  if (typeof modelName !== "string" || !modelName.trim()) {
    throw new TypeError("prismaAdapter model must be a non-empty string");
  }
  if (Object.values(fields).some((field) => typeof field !== "string" || !field.trim())) {
    throw new TypeError("prismaAdapter field mappings must be non-empty strings");
  }

  return {
    async findOrCreateUser({ email }) {
      const model = prisma[modelName];
      if (!model || typeof model.upsert !== "function") {
        throw new TypeError(`Prisma model "${modelName}" must expose an upsert method`);
      }

      const record = await model.upsert({
        where: { [fields.email]: email },
        update: {},
        create: { [fields.email]: email }
      });

      if (!record || record[fields.id] === undefined || !record[fields.email]) {
        throw new TypeError(
          `Prisma model "${modelName}" must return the configured id and email fields`
        );
      }

      return {
        ...record,
        id: record[fields.id],
        email: record[fields.email],
        ...(record[fields.role] !== undefined ? { role: record[fields.role] } : {})
      };
    }
  };
}

module.exports = prismaAdapter;
module.exports.prismaAdapter = prismaAdapter;
