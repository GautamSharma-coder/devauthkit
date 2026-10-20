import type { UserAdapter } from "../../index";

export interface MongooseAdapterOptions {
  fields?: {
    id?: string;
    email?: string;
    role?: string;
  };
}

export function mongooseAdapter<TModel extends object>(
  model: TModel,
  options?: MongooseAdapterOptions
): UserAdapter;

export default mongooseAdapter;
