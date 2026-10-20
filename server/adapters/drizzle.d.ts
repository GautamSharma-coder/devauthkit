import type { UserAdapter } from "../../index";

export interface DrizzleAdapterOptions<TTable = any> {
  table: TTable;
  eq?: (column: any, value: any) => any;
  fields?: {
    id?: string;
    email?: string;
    role?: string;
  };
}

export function drizzleAdapter<TDb extends object, TTable extends object>(
  db: TDb,
  options: DrizzleAdapterOptions<TTable>
): UserAdapter;

export default drizzleAdapter;
