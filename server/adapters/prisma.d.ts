import type { UserAdapter } from "../../index";

export interface PrismaAdapterOptions {
  /** Prisma client model delegate name. @default "user" */
  model?: string;
  /** Model fields used for identity lookup and normalized user claims. */
  fields?: {
    id?: string;
    email?: string;
    role?: string;
  };
}

export function prismaAdapter<T extends object>(
  prisma: T,
  options?: PrismaAdapterOptions
): UserAdapter;

export default prismaAdapter;
