import type { Hono, MiddlewareHandler } from "hono";
import type { DevAuthConfigOptions } from "../../index";

export function createAuthRouter(options: DevAuthConfigOptions & { jwtSecret: string }): Hono;
export function requireAuth(): MiddlewareHandler;
export function requireDPoP(): MiddlewareHandler;
export function requireOrg(): MiddlewareHandler;
export function requireOrgRole(allowedRoles: string | string[], options?: { errorMessage?: string }): MiddlewareHandler;
export function requireOrgPermission(requiredPermission: string, options?: { errorMessage?: string }): MiddlewareHandler;
