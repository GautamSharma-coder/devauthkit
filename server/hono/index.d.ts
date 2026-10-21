import type { Hono, MiddlewareHandler } from "hono";
import type { DevAuthConfigOptions } from "../../index";

export function createAuthRouter(options: DevAuthConfigOptions & { jwtSecret: string }): Hono;
export function requireAuth(): MiddlewareHandler;
export function requireDPoP(): MiddlewareHandler;
