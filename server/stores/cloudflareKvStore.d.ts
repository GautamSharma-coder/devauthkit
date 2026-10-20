import type { OtpStore, RateLimitStore } from "../../index";

export interface CloudflareKvNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

export interface CloudflareMagicLinkRecord {
  email: string;
  expiresAt: number;
}

export interface AtomicCounterStore {
  get(key: string): number | Promise<number>;
  increment(key: string, ttlMs: number): number | Promise<number>;
  delete(key: string): void | Promise<void>;
}

export interface MagicLinkStore {
  get(tokenHash: string): CloudflareMagicLinkRecord | null | Promise<CloudflareMagicLinkRecord | null>;
  set(tokenHash: string, record: CloudflareMagicLinkRecord): void | Promise<void>;
  delete(tokenHash: string): void | Promise<void>;
}

export class CloudflareKvOtpStore implements OtpStore {
  constructor(namespace: CloudflareKvNamespace, options: {
    keyPrefix?: string;
    ttlSeconds?: number;
    counterStore: AtomicCounterStore;
  });
  get(email: string): Promise<{ otp: string; attempts: number; createdAt: number } | null>;
  set(email: string, data: { otp: string; attempts: number; createdAt: number }): Promise<void>;
  delete(email: string): Promise<void>;
  recordAttempt(email: string): Promise<number>;
}

export class CloudflareKvRateLimitStore implements RateLimitStore {
  constructor(namespace: CloudflareKvNamespace, options: {
    keyPrefix?: string;
    counterStore: Pick<AtomicCounterStore, "increment">;
  });
  increment(key: string, windowMs: number): Promise<number>;
}

export class CloudflareKvMagicLinkStore implements MagicLinkStore {
  constructor(namespace: CloudflareKvNamespace, options?: { keyPrefix?: string });
  get(tokenHash: string): Promise<CloudflareMagicLinkRecord | null>;
  set(tokenHash: string, record: CloudflareMagicLinkRecord): Promise<void>;
  delete(tokenHash: string): Promise<void>;
}
