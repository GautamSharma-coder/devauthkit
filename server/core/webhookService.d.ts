import type { Request, Response, NextFunction } from "express";

export class WebhookVerificationError extends Error {
  code: string;
  constructor(message: string, code?: string);
}

export function generateWebhookSecret(prefix?: string): string;

export function computeWebhookSignature(
  rawBody: string | Buffer | Uint8Array,
  secret: string,
  timestamp: number | string
): Promise<string>;

export function buildSignatureHeader(
  signature: string,
  timestamp: number | string
): string;

export function parseSignatureHeader(
  header: string
): { timestamp: number; signatures: string[] };

export function verifyWebhookSignature(options: {
  rawBody: string | Buffer | Uint8Array;
  signatureHeader: string;
  secret: string;
  toleranceSeconds?: number;
}): Promise<boolean>;

export function matchesEvent(
  subscribedEvents: string | string[],
  incomingEvent: string
): boolean;

export interface WebhookHandlerOptions {
  secret: string | (() => string | Promise<string>);
  toleranceSeconds?: number;
  onEvent?: (event: {
    id: string;
    event: string;
    timestamp: number;
    data: any;
  }) => void | Promise<void>;
  onError?: (err: Error, req: Request, res: Response) => void;
}

export function createWebhookHandler(
  options: WebhookHandlerOptions
): (req: Request, res: Response, next?: NextFunction) => Promise<any>;
