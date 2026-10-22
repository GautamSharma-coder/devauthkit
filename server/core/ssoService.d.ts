export class SsoError extends Error {
  code: string;
  status: number;
  constructor(message: string, code?: string, status?: number);
}

export function formatX509Cert(rawCert: string): string;

export function canonicalizeXml(xmlString: string): string;

export function computeXmlDigest(xml: string, algorithm?: "sha256" | "sha1"): string;

export function verifyRsaSignature(
  data: string,
  signatureBase64: string,
  certPem: string,
  algorithm?: "RSA-SHA256" | "RSA-SHA1"
): boolean;

export interface VerifySamlOptions {
  samlResponse: string;
  idpCertificates: string | string[];
  spEntityId?: string;
  clockSkewSeconds?: number;
  replayStore?: {
    isUsed(id: string): Promise<boolean> | boolean;
    record(id: string, ttlSeconds: number): Promise<boolean> | boolean;
  };
}

export interface SamlIdentityResult {
  nameId: string;
  email: string;
  displayName?: string;
  firstName?: string;
  lastName?: string;
  groups: string[];
  attributes: Record<string, string | string[]>;
  assertionId: string;
  promotedCert?: string | null;
}

export function verifySamlResponse(options: VerifySamlOptions): Promise<SamlIdentityResult>;

export function generateSamlAuthnRequest(options: {
  spEntityId: string;
  acsUrl: string;
  idpSsoUrl: string;
  relayState?: string;
}): {
  id: string;
  xml: string;
  base64Request: string;
  redirectUrl: string;
};

export function generateSpMetadataXml(options: {
  spEntityId: string;
  acsUrl: string;
  sloUrl?: string;
  signingCert?: string;
}): string;

export function generateDomainVerificationToken(): string;

export function verifyDomainTxt(
  domain: string,
  expectedToken: string,
  customFetch?: any
): Promise<boolean>;

export function deflateRaw(str: string): Buffer;
export function inflateRaw(buf: Buffer | Uint8Array): string;
