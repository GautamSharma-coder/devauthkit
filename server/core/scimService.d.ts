export function generateScimBearerToken(): string;

export function hashScimBearerToken(token: string): Promise<string>;

export function verifyScimBearerToken(
  presentedToken: string,
  storedHash: string
): Promise<boolean>;

export function getServiceProviderConfig(baseUrl: string): Record<string, any>;

export function getSchemas(): Record<string, any>;

export function formatScimUser(
  user: any,
  member: any,
  scimBaseUrl: string
): Record<string, any>;

export function formatScimGroup(
  group: any,
  scimBaseUrl: string
): Record<string, any>;

export function formatScimList(
  resources: any[],
  totalResults: number,
  startIndex?: number,
  count?: number
): Record<string, any>;

export function formatScimError(
  status: number | string,
  detail: string,
  scimType?: string | null
): Record<string, any>;

export function parseScimFilter(
  filter: string
): { attribute: string; operator: string; value: string } | null;

export function parseScimPatchOperations(
  operations: any[]
): {
  active?: boolean;
  updates: Record<string, any>;
  addMembers: string[];
  removeMembers: string[];
};
