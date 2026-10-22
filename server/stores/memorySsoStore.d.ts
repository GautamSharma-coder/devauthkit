export interface SsoConnection {
  id: string;
  orgId: string;
  name: string;
  type: "SAML" | "OIDC";
  domains: string[];
  domainVerified: boolean;
  domainVerificationToken: string;
  idpEntityId: string | null;
  idpSsoUrl: string | null;
  idpSloUrl: string | null;
  idpCertificates: string[];
  spEntityId: string;
  spAcsUrl: string;
  oidcIssuer: string | null;
  oidcClientId: string | null;
  oidcClientSecret: string | null;
  oidcDiscoveryUrl: string | null;
  defaultRole: string;
  attributeMapping: Record<string, string>;
  active: boolean;
  createdAt: number;
  updatedAt: number;
}

export interface ScimDirectory {
  id: string;
  orgId: string;
  bearerTokenHash: string;
  scimBaseUrl: string;
  active: boolean;
  lastSyncedAt: number | null;
  createdAt: number;
  updatedAt: number;
}

export interface ScimUserMapping {
  id: string;
  directoryId: string;
  orgId: string;
  userId: string;
  idpExternalId: string;
  attributes: Record<string, any>;
  active: boolean;
  createdAt: number;
  updatedAt: number;
}

export interface ScimGroupMapping {
  id: string;
  directoryId: string;
  orgId: string;
  idpGroupId: string;
  groupName: string;
  mappedOrgRole: string;
  members: string[];
  createdAt: number;
}

export class MemorySsoStore {
  connections: Map<string, SsoConnection>;
  assertions: Map<string, number>;
  directories: Map<string, ScimDirectory>;
  userMappings: Map<string, ScimUserMapping>;
  groupMappings: Map<string, ScimGroupMapping>;

  createConnection(data: {
    id?: string;
    orgId: string;
    name: string;
    type?: "SAML" | "OIDC";
    domains?: string[];
    domainVerified?: boolean;
    domainVerificationToken?: string;
    idpEntityId?: string;
    idpSsoUrl?: string;
    idpSloUrl?: string;
    idpCertificates?: string | string[];
    spEntityId?: string;
    spAcsUrl?: string;
    oidcIssuer?: string;
    oidcClientId?: string;
    oidcClientSecret?: string;
    oidcDiscoveryUrl?: string;
    defaultRole?: string;
    attributeMapping?: Record<string, string>;
    active?: boolean;
  }): Promise<SsoConnection>;

  getConnection(id: string): Promise<SsoConnection | null>;
  listConnections(orgId?: string): Promise<SsoConnection[]>;
  getConnectionByDomain(domain: string): Promise<SsoConnection | null>;
  updateConnection(id: string, updates?: Partial<SsoConnection>): Promise<SsoConnection | null>;
  deleteConnection(id: string): Promise<boolean>;
  verifyDomain(id: string): Promise<SsoConnection | null>;

  recordAssertion(assertionId: string, ttlSeconds?: number): Promise<boolean>;
  isAssertionReplayed(assertionId: string): Promise<boolean>;

  createDirectory(data: {
    id?: string;
    orgId: string;
    bearerTokenHash: string;
    scimBaseUrl?: string;
    active?: boolean;
  }): Promise<ScimDirectory>;

  getDirectory(id: string): Promise<ScimDirectory | null>;
  getDirectoryByTokenHash(tokenHash: string): Promise<ScimDirectory | null>;
  listDirectories(orgId?: string): Promise<ScimDirectory[]>;
  updateDirectory(id: string, updates?: Partial<ScimDirectory>): Promise<ScimDirectory | null>;
  deleteDirectory(id: string): Promise<boolean>;

  createScimUserMapping(data: {
    id?: string;
    directoryId: string;
    orgId: string;
    userId: string;
    idpExternalId: string;
    attributes?: Record<string, any>;
    active?: boolean;
  }): Promise<ScimUserMapping>;

  getScimUserMapping(directoryId: string, idpExternalId: string): Promise<ScimUserMapping | null>;
  getScimUserMappingByUserId(directoryId: string, userId: string): Promise<ScimUserMapping | null>;
  listScimUserMappings(directoryId: string): Promise<ScimUserMapping[]>;
  updateScimUserMapping(id: string, updates?: Partial<ScimUserMapping>): Promise<ScimUserMapping | null>;
  deleteScimUserMapping(id: string): Promise<boolean>;

  createScimGroupMapping(data: {
    id?: string;
    directoryId: string;
    orgId: string;
    idpGroupId: string;
    groupName: string;
    mappedOrgRole?: string;
    members?: string[];
  }): Promise<ScimGroupMapping>;

  getScimGroupMapping(directoryId: string, idpGroupId: string): Promise<ScimGroupMapping | null>;
  getScimGroupMappingById(id: string): Promise<ScimGroupMapping | null>;
  listScimGroupMappings(directoryId: string): Promise<ScimGroupMapping[]>;
  updateScimGroupMapping(id: string, updates?: Partial<ScimGroupMapping>): Promise<ScimGroupMapping | null>;
  deleteScimGroupMapping(id: string): Promise<boolean>;
}
