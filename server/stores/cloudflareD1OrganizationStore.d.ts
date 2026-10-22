export interface D1PreparedStatementLike {
  bind(...values: any[]): D1PreparedStatementLike;
  first<T = unknown>(column?: string): Promise<T | null>;
  all<T = unknown>(): Promise<{ results?: T[]; success?: boolean; error?: string }>;
  run(): Promise<{ success?: boolean; meta?: Record<string, unknown> }>;
}

export interface D1DatabaseLike {
  prepare(query: string): D1PreparedStatementLike;
  batch<T = unknown>(statements: D1PreparedStatementLike[]): Promise<Array<{ results?: T[]; success?: boolean }>>;
}

export interface CloudflareD1OrganizationStoreOptions {
  tablePrefix?: string;
}

export interface OrganizationRecord {
  id: string;
  name: string;
  slug: string;
  logoUrl?: string | null;
  metadata?: Record<string, any> | null;
  createdAt: number;
  updatedAt: number;
}

export interface OrganizationMemberRecord {
  id: string;
  orgId: string;
  userId: string;
  email?: string | null;
  role: string;
  joinedAt: number;
  updatedAt: number;
}

export interface OrganizationInvitationRecord {
  id: string;
  orgId: string;
  email: string;
  role: string;
  inviterId: string;
  tokenHash: string;
  expiresAt: number;
  createdAt: number;
}

export class CloudflareD1OrganizationStore {
  constructor(database: D1DatabaseLike, options?: CloudflareD1OrganizationStoreOptions);
  readonly tablePrefix: string;
  readonly orgsTable: string;
  readonly membersTable: string;
  readonly invitationsTable: string;

  createOrg(params: {
    name: string;
    slug?: string;
    logoUrl?: string | null;
    metadata?: Record<string, any> | null;
    ownerUserId: string | number;
    ownerEmail?: string | null;
  }): Promise<{ organization: OrganizationRecord; member: OrganizationMemberRecord }>;

  getOrgById(orgId: string): Promise<OrganizationRecord | null>;
  getOrgBySlug(slug: string): Promise<OrganizationRecord | null>;
  updateOrg(orgId: string, updates: Partial<Pick<OrganizationRecord, "name" | "slug" | "logoUrl" | "metadata">>): Promise<OrganizationRecord | null>;
  deleteOrg(orgId: string): Promise<boolean>;

  listUserOrgs(userId: string | number): Promise<Array<{
    organization: OrganizationRecord;
    member: OrganizationMemberRecord;
    role: string;
    joinedAt: number;
  }>>;

  getMember(orgId: string, userId: string | number): Promise<OrganizationMemberRecord | null>;
  listMembers(orgId: string): Promise<OrganizationMemberRecord[]>;
  addMember(orgId: string, userId: string | number, role?: string, email?: string | null): Promise<OrganizationMemberRecord>;
  updateMemberRole(orgId: string, userId: string | number, role: string): Promise<OrganizationMemberRecord | null>;
  removeMember(orgId: string, userId: string | number): Promise<boolean>;

  createInvitation(params: {
    orgId: string;
    email: string;
    role?: string;
    inviterId: string | number;
    tokenHash: string;
    expiresAt: number;
  }): Promise<OrganizationInvitationRecord>;

  getInvitationByTokenHash(tokenHash: string): Promise<OrganizationInvitationRecord | null>;
  listInvitations(orgId: string): Promise<OrganizationInvitationRecord[]>;
  deleteInvitation(inviteId: string): Promise<boolean>;
}
