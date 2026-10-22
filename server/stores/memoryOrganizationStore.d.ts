import type {
  OrganizationRecord,
  OrganizationMemberRecord,
  OrganizationInvitationRecord
} from "./cloudflareD1OrganizationStore";

export class MemoryOrganizationStore {
  constructor();
  orgs: Map<string, OrganizationRecord>;
  slugToId: Map<string, string>;
  members: Map<string, OrganizationMemberRecord>;
  orgUserToMemberId: Map<string, string>;
  invitations: Map<string, OrganizationInvitationRecord>;
  tokenHashToInviteId: Map<string, string>;

  createOrg(params: {
    name: string;
    slug?: string;
    logoUrl?: string | null;
    metadata?: Record<string, any> | null;
    ownerUserId: string | number;
    ownerEmail?: string | null;
  }): Promise<{ organization: OrganizationRecord; member: OrganizationMemberRecord }>;

  getOrg(orgId: string): Promise<OrganizationRecord | null>;
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
