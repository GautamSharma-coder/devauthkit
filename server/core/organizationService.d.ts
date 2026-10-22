export interface OrgRoleDefinition {
  name: string;
  description: string;
  permissions: string[];
}

export declare const DEFAULT_ORG_ROLES: Record<string, OrgRoleDefinition>;

export declare const ROLE_RANK: Record<string, number>;

export declare function slugify(str: string): string;

export declare function hasOrgPermission(
  userRole: string,
  permission: string,
  customRoles?: Record<string, OrgRoleDefinition>
): boolean;

export declare function getRolePermissions(
  role: string,
  customRoles?: Record<string, OrgRoleDefinition>
): string[];

export declare function canManageRole(
  actorRole: string,
  targetRole: string,
  customRoles?: Record<string, OrgRoleDefinition>
): boolean;

export declare function generateInvitationToken(): string;

export declare function hashInvitationToken(rawToken: string): Promise<string>;
