import * as React from "react";
import {
  DevAuthClient,
  AuthUser,
  ClientOrg,
  ClientOrgMember,
  SendOTPResponse,
  VerifyOTPResponse,
  RefreshResponse
} from "../index";

export interface AuthContextValue {
  user: AuthUser | null;
  token: string | null;
  isAuthenticated: boolean;
  isDPoPBound: boolean;
  isLoading: boolean;
  client: DevAuthClient;
  sendOTP: (email: string) => Promise<SendOTPResponse>;
  verifyOTP: (email: string, otp: string | number) => Promise<VerifyOTPResponse>;
  logout: () => Promise<{ success: boolean }>;
  refresh: () => Promise<RefreshResponse>;
  getProfile: () => Promise<AuthUser>;
  loginWithGoogle: (options?: { successRedirectURL?: string }) => void;
  loginWithGitHub: (options?: { successRedirectURL?: string }) => void;
}

export interface UseOrgResult {
  activeOrg: ClientOrg | null;
  organizations: ClientOrg[];
  isLoading: boolean;
  loadOrgs: () => Promise<void>;
  createOrg: (params: {
    name: string;
    slug?: string;
    logoUrl?: string;
    metadata?: Record<string, any>;
  }) => Promise<{ success: boolean; organization: ClientOrg; member: ClientOrgMember }>;
  switchOrg: (orgId: string) => Promise<{
    success: boolean;
    token: string;
    organization: ClientOrg;
    member: ClientOrgMember;
  }>;
  inviteMember: (
    orgId: string,
    params: { email: string; role?: string }
  ): Promise<{ success: boolean; invitation: any; devModeInviteToken?: string }>;
  joinOrg: (token: string) => Promise<{
    success: boolean;
    token: string;
    organization: ClientOrg;
    member: ClientOrgMember;
  }>;
  listInvitations: (orgId: string) => Promise<any[]>;
  revokeInvitation: (orgId: string, inviteId: string) => Promise<{ success: boolean }>;
  updateMemberRole: (
    orgId: string,
    userId: string,
    role: string
  ): Promise<{ success: boolean; member: ClientOrgMember }>;
  removeMember: (orgId: string, userId: string) => Promise<{ success: boolean }>;
}

export interface AuthProviderProps {
  client?: DevAuthClient;
  initialUser?: AuthUser | null;
  children: React.ReactNode;
}

export function AuthProvider(props: AuthProviderProps): React.ReactElement;

export function useAuth(): AuthContextValue;

export function useOrg(): UseOrgResult;

export const AuthContext: React.Context<AuthContextValue | null>;

