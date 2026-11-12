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

export interface ClientSession {
  id: string;
  ip?: string;
  isCurrent?: boolean;
  device?: {
    browser?: string;
    os?: string;
    platform?: string;
  };
  createdAt?: string;
  lastActiveAt?: string;
}

export interface UseSessionsResult {
  sessions: ClientSession[];
  isLoading: boolean;
  loadSessions: () => Promise<void>;
  revokeSession: (sessionId: string) => Promise<{ success: boolean }>;
  revokeOtherSessions: () => Promise<{ success: boolean; revokedCount: number }>;
}

export interface ClientApiKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  expiresAt?: string | null;
  createdAt?: string;
}

export interface UseApiKeysResult {
  apiKeys: ClientApiKey[];
  isLoading: boolean;
  loadApiKeys: () => Promise<void>;
  createApiKey: (options: { name: string; scopes?: string[]; expiresAt?: string }) => Promise<{ success: boolean; key: string; apiKey: ClientApiKey }>;
  revokeApiKey: (keyId: string) => Promise<{ success: boolean }>;
  rollApiKey: (keyId: string) => Promise<{ success: boolean; key: string; apiKey: ClientApiKey }>;
}

export interface ComponentAppearance {
  theme?: "dark" | "light" | "auto";
  className?: string;
  variables?: Record<string, string>;
}

export interface SignInProps {
  appearance?: ComponentAppearance;
  redirectUrl?: string;
  onSuccess?: (user: AuthUser) => void;
  onError?: (error: Error) => void;
  showSocial?: boolean;
  showPasskey?: boolean;
  showSSO?: boolean;
  initialStep?: "email" | "otp" | "sso";
}

export interface SignUpProps extends SignInProps {}

export interface UserButtonProps {
  appearance?: ComponentAppearance;
  showName?: boolean;
  afterSignOutUrl?: string;
}

export interface OrganizationSwitcherProps {
  appearance?: ComponentAppearance;
}

export interface UserProfileProps {
  appearance?: ComponentAppearance;
}

export interface AuthProviderProps {
  client?: DevAuthClient;
  initialUser?: AuthUser | null;
  children: React.ReactNode;
}

export function AuthProvider(props: AuthProviderProps): React.ReactElement;

export function useAuth(): AuthContextValue;

export function useOrg(): UseOrgResult;

export function useSessions(): UseSessionsResult;

export function useApiKeys(): UseApiKeysResult;

export function SignIn(props?: SignInProps): React.ReactElement | null;

export function SignUp(props?: SignUpProps): React.ReactElement | null;

export function UserButton(props?: UserButtonProps): React.ReactElement | null;

export function OrganizationSwitcher(props?: OrganizationSwitcherProps): React.ReactElement | null;

export function UserProfile(props?: UserProfileProps): React.ReactElement | null;

export const AuthContext: React.Context<AuthContextValue | null>;

