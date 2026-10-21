import * as React from "react";
import {
  DevAuthClient,
  AuthUser,
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

export interface AuthProviderProps {
  client?: DevAuthClient;
  initialUser?: AuthUser | null;
  children: React.ReactNode;
}

export function AuthProvider(props: AuthProviderProps): React.ReactElement;

export function useAuth(): AuthContextValue;

export const AuthContext: React.Context<AuthContextValue | null>;
