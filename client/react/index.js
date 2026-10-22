"use client";

// client/react/index.js
let React = null;
try {
  React = require("react");
} catch {
  // React is an optional peer dependency
}

const { DevAuthClient } = require("../index");

const AuthContext = React ? React.createContext(null) : null;

function assertReact() {
  if (!React) {
    throw new Error(
      "[DevAuthKit] React is not installed. To use devauthkit/react, please install react: npm install react"
    );
  }
}

/**
 * Authentication Provider component for React and Next.js applications.
 *
 * @param {Object} props
 * @param {DevAuthClient} [props.client] - Optional DevAuthClient instance
 * @param {Object} [props.initialUser=null] - Optional initial server-rendered user profile
 * @param {React.ReactNode} props.children - Child components
 */
function AuthProvider({ client, initialUser = null, children }) {
  const [authClient] = React.useState(() => client || new DevAuthClient());
  const [user, setUser] = React.useState(() => initialUser || authClient.getUser());
  const [token, setToken] = React.useState(() => authClient.getToken());
  const [isDPoPBound, setIsDPoPBound] = React.useState(() => authClient.isDPoPBound());
  const [isLoading, setIsLoading] = React.useState(true);

  React.useEffect(() => {
    // Sync initial state from client storage
    const currentUser = authClient.getUser();
    setUser(currentUser);
    setToken(authClient.getToken());
    setIsDPoPBound(authClient.isDPoPBound());
    setIsLoading(false);

    // Subscribe to client authentication state changes
    const unsubscribe = authClient.onAuthStateChanged((newUser) => {
      setUser(newUser);
      setToken(authClient.getToken());
      setIsDPoPBound(authClient.isDPoPBound());
    });

    return () => {
      if (typeof unsubscribe === "function") unsubscribe();
    };
  }, [authClient]);

  const sendOTP = React.useCallback(
    (email) => authClient.sendOTP(email),
    [authClient]
  );

  const verifyOTP = React.useCallback(
    async (email, otp) => {
      const result = await authClient.verifyOTP(email, otp);
      setUser(result.user);
      setToken(authClient.getToken());
      return result;
    },
    [authClient]
  );

  const logout = React.useCallback(async () => {
    const result = await authClient.logout();
    setUser(null);
    setToken(null);
    return result;
  }, [authClient]);

  const refresh = React.useCallback(async () => {
    const result = await authClient.refresh();
    setUser(result.user);
    setToken(authClient.getToken());
    return result;
  }, [authClient]);

  const getProfile = React.useCallback(async () => {
    const profile = await authClient.getProfile();
    setUser(profile);
    return profile;
  }, [authClient]);

  const loginWithGoogle = React.useCallback(
    (options = {}) => {
      const baseUrl = authClient.apiUrl || "";
      const prefix = authClient.apiPrefix || "/auth";
      const targetUrl = new URL(`${baseUrl}${prefix}/google`, window.location.origin);
      if (options.successRedirectURL) {
        targetUrl.searchParams.set("successRedirectURL", options.successRedirectURL);
      }
      window.location.href = targetUrl.toString();
    },
    [authClient]
  );

  const loginWithGitHub = React.useCallback(
    (options = {}) => {
      const baseUrl = authClient.apiUrl || "";
      const prefix = authClient.apiPrefix || "/auth";
      const targetUrl = new URL(`${baseUrl}${prefix}/github`, window.location.origin);
      if (options.successRedirectURL) {
        targetUrl.searchParams.set("successRedirectURL", options.successRedirectURL);
      }
      window.location.href = targetUrl.toString();
    },
    [authClient]
  );

  const value = React.useMemo(
    () => ({
      user,
      token,
      isAuthenticated: Boolean(user || token),
      isDPoPBound,
      isLoading,
      client: authClient,
      sendOTP,
      verifyOTP,
      logout,
      refresh,
      getProfile,
      loginWithGoogle,
      loginWithGitHub
    }),
    [
      user,
      token,
      isDPoPBound,
      isLoading,
      authClient,
      sendOTP,
      verifyOTP,
      logout,
      refresh,
      getProfile,
      loginWithGoogle,
      loginWithGitHub
    ]
  );

  return React.createElement(AuthContext.Provider, { value }, children);
}

/**
 * Hook to consume DevAuthKit authentication state and helpers.
 * Must be used within an AuthProvider.
 */
function useAuth() {
  const context = React.useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an <AuthProvider>");
  }
  return context;
}

/**
 * Hook to consume DevAuthKit organization and workspace state.
 * Must be used within an AuthProvider.
 */
function useOrg() {
  const { client, token } = useAuth();
  const [activeOrg, setActiveOrg] = React.useState(() => client.getActiveOrg());
  const [organizations, setOrganizations] = React.useState([]);
  const [isLoading, setIsLoading] = React.useState(true);

  const loadOrgs = React.useCallback(async () => {
    if (!client.isAuthenticated()) {
      setOrganizations([]);
      setActiveOrg(null);
      setIsLoading(false);
      return;
    }
    try {
      setIsLoading(true);
      const list = await client.listOrgs();
      setOrganizations(list);
      const current = client.getActiveOrg();
      if (!current && list.length > 0) {
        setActiveOrg(list[0]);
      } else {
        setActiveOrg(current);
      }
    } catch (e) {
      // Ignore if user has no orgs or backend orgs not enabled
    } finally {
      setIsLoading(false);
    }
  }, [client]);

  React.useEffect(() => {
    loadOrgs();
  }, [loadOrgs, token]);

  const switchOrg = React.useCallback(
    async (orgId) => {
      const result = await client.switchOrg(orgId);
      setActiveOrg(result.organization);
      await loadOrgs();
      return result;
    },
    [client, loadOrgs]
  );

  const createOrg = React.useCallback(
    async (params) => {
      const result = await client.createOrg(params);
      if (result.organization?.id) {
        await switchOrg(result.organization.id);
      }
      return result;
    },
    [client, switchOrg]
  );

  const inviteMember = React.useCallback(
    (orgId, params) => {
      return client.inviteMember(orgId, params);
    },
    [client]
  );

  const joinOrg = React.useCallback(
    async (inviteToken) => {
      const result = await client.joinOrg(inviteToken);
      if (result.organization) {
        setActiveOrg(result.organization);
      }
      await loadOrgs();
      return result;
    },
    [client, loadOrgs]
  );

  return {
    activeOrg,
    organizations,
    isLoading,
    loadOrgs,
    createOrg,
    switchOrg,
    inviteMember,
    joinOrg,
    listInvitations: (orgId) => client.listInvitations(orgId),
    revokeInvitation: (orgId, inviteId) => client.revokeInvitation(orgId, inviteId),
    updateMemberRole: (orgId, userId, role) => client.updateMemberRole(orgId, userId, role),
    removeMember: (orgId, userId) => client.removeMember(orgId, userId)
  };
}

module.exports = {
  AuthProvider,
  useAuth,
  useOrg,
  AuthContext
};
