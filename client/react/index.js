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

module.exports = {
  AuthProvider,
  useAuth,
  AuthContext
};
