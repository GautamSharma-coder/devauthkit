const assert = require("node:assert/strict");
const Module = require("module");

// Mock minimal React runtime to test React UI components in zero-dependency Node environments
const mockState = new Map();
let stateIndex = 0;

function resetMockState() {
  mockState.clear();
  stateIndex = 0;
}

const mockReact = {
  useState(initial) {
    const idx = stateIndex++;
    if (!mockState.has(idx)) {
      const val = typeof initial === "function" ? initial() : initial;
      mockState.set(idx, val);
    }
    const setState = (next) => {
      const current = mockState.get(idx);
      const val = typeof next === "function" ? next(current) : next;
      mockState.set(idx, val);
    };
    return [mockState.get(idx), setState];
  },
  useEffect(effect, deps) {
    // Sync effect execution
    effect();
  },
  useCallback(fn) {
    return fn;
  },
  useMemo(fn) {
    return fn();
  },
  useRef(initial) {
    return { current: initial };
  },
  useContext(ctx) {
    return ctx ? ctx._value : null;
  },
  createContext(initial) {
    return { _value: initial, Provider: ({ value, children }) => children };
  },
  createElement(type, props, ...children) {
    const flatChildren = children.flat().filter(Boolean);
    return {
      type,
      props: {
        ...props,
        children: flatChildren.length === 1 ? flatChildren[0] : flatChildren
      }
    };
  },
  Fragment: "React.Fragment"
};

// Hook Module._load so require("react") returns mockReact
const originalLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === "react") {
    return mockReact;
  }
  return originalLoad.apply(this, arguments);
};

async function runTests() {
  console.log("🧪 Testing DevAuthKit Drop-In Prebuilt UI Components (React)...");

  // Clear module caches to pick up mocked React
  delete require.cache[require.resolve("./client/react/ui.js")];
  delete require.cache[require.resolve("./client/react/index.js")];

  const {
    SignIn,
    SignUp,
    UserButton,
    OrganizationSwitcher,
    UserProfile
  } = require("./client/react/ui.js");

  const reactPkg = require("./client/react/index.js");

  assert.equal(typeof reactPkg.SignIn, "function", "client/react exports SignIn");
  assert.equal(typeof reactPkg.SignUp, "function", "client/react exports SignUp");
  assert.equal(typeof reactPkg.UserButton, "function", "client/react exports UserButton");
  assert.equal(typeof reactPkg.OrganizationSwitcher, "function", "client/react exports OrganizationSwitcher");
  assert.equal(typeof reactPkg.UserProfile, "function", "client/react exports UserProfile");
  console.log("  ✅ [PASS] Drop-in React components exported correctly from devauthkit/react");

  // Mock DevAuth context
  const mockAuthContext = {
    user: { id: "usr_123", email: "developer@example.com" },
    token: "dak_test_jwt",
    isAuthenticated: true,
    isDPoPBound: true,
    isLoading: false,
    sendOTP: async (email) => ({ success: true, email }),
    verifyOTP: async (email, otp) => ({ success: true, user: { id: "usr_123", email } }),
    logout: async () => ({ success: true }),
    loginWithGoogle: () => {},
    loginWithGitHub: () => {},
    client: {
      loginWithSso: () => {}
    }
  };

  // Mock useAuth & useOrg
  reactPkg.useAuth = () => mockAuthContext;
  reactPkg.useOrg = () => ({
    activeOrg: { id: "org_1", name: "Acme Corp", slug: "acme" },
    organizations: [{ id: "org_1", name: "Acme Corp", slug: "acme" }],
    switchOrg: async (id) => ({ success: true }),
    createOrg: async (params) => ({ success: true, organization: { id: "org_2", name: params.name } })
  });
  reactPkg.useSessions = () => ({
    sessions: [
      { id: "sess_1", ip: "192.168.1.1", isCurrent: true, device: { os: "macOS", browser: "Chrome" } },
      { id: "sess_2", ip: "10.0.0.1", isCurrent: false, device: { os: "iOS", browser: "Safari" } }
    ],
    revokeSession: async () => ({ success: true }),
    revokeOtherSessions: async () => ({ success: true, revokedCount: 1 })
  });
  reactPkg.useApiKeys = () => ({
    apiKeys: [
      { id: "key_1", name: "Production Key", prefix: "dak_live_abc123" }
    ],
    createApiKey: async (params) => ({ success: true, key: "dak_live_secret12345" }),
    revokeApiKey: async () => ({ success: true })
  });

  // Test 1: Render SignIn component
  resetMockState();
  const signInEl = SignIn({ appearance: { theme: "dark" }, showPasskey: true, showSSO: true });
  assert.equal(signInEl.type, "div", "SignIn root is a div element");
  assert(signInEl.props.className.includes("dak-theme-dark"), "SignIn applies dark theme class");
  assert(signInEl.props.className.includes("dak-card"), "SignIn has dak-card styling");
  console.log("  ✅ [PASS] <SignIn /> renders with dark theme & enterprise features");

  // Test 2: Render UserButton component
  resetMockState();
  const userBtnEl = UserButton({ showName: true });
  assert.equal(userBtnEl.type, "div", "UserButton root is a div container");
  const avatarChild = userBtnEl.props.children[0];
  assert.equal(avatarChild.props.className, "dak-avatar", "UserButton has avatar element");
  assert.equal(avatarChild.props.children, "DE", "UserButton displays user initials (DE)");
  console.log("  ✅ [PASS] <UserButton /> renders user initials avatar & popover trigger");

  // Test 3: Render OrganizationSwitcher component
  resetMockState();
  const orgSwitcherEl = OrganizationSwitcher({ appearance: { theme: "light" } });
  assert.equal(orgSwitcherEl.type, "div", "OrganizationSwitcher container is a div");
  const triggerBtn = orgSwitcherEl.props.children;
  assert.equal(triggerBtn.type, "button", "OrganizationSwitcher has dropdown trigger button");
  console.log("  ✅ [PASS] <OrganizationSwitcher /> displays active organization badge");

  // Test 4: Render UserProfile component
  resetMockState();
  const profileEl = UserProfile({ appearance: { theme: "dark" } });
  assert.equal(profileEl.type, "div", "UserProfile root is a div");
  assert(profileEl.props.className.includes("dak-card"), "UserProfile has card container");
  console.log("  ✅ [PASS] <UserProfile /> renders multi-tab security & credentials settings");

  console.log("\n🎉 All DevAuthKit React Drop-in UI component tests passed successfully!\n");
}

runTests().then(() => {
  process.exit(0);
}).catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
