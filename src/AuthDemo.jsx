import React, { createContext, useContext, useReducer, useEffect, useState } from "react";
import { Lock, User, Shield, LogIn, LogOut, RefreshCw, Trash2, UserCheck, Key, Users, Settings, Home, Award, Eye, EyeOff } from "lucide-react";

/*
  Modern Authentication & Authorization Demo
  - JWT-based auth simulation
  - Role-based access control (Admin/User)
  - Beautiful modern UI with Tailwind
*/

/* ---------------- Auth "API"  ---------------- */
const _DB_KEY = "auth_demo_users_v1";

const loadUsers = () => {
  try {
    return JSON.parse(localStorage.getItem(_DB_KEY) || "null") || [
      { id: 1, username: "admin", password: "password", role: "admin" },
      { id: 2, username: "kapil", password: "password", role: "user" },
    ];
  } catch {
    return [];
  }
};
const saveUsers = (users) => localStorage.setItem(_DB_KEY, JSON.stringify(users));

const createToken = ({ id, username, role }, expiresInSeconds = 60 * 60) => {
  const exp = Math.floor(Date.now() / 1000) + expiresInSeconds;
  const payload = { sub: id, username, role, exp };
  return btoa(JSON.stringify(payload));
};

const decodeToken = (token) => {
  try {
    return JSON.parse(atob(token));
  } catch {
    return null;
  }
};

const AuthApi = {
  signup: ({ username, password, role = "user" }) =>
    new Promise((resolve, reject) => {
      setTimeout(() => {
        const users = loadUsers();
        if (users.find((u) => u.username === username)) {
          return reject(new Error("Username already taken"));
        }
        const id = (users[users.length - 1]?.id || 0) + 1;
        const newUser = { id, username, password, role };
        users.push(newUser);
        saveUsers(users);
        const token = createToken(newUser, 60 * 15);
        return resolve({ user: { id, username, role }, token });
      }, 400);
    }),

  login: ({ username, password }) =>
    new Promise((resolve, reject) => {
      setTimeout(() => {
        const users = loadUsers();
        const found = users.find((u) => u.username === username && u.password === password);
        if (!found) return reject(new Error("Invalid credentials"));
        const token = createToken(found, 60 * 15);
        return resolve({ user: { id: found.id, username: found.username, role: found.role }, token });
      }, 400);
    }),

  verifyToken: (token) =>
    new Promise((resolve, reject) => {
      setTimeout(() => {
        const payload = decodeToken(token);
        if (!payload) return reject(new Error("Invalid token"));
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp < now) return reject(new Error("Token expired"));
        return resolve({ user: { id: payload.sub, username: payload.username, role: payload.role }, payload });
      }, 200);
    }),

  refreshToken: (token) =>
    new Promise((resolve, reject) => {
      setTimeout(() => {
        const payload = decodeToken(token);
        if (!payload) return reject(new Error("Invalid token"));
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp + 24 * 3600 < now) return reject(new Error("Refresh window expired"));
        const users = loadUsers();
        const user = users.find((u) => u.id === payload.sub);
        if (!user) return reject(new Error("User not found"));
        const newToken = createToken(user, 60 * 15);
        return resolve({ token: newToken });
      }, 300);
    }),
};

/* ---------------- Auth Context ---------------- */
const AUTH_STORAGE_KEY = "auth_demo_token_v1";

const initialState = {
  user: null,
  token: null,
  loading: true,
  error: null,
};

function authReducer(state, action) {
  switch (action.type) {
    case "RESTORE":
      return { ...state, user: action.user, token: action.token, loading: false };
    case "LOGIN":
      return { ...state, user: action.user, token: action.token, error: null };
    case "LOGOUT":
      return { ...initialState, loading: false };
    case "ERROR":
      return { ...state, error: action.error };
    default:
      return state;
  }
}

const AuthContext = createContext(null);

function useProvideAuth() {
  const [state, dispatch] = useReducer(authReducer, initialState);

  useEffect(() => {
    const token = localStorage.getItem(AUTH_STORAGE_KEY);
    if (!token) {
      dispatch({ type: "RESTORE", user: null, token: null });
      return;
    }
    AuthApi
      .verifyToken(token)
      .then(({ user }) => {
        dispatch({ type: "RESTORE", user, token });
      })
      .catch(() => {
        AuthApi
          .refreshToken(token)
          .then(({ token: newToken }) => {
            localStorage.setItem(AUTH_STORAGE_KEY, newToken);
            return AuthApi.verifyToken(newToken);
          })
          .then(({ user }) => {
            dispatch({ type: "RESTORE", user, token: localStorage.getItem(AUTH_STORAGE_KEY) });
          })
          .catch(() => {
            localStorage.removeItem(AUTH_STORAGE_KEY);
            dispatch({ type: "RESTORE", user: null, token: null });
          });
      });
  }, []);

  const signup = async ({ username, password, role }) => {
    try {
      const { user, token } = await AuthApi.signup({ username, password, role });
      localStorage.setItem(AUTH_STORAGE_KEY, token);
      dispatch({ type: "LOGIN", user, token });
      return user;
    } catch (err) {
      dispatch({ type: "ERROR", error: err.message });
      throw err;
    }
  };

  const login = async ({ username, password }) => {
    try {
      const { user, token } = await AuthApi.login({ username, password });
      localStorage.setItem(AUTH_STORAGE_KEY, token);
      dispatch({ type: "LOGIN", user, token });
      return user;
    } catch (err) {
      dispatch({ type: "ERROR", error: err.message });
      throw err;
    }
  };

  const logout = () => {
    localStorage.removeItem(AUTH_STORAGE_KEY);
    dispatch({ type: "LOGOUT" });
  };

  return {
    user: state.user,
    token: state.token,
    loading: state.loading,
    error: state.error,
    signup,
    login,
    logout,
    dispatch,
  };
}

export function AuthProvider({ children }) {
  const auth = useProvideAuth();
  return <AuthContext.Provider value={auth}>{children}</AuthContext.Provider>;
}

export const useAuth = () => useContext(AuthContext);

/* ---------------- Main App ---------------- */
export default function AuthDemo() {
  return (
    <AuthProvider>
      <AuthDemoUI />
    </AuthProvider>
  );
}

/* ---------------- UI Components ---------------- */
function AuthDemoUI() {
  const auth = useAuth();
  const [view, setView] = useState("public");

  if (auth.loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 flex items-center justify-center">
        <div className="relative">
          <div className="w-16 h-16 border-4 border-blue-200 border-t-blue-600 rounded-full animate-spin"></div>
          <Shield className="w-6 h-6 text-blue-600 absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
        </div>
      </div>
    );
  }

  const requireAuth = (neededRole) => {
    if (!auth.user) {
      alert("You must be logged in to access this area.");
      return false;
    }
    if (neededRole && auth.user.role !== neededRole) {
      alert(`Access denied. This area requires role: ${neededRole}`);
      return false;
    }
    return true;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
      {/* Header */}
      <header className="backdrop-blur-md bg-white/80 border-b border-slate-200 shadow-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-xl flex items-center justify-center shadow-lg">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-slate-800">Auth Demo</h1>
                <p className="text-xs text-slate-500">Modern Authentication</p>
              </div>
            </div>

            <nav className="flex items-center gap-2">
              <button
                onClick={() => setView("public")}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                  view === "public" ? "bg-blue-600 text-white" : "text-slate-600 hover:bg-slate-100"
                }`}
              >
                <Home className="w-4 h-4 inline mr-1" />
                Public
              </button>
              <button
                onClick={() => { if (requireAuth("user")) setView("user"); }}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                  view === "user" ? "bg-blue-600 text-white" : "text-slate-600 hover:bg-slate-100"
                }`}
              >
                <User className="w-4 h-4 inline mr-1" />
                Dashboard
              </button>
              <button
                onClick={() => { if (requireAuth("admin")) setView("admin"); }}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                  view === "admin" ? "bg-blue-600 text-white" : "text-slate-600 hover:bg-slate-100"
                }`}
              >
                <Settings className="w-4 h-4 inline mr-1" />
                Admin
              </button>
            </nav>

            {auth.user && (
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-100 rounded-lg">
                  <div className="w-7 h-7 bg-gradient-to-br from-blue-500 to-purple-500 rounded-full flex items-center justify-center text-white text-xs font-bold">
                    {auth.user.username.charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-slate-800">{auth.user.username}</div>
                    <div className="text-[10px] text-slate-500 capitalize">{auth.user.role}</div>
                  </div>
                </div>
                <button
                  onClick={auth.logout}
                  className="p-2 rounded-lg bg-red-50 text-red-600 hover:bg-red-100 transition-colors"
                  title="Logout"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Auth Form */}
          <div className="lg:col-span-1">
            <AuthCard />
            {auth.user && <SessionCard />}
          </div>

          {/* Right Column - Protected Areas */}
          <div className="lg:col-span-2">
            <div className="bg-white rounded-2xl shadow-lg border border-slate-200 overflow-hidden">
              <div className="bg-gradient-to-r from-blue-600 to-indigo-600 px-6 py-4">
                <h2 className="text-xl font-bold text-white flex items-center gap-2">
                  {view === "public" && <><Home className="w-5 h-5" /> Public Page</>}
                  {view === "user" && <><User className="w-5 h-5" /> User Dashboard</>}
                  {view === "admin" && <><Settings className="w-5 h-5" /> Admin Panel</>}
                </h2>
              </div>
              <div className="p-6">
                {view === "public" && <PublicPage />}
                {view === "user" && <UserDashboard />}
                {view === "admin" && <AdminPanel />}
              </div>
            </div>
          </div>
        </div>

        {/* Info Banner */}
        <div className="mt-6 bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-start gap-3">
          <Award className="w-5 h-5 text-amber-600 mt-0.5 flex-shrink-0" />
          <div className="text-sm text-amber-800">
            <strong>Note:</strong> This is a Full demonstration. Tokens are simulated and stored.
             used a secure backend with HTTPS, real JWT tokens, and proper security measures.
          </div>
        </div>
      </main>
    </div>
  );
}

/* Auth Card Component */
function AuthCard() {
  const auth = useAuth();
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("user");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage("");
    try {
      if (mode === "login") {
        await auth.login({ username, password });
        setMessage("✅ Logged in successfully!");
      } else {
        await auth.signup({ username, password, role });
        setMessage("✅ Account created and logged in!");
      }
      setUsername("");
      setPassword("");
    } catch (err) {
      setMessage("❌ " + (err.message || "Failed"));
    } finally {
      setLoading(false);
    }
  };

  if (auth.user) return null;

  return (
    <div className="bg-white rounded-2xl shadow-lg border border-slate-200 overflow-hidden mb-6">
      <div className="flex border-b border-slate-200">
        <button
          onClick={() => setMode("login")}
          className={`flex-1 px-6 py-4 font-semibold transition-all ${
            mode === "login"
              ? "bg-white text-blue-600 border-b-2 border-blue-600"
              : "bg-slate-50 text-slate-500 hover:bg-slate-100"
          }`}
        >
          <LogIn className="w-4 h-4 inline mr-2" />
          Login
        </button>
        <button
          onClick={() => setMode("signup")}
          className={`flex-1 px-6 py-4 font-semibold transition-all ${
            mode === "signup"
              ? "bg-white text-blue-600 border-b-2 border-blue-600"
              : "bg-slate-50 text-slate-500 hover:bg-slate-100"
          }`}
        >
          <UserCheck className="w-4 h-4 inline mr-2" />
          Sign Up
        </button>
      </div>

      <form onSubmit={submit} className="p-6 space-y-4">
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-2 flex items-center gap-2">
            <User className="w-4 h-4" />
            Username
          </label>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter username"
            className="w-full px-4 py-3 rounded-xl bg-slate-50 border border-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-300 transition-all"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-700 mb-2 flex items-center gap-2">
            <Lock className="w-4 h-4" />
            Password
          </label>
          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              className="w-full px-4 py-3 rounded-xl bg-slate-50 border border-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-300 transition-all pr-12"
              required
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
            >
              {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {mode === "signup" && (
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-2 flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Role
            </label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="w-full px-4 py-3 rounded-xl bg-slate-50 border border-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-300 transition-all"
            >
              <option value="user">👤 User</option>
              <option value="admin">👑 Admin</option>
            </select>
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className={`w-full px-6 py-3 rounded-xl font-bold shadow-lg transition-all duration-300 ${
            loading
              ? "bg-slate-300 text-slate-500 cursor-not-allowed"
              : "bg-gradient-to-r from-blue-600 to-indigo-600 text-white hover:shadow-xl transform hover:scale-[1.02]"
          }`}
        >
          {loading ? (
            <div className="flex items-center justify-center gap-2">
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
              Please wait...
            </div>
          ) : mode === "login" ? (
            "Login to Account"
          ) : (
            "Create Account"
          )}
        </button>

        {message && (
          <div className={`p-3 rounded-lg text-sm ${
            message.includes("✅")
              ? "bg-green-50 text-green-700 border border-green-200"
              : "bg-red-50 text-red-700 border border-red-200"
          }`}>
            {message}
          </div>
        )}

        {mode === "login" && (
          <div className="text-center text-sm text-slate-500 pt-2">
            Demo credentials: <strong>admin/password</strong> (admin) or <strong>kapil/password</strong> (user)
          </div>
        )}
      </form>
    </div>
  );
}

/* Session Card Component */
function SessionCard() {
  const auth = useAuth();
  const [decoded, setDecoded] = useState(null);
  const [showToken, setShowToken] = useState(false);

  useEffect(() => {
    if (!auth.token) {
      setDecoded(null);
      return;
    }
    const payload = decodeToken(auth.token);
    setDecoded(payload);
  }, [auth.token]);

  const tryRefresh = async () => {
    try {
      const res = await AuthApi.refreshToken(auth.token);
      localStorage.setItem(AUTH_STORAGE_KEY, res.token);
      const verify = await AuthApi.verifyToken(res.token);
      auth.dispatch({ type: "LOGIN", user: verify.user, token: res.token });
      alert("✅ Token refreshed successfully!");
    } catch (err) {
      alert("❌ Refresh failed: " + err.message);
    }
  };

  const getTimeRemaining = () => {
    if (!decoded?.exp) return null;
    const now = Math.floor(Date.now() / 1000);
    const remaining = decoded.exp - now;
    if (remaining < 0) return "Expired";
    const minutes = Math.floor(remaining / 60);
    const seconds = remaining % 60;
    return `${minutes}m ${seconds}s`;
  };

  return (
    <div className="bg-white rounded-2xl shadow-lg border border-slate-200 overflow-hidden">
      <div className="bg-gradient-to-r from-green-600 to-emerald-600 px-6 py-4">
        <h3 className="text-lg font-bold text-white flex items-center gap-2">
          <Key className="w-5 h-5" />
          Session Info
        </h3>
      </div>

      <div className="p-6 space-y-4">
        <div className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
          <span className="text-sm font-medium text-slate-600">Status</span>
          <span className="px-3 py-1 bg-green-100 text-green-700 rounded-full text-xs font-bold">
            Active
          </span>
        </div>

        <div className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
          <span className="text-sm font-medium text-slate-600">Token Expires In</span>
          <span className="text-sm font-bold text-slate-800">{getTimeRemaining()}</span>
        </div>

        <div>
          <button
            onClick={() => setShowToken(!showToken)}
            className="w-full text-left p-3 bg-slate-50 rounded-lg hover:bg-slate-100 transition-colors"
          >
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium text-slate-600">Token Payload</span>
              <span className="text-xs text-blue-600">{showToken ? "Hide" : "Show"}</span>
            </div>
          </button>
          {showToken && (
            <pre className="mt-2 p-3 bg-slate-800 text-green-400 rounded-lg text-xs overflow-x-auto">
              {JSON.stringify(decoded, null, 2)}
            </pre>
          )}
        </div>

        <div className="flex gap-2">
          <button
            onClick={tryRefresh}
            className="flex-1 px-4 py-2 rounded-lg bg-blue-50 text-blue-600 font-medium hover:bg-blue-100 transition-colors text-sm flex items-center justify-center gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <button
            onClick={() => {
              localStorage.removeItem(AUTH_STORAGE_KEY);
              auth.logout();
            }}
            className="flex-1 px-4 py-2 rounded-lg bg-red-50 text-red-600 font-medium hover:bg-red-100 transition-colors text-sm flex items-center justify-center gap-2"
          >
            <LogOut className="w-4 h-4" />
            Logout
          </button>
        </div>
      </div>
    </div>
  );
}

/* Page Components */
function PublicPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-start gap-4 p-4 bg-blue-50 rounded-xl border border-blue-200">
        <Home className="w-6 h-6 text-blue-600 mt-1 flex-shrink-0" />
        <div>
          <h3 className="font-bold text-slate-800 mb-2">Welcome to the Public Area</h3>
          <p className="text-sm text-slate-600 leading-relaxed">
            This page is accessible to everyone, no authentication required. Explore our demo authentication
            system by logging in or creating a new account to access protected areas.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 bg-slate-50 rounded-xl border border-slate-200">
          <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center mb-3">
            <User className="w-5 h-5 text-blue-600" />
          </div>
          <h4 className="font-semibold text-slate-800 mb-2">User Dashboard</h4>
          <p className="text-sm text-slate-600">Access your personal dashboard and manage your profile.</p>
        </div>

        <div className="p-4 bg-slate-50 rounded-xl border border-slate-200">
          <div className="w-10 h-10 bg-purple-100 rounded-lg flex items-center justify-center mb-3">
            <Shield className="w-5 h-5 text-purple-600" />
          </div>
          <h4 className="font-semibold text-slate-800 mb-2">Admin Panel</h4>
          <p className="text-sm text-slate-600">Manage users and system settings (admin only).</p>
        </div>
      </div>
    </div>
  );
}

function UserDashboard() {
  const auth = useAuth();
  return (
    <div className="space-y-6">
      <div className="flex items-start gap-4 p-4 bg-green-50 rounded-xl border border-green-200">
        <UserCheck className="w-6 h-6 text-green-600 mt-1 flex-shrink-0" />
        <div>
          <h3 className="font-bold text-slate-800 mb-2">Welcome, {auth.user?.username}!</h3>
          <p className="text-sm text-slate-600 leading-relaxed">
            This is your personal dashboard. As a verified user, you have access to user-level features
            and can manage your account settings.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="p-6 bg-gradient-to-br from-blue-50 to-indigo-50 rounded-xl border border-blue-200">
          <div className="text-3xl font-bold text-blue-600 mb-2">24</div>
          <div className="text-sm text-slate-600">Active Sessions</div>
        </div>
        <div className="p-6 bg-gradient-to-br from-purple-50 to-pink-50 rounded-xl border border-purple-200">
          <div className="text-3xl font-bold text-purple-600 mb-2">156</div>
          <div className="text-sm text-slate-600">Total Actions</div>
        </div>
      </div>

      <div className="p-4 bg-slate-50 rounded-xl border border-slate-200">
        <h4 className="font-semibold text-slate-800 mb-3">Recent Activity</h4>
        <div className="space-y-2">
          {[
            { action: "Logged in", time: "2 minutes ago" },
            { action: "Updated profile", time: "1 hour ago" },
            { action: "Changed password", time: "2 days ago" },
          ].map((item, i) => (
            <div key={i} className="flex items-center justify-between p-2 hover:bg-white rounded-lg transition-colors">
              <span className="text-sm text-slate-700">{item.action}</span>
              <span className="text-xs text-slate-500">{item.time}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function AdminPanel() {
  const auth = useAuth();
  const [users, setUsers] = useState(loadUsers());

  const deleteUser = (id) => {
    if (window.confirm("⚠️ Are you sure you want to delete this user?")) {
      const updated = users.filter((u) => u.id !== id);
      saveUsers(updated);
      setUsers(updated);
      alert("✅ User deleted successfully");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start gap-4 p-4 bg-purple-50 rounded-xl border border-purple-200">
        <Shield className="w-6 h-6 text-purple-600 mt-1 flex-shrink-0" />
        <div>
          <h3 className="font-bold text-slate-800 mb-2">Admin Control Panel</h3>
          <p className="text-sm text-slate-600 leading-relaxed">
            Welcome, {auth.user?.username}. You have administrator privileges and can manage all system users
            and settings. Handle with care!
          </p>
        </div>
      </div>

      <div className="bg-slate-50 rounded-xl border border-slate-200 p-6">
        <div className="flex items-center justify-between mb-4">
          <h4 className="font-semibold text-slate-800 flex items-center gap-2">
            <Users className="w-5 h-5" />
            Registered Users ({users.length})
          </h4>
        </div>

        <div className="space-y-2">
          {users.map((u) => (
            <div
              key={u.id}
              className="flex items-center justify-between p-4 bg-white rounded-lg border border-slate-200 hover:border-blue-300 transition-all"
            >
              <div className="flex items-center gap-3">
                <div className={`w-10 h-10 rounded-full flex items-center justify-center text-white font-bold ${
                  u.role === "admin" ? "bg-gradient-to-br from-purple-500 to-pink-500" : "bg-gradient-to-br from-blue-500 to-indigo-500"
                }`}>
                  {u.username.charAt(0).toUpperCase()}
                </div>
                <div>
                  <div className="font-semibold text-slate-800 flex items-center gap-2">
                    {u.username}
                    {u.role === "admin" && (
                      <span className="px-2 py-0.5 bg-purple-100 text-purple-700 rounded text-xs font-medium">
                        Admin
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-slate-500">ID: {u.id} • Role: {u.role}</div>
                </div>
              </div>

              <button
                onClick={() => deleteUser(u.id)}
                className="px-3 py-1.5 rounded-lg bg-red-50 text-red-600 hover:bg-red-100 transition-colors text-sm font-medium flex items-center gap-1"
              >
                <Trash2 className="w-4 h-4" />
                Delete
              </button>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="p-4 bg-gradient-to-br from-blue-50 to-indigo-50 rounded-xl border border-blue-200">
          <div className="text-2xl font-bold text-blue-600 mb-1">{users.length}</div>
          <div className="text-xs text-slate-600">Total Users</div>
        </div>
        <div className="p-4 bg-gradient-to-br from-purple-50 to-pink-50 rounded-xl border border-purple-200">
          <div className="text-2xl font-bold text-purple-600 mb-1">
            {users.filter(u => u.role === "admin").length}
          </div>
          <div className="text-xs text-slate-600">Admins</div>
        </div>
        <div className="p-4 bg-gradient-to-br from-green-50 to-emerald-50 rounded-xl border border-green-200">
          <div className="text-2xl font-bold text-green-600 mb-1">
            {users.filter(u => u.role === "user").length}
          </div>
          <div className="text-xs text-slate-600">Users</div>
        </div>
      </div>

      <div className="p-4 bg-amber-50 border border-amber-200 rounded-xl">
        <div className="flex items-start gap-3">
          <Award className="w-5 h-5 text-amber-600 mt-0.5 flex-shrink-0" />
          <div className="text-sm text-amber-800">
            <strong>Security Note:</strong> In a real application, all admin actions should be validated
            on the backend. Never trust client-side role checks for critical operations.
          </div>
        </div>
      </div>
    </div>
  );
}