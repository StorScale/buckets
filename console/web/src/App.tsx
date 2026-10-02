import { useCallback, useEffect, useState } from "react";
import { Navigate, NavLink, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { logout, session, Session, SESSION_EXPIRED } from "./api";
import { Spinner } from "./components";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Buckets from "./pages/Buckets";
import Browser from "./pages/Browser";
import BucketSettings from "./pages/BucketSettings";
import Users from "./pages/Users";
import Groups from "./pages/Groups";
import Policies from "./pages/Policies";
import AccessKeys from "./pages/AccessKeys";
import Configuration from "./pages/Configuration";
import Encryption from "./pages/Encryption";
import Trace from "./pages/Trace";
import Logs from "./pages/Logs";
import Events from "./pages/Events";

export default function App() {
  const [user, setUser] = useState<Session | null | undefined>(undefined);
  const navigate = useNavigate();
  const location = useLocation();

  const refresh = useCallback(() => {
    session()
      .then(setUser)
      .catch(() => setUser(null));
  }, []);
  useEffect(refresh, [refresh]);
  useEffect(() => {
    const expired = () => setUser(null);
    window.addEventListener(SESSION_EXPIRED, expired);
    return () => window.removeEventListener(SESSION_EXPIRED, expired);
  }, []);

  if (user === undefined)
    return (
      <div className="center">
        <Spinner />
      </div>
    );
  if (user === null)
    return (
      <Routes>
        <Route path="/login" element={<Login onLogin={refresh} />} />
        <Route path="*" element={<Navigate to="/login" replace state={{ from: location.pathname }} />} />
      </Routes>
    );

  const signOut = async () => {
    await logout().catch(() => undefined);
    setUser(null);
    navigate("/login");
  };
  return (
    <div className="shell">
      <nav className="sidebar">
        <div className="brand">
          <img src="/favicon.svg" alt="" /> Buckets
        </div>
        <NavLink to="/" end>
          Dashboard
        </NavLink>
        <NavLink to="/buckets">Buckets</NavLink>
        <div className="nav-group">Identity</div>
        <NavLink to="/identity/users">Users</NavLink>
        <NavLink to="/identity/groups">Groups</NavLink>
        <NavLink to="/identity/policies">Policies</NavLink>
        <NavLink to="/identity/access-keys">Access Keys</NavLink>
        <div className="nav-group">Monitoring</div>
        <NavLink to="/monitoring/trace">Trace</NavLink>
        <NavLink to="/monitoring/logs">Logs</NavLink>
        <NavLink to="/monitoring/events">Events</NavLink>
        <div className="nav-group">Administration</div>
        <NavLink to="/configuration">Configuration</NavLink>
        <NavLink to="/encryption">Encryption</NavLink>
        <div className="sidebar-foot">
          <div className="whoami" data-testid="whoami">
            {user.accessKey}
          </div>
          <button className="link" onClick={signOut} data-testid="logout">
            Sign out
          </button>
        </div>
      </nav>
      <main className="content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/monitoring/trace" element={<Trace />} />
          <Route path="/monitoring/logs" element={<Logs />} />
          <Route path="/monitoring/events" element={<Events />} />
          <Route path="/buckets" element={<Buckets />} />
          <Route path="/buckets/:bucket/browse/*" element={<Browser />} />
          <Route path="/buckets/:bucket/settings" element={<BucketSettings />} />
          <Route path="/identity/users" element={<Users />} />
          <Route path="/identity/groups" element={<Groups />} />
          <Route path="/identity/policies" element={<Policies />} />
          <Route path="/identity/access-keys" element={<AccessKeys />} />
          <Route path="/configuration" element={<Configuration />} />
          <Route path="/encryption" element={<Encryption />} />
          <Route path="/login" element={<Navigate to="/" replace />} />
          <Route path="*" element={<p>Page not found.</p>} />
        </Routes>
      </main>
    </div>
  );
}
