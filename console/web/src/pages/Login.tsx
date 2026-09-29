import { FormEvent, useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { login, loginMethods, LoginMethods } from "../api";
import { ErrorBanner } from "../components";

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [accessKey, setAccessKey] = useState("");
  const [secretKey, setSecretKey] = useState("");
  // A failed OpenID sign-in comes back as /login?error=...
  const [error, setError] = useState<unknown>(() => {
    const e = new URLSearchParams(window.location.search).get("error");
    return e ? new Error(e) : undefined;
  });
  const [methods, setMethods] = useState<LoginMethods | null>(null);
  const [busy, setBusy] = useState(false);
  const [ldapOffered, setLdapOffered] = useState(false);
  const [useLdap, setUseLdap] = useState(false);
  useEffect(() => {
    loginMethods()
      .then((m) => {
        setMethods(m);
        setLdapOffered(m.ldap);
      })
      .catch(() => undefined);
  }, []);
  const navigate = useNavigate();
  const from = (useLocation().state as { from?: string } | null)?.from ?? "/";

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await login(accessKey, secretKey, useLdap ? "ldap" : undefined);
      onLogin();
      navigate(from === "/login" ? "/" : from, { replace: true });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="login">
      <form onSubmit={submit} className="card login-card">
        <div className="brand big">
          <img src="/favicon.svg" alt="" /> Buckets
        </div>
        <ErrorBanner error={error} />
        {ldapOffered && (
          <div className="tabs" role="tablist">
            <button type="button" role="tab" aria-selected={!useLdap} className={!useLdap ? "active" : ""} onClick={() => setUseLdap(false)}>
              Access keys
            </button>
            <button type="button" role="tab" aria-selected={useLdap} className={useLdap ? "active" : ""} onClick={() => setUseLdap(true)} data-testid="ldap-tab">
              LDAP
            </button>
          </div>
        )}
        <label>
          {useLdap ? "Username" : "Access key"}
          <input value={accessKey} onChange={(e) => setAccessKey(e.target.value)} autoFocus autoComplete="username" data-testid="access-key" />
        </label>
        <label>
          {useLdap ? "Password" : "Secret key"}
          <input type="password" value={secretKey} onChange={(e) => setSecretKey(e.target.value)} autoComplete="current-password" data-testid="secret-key" />
        </label>
        <button className="primary" disabled={busy || !accessKey || !secretKey} data-testid="login">
          {busy ? "Signing in…" : "Sign in"}
        </button>
        {methods?.oidc && (
          <>
            <div className="or">or</div>
            <a className="button sso" href="/api/v1/login/oidc" data-testid="oidc-login">
              Sign in with {methods.oidcName ?? "OpenID"}
            </a>
          </>
        )}
      </form>
    </div>
  );
}
