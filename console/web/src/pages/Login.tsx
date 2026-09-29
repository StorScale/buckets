import { FormEvent, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { login } from "../api";
import { ErrorBanner } from "../components";

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [accessKey, setAccessKey] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();
  const from = (useLocation().state as { from?: string } | null)?.from ?? "/";

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await login(accessKey, secretKey);
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
        <label>
          Access key
          <input value={accessKey} onChange={(e) => setAccessKey(e.target.value)} autoFocus autoComplete="username" data-testid="access-key" />
        </label>
        <label>
          Secret key
          <input type="password" value={secretKey} onChange={(e) => setSecretKey(e.target.value)} autoComplete="current-password" data-testid="secret-key" />
        </label>
        <button className="primary" disabled={busy || !accessKey || !secretKey} data-testid="login">
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
