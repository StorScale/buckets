import { Link } from "react-router-dom";
import { FormEvent, useState } from "react";
import {
  addUser,
  attachPolicies,
  listOpenIDUsers,
  listPolicies,
  listUsers,
  loginMethods,
  OpenIDUser,
  removeUser,
  setUserStatus,
  UserInfo,
} from "../api";
import { ConfirmButton, ErrorBanner, Modal, Notice, Spinner, useLoad } from "../components";

export default function Users() {
  const methods = useLoad(loginMethods, []);
  const { data, error, loading, reload, setError } = useLoad(listUsers, []);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<[string, UserInfo] | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const users = Object.entries(data ?? {}).sort(([a], [b]) => a.localeCompare(b));
  // With OpenID sign-in, people come from the identity provider; local users
  // are listed only if some exist or the console is set to allow them.
  const oidc = methods.data?.oidc ?? false;
  const canCreate = methods.data?.localUsers ?? false;
  const showLocal = !oidc || canCreate || users.length > 0;
  return (
    <div>
      <div className="page-head">
        <h1>Users</h1>
        {canCreate && (
          <button className="primary" onClick={() => setAdding(true)} data-testid="create-user">
            Create user
          </button>
        )}
      </div>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />
      <Notice text={notice} />
      {oidc && <OpenIDUsers provider={methods.data?.oidcName ?? "OpenID"} />}
      {oidc && showLocal && <h2>Local users</h2>}
      {showLocal && loading && !data && <Spinner />}
      {showLocal && data && users.length === 0 && <p className="muted">No users yet.</p>}
      {showLocal && users.length > 0 && (
        <table data-testid="user-table">
          <thead>
            <tr>
              <th>Access key</th>
              <th>Status</th>
              <th>Policies</th>
              <th>Groups</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {users.map(([name, u]) => (
              <tr key={name} data-testid={`user-${name}`}>
                <td>{name}</td>
                <td>
                  <span className={`pill ${u.status === "enabled" ? "ok" : "bad"}`}>{u.status}</span>
                </td>
                <td>{u.policyName || "—"}</td>
                <td>{u.memberOf?.join(", ") || "—"}</td>
                <td className="row-actions">
                  <button onClick={() => setEditing([name, u])}>Policies</button>
                  <button
                    onClick={() =>
                      setUserStatus(name, u.status === "enabled" ? "disabled" : "enabled")
                        .then(reload)
                        .catch(setError)
                    }
                  >
                    {u.status === "enabled" ? "Disable" : "Enable"}
                  </button>
                  <Link className="button" to={`/reports/audit?range=7d&user=${encodeURIComponent(name)}`} data-testid={`audit-user-${name}`}>
                    Actions
                  </Link>
                  <ConfirmButton
                    label="Delete"
                    confirm={`Delete ${name}?`}
                    testId={`delete-user-${name}`}
                    onConfirm={() =>
                      removeUser(name)
                        .then(reload)
                        .catch(setError)
                    }
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {adding && (
        <AddUser
          onClose={() => setAdding(false)}
          onDone={(n) => {
            setAdding(false);
            setNotice(`User ${n} created.`);
            reload();
          }}
        />
      )}
      {editing && (
        <PolicyPicker
          title={`Policies of ${editing[0]}`}
          current={(editing[1].policyName ?? "").split(",").filter(Boolean)}
          onClose={() => setEditing(null)}
          onSave={async (add, remove) => {
            if (add.length) await attachPolicies(add, { user: editing[0] });
            if (remove.length) await attachPolicies(remove, { user: editing[0] }, true);
            setEditing(null);
            reload();
          }}
        />
      )}
    </div>
  );
}

function AddUser({ onClose, onDone }: { onClose: () => void; onDone: (name: string) => void }) {
  const [ak, setAk] = useState("");
  const [sk, setSk] = useState("");
  const [policies, setPolicies] = useState<string[]>(["readwrite"]);
  const [error, setError] = useState<unknown>();
  const all = useLoad(listPolicies, []);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await addUser(ak, sk);
      if (policies.length) await attachPolicies(policies, { user: ak });
      onDone(ak);
    } catch (err) {
      setError(err);
    }
  };
  return (
    <Modal title="Create user" onClose={onClose}>
      <form onSubmit={submit}>
        <ErrorBanner error={error} />
        <label>
          Access key
          <input value={ak} onChange={(e) => setAk(e.target.value.trim())} autoFocus data-testid="new-access-key" />
        </label>
        <label>
          Secret key (at least 8 characters)
          <input type="password" value={sk} onChange={(e) => setSk(e.target.value)} data-testid="new-secret-key" />
        </label>
        <fieldset>
          <legend>Policies</legend>
          {Object.keys(all.data ?? {}).map((p) => (
            <label key={p} className="check">
              <input type="checkbox" checked={policies.includes(p)} onChange={(e) => setPolicies(e.target.checked ? [...policies, p] : policies.filter((x) => x !== p))} />{" "}
              {p}
            </label>
          ))}
        </fieldset>
        <div className="form-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={!ak || sk.length < 8} data-testid="user-create-submit">
            Create
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function PolicyPicker({
  title,
  current,
  onClose,
  onSave,
}: {
  title: string;
  current: string[];
  onClose: () => void;
  onSave: (add: string[], remove: string[]) => Promise<void>;
}) {
  const all = useLoad(listPolicies, []);
  const [chosen, setChosen] = useState<string[]>(current);
  const [error, setError] = useState<unknown>();
  return (
    <Modal title={title} onClose={onClose}>
      <ErrorBanner error={error} />
      {Object.keys(all.data ?? {}).map((p) => (
        <label key={p} className="check">
          <input type="checkbox" checked={chosen.includes(p)} onChange={(e) => setChosen(e.target.checked ? [...chosen, p] : chosen.filter((x) => x !== p))} /> {p}
        </label>
      ))}
      <div className="form-actions">
        <button onClick={onClose}>Cancel</button>
        <button
          className="primary"
          onClick={() =>
            onSave(
              chosen.filter((p) => !current.includes(p)),
              current.filter((p) => !chosen.includes(p)),
            ).catch(setError)
          }
        >
          Save
        </button>
      </div>
    </Modal>
  );
}

// Read-only: who can sign in, and with which roles, is managed in the identity provider.
function OpenIDUsers({ provider }: { provider: string }) {
  const { data, error, loading, setError } = useLoad(listOpenIDUsers, []);
  const label = (u: OpenIDUser) => u.displayName || u.readableName || u.email || u.ID;
  const users = (data ?? []).slice().sort((a, b) => label(a).localeCompare(label(b)));
  const now = Date.now();
  const signedInUntil = (u: OpenIDUser) =>
    Math.max(0, ...(u.stsKeys ?? []).map((k) => (k.expiration ? Date.parse(k.expiration) : 0)).filter((t) => t > now));
  return (
    <section data-testid="oidc-users">
      <h2>{provider} users</h2>
      <p className="muted">
        People appear here while they are signed in or hold access keys. Who can sign in, and with which roles, is managed in {provider}.
      </p>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />
      {loading && !data && <Spinner />}
      {data && users.length === 0 && <p className="muted">Nobody has signed in through {provider} yet.</p>}
      {users.length > 0 && (
        <table data-testid="oidc-user-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Sign-in name</th>
              <th>Roles</th>
              <th>Signed in until</th>
              <th>Access keys</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => {
              const until = signedInUntil(u);
              return (
                <tr key={u.minioAccessKey} data-testid={`oidc-user-${u.email || u.ID}`}>
                  <td>{u.displayName || u.readableName || "—"}</td>
                  <td>{u.email || <span className="mono">{u.ID}</span>}</td>
                  <td>{u.policies?.length ? u.policies.map((p) => <span key={p} className="pill">{p}</span>) : "—"}</td>
                  <td>{until ? new Date(until).toLocaleString() : "—"}</td>
                  <td>
                    {u.serviceAccounts?.length ?? 0}
                    {(() => {
                      const left = (u.serviceAccounts ?? []).filter((k) => k.ownerLeft).map((k) => k.ownerLeft!);
                      if (!left.length) return null;
                      const del = left.map((l) => l.deleteAt).sort()[0];
                      return (
                        <span className="pill warn" title="This person left the identity provider: the identity sync turned their keys off." data-testid={`left-${u.email || u.ID}`}>
                          left: {left.length === u.serviceAccounts!.length ? "all" : left.length} off, deleted {new Date(del).toLocaleDateString()}
                        </span>
                      );
                    })()}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}
