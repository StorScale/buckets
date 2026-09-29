import { FormEvent, useState } from "react";
import { addUser, attachPolicies, listPolicies, listUsers, removeUser, setUserStatus, UserInfo } from "../api";
import { ConfirmButton, ErrorBanner, Modal, Notice, Spinner, useLoad } from "../components";

export default function Users() {
  const { data, error, loading, reload, setError } = useLoad(listUsers, []);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<[string, UserInfo] | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const users = Object.entries(data ?? {}).sort(([a], [b]) => a.localeCompare(b));
  return (
    <div>
      <div className="page-head">
        <h1>Users</h1>
        <button className="primary" onClick={() => setAdding(true)} data-testid="create-user">
          Create user
        </button>
      </div>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />
      <Notice text={notice} />
      {loading && !data && <Spinner />}
      {data && users.length === 0 && <p className="muted">No users yet.</p>}
      {users.length > 0 && (
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
