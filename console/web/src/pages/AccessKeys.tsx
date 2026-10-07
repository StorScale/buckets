import { FormEvent, useState } from "react";
import { addServiceAccount, deleteServiceAccount, listServiceAccounts } from "../api";
import { ConfirmButton, ErrorBanner, Modal, Spinner, useLoad } from "../components";

export default function AccessKeys() {
  const { data, error, loading, reload, setError } = useLoad(listServiceAccounts, []);
  const [adding, setAdding] = useState(false);
  const [created, setCreated] = useState<{ accessKey: string; secretKey: string } | null>(null);
  const accounts = data?.accounts ?? [];
  return (
    <div>
      <div className="page-head">
        <h1>Access keys</h1>
        <button className="primary" onClick={() => setAdding(true)} data-testid="create-key">
          Create access key
        </button>
      </div>
      <p className="muted">Keys that act as you, optionally restricted by a policy of their own.</p>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />
      {loading && !data && <Spinner />}
      {data && accounts.length === 0 && <p className="muted">No access keys yet.</p>}
      {accounts.length > 0 && (
        <table data-testid="key-table">
          <thead>
            <tr>
              <th>Access key</th>
              <th>Name</th>
              <th>Status</th>
              <th>Expires</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {accounts.map((a) => (
              <tr key={a.accessKey} data-testid={`key-${a.accessKey}`}>
                <td className="mono">{a.accessKey}</td>
                <td>{a.name || "—"}</td>
                <td>
                  {a.ownerLeft ? (
                    <span title={`Turned off by the identity sync: its owner left the identity provider on ${new Date(a.ownerLeft.since).toLocaleString()}.`} data-testid={`owner-left-${a.accessKey}`}>
                      off: owner left · deleted on {new Date(a.ownerLeft.deleteAt).toLocaleDateString()}
                    </span>
                  ) : (
                    a.accountStatus ?? "on"
                  )}
                </td>
                <td>{a.expiration && !a.expiration.startsWith("1970") && !a.expiration.startsWith("9999") ? a.expiration : "never"}</td>
                <td className="row-actions">
                  <ConfirmButton
                    label="Delete"
                    confirm="Delete this key?"
                    onConfirm={() =>
                      deleteServiceAccount(a.accessKey)
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
        <AddKey
          onClose={() => setAdding(false)}
          onDone={(c) => {
            setAdding(false);
            setCreated(c);
            reload();
          }}
        />
      )}
      {created && (
        <Modal title="Access key created" onClose={() => setCreated(null)}>
          <p>Copy the secret key now: it is not shown again.</p>
          <table className="kv">
            <tbody>
              <tr>
                <th>Access key</th>
                <td className="mono" data-testid="created-access-key">
                  {created.accessKey}
                </td>
              </tr>
              <tr>
                <th>Secret key</th>
                <td className="mono" data-testid="created-secret-key">
                  {created.secretKey}
                </td>
              </tr>
            </tbody>
          </table>
          <div className="form-actions">
            <button className="primary" onClick={() => setCreated(null)}>
              Done
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function AddKey({ onClose, onDone }: { onClose: () => void; onDone: (c: { accessKey: string; secretKey: string }) => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [policy, setPolicy] = useState("");
  const [error, setError] = useState<unknown>();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      if (policy.trim()) JSON.parse(policy);
      const r = await addServiceAccount({ name: name || undefined, description: description || undefined, policy: policy.trim() || undefined });
      onDone(r.credentials);
    } catch (err) {
      setError(err);
    }
  };
  return (
    <Modal title="Create access key" onClose={onClose}>
      <form onSubmit={submit}>
        <ErrorBanner error={error} />
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} autoFocus data-testid="key-name" />
        </label>
        <label>
          Description
          <input value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
        <label>
          Policy (JSON, optional: empty inherits yours)
          <textarea rows={8} value={policy} onChange={(e) => setPolicy(e.target.value)} className="mono" />
        </label>
        <div className="form-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" data-testid="key-create-submit">
            Create
          </button>
        </div>
      </form>
    </Modal>
  );
}
