import { FormEvent, useState } from "react";
import { attachPolicies, groupInfo, GroupInfo, listGroups, listUsers, setGroupStatus, updateGroupMembers } from "../api";
import { ConfirmButton, ErrorBanner, Modal, Spinner, useLoad } from "../components";
import { PolicyPicker } from "./Users";

export default function Groups() {
  const { data, error, loading, reload, setError } = useLoad(async () => {
    const names = (await listGroups()) ?? [];
    return Promise.all(names.map((g) => groupInfo(g)));
  }, []);
  const [adding, setAdding] = useState(false);
  const [policies, setPolicies] = useState<GroupInfo | null>(null);
  return (
    <div>
      <div className="page-head">
        <h1>Groups</h1>
        <button className="primary" onClick={() => setAdding(true)} data-testid="create-group">
          Create group
        </button>
      </div>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />
      {loading && !data && <Spinner />}
      {data && data.length === 0 && <p className="muted">No groups yet.</p>}
      {data && data.length > 0 && (
        <table data-testid="group-table">
          <thead>
            <tr>
              <th>Group</th>
              <th>Status</th>
              <th>Members</th>
              <th>Policies</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {data.map((g) => (
              <tr key={g.name} data-testid={`group-${g.name}`}>
                <td>{g.name}</td>
                <td>
                  <span className={`pill ${g.status === "enabled" ? "ok" : "bad"}`}>{g.status}</span>
                </td>
                <td>{g.members?.join(", ") || "—"}</td>
                <td>{g.policy || "—"}</td>
                <td className="row-actions">
                  <button onClick={() => setPolicies(g)}>Policies</button>
                  <button
                    onClick={() =>
                      setGroupStatus(g.name, g.status === "enabled" ? "disabled" : "enabled")
                        .then(reload)
                        .catch(setError)
                    }
                  >
                    {g.status === "enabled" ? "Disable" : "Enable"}
                  </button>
                  <ConfirmButton
                    label="Delete"
                    confirm={`Delete ${g.name}?`}
                    onConfirm={() =>
                      updateGroupMembers(g.name, [], true)
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
      {adding && <AddGroup onClose={() => setAdding(false)} onDone={() => (setAdding(false), reload())} />}
      {policies && (
        <PolicyPicker
          title={`Policies of ${policies.name}`}
          current={(policies.policy ?? "").split(",").filter(Boolean)}
          onClose={() => setPolicies(null)}
          onSave={async (add, remove) => {
            if (add.length) await attachPolicies(add, { group: policies.name });
            if (remove.length) await attachPolicies(remove, { group: policies.name }, true);
            setPolicies(null);
            reload();
          }}
        />
      )}
    </div>
  );
}

function AddGroup({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const users = useLoad(listUsers, []);
  const [name, setName] = useState("");
  const [members, setMembers] = useState<string[]>([]);
  const [error, setError] = useState<unknown>();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await updateGroupMembers(name, members, false);
      onDone();
    } catch (err) {
      setError(err);
    }
  };
  return (
    <Modal title="Create group" onClose={onClose}>
      <form onSubmit={submit}>
        <ErrorBanner error={error} />
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value.trim())} autoFocus data-testid="group-name" />
        </label>
        <fieldset>
          <legend>Members</legend>
          {Object.keys(users.data ?? {}).map((u) => (
            <label key={u} className="check">
              <input type="checkbox" checked={members.includes(u)} onChange={(e) => setMembers(e.target.checked ? [...members, u] : members.filter((x) => x !== u))} />{" "}
              {u}
            </label>
          ))}
        </fieldset>
        <div className="form-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={!name} data-testid="group-create-submit">
            Create
          </button>
        </div>
      </form>
    </Modal>
  );
}
