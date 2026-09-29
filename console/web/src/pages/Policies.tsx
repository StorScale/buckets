import { useState } from "react";
import { getPolicy, listPolicies, putPolicy, removePolicy } from "../api";
import { ConfirmButton, ErrorBanner, Modal, Spinner, useLoad } from "../components";

const BUILTIN = ["readwrite", "readonly", "writeonly", "diagnostics", "consoleAdmin"];
const TEMPLATE = JSON.stringify(
  { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: ["s3:GetObject"], Resource: ["arn:aws:s3:::my-bucket/*"] }] },
  null,
  2,
);

export default function Policies() {
  const { data, error, loading, reload, setError } = useLoad(listPolicies, []);
  const [editing, setEditing] = useState<{ name: string; doc: string; isNew: boolean } | null>(null);
  const names = Object.keys(data ?? {}).sort();
  const open = async (name: string) => {
    try {
      const p = await getPolicy(name);
      setEditing({ name, doc: JSON.stringify(p.Policy, null, 2), isNew: false });
    } catch (e) {
      setError(e);
    }
  };
  return (
    <div>
      <div className="page-head">
        <h1>Policies</h1>
        <button className="primary" onClick={() => setEditing({ name: "", doc: TEMPLATE, isNew: true })} data-testid="create-policy">
          Create policy
        </button>
      </div>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />
      {loading && !data && <Spinner />}
      {names.length > 0 && (
        <table data-testid="policy-table">
          <thead>
            <tr>
              <th>Name</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {names.map((n) => (
              <tr key={n} data-testid={`policy-${n}`}>
                <td>
                  <a
                    href="#"
                    onClick={(e) => {
                      e.preventDefault();
                      open(n);
                    }}
                  >
                    {n}
                  </a> {BUILTIN.includes(n) && <span className="pill">built in</span>}
                </td>
                <td className="row-actions">
                  <button onClick={() => open(n)}>{BUILTIN.includes(n) ? "View" : "Edit"}</button>
                  {!BUILTIN.includes(n) && (
                    <ConfirmButton
                      label="Delete"
                      confirm={`Delete ${n}?`}
                      testId={`delete-policy-${n}`}
                      onConfirm={() =>
                        removePolicy(n)
                          .then(reload)
                          .catch(setError)
                      }
                    />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {editing && (
        <PolicyEditor
          initial={editing}
          readOnly={BUILTIN.includes(editing.name)}
          onClose={() => setEditing(null)}
          onSaved={() => (setEditing(null), reload())}
        />
      )}
    </div>
  );
}

function PolicyEditor({
  initial,
  readOnly,
  onClose,
  onSaved,
}: {
  initial: { name: string; doc: string; isNew: boolean };
  readOnly: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(initial.name);
  const [doc, setDoc] = useState(initial.doc);
  const [error, setError] = useState<unknown>();
  const save = async () => {
    try {
      JSON.parse(doc);
    } catch {
      setError(new Error("The policy is not valid JSON."));
      return;
    }
    try {
      await putPolicy(name, doc);
      onSaved();
    } catch (e) {
      setError(e);
    }
  };
  return (
    <Modal title={initial.isNew ? "Create policy" : initial.name} onClose={onClose}>
      <ErrorBanner error={error} />
      {initial.isNew && (
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value.trim())} autoFocus data-testid="policy-name" />
        </label>
      )}
      <textarea rows={18} value={doc} onChange={(e) => setDoc(e.target.value)} readOnly={readOnly} className="mono" data-testid="policy-doc" />
      <div className="form-actions">
        <button onClick={onClose}>{readOnly ? "Close" : "Cancel"}</button>
        {!readOnly && (
          <button className="primary" onClick={save} disabled={!name} data-testid="policy-save">
            Save
          </button>
        )}
      </div>
    </Modal>
  );
}
