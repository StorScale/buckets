import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { deleteBucket, listBuckets, makeBucket } from "../api";
import { ConfirmButton, ErrorBanner, formatDate, Modal, Spinner, useLoad } from "../components";

export default function Buckets() {
  const { data, error, loading, reload, setError } = useLoad(listBuckets, []);
  const [creating, setCreating] = useState(false);
  const [filter, setFilter] = useState("");
  const buckets = (data ?? []).filter((b) => b.name.includes(filter));
  return (
    <div>
      <div className="page-head">
        <h1>Buckets</h1>
        <div className="actions">
          <input placeholder="Filter" value={filter} onChange={(e) => setFilter(e.target.value)} />
          <button className="primary" onClick={() => setCreating(true)} data-testid="create-bucket">
            Create bucket
          </button>
        </div>
      </div>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />
      {loading && !data && <Spinner />}
      {data && buckets.length === 0 && <p className="muted">No buckets yet.</p>}
      {buckets.length > 0 && (
        <table data-testid="bucket-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Created</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {buckets.map((b) => (
              <tr key={b.name} data-testid={`bucket-${b.name}`}>
                <td>
                  <Link to={`/buckets/${encodeURIComponent(b.name)}/browse/`}>{b.name}</Link>
                </td>
                <td>{formatDate(b.created)}</td>
                <td className="row-actions">
                  <Link to={`/buckets/${encodeURIComponent(b.name)}/settings`} className="button">
                    Settings
                  </Link>
                  <Link to={`/identity/access-review?bucket=${encodeURIComponent(b.name)}`} className="button" data-testid={`access-${b.name}`}>
                    Access
                  </Link>
                  <ConfirmButton
                    label="Delete"
                    confirm={`Delete ${b.name}?`}
                    testId={`delete-${b.name}`}
                    onConfirm={() =>
                      deleteBucket(b.name)
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
      {creating && <CreateBucket onDone={() => (setCreating(false), reload())} onClose={() => setCreating(false)} />}
    </div>
  );
}

function CreateBucket({ onDone, onClose }: { onDone: () => void; onClose: () => void }) {
  const [name, setName] = useState("");
  const [locking, setLocking] = useState(false);
  const [error, setError] = useState<unknown>();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await makeBucket(name, locking);
      onDone();
    } catch (err) {
      setError(err);
    }
  };
  return (
    <Modal title="Create bucket" onClose={onClose}>
      <form onSubmit={submit}>
        <ErrorBanner error={error} />
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value.trim())} autoFocus data-testid="bucket-name" />
        </label>
        <label className="check">
          <input type="checkbox" checked={locking} onChange={(e) => setLocking(e.target.checked)} /> Object locking (enables versioning; cannot
          be turned off)
        </label>
        <div className="form-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={!name} data-testid="bucket-create-submit">
            Create
          </button>
        </div>
      </form>
    </Modal>
  );
}
