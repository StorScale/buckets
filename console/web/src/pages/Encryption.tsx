import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  bucketDocs,
  kmsCheckKey,
  kmsCreateKey,
  kmsDeleteKey,
  kmsListKeys,
  kmsStatus,
  KMSKeyCheck,
  KMSStatus,
  listBuckets,
} from "../api";
import { ErrorBanner, Modal, Notice, Spinner } from "../components";

type KeyRow = { name: string; check?: KMSKeyCheck; usedBy: string[] };

// Buckets whose default encryption is SSE-KMS, by key (the KMS's default key
// when the bucket names none).
async function keyUsage(defaultKey: string): Promise<Map<string, string[]>> {
  const usage = new Map<string, string[]>();
  const buckets = await listBuckets();
  await Promise.all(
    buckets.map(async (b) => {
      const x = await bucketDocs.encryption.get(b.name).catch(() => null);
      if (!x) return;
      const d = new DOMParser().parseFromString(x, "application/xml");
      if (d.querySelector("SSEAlgorithm")?.textContent !== "aws:kms") return;
      const key = (d.querySelector("KMSMasterKeyID")?.textContent || defaultKey).replace(/^arn:aws:kms:/, "");
      usage.set(key, [...(usage.get(key) ?? []), b.name].sort());
    }),
  );
  return usage;
}

export default function Encryption() {
  const [status, setStatus] = useState<KMSStatus | null>(null);
  const [noKms, setNoKms] = useState<string | null>(null);
  const [rows, setRows] = useState<KeyRow[] | null>(null);
  const [error, setError] = useState<unknown>();
  const [notice, setNotice] = useState<string | null>(null);
  const [newKey, setNewKey] = useState("");
  const [deleting, setDeleting] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const reload = () => setTick((t) => t + 1);

  useEffect(() => {
    let live = true;
    (async () => {
      let st: KMSStatus;
      try {
        st = await kmsStatus();
      } catch (e) {
        if (live) setNoKms(e instanceof Error ? e.message : String(e));
        return;
      }
      if (!live) return;
      setStatus(st);
      try {
        const [names, usage] = await Promise.all([kmsListKeys(), keyUsage(st["default-key-id"])]);
        if (!live) return;
        const base = names.map((name) => ({ name, usedBy: usage.get(name) ?? [] }));
        setRows(base);
        // each key's health, as it comes in
        names.forEach((name) =>
          kmsCheckKey(name)
            .then((check) => live && setRows((rs) => rs && rs.map((r) => (r.name === name ? { ...r, check } : r))))
            .catch((e) => live && setRows((rs) => rs && rs.map((r) => (r.name === name ? { ...r, check: { "key-id": name, "encryption-error": String(e.message ?? e) } } : r)))),
        );
      } catch (e) {
        if (live) setError(e);
      }
    })();
    return () => {
      live = false;
    };
  }, [tick]);

  const kes = status?.name.includes("KES") ?? false;
  const defaultKey = status?.["default-key-id"] ?? "";

  if (noKms !== null) {
    return (
      <div>
        <h1>Encryption</h1>
        <div className="card section" data-testid="no-kms">
          <h2>No KMS configured</h2>
          <p className="muted">
            Objects can be encrypted with SSE-C (keys the client sends) but not with SSE-S3 or SSE-KMS. Configure a KMS on the servers: a KES server
            (<span className="mono">MINIO_KMS_KES_ENDPOINT</span>, <span className="mono">MINIO_KMS_KES_KEY_NAME</span> and its credentials) to manage
            several keys, or a single static key (<span className="mono">MINIO_KMS_SECRET_KEY</span>).
          </p>
          <p className="muted">{noKms}</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <h1>Encryption</h1>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />
      <Notice text={notice} />
      {!status && <Spinner />}
      {status && (
        <div className="card section" data-testid="kms-status">
          <h2>Key management service</h2>
          <table className="kv">
            <tbody>
              <tr>
                <th>Backend</th>
                <td>{kes ? "KES" : "Built-in static key"}</td>
              </tr>
              <tr>
                <th>Default key</th>
                <td className="mono">{defaultKey}</td>
              </tr>
              <tr>
                <th>Endpoints</th>
                <td>
                  {Object.entries(status.endpoints).map(([ep, state]) => (
                    <div key={ep}>
                      <span className="mono">{ep}</span> <span className={`pill ${state === "online" ? "ok" : "bad"}`}>{state}</span>
                    </div>
                  ))}
                </td>
              </tr>
            </tbody>
          </table>
          {!kes && (
            <p className="muted">
              The built-in KMS has one fixed key. Use a KES server to create, rotate between and delete keys.
            </p>
          )}
        </div>
      )}

      {status && (
        <div className="card section">
          <div className="page-head">
            <h2>Keys</h2>
            {kes && (
              <form
                className="inline"
                onSubmit={(e) => {
                  e.preventDefault();
                  const k = newKey.trim();
                  kmsCreateKey(k)
                    .then(() => {
                      setNotice(`Key ${k} created.`);
                      setNewKey("");
                      reload();
                    })
                    .catch(setError);
                }}
              >
                <input placeholder="new key name" value={newKey} onChange={(e) => setNewKey(e.target.value)} data-testid="new-kms-key" />
                <button className="primary" disabled={!newKey.trim()} data-testid="create-kms-key">
                  Create key
                </button>
              </form>
            )}
          </div>
          {!rows && <Spinner />}
          {rows && rows.length === 0 && <p className="muted">The KMS has no keys.</p>}
          {rows && rows.length > 0 && (
            <table data-testid="kms-keys">
              <thead>
                <tr>
                  <th>Key</th>
                  <th>Status</th>
                  <th>Default encryption of</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const err = r.check?.["encryption-error"] || r.check?.["decryption-error"];
                  const isDefault = r.name === defaultKey;
                  const blocked = isDefault ? "the KMS's default key" : r.usedBy.length ? "in use by buckets" : "";
                  return (
                    <tr key={r.name} data-testid={`kms-key-${r.name}`}>
                      <td className="mono">
                        {r.name} {isDefault && <span className="pill">default</span>}
                      </td>
                      <td>{!r.check ? <span className="muted">checking…</span> : err ? <span className="bad">{err}</span> : <span className="pill ok">works</span>}</td>
                      <td>
                        {r.usedBy.length
                          ? r.usedBy.map((b, i) => (
                              <span key={b}>
                                {i > 0 && ", "}
                                <Link to={`/buckets/${encodeURIComponent(b)}/settings`}>{b}</Link>
                              </span>
                            ))
                          : "—"}
                      </td>
                      <td className="row-actions">
                        {kes && (
                          <button disabled={!!blocked} title={blocked ? `Cannot delete: ${blocked}` : undefined} onClick={() => setDeleting(r.name)} data-testid={`delete-kms-key-${r.name}`}>
                            Delete
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {deleting && (
        <DeleteKey
          name={deleting}
          onClose={() => setDeleting(null)}
          onDone={() => {
            setDeleting(null);
            setNotice(`Key ${deleting} deleted.`);
            reload();
          }}
        />
      )}
    </div>
  );
}

function DeleteKey({ name, onClose, onDone }: { name: string; onClose: () => void; onDone: () => void }) {
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<unknown>();
  return (
    <Modal title={`Delete key ${name}`} onClose={onClose}>
      <ErrorBanner error={error} />
      <p>
        <strong>This cannot be undone.</strong> Every object encrypted with <span className="mono">{name}</span> becomes unreadable for good, including
        objects in buckets that no longer use it by default. Before deleting, re-encrypt any such objects with another key.
      </p>
      <label>
        Type the key name to confirm
        <input value={typed} onChange={(e) => setTyped(e.target.value)} autoFocus data-testid="confirm-kms-key" />
      </label>
      <button className="danger" disabled={typed !== name} onClick={() => kmsDeleteKey(name).then(onDone).catch(setError)} data-testid="confirm-delete-kms-key">
        Delete {name}
      </button>
    </Modal>
  );
}
