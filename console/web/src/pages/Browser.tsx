import { ChangeEvent, useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  bucketDocs,
  deleteObject,
  deleteObjects,
  downloadUrl,
  getLegalHold,
  getObjectTags,
  getRetention,
  headObject,
  inlineUrl,
  loginMethods,
  Retention,
  setLegalHold,
  setRetention,
  shareLink,
  listObjects,
  listVersions,
  Listing,
  putObject,
  setObjectTags,
  Tag,
  VersionInfo,
} from "../api";
import { ConfirmButton, ErrorBanner, formatBytes, formatDate, Modal, Notice, Spinner } from "../components";

type Upload = { name: string; done: number; total: number; error?: string };

export default function Browser() {
  const { bucket = "", "*": rest = "" } = useParams();
  const prefix = rest && !rest.endsWith("/") ? rest + "/" : rest;
  const navigate = useNavigate();
  const [listing, setListing] = useState<Listing | null>(null);
  const [error, setError] = useState<unknown>();
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [uploads, setUploads] = useState<Upload[]>([]);
  const [details, setDetails] = useState<string | null>(null);
  const [showVersions, setShowVersions] = useState(false);
  const [versions, setVersions] = useState<VersionInfo[] | null>(null);
  const [newFolder, setNewFolder] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const load = async (append?: string) => {
    setLoading(true);
    setError(undefined);
    try {
      const l = await listObjects(bucket, prefix, append);
      setListing((old) => (append && old ? { prefixes: [...old.prefixes, ...l.prefixes], objects: [...old.objects, ...l.objects], next: l.next } : l));
      if (showVersions) setVersions(await listVersions(bucket, prefix));
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    setSelected(new Set());
    setListing(null);
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bucket, prefix, showVersions]);

  const hrefOf = (p: string) => `/buckets/${encodeURIComponent(bucket)}/browse/${p.split("/").map(encodeURIComponent).join("/")}`;
  const go = (p: string) => navigate(hrefOf(p));
  // Real links (so they open in new tabs and read as links), routed in-app.
  const nav = (p: string) => ({
    href: hrefOf(p),
    onClick: (e: { preventDefault: () => void }) => {
      e.preventDefault();
      go(p);
    },
  });
  const crumbs = prefix.split("/").filter(Boolean);

  const upload = async (e: ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files ?? []);
    e.target.value = "";
    if (!files.length) return;
    setUploads(files.map((f) => ({ name: f.name, done: 0, total: f.size })));
    let failed = 0;
    await Promise.all(
      files.map((f, i) =>
        putObject(bucket, prefix + ((f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name), f, (done, total) =>
          setUploads((u) => u.map((x, j) => (j === i ? { ...x, done, total } : x))),
        ).catch((err) => {
          failed++;
          setUploads((u) => u.map((x, j) => (j === i ? { ...x, error: String(err.message ?? err) } : x)));
        }),
      ),
    );
    if (!failed) {
      setUploads([]);
      setNotice(`Uploaded ${files.length} file${files.length > 1 ? "s" : ""}.`);
    }
    load();
  };

  const removeSelected = async () => {
    const keys = Array.from(selected);
    try {
      // A folder removes everything under it.
      const items: { key: string }[] = [];
      for (const k of keys) {
        if (!k.endsWith("/")) {
          items.push({ key: k });
          continue;
        }
        let token: string | undefined;
        do {
          const l = await listAllUnder(bucket, k, token);
          items.push(...l.keys.map((key) => ({ key })));
          token = l.next;
        } while (token);
      }
      const failed = await deleteObjects(bucket, items);
      if (failed.length) setError(new Error(`Some objects were not deleted: ${failed.slice(0, 3).join("; ")}`));
      else setNotice(`Deleted ${items.length} object${items.length === 1 ? "" : "s"}.`);
    } catch (e) {
      setError(e);
    }
    setSelected(new Set());
    load();
  };

  const toggle = (k: string) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(k)) n.delete(k);
      else n.add(k);
      return n;
    });
  const rows = listing ? [...listing.prefixes.map((p) => ({ prefix: p })), ...listing.objects.filter((o) => o.key !== prefix)] : [];

  return (
    <div>
      <div className="page-head">
        <h1>
          <Link to="/buckets">Buckets</Link> / <a {...nav("")}>{bucket}</a>
          {crumbs.map((c, i) => (
            <span key={i}>
              {" / "}
              <a {...nav(crumbs.slice(0, i + 1).join("/") + "/")}>{c}</a>
            </span>
          ))}
        </h1>
        <div className="actions">
          <label className="check">
            <input type="checkbox" checked={showVersions} onChange={(e) => setShowVersions(e.target.checked)} data-testid="show-versions" /> Versions
          </label>
          <Link className="button" to={`/buckets/${encodeURIComponent(bucket)}/settings`}>
            Settings
          </Link>
          <button onClick={() => setNewFolder(true)} data-testid="new-folder">
            New folder
          </button>
          <button className="primary" onClick={() => fileInput.current?.click()} data-testid="upload">
            Upload
          </button>
          <input ref={fileInput} type="file" multiple hidden onChange={upload} data-testid="file-input" />
        </div>
      </div>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />
      <Notice text={notice} />
      {uploads.length > 0 && (
        <div className="card uploads" data-testid="uploads">
          {uploads.map((u, i) => (
            <div key={i} className="upload-row">
              <span>{u.name}</span>
              {u.error ? <span className="bad">{u.error}</span> : <progress value={u.done} max={u.total || 1} />}
            </div>
          ))}
        </div>
      )}
      {selected.size > 0 && (
        <div className="selection">
          {selected.size} selected
          <ConfirmButton label="Delete" confirm="Delete the selection?" onConfirm={removeSelected} testId="delete-selected" />
        </div>
      )}
      {loading && !listing && <Spinner />}
      {listing && rows.length === 0 && !showVersions && <p className="muted">This folder is empty.</p>}
      {rows.length > 0 && !showVersions && (
        <table data-testid="object-table">
          <thead>
            <tr>
              <th className="narrow" />
              <th>Name</th>
              <th>Size</th>
              <th>Last modified</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((r) =>
              "prefix" in r ? (
                <tr key={r.prefix} data-testid={`row-${r.prefix}`}>
                  <td>
                    <input type="checkbox" checked={selected.has(r.prefix)} onChange={() => toggle(r.prefix)} />
                  </td>
                  <td>
                    <a {...nav(r.prefix)} className="folder">
                      📁 {r.prefix.slice(prefix.length)}
                    </a>
                  </td>
                  <td>—</td>
                  <td>—</td>
                  <td />
                </tr>
              ) : (
                <tr key={r.key} data-testid={`row-${r.key}`}>
                  <td>
                    <input type="checkbox" checked={selected.has(r.key)} onChange={() => toggle(r.key)} data-testid={`select-${r.key}`} />
                  </td>
                  <td>
                    <a
                      href={hrefOf(r.key)}
                      onClick={(e) => {
                        e.preventDefault();
                        setDetails(r.key);
                      }}
                    >
                      {r.key.slice(prefix.length)}
                    </a>
                  </td>
                  <td>{formatBytes(r.size)}</td>
                  <td>{formatDate(r.lastModified)}</td>
                  <td className="row-actions">
                    <a className="button" href={downloadUrl(bucket, r.key)} data-testid={`download-${r.key}`}>
                      Download
                    </a>
                  </td>
                </tr>
              ),
            )}
          </tbody>
        </table>
      )}
      {showVersions && versions && (
        <table data-testid="version-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Version</th>
              <th>Size</th>
              <th>Last modified</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {versions.map((v) => (
              <tr key={v.key + v.versionId}>
                <td>
                  {v.key.slice(prefix.length)} {v.isLatest && <span className="pill ok">latest</span>}
                  {v.deleteMarker && <span className="pill bad">delete marker</span>}
                </td>
                <td className="mono">{v.versionId}</td>
                <td>{v.deleteMarker ? "—" : formatBytes(v.size)}</td>
                <td>{formatDate(v.lastModified)}</td>
                <td className="row-actions">
                  {!v.deleteMarker && (
                    <a className="button" href={downloadUrl(bucket, v.key, v.versionId)}>
                      Download
                    </a>
                  )}
                  <ConfirmButton
                    label="Delete"
                    confirm="Delete this version for good?"
                    onConfirm={() =>
                      deleteObject(bucket, v.key, v.versionId)
                        .then(() => load())
                        .catch(setError)
                    }
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {listing?.next && !showVersions && (
        <button onClick={() => load(listing.next)} disabled={loading}>
          Load more
        </button>
      )}
      {details && <ObjectDetails bucket={bucket} objectKey={details} onClose={() => setDetails(null)} onDeleted={() => (setDetails(null), load())} />}
      {newFolder && (
        <NewFolder
          onClose={() => setNewFolder(false)}
          onCreate={(name) => {
            setNewFolder(false);
            go(prefix + name.replace(/^\/+|\/+$/g, "") + "/");
          }}
        />
      )}
    </div>
  );
}

async function listAllUnder(bucket: string, prefix: string, token?: string): Promise<{ keys: string[]; next?: string }> {
  // Flat listing (no delimiter) for recursive deletes.
  const res = await fetch(
    `/api/v1/s3/${encodeURIComponent(bucket)}?list-type=2&max-keys=1000&prefix=${encodeURIComponent(prefix)}${token ? `&continuation-token=${encodeURIComponent(token)}` : ""}`,
    { credentials: "same-origin" },
  );
  const d = new DOMParser().parseFromString(await res.text(), "application/xml");
  const keys = Array.from(d.getElementsByTagName("Contents")).map((c) => c.getElementsByTagName("Key")[0]?.textContent ?? "");
  const truncated = d.getElementsByTagName("IsTruncated")[0]?.textContent === "true";
  return { keys, next: truncated ? d.getElementsByTagName("NextContinuationToken")[0]?.textContent ?? undefined : undefined };
}

function NewFolder({ onClose, onCreate }: { onClose: () => void; onCreate: (name: string) => void }) {
  const [name, setName] = useState("");
  return (
    <Modal title="New folder" onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (name) onCreate(name);
        }}
      >
        <p className="muted">Folders exist once something is uploaded into them.</p>
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} autoFocus data-testid="folder-name" />
        </label>
        <div className="form-actions">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={!name} data-testid="folder-create">
            Open
          </button>
        </div>
      </form>
    </Modal>
  );
}

function ObjectDetails({ bucket, objectKey, onClose, onDeleted }: { bucket: string; objectKey: string; onClose: () => void; onDeleted: () => void }) {
  const [headers, setHeaders] = useState<Headers | null>(null);
  const [tags, setTags] = useState<Tag[]>([]);
  const [error, setError] = useState<unknown>();
  const [saved, setSaved] = useState<string | null>(null);
  const [retention, setRet] = useState<Retention | null>(null);
  const [hold, setHold] = useState<boolean | null>(null);
  const [locking, setLocking] = useState(false);
  const [canShare, setCanShare] = useState(false);
  const [share, setShare] = useState<{ url: string; expiresAt: number } | null>(null);
  const [shareFor, setShareFor] = useState(24 * 3600);
  const [preview, setPreview] = useState<string | null>(null);
  useEffect(() => {
    headObject(bucket, objectKey).then(setHeaders).catch(setError);
    getObjectTags(bucket, objectKey).then(setTags).catch(setError);
    // Retention and legal hold exist only in buckets with object locking.
    bucketDocs.objectLock
      .get(bucket)
      .then((x) => {
        if (!x || !x.includes("<ObjectLockEnabled>Enabled</ObjectLockEnabled>")) return;
        setLocking(true);
        getRetention(bucket, objectKey).then(setRet).catch(() => undefined);
        getLegalHold(bucket, objectKey).then(setHold).catch(() => undefined);
      })
      .catch(() => undefined);
    loginMethods()
      .then((m) => setCanShare(m.share))
      .catch(() => undefined);
  }, [bucket, objectKey]);
  // Small text objects preview inline; images load by URL.
  const type = headers?.get("content-type") ?? "";
  const size = Number(headers?.get("content-length") ?? 0);
  const isImage = type.startsWith("image/");
  const isText = (type.startsWith("text/") || type === "application/json") && size <= 256 * 1024;
  useEffect(() => {
    if (!isText) return;
    fetch(inlineUrl(bucket, objectKey), { credentials: "same-origin" })
      .then((r) => r.text())
      .then(setPreview)
      .catch(() => undefined);
  }, [bucket, objectKey, isText]);
  const meta: [string, string][] = [];
  headers?.forEach((v, k) => {
    if (["content-type", "etag", "last-modified", "content-length", "x-amz-version-id", "x-amz-server-side-encryption"].includes(k) || k.startsWith("x-amz-meta-"))
      meta.push([k, v]);
  });
  return (
    <Modal title={objectKey} onClose={onClose}>
      <ErrorBanner error={error} />
      <Notice text={saved} />
      <table className="kv">
        <tbody>
          {meta.map(([k, v]) => (
            <tr key={k}>
              <th>{k}</th>
              <td className="mono">{k === "content-length" ? `${formatBytes(Number(v))} (${v} bytes)` : v}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {isImage && <img className="preview" src={inlineUrl(bucket, objectKey)} alt={objectKey} data-testid="preview" />}
      {isText && preview !== null && (
        <pre className="preview" data-testid="preview">
          {preview}
        </pre>
      )}
      {canShare && (
        <>
          <h3>Share</h3>
          <div className="share">
            <select value={shareFor} onChange={(e) => setShareFor(Number(e.target.value))}>
              <option value={3600}>1 hour</option>
              <option value={24 * 3600}>1 day</option>
              <option value={7 * 24 * 3600}>7 days</option>
            </select>
            <button
              data-testid="share"
              onClick={() =>
                shareLink(bucket, objectKey, shareFor)
                  .then(setShare)
                  .catch(setError)
              }
            >
              Create link
            </button>
            {share && (
              <>
                <input className="url" readOnly value={share.url} onFocus={(e) => e.target.select()} data-testid="share-url" />
                <span className="muted">until {new Date(share.expiresAt * 1000).toLocaleString()}</span>
              </>
            )}
          </div>
        </>
      )}
      {locking && (
        <LockPanel
          bucket={bucket}
          objectKey={objectKey}
          retention={retention}
          hold={hold}
          onChange={(r, h) => {
            setRet(r);
            setHold(h);
          }}
          onError={setError}
          onSaved={setSaved}
        />
      )}
      <h3>Tags</h3>
      <TagEditor
        tags={tags}
        onChange={setTags}
        onSave={() =>
          setObjectTags(bucket, objectKey, tags)
            .then(() => setSaved("Tags saved."))
            .catch(setError)
        }
      />
      <div className="form-actions">
        <a className="button" href={downloadUrl(bucket, objectKey)}>
          Download
        </a>
        <ConfirmButton
          label="Delete"
          confirm="Delete this object?"
          testId="delete-object"
          onConfirm={() =>
            deleteObject(bucket, objectKey)
              .then(onDeleted)
              .catch(setError)
          }
        />
      </div>
    </Modal>
  );
}

function LockPanel({
  bucket,
  objectKey,
  retention,
  hold,
  onChange,
  onError,
  onSaved,
}: {
  bucket: string;
  objectKey: string;
  retention: Retention | null;
  hold: boolean | null;
  onChange: (r: Retention | null, h: boolean | null) => void;
  onError: (e: unknown) => void;
  onSaved: (s: string) => void;
}) {
  const [mode, setMode] = useState(retention?.mode || "GOVERNANCE");
  const [until, setUntil] = useState(retention?.until ? retention.until.slice(0, 10) : "");
  return (
    <>
      <h3>Retention</h3>
      <p className="muted" data-testid="retention">
        {retention?.mode ? `${retention.mode} until ${new Date(retention.until).toLocaleString()}` : "No retention."}
      </p>
      <label className="inline">
        <select value={mode} onChange={(e) => setMode(e.target.value)}>
          <option value="GOVERNANCE">Governance</option>
          <option value="COMPLIANCE">Compliance</option>
        </select>
        <input type="date" value={until} onChange={(e) => setUntil(e.target.value)} data-testid="retain-until" />
        <button
          disabled={!until}
          data-testid="save-retention"
          onClick={() =>
            setRetention(bucket, objectKey, mode, `${until}T23:59:59Z`)
              .then(() => getRetention(bucket, objectKey))
              .then((r) => {
                onChange(r, hold);
                onSaved("Retention saved.");
              })
              .catch(onError)
          }
        >
          Set retention
        </button>
      </label>
      <h3>Legal hold</h3>
      <label className="check">
        <input
          type="checkbox"
          checked={!!hold}
          data-testid="legal-hold"
          onChange={(e) => {
            const on = e.target.checked;
            onChange(retention, on); /* optimistic; undone if the server says no */
            setLegalHold(bucket, objectKey, on)
              .then(() => onSaved(on ? "Legal hold on." : "Legal hold off."))
              .catch((err) => {
                onChange(retention, !on);
                onError(err);
              });
          }}
        />{" "}
        Legal hold (blocks deletion of this version)
      </label>
    </>
  );
}

export function TagEditor({ tags, onChange, onSave }: { tags: Tag[]; onChange: (t: Tag[]) => void; onSave: () => void }) {
  return (
    <div className="tags" data-testid="tag-editor">
      {tags.map((t, i) => (
        <div key={i} className="tag-row">
          <input value={t.key} placeholder="key" onChange={(e) => onChange(tags.map((x, j) => (j === i ? { ...x, key: e.target.value } : x)))} />
          <input value={t.value} placeholder="value" onChange={(e) => onChange(tags.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))} />
          <button onClick={() => onChange(tags.filter((_, j) => j !== i))} aria-label="remove tag">
            ×
          </button>
        </div>
      ))}
      <div className="form-actions">
        <button onClick={() => onChange([...tags, { key: "", value: "" }])} data-testid="add-tag">
          Add tag
        </button>
        <button className="primary" onClick={onSave} data-testid="save-tags">
          Save tags
        </button>
      </div>
    </div>
  );
}
