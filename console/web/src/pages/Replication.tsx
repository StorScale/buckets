import { ReactNode, useEffect, useState } from "react";
import {
  DeclaredBucket,
  NewTarget,
  removeRemoteTarget,
  ReplicationBucket,
  replicationDoc,
  replicationResync,
  replicationStatus,
  replicationTest,
  ReplicationTarget,
  setRemoteTarget,
  setVersioning,
} from "../api";
import { ConfirmButton, errorText, formatBytes, Spinner } from "../components";

// A bucket's replication (docs/design/lifecycle-replication-editor.md): set up in one form (the target, a test,
// what goes), each target's state, resync, and removal. Saving makes the remote target, then the rule pointing at
// it; a refused rule takes the new target away again.

function Field({ label, help, children }: { label: string; help?: ReactNode; children: ReactNode }) {
  return (
    <label>
      <span className="field-label">{label}</span>
      {children}
      {help && <span className="field-help">{help}</span>}
    </label>
  );
}

type Form = NewTarget & {
  prefix: string;
  deletes: boolean;
  deleteMarkers: boolean;
  existing: boolean;
  metadataSync: boolean;
  bandwidthMbps: string;
};
const blank: Form = {
  endpoint: "",
  bucket: "",
  accessKey: "",
  secretKey: "",
  prefix: "",
  deletes: true,
  deleteMarkers: true,
  existing: true,
  metadataSync: false,
  bandwidthMbps: "",
  storageClass: "",
};

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const status = (on: boolean) => `<Status>${on ? "Enabled" : "Disabled"}</Status>`;

// The configuration with one more rule, for arn (existing rules kept as they are).
export function withRule(current: string | null, f: Form, arn: string, id: string): string {
  const doc = current ? new DOMParser().parseFromString(current, "application/xml") : null;
  const prios = doc ? Array.from(doc.getElementsByTagName("Priority")).map((p) => Number(p.textContent) || 0) : [];
  const rule =
    `<Rule><ID>${esc(id)}</ID><Status>Enabled</Status><Priority>${Math.max(0, ...prios) + 1}</Priority>` +
    `<DeleteMarkerReplication>${status(f.deleteMarkers)}</DeleteMarkerReplication>` +
    `<DeleteReplication>${status(f.deletes)}</DeleteReplication>` +
    `<ExistingObjectReplication>${status(f.existing)}</ExistingObjectReplication>` +
    `<Filter><Prefix>${esc(f.prefix)}</Prefix></Filter>` +
    `<Destination><Bucket>${esc(arn)}</Bucket>${f.storageClass ? `<StorageClass>${esc(f.storageClass)}</StorageClass>` : ""}</Destination>` +
    `<SourceSelectionCriteria><ReplicaModifications>${status(f.metadataSync)}</ReplicaModifications></SourceSelectionCriteria></Rule>`;
  if (!current || !current.includes("</ReplicationConfiguration>")) return `<ReplicationConfiguration><Role></Role>${rule}</ReplicationConfiguration>`;
  return current.replace("</ReplicationConfiguration>", `${rule}</ReplicationConfiguration>`);
}

// The configuration without the rules for arn; "" when none are left.
export function withoutTarget(current: string, arn: string): string {
  const doc = new DOMParser().parseFromString(current, "application/xml");
  const rules = Array.from(doc.documentElement.children).filter((c) => c.localName === "Rule");
  let left = 0;
  for (const r of rules) {
    const dest = Array.from(r.getElementsByTagName("Bucket"))[0]?.textContent?.trim();
    if (dest === arn) r.remove();
    else left++;
  }
  return left ? new XMLSerializer().serializeToString(doc) : "";
}

type Props = {
  bucket: string;
  versioned: boolean;
  declared: DeclaredBucket | null;
  onVersioning: () => void;
  onSaved: (text: string) => void;
  onError: (e: unknown) => void;
};

export default function ReplicationSection({ bucket, versioned, declared, onVersioning, onSaved, onError }: Props) {
  const [st, setSt] = useState<ReplicationBucket | null>(null);
  const [site, setSite] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [adding, setAdding] = useState(false);
  const [f, setF] = useState<Form>(blank);
  const [test, setTest] = useState<{ ok: boolean; text: string; sourceVersioned?: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [turnOnVersioning, setTurnOnVersioning] = useState(true);
  const readOnly = !!declared?.replication;

  const load = async () => {
    const s = await replicationStatus(bucket);
    setSite(s.siteReplication);
    setSt(s.buckets[0] ?? null);
  };
  useEffect(() => {
    load()
      .catch(onError)
      .finally(() => setLoaded(true));
    const t = setInterval(() => load().catch(() => undefined), 15000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bucket]);

  const set = (p: Partial<Form>) => {
    setF({ ...f, ...p });
    setTest(null);
  };
  const target = (): NewTarget => ({
    endpoint: f.endpoint.trim(),
    bucket: f.bucket.trim(),
    accessKey: f.accessKey.trim(),
    secretKey: f.secretKey,
    bandwidthLimit: f.bandwidthMbps ? Math.round(Number(f.bandwidthMbps) * 125000) : 0,
    storageClass: f.storageClass,
  });

  const runTest = async () => {
    setBusy(true);
    try {
      const r = await replicationTest(bucket, target());
      setTest({ ok: true, sourceVersioned: r.sourceVersioned, text: "The target answers, the credentials work, and versioning is on there." });
    } catch (e) {
      setTest({ ok: false, text: errorText(e) });
    } finally {
      setBusy(false);
    }
  };

  const save = async () => {
    setBusy(true);
    let arn = "";
    let made = false;
    try {
      if (!versioned) {
        await setVersioning(bucket, "Enabled");
        onVersioning();
      }
      const before = new Set((st?.targets ?? []).map((t) => t.arn));
      arn = await setRemoteTarget(bucket, target());
      made = !before.has(arn);
      const cur = await replicationDoc.get(bucket);
      const id = `to-${f.bucket.trim()}-${Date.now().toString(36)}`;
      await replicationDoc.put(bucket, withRule(cur, f, arn, id));
      setAdding(false);
      setF(blank);
      setTest(null);
      await load();
      onSaved(`Replication to ${f.bucket.trim()} saved.`);
    } catch (e) {
      if (made && arn) await removeRemoteTarget(bucket, arn).catch(() => undefined); // nothing half done
      onError(e);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (t: ReplicationTarget) => {
    try {
      const cur = await replicationDoc.get(bucket);
      const next = cur ? withoutTarget(cur, t.arn) : "";
      if (next) await replicationDoc.put(bucket, next);
      // the last rule gone: deleting the configuration takes the bucket's targets with it, as MinIO does
      if (next || !cur) await removeRemoteTarget(bucket, t.arn);
      else await replicationDoc.del(bucket);
      await load();
      onSaved(`Replication to ${t.bucket} removed.`);
    } catch (e) {
      onError(e);
    }
  };

  const resync = async (t: ReplicationTarget) => {
    try {
      await replicationResync(bucket, t.arn);
      onSaved(`Copying every object to ${t.bucket} again.`);
    } catch (e) {
      onError(e);
    }
  };

  if (!loaded) return <Spinner />;
  if (site)
    return (
      <p className="muted" data-testid="replication-site">
        This cluster is in a site replication group: every bucket is replicated to every site already, so there is
        nothing to set up here. The group is managed with <code>mc admin replicate</code>.
      </p>
    );
  const targets = st?.targets ?? [];
  const canSave = f.endpoint && f.bucket && f.accessKey && f.secretKey && test?.ok && (versioned || turnOnVersioning);

  return (
    <div data-testid="replication-section">
      {readOnly && (
        <p className="banner warn" data-testid="replication-declared">
          Declared in Kubernetes (Bucket {declared!.resource}): change it there, or the operator will put it back within
          10 minutes.
        </p>
      )}
      {targets.length === 0 && !adding && <p className="muted">Not replicated.</p>}
      {targets.map((t) => {
        // a target added since the servers' last health check (every 5 seconds) hasn't been seen either way
        const unchecked = !t.online && !t.lastOnline && !t.offlineCount;
        return (
        <div key={t.arn} className="team-level" data-testid={`repl-target-${t.bucket}`}>
          <div>
            <span className={`pill ${t.online ? "ok" : unchecked ? "warn" : "bad"}`} data-testid={`repl-online-${t.bucket}`}>
              {t.online ? "online" : unchecked ? "checking" : "offline"}
            </span>{" "}
            <strong>
              {t.secure ? "https" : "http"}://{t.endpoint}/{t.bucket}
            </strong>{" "}
            <span className="muted">as {t.accessKey}</span>
          </div>
          <div className="muted" data-testid={`repl-counts-${t.bucket}`}>
            {t.replicated.toLocaleString()} replicated · {t.failedLastHour.toLocaleString()} failed in the last hour ·{" "}
            {t.failedSinceStart.toLocaleString()} failed since the servers started
            {t.online && ` · ${t.latencyMs} ms latency`}
            {t.bandwidthLimit > 0 && ` · limited to ${(t.bandwidthLimit / 125000).toFixed(0)} Mbit/s`}
          </div>
          {!readOnly && (
            <div className="actions">
              <ConfirmButton
                label="Resync"
                confirm={`Copy every object to ${t.bucket} again?`}
                onConfirm={() => resync(t)}
                testId={`repl-resync-${t.bucket}`}
              />
              <ConfirmButton
                label="Remove"
                confirm={`Stop replicating to ${t.bucket}? What's there stays.`}
                onConfirm={() => remove(t)}
                testId={`repl-remove-${t.bucket}`}
              />
            </div>
          )}
        </div>
        );
      })}
      {st && (st.pending.objects > 0 || targets.length > 0) && (
        <p className="muted" data-testid="repl-pending">
          Waiting to go: {st.pending.objects.toLocaleString()} versions ({formatBytes(st.pending.bytes)}).
        </p>
      )}

      {!readOnly && !adding && (
        <div className="form-actions">
          <button onClick={() => setAdding(true)} data-testid="repl-add">
            {targets.length ? "Replicate to another target" : "Set up replication"}
          </button>
        </div>
      )}

      {adding && (
        <div className="subsection" data-testid="repl-form">
          <h3>1. Where to</h3>
          <div className="field-row">
            <Field label="Endpoint" help="Another Buckets or MinIO cluster, or any S3 service.">
              <input value={f.endpoint} placeholder="https://s3.dr.example.com" onChange={(e) => set({ endpoint: e.target.value })} data-testid="repl-endpoint" />
            </Field>
            <Field label="Bucket there">
              <input value={f.bucket} onChange={(e) => set({ bucket: e.target.value })} data-testid="repl-bucket" />
            </Field>
          </div>
          <div className="field-row">
            <Field label="Access key">
              <input value={f.accessKey} autoComplete="off" onChange={(e) => set({ accessKey: e.target.value })} data-testid="repl-access-key" />
            </Field>
            <Field label="Secret key" help="Kept by the servers, encrypted; never shown again.">
              <input type="password" value={f.secretKey} autoComplete="new-password" onChange={(e) => set({ secretKey: e.target.value })} data-testid="repl-secret-key" />
            </Field>
          </div>
          <h3>2. Test</h3>
          <div className="form-actions">
            <button onClick={runTest} disabled={busy || !f.endpoint || !f.bucket || !f.accessKey || !f.secretKey} data-testid="repl-test">
              Test
            </button>
          </div>
          {test && (
            <p className={`test-result ${test.ok ? "ok" : "failed"}`} data-testid="repl-test-result">
              {test.text}
            </p>
          )}
          {test?.ok && !versioned && (
            <label className="checklist">
              <input type="checkbox" checked={turnOnVersioning} onChange={(e) => setTurnOnVersioning(e.target.checked)} data-testid="repl-versioning" />
              Turn on versioning for {bucket}: replication needs it here too
            </label>
          )}
          <h3>3. What</h3>
          <div className="field-row">
            <Field label="Object prefix" help="Empty: the whole bucket.">
              <input value={f.prefix} onChange={(e) => set({ prefix: e.target.value })} data-testid="repl-prefix" />
            </Field>
            <Field label="Bandwidth limit (Mbit/s)" help="Empty: none. At least 100 Mbit/s.">
              <input type="number" min={100} value={f.bandwidthMbps} onChange={(e) => set({ bandwidthMbps: e.target.value })} />
            </Field>
            <Field label="Storage class there" help="Empty: the target's default.">
              <input value={f.storageClass} onChange={(e) => set({ storageClass: e.target.value })} />
            </Field>
          </div>
          <label className="checklist">
            <input type="checkbox" checked={f.existing} onChange={(e) => set({ existing: e.target.checked })} data-testid="repl-existing" />
            Copy the objects already in the bucket, not only new ones
          </label>
          <label className="checklist">
            <input type="checkbox" checked={f.deletes} onChange={(e) => set({ deletes: e.target.checked })} />
            Deleting a version here deletes it there
          </label>
          <label className="checklist">
            <input type="checkbox" checked={f.deleteMarkers} onChange={(e) => set({ deleteMarkers: e.target.checked })} />
            Deleting an object here deletes it there (a delete marker)
          </label>
          <label className="checklist">
            <input type="checkbox" checked={f.metadataSync} onChange={(e) => set({ metadataSync: e.target.checked })} />
            Two-way: changes to tags and metadata made there come back (set the same up on the other side)
          </label>
          <div className="form-actions">
            <button className="primary" onClick={save} disabled={busy || !canSave} data-testid="repl-save">
              Save
            </button>
            <button
              onClick={() => {
                setAdding(false);
                setF(blank);
                setTest(null);
              }}
            >
              Cancel
            </button>
          </div>
          {!test?.ok && <p className="field-help">Test the target first.</p>}
        </div>
      )}
    </div>
  );
}
