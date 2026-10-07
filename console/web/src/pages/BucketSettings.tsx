import { ReactNode, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  bucketDocs,
  encryptExisting,
  getQuota,
  getVersioning,
  jobProgress,
  JobProgress,
  kmsListKeys,
  kmsStatus,
  parseTags,
  setQuota,
  setVersioning,
  Tag,
  tagsXml,
} from "../api";
import { ErrorBanner, formatBytes, Notice, Spinner } from "../components";
import { TagEditor } from "./Browser";

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="card section">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

const policyPreset = (bucket: string, kind: "public-read" | "public") => {
  const actions = kind === "public-read" ? ["s3:GetObject"] : ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"];
  const bucketActions = kind === "public-read" ? ["s3:ListBucket", "s3:GetBucketLocation"] : ["s3:ListBucket", "s3:GetBucketLocation", "s3:ListBucketMultipartUploads"];
  return JSON.stringify(
    {
      Version: "2012-10-17",
      Statement: [
        { Effect: "Allow", Principal: { AWS: ["*"] }, Action: bucketActions, Resource: [`arn:aws:s3:::${bucket}`] },
        { Effect: "Allow", Principal: { AWS: ["*"] }, Action: actions, Resource: [`arn:aws:s3:::${bucket}/*`] },
      ],
    },
    null,
    2,
  );
};

export default function BucketSettings() {
  const { bucket = "" } = useParams();
  const [error, setError] = useState<unknown>();
  const [notice, setNotice] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [versioning, setVer] = useState("");
  const [quotaGiB, setQuotaGiB] = useState("");
  const [tags, setTags] = useState<Tag[]>([]);
  const [policy, setPolicy] = useState("");
  const [lifecycle, setLifecycle] = useState("");
  const [sse, setSse] = useState<{ alg: string; key: string }>({ alg: "", key: "" });
  // the encryption as saved: what encrypting existing objects applies
  const [savedSse, setSavedSse] = useState<{ alg: string; key: string }>({ alg: "", key: "" });
  const [encJob, setEncJob] = useState<{ id: string; progress?: JobProgress } | null>(null);
  // the KMS's keys for SSE-KMS; null when they cannot be listed (no KMS, or no permission)
  const [kmsKeys, setKmsKeys] = useState<{ keys: string[]; defaultKey: string } | null>(null);
  const [lock, setLock] = useState<{ enabled: boolean; mode: string; days: string }>({ enabled: false, mode: "", days: "" });

  const ok = (text: string) => () => {
    setError(undefined);
    setNotice(text);
  };
  const fail = (e: unknown) => {
    setNotice(null);
    setError(e);
  };

  useEffect(() => {
    Promise.all([kmsListKeys(), kmsStatus()])
      .then(([keys, st]) => setKmsKeys({ keys, defaultKey: st["default-key-id"] }))
      .catch(() => setKmsKeys(null));
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const [v, q, t, p, l, e, o] = await Promise.all([
          getVersioning(bucket),
          getQuota(bucket).catch(() => ({ quota: 0 })),
          bucketDocs.tagging.get(bucket),
          bucketDocs.policy.get(bucket),
          bucketDocs.lifecycle.get(bucket),
          bucketDocs.encryption.get(bucket),
          bucketDocs.objectLock.get(bucket),
        ]);
        setVer(v);
        setQuotaGiB(q.quota ? String(q.quota / 2 ** 30) : "");
        setTags(parseTags(t));
        setPolicy(p ? JSON.stringify(JSON.parse(p), null, 2) : "");
        setLifecycle(l ?? "");
        if (e) {
          const d = new DOMParser().parseFromString(e, "application/xml");
          const cur = { alg: d.querySelector("SSEAlgorithm")?.textContent ?? "", key: d.querySelector("KMSMasterKeyID")?.textContent ?? "" };
          setSse(cur);
          setSavedSse(cur);
        }
        if (o) {
          const d = new DOMParser().parseFromString(o, "application/xml");
          setLock({
            enabled: d.querySelector("ObjectLockEnabled")?.textContent === "Enabled",
            mode: d.querySelector("Mode")?.textContent ?? "",
            days: d.querySelector("Days")?.textContent ?? d.querySelector("Years")?.textContent ?? "",
          });
        }
      } catch (err) {
        setError(err);
      } finally {
        setLoaded(true);
      }
    })();
  }, [bucket]);

  // the encrypt job's progress, until it ends
  useEffect(() => {
    if (!encJob || encJob.progress?.complete || encJob.progress?.failed) return;
    const t = setTimeout(
      () =>
        jobProgress(encJob.id)
          .then((progress) => {
            setEncJob({ id: encJob.id, progress });
            if (progress.complete || progress.failed)
              setNotice(
                `Encrypted ${progress.objects - progress.objectsFailed} existing object version(s)` +
                  (progress.objectsFailed ? `; ${progress.objectsFailed} failed (run it again to retry them).` : "."),
              );
          })
          .catch(fail),
      1000,
    );
    return () => clearTimeout(t);
  }, [encJob]);

  if (!loaded) return <Spinner />;
  const encRunning = !!encJob && !encJob.progress?.complete && !encJob.progress?.failed;
  return (
    <div>
      <div className="page-head">
        <h1>
          <Link to="/buckets">Buckets</Link> / <Link to={`/buckets/${encodeURIComponent(bucket)}/browse/`}>{bucket}</Link> / Settings
        </h1>
        <Link to={`/identity/access-review?bucket=${encodeURIComponent(bucket)}`} className="button" data-testid="who-has-access">
          Who has access
        </Link>
      </div>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />
      <Notice text={notice} />

      <Section title="Versioning">
        <p>
          Status: <strong data-testid="versioning-status">{versioning || "Unversioned"}</strong>
        </p>
        <div className="form-actions">
          <button
            disabled={versioning === "Enabled"}
            data-testid="enable-versioning"
            onClick={() =>
              setVersioning(bucket, "Enabled")
                .then(() => setVer("Enabled"))
                .then(ok("Versioning enabled."))
                .catch(fail)
            }
          >
            Enable
          </button>
          <button
            disabled={versioning !== "Enabled" || lock.enabled}
            data-testid="suspend-versioning"
            onClick={() =>
              setVersioning(bucket, "Suspended")
                .then(() => setVer("Suspended"))
                .then(ok("Versioning suspended."))
                .catch(fail)
            }
          >
            Suspend
          </button>
        </div>
      </Section>

      <Section title="Quota">
        <label className="inline">
          Hard quota (GiB, empty for none)
          <input value={quotaGiB} onChange={(e) => setQuotaGiB(e.target.value)} inputMode="decimal" data-testid="quota" />
        </label>
        <button
          data-testid="save-quota"
          onClick={() =>
            setQuota(bucket, Math.round(Number(quotaGiB || 0) * 2 ** 30))
              .then(ok(quotaGiB ? `Quota set to ${formatBytes(Number(quotaGiB) * 2 ** 30)}.` : "Quota cleared."))
              .catch(fail)
          }
        >
          Save
        </button>
      </Section>

      <Section title="Tags">
        <TagEditor
          tags={tags}
          onChange={setTags}
          onSave={() =>
            (tags.length ? bucketDocs.tagging.put(bucket, tagsXml(tags)) : bucketDocs.tagging.del(bucket)).then(ok("Tags saved.")).catch(fail)
          }
        />
      </Section>

      <Section title="Access policy">
        <div className="form-actions">
          <button onClick={() => setPolicy("")}>Private</button>
          <button onClick={() => setPolicy(policyPreset(bucket, "public-read"))} data-testid="policy-public-read">
            Public read
          </button>
          <button onClick={() => setPolicy(policyPreset(bucket, "public"))}>Public read/write</button>
        </div>
        <textarea rows={10} value={policy} onChange={(e) => setPolicy(e.target.value)} placeholder="No policy: only authenticated users with access" data-testid="policy" />
        <button
          data-testid="save-policy"
          onClick={() => (policy.trim() ? bucketDocs.policy.put(bucket, policy) : bucketDocs.policy.del(bucket)).then(ok("Policy saved.")).catch(fail)}
        >
          Save policy
        </button>
      </Section>

      <Section title="Default encryption">
        <label className="inline">
          <select value={sse.alg} onChange={(e) => setSse({ ...sse, alg: e.target.value })} data-testid="sse-alg">
            <option value="">None</option>
            <option value="AES256">SSE-S3</option>
            <option value="aws:kms">SSE-KMS</option>
          </select>
          {sse.alg === "aws:kms" &&
            (kmsKeys ? (
              // SSE-KMS needs a key ID: the default key is named, not left out
              <select value={sse.key || kmsKeys.defaultKey} onChange={(e) => setSse({ ...sse, key: e.target.value })} data-testid="sse-key">
                <option value={kmsKeys.defaultKey}>{kmsKeys.defaultKey} (KMS default key)</option>
                {kmsKeys.keys
                  .filter((k) => k !== kmsKeys.defaultKey)
                  .map((k) => (
                    <option key={k} value={k}>
                      {k}
                    </option>
                  ))}
                {sse.key && !kmsKeys.keys.includes(sse.key) && <option value={sse.key}>{sse.key} (not in the KMS)</option>}
              </select>
            ) : (
              <input placeholder="KMS key ID" value={sse.key} onChange={(e) => setSse({ ...sse, key: e.target.value })} data-testid="sse-key" />
            ))}
        </label>
        <p className="muted">Applies to objects uploaded from now on. Keys are managed under Encryption.</p>
        <button
          data-testid="save-sse"
          onClick={() =>
            (sse.alg
              ? bucketDocs.encryption.put(
                  bucket,
                  `<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>${sse.alg}</SSEAlgorithm>${
                    sse.alg === "aws:kms" && (sse.key || kmsKeys?.defaultKey)
                      ? `<KMSMasterKeyID>${sse.key || kmsKeys?.defaultKey}</KMSMasterKeyID>`
                      : ""
                  }</ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`,
                )
              : bucketDocs.encryption.del(bucket)
            )
              .then(() => setSavedSse({ alg: sse.alg, key: sse.alg === "aws:kms" ? sse.key || kmsKeys?.defaultKey || "" : "" }))
              .then(ok("Encryption saved."))
              .catch(fail)
          }
        >
          Save
        </button>
        {savedSse.alg && (
          <div className="subsection" data-testid="encrypt-existing">
            <h3>Existing objects</h3>
            <p className="muted">
              Objects uploaded before encryption was turned on stay unencrypted. Encrypt them in place, every version, with{" "}
              {savedSse.alg === "aws:kms" ? (
                <>
                  SSE-KMS key <span className="mono">{savedSse.key || kmsKeys?.defaultKey}</span>
                </>
              ) : (
                "SSE-S3"
              )}
              : their version IDs, dates, metadata and tags are kept. Objects already encrypted are left as they are.
            </p>
            <button
              data-testid="encrypt-existing-start"
              disabled={encRunning}
              onClick={() =>
                encryptExisting(bucket, savedSse.alg as "AES256" | "aws:kms", savedSse.key || kmsKeys?.defaultKey)
                  .then((id) => {
                    setNotice(null);
                    setEncJob({ id });
                  })
                  .catch(fail)
              }
            >
              Encrypt existing objects
            </button>
            {encRunning && (
              <span className="muted" data-testid="encrypt-existing-progress">
                {" "}
                Encrypting… {encJob?.progress ? `${encJob.progress.objects} done` : "starting"}
              </span>
            )}
          </div>
        )}
      </Section>

      <Section title="Object locking">
        {!lock.enabled ? (
          <p className="muted">Object locking is off; it can only be turned on when a bucket is created.</p>
        ) : (
          <>
            <label className="inline">
              Default retention
              <select value={lock.mode} onChange={(e) => setLock({ ...lock, mode: e.target.value })}>
                <option value="">None</option>
                <option value="GOVERNANCE">Governance</option>
                <option value="COMPLIANCE">Compliance</option>
              </select>
              {lock.mode && <input placeholder="days" value={lock.days} onChange={(e) => setLock({ ...lock, days: e.target.value })} />}
            </label>
            <button
              onClick={() =>
                bucketDocs.objectLock
                  .put(
                    bucket,
                    `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>${
                      lock.mode ? `<Rule><DefaultRetention><Mode>${lock.mode}</Mode><Days>${Number(lock.days)}</Days></DefaultRetention></Rule>` : ""
                    }</ObjectLockConfiguration>`,
                  )
                  .then(ok("Object lock configuration saved."))
                  .catch(fail)
              }
            >
              Save
            </button>
          </>
        )}
      </Section>

      <Section title="Lifecycle">
        <textarea
          rows={10}
          value={lifecycle}
          onChange={(e) => setLifecycle(e.target.value)}
          placeholder={'<LifecycleConfiguration><Rule><ID>expire-logs</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>'}
          data-testid="lifecycle"
        />
        <button
          data-testid="save-lifecycle"
          onClick={() => (lifecycle.trim() ? bucketDocs.lifecycle.put(bucket, lifecycle) : bucketDocs.lifecycle.del(bucket)).then(ok("Lifecycle saved.")).catch(fail)}
        >
          Save lifecycle
        </button>
      </Section>
    </div>
  );
}
