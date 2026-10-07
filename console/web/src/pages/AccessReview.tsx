import { FormEvent, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  ACCESS_LEVELS,
  AccessBy,
  accessCheck,
  AccessDecision,
  AccessLevel,
  accessLocalUsers,
  accessPrincipals,
  accessReview,
  AccessReview as Review,
  AccessRow,
  AccessWho,
  listBuckets,
} from "../api";
import { ErrorBanner, Spinner, useLoad } from "../components";

const LEVEL_TEXT: Record<AccessLevel, string> = {
  read: "Read (list and download)",
  write: "Write (upload)",
  delete: "Delete objects",
  manage: "Manage settings (policy, lifecycle, versioning, encryption, …)",
  any: "Any of these",
};

const KIND_TEXT: Record<string, string> = {
  root: "root user",
  user: "local user",
  group: "local group",
  "ldap-user": "LDAP user",
  "ldap-group": "LDAP group",
  "openid-role": "OpenID role",
  key: "access key",
  anyone: "bucket policy",
  account: "bucket policy",
};

const byText = (b: AccessBy) =>
  `${b.effect === "Deny" ? "Deny: " : ""}${b.bucketPolicy ? "bucket policy" : b.policy}${b.sid ? ` › ${b.sid}` : ` › statement ${b.statement + 1}`}${
    b.conditions?.length ? ` (if ${b.conditions.join(", ")})` : ""
  }`;

// Who a row is, in words: "anyone with the OpenID role X", "group g (members …)".
function who(r: AccessRow): string {
  if (r.kind === "openid-role") return `anyone with the role ${r.name}`;
  if (r.kind === "anyone") return "everyone, signed in or not";
  return r.name;
}

const day = (iso: string) => new Date(iso).toLocaleDateString();

function whoDetail(r: AccessRow): string {
  const parts: string[] = [KIND_TEXT[r.kind] ?? r.kind];
  if (r.status === "disabled") parts.push("disabled");
  if (r.members?.length) parts.push(`members: ${r.members.join(", ")}`);
  if (r.kind === "openid-role") parts.push(r.seen?.length ? `seen: ${r.seen.join(", ")}` : "nobody seen yet");
  if (r.owner) parts.push(`of ${r.owner}, with its own policy`);
  if (r.ownerLeft) parts.push(`its owner left on ${day(r.ownerLeft.since)}; deleted on ${day(r.ownerLeft.deleteAt)}`);
  return parts.join(" · ");
}

const csvCell = (s: string) => (/[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);

// One line per row and action: what an auditor files.
function toCsv(rv: Review): string {
  const lines = [["bucket", "level", "principal", "kind", "status", "action", "decision", "limits", "granted by", "reviewed at"].join(",")];
  const at = new Date(rv.at * 1000).toISOString();
  for (const r of rv.rows)
    for (const a of r.actions)
      lines.push(
        [
          rv.bucket,
          rv.level,
          who(r),
          KIND_TEXT[r.kind] ?? r.kind,
          r.status ?? "",
          a.action,
          a.decision,
          (a.limits ?? []).join(" "),
          a.by.map(byText).join("; "),
          at,
        ]
          .map(csvCell)
          .join(","),
      );
  return lines.join("\n") + "\n";
}

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/csv" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export default function AccessReviewPage() {
  const [params, setParams] = useSearchParams();
  const buckets = useLoad(listBuckets, []);
  const bucket = params.get("bucket") ?? "";
  const level = (params.get("level") as AccessLevel) || "read";
  const set = (k: string, v: string) => {
    const p = new URLSearchParams(params);
    p.set(k, v);
    setParams(p, { replace: true });
  };
  useEffect(() => {
    if (!bucket && buckets.data?.length) set("bucket", buckets.data[0].name);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [buckets.data]);
  const review = useLoad(async () => (bucket ? accessReview(bucket, level) : undefined), [bucket, level]);
  return (
    <div>
      <h1>Access review</h1>
      <LocalUsers />
      <section className="card section">
        <h2>Who can reach a bucket</h2>
        <div className="row-form">
          <label>
            Bucket
            <select value={bucket} onChange={(e) => set("bucket", e.target.value)} data-testid="review-bucket">
              {(buckets.data ?? []).map((b) => (
                <option key={b.name} value={b.name}>
                  {b.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Access
            <select value={level} onChange={(e) => set("level", e.target.value)} data-testid="review-level">
              {ACCESS_LEVELS.map((l) => (
                <option key={l} value={l}>
                  {LEVEL_TEXT[l]}
                </option>
              ))}
            </select>
          </label>
          {review.data && (
            <button onClick={() => download(`access-${review.data!.bucket}-${review.data!.level}.csv`, toCsv(review.data!))} data-testid="review-csv">
              Export CSV
            </button>
          )}
        </div>
        <ErrorBanner error={buckets.error ?? review.error} onClose={() => review.setError(undefined)} />
        {review.loading && <Spinner />}
        {review.data && <ReviewTable rv={review.data} />}
      </section>
      <Check bucket={bucket} buckets={(buckets.data ?? []).map((b) => b.name)} />
    </div>
  );
}

function Missing({ missing }: { missing: string[] }) {
  if (!missing.length) return null;
  return (
    <p className="banner error" role="alert" data-testid="review-missing">
      Not included, as your account may not read them: {missing.join(", ")}. The answer may leave out access that comes through them.
    </p>
  );
}

function ReviewTable({ rv }: { rv: Review }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <>
      <Missing missing={rv.missing} />
      <p className="muted">
        Reviewed {new Date(rv.at * 1000).toLocaleString()}: {rv.rows.length} {rv.rows.length === 1 ? "way" : "ways"} to{" "}
        {rv.level === "any" ? "reach" : rv.level} <span className="mono">{rv.bucket}</span>. Actions checked: {rv.actions.join(", ")}.
      </p>
      <table data-testid="review-table">
        <thead>
          <tr>
            <th>Who</th>
            <th>Access</th>
            <th>Granted by</th>
          </tr>
        </thead>
        <tbody>
          {rv.rows.map((r) => {
            const key = `${r.kind}:${r.name}`;
            const by = Array.from(new Set(r.actions.flatMap((a) => a.by.map((b) => (b.bucketPolicy ? "bucket policy" : b.policy!)))));
            const limits = Array.from(new Set(r.actions.flatMap((a) => a.limits ?? [])));
            return (
              <tr key={key} data-testid={`review-row-${r.name}`} onClick={() => setOpen(open === key ? null : key)} className="clickable">
                <td>
                  <div>{who(r)}</div>
                  <div className="muted">{whoDetail(r)}</div>
                </td>
                <td>
                  <span className={`pill ${r.access === "full" ? "ok" : "warn"}`}>{r.access}</span>
                  {limits.length > 0 && <div className="muted">only {limits.join(", ")}</div>}
                  {open === key && (
                    <ul className="members">
                      {r.actions.map((a) => (
                        <li key={a.action}>
                          <span className="mono">{a.action}</span>: {a.decision}
                          {a.limits?.length ? ` (${a.limits.join(", ")})` : ""}
                        </li>
                      ))}
                    </ul>
                  )}
                </td>
                <td>
                  {open === key ? (
                    <ul className="members">
                      {Array.from(new Set(r.actions.flatMap((a) => a.by.map(byText)))).map((t) => (
                        <li key={t}>{t}</li>
                      ))}
                    </ul>
                  ) : (
                    by.join(", ") || (r.kind === "root" ? "the root user" : "—")
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {rv.rows.some((r) => r.kind === "openid-role") && (
        <p className="muted">
          Buckets cannot list everyone your identity provider gives a role: the people shown are those seen signing in. Check the role's assignments in the
          provider (in Entra: Enterprise applications → the app → Users and groups).
        </p>
      )}
    </>
  );
}

const COMMON_ACTIONS = [
  "s3:GetObject",
  "s3:PutObject",
  "s3:DeleteObject",
  "s3:ListBucket",
  "s3:PutBucketPolicy",
  "s3:PutLifecycleConfiguration",
  "s3:DeleteBucket",
];

function Check({ bucket, buckets }: { bucket: string; buckets: string[] }) {
  const principals = useLoad(accessPrincipals, []);
  const [kind, setKind] = useState("user");
  const [name, setName] = useState("");
  const [roles, setRoles] = useState("");
  const [action, setAction] = useState("s3:GetObject");
  const [target, setTarget] = useState(bucket);
  const [object, setObject] = useState("");
  const [ip, setIp] = useState("");
  const [result, setResult] = useState<AccessDecision | null>(null);
  const [error, setError] = useState<unknown>();
  useEffect(() => setTarget((t) => t || bucket), [bucket]);
  const names = (principals.data?.principals ?? []).filter((p) => p.kind === kind);
  const kinds = [
    ["user", "Local user"],
    ["group", "Local group"],
    ["ldap-user", "LDAP user"],
    ["ldap-group", "LDAP group"],
    ["key", "Access key"],
    ["openid", "Someone with OpenID roles"],
    ["anonymous", "Anyone, without signing in"],
  ].filter(([k]) => (k === "openid" ? principals.data?.openid : k.startsWith("ldap") ? principals.data?.ldap : true));
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setResult(null);
    const w: AccessWho =
      kind === "openid" ? { kind, roles: roles.split(/[\s,]+/).filter(Boolean) } : kind === "anonymous" ? { kind } : { kind, name: name || names[0]?.name };
    try {
      setResult(await accessCheck(w, action, target, object, ip ? { SourceIp: ip } : undefined));
    } catch (err) {
      setError(err);
    }
  };
  return (
    <section className="card section">
      <h2>Would this be allowed?</h2>
      <form onSubmit={submit}>
        <ErrorBanner error={error ?? principals.error} onClose={() => setError(undefined)} />
        <div className="row-form">
          <label>
            Who
            <select value={kind} onChange={(e) => (setKind(e.target.value), setName(""))} data-testid="check-kind">
              {kinds.map(([k, t]) => (
                <option key={k} value={k}>
                  {t}
                </option>
              ))}
            </select>
          </label>
          {kind === "openid" ? (
            <label>
              Roles
              <input value={roles} onChange={(e) => setRoles(e.target.value)} placeholder="team-finance-rw" data-testid="check-roles" />
            </label>
          ) : kind !== "anonymous" ? (
            <label>
              Name
              <select value={name || names[0]?.name || ""} onChange={(e) => setName(e.target.value)} data-testid="check-name">
                {names.map((p) => (
                  <option key={p.name} value={p.name}>
                    {p.name}
                    {p.owner ? ` (${p.owner})` : ""}
                    {p.status === "disabled" ? " (disabled)" : ""}
                  </option>
                ))}
              </select>
            </label>
          ) : null}
          <label>
            Action
            <input value={action} onChange={(e) => setAction(e.target.value.trim())} list="check-actions" data-testid="check-action" />
            <datalist id="check-actions">
              {COMMON_ACTIONS.map((a) => (
                <option key={a} value={a} />
              ))}
            </datalist>
          </label>
          <label>
            Bucket
            <select value={target} onChange={(e) => setTarget(e.target.value)} data-testid="check-bucket">
              {buckets.map((b) => (
                <option key={b} value={b}>
                  {b}
                </option>
              ))}
            </select>
          </label>
          <label>
            Object
            <input value={object} onChange={(e) => setObject(e.target.value)} placeholder="empty for bucket actions" data-testid="check-object" />
          </label>
          <label>
            Source IP
            <input value={ip} onChange={(e) => setIp(e.target.value.trim())} placeholder="optional, e.g. 10.1.2.3" data-testid="check-ip" />
          </label>
        </div>
        <div className="form-actions">
          <button className="primary" disabled={!target || !action} data-testid="check-submit">
            Check
          </button>
        </div>
      </form>
      {result && (
        <div className={`banner ${result.decision === "allowed" ? "ok" : "error"}`} role="status" data-testid="check-result">
          <div>
            <strong>{result.decision === "allowed" ? "Allowed" : result.decision === "denied" ? "Denied" : "Depends on conditions"}</strong>. {result.reason}
            {result.by.length > 0 && (
              <ul className="members">
                {result.by.map((b) => (
                  <li key={byText(b)}>{byText(b)}</li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
      {result && <Missing missing={result.missing} />}
    </section>
  );
}

// Local users left while sign-in goes through an identity provider: reported, to be disabled or deleted on the Users page.
function LocalUsers() {
  const { data } = useLoad(accessLocalUsers, []);
  if (!data?.provider || !data.users.length) return null;
  return (
    <section className="card section" data-testid="local-users">
      <h2>Local users while {data.provider} sign-in is on</h2>
      <p className="muted">
        People should sign in through {data.provider}. These local users remain; disable or delete the ones nobody needs on the Users page.
      </p>
      <table>
        <thead>
          <tr>
            <th>User</th>
            <th>Status</th>
            <th>Policies</th>
            <th>Access keys</th>
          </tr>
        </thead>
        <tbody>
          {data.users.map((u) => (
            <tr key={u.name}>
              <td>{u.name}</td>
              <td>
                <span className={`pill ${u.status === "enabled" ? "warn" : "ok"}`}>{u.status}</span>
              </td>
              <td>{[...u.policies, ...u.groups.map((g) => `group ${g}`)].join(", ") || "—"}</td>
              <td>{u.keys || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
