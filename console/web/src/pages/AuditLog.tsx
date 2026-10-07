import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { AuditEntry, AuditFilter, AuditPage, auditLog } from "../api";
import { ErrorBanner, formatBytes, Modal, Spinner } from "../components";

// What was done, by whom, from where (docs/design/audit-log.md): each server's own copy of the audit entries of
// what it served, merged newest first. Filters live in the address, so other pages link here already filtered.

type Range = "1h" | "24h" | "7d" | "custom";
const RANGE_MS: Record<Exclude<Range, "custom">, number> = {
  "1h": 3600e3,
  "24h": 86400e3,
  "7d": 7 * 86400e3,
};
const FILTERS: [keyof AuditFilter, string][] = [
  ["user", "Person"],
  ["accessKey", "Access key"],
  ["bucket", "Bucket"],
  ["prefix", "Object prefix"],
  ["api", "API"],
  ["ip", "Source IP"],
];
const EXPORT_MAX = 10000;

// an OpenID sign-in's parent user is a hash: the token's own name says who
const who = (e: AuditEntry) =>
  e.requestClaims?.preferred_username ||
  e.requestClaims?.upn ||
  e.requestClaims?.email ||
  e.parentUser ||
  e.accessKey ||
  (e.api.name ? "anonymous" : "Buckets");
// the server's own work (healing, lifecycle) has an event and no API
const action = (e: AuditEntry) => e.api.name || e.event || "";
const objectOf = (e: AuditEntry) =>
  e.api.object ??
  (e.api.objects?.length
    ? e.api.objects.map((o) => o.objectName).join(", ")
    : "");
const statusClass = (c?: number) =>
  !c || c < 400 ? "ok" : c === 401 || c === 403 ? "warn" : "bad";
const local = (iso: string) => new Date(iso).toLocaleString();
const csvCell = (s: string | number) =>
  typeof s === "string" && /[",\n]/.test(s)
    ? `"${s.replace(/"/g, '""')}"`
    : String(s);

export default function AuditLogPage() {
  const [params, setParams] = useSearchParams();
  const range = (params.get("range") as Range) || "1h";
  const filter: AuditFilter = {};
  for (const [k] of FILTERS) if (params.get(k)) filter[k] = params.get(k)!;
  if (params.get("kind")) filter.kind = params.get("kind")!;
  if (params.get("status")) filter.status = params.get("status")!;
  if (range === "custom") {
    if (params.get("from")) filter.from = params.get("from")!;
    if (params.get("to")) filter.to = params.get("to")!;
  }
  const key = params.toString();
  const [page, setPage] = useState<AuditPage>();
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>();
  const [open, setOpen] = useState<AuditEntry | null>(null);
  const [draft, setDraft] = useState<Record<string, string>>({});

  const period = (): AuditFilter => {
    if (range === "custom") return filter;
    const to = new Date();
    return {
      ...filter,
      from: new Date(to.getTime() - RANGE_MS[range]).toISOString(),
      to: to.toISOString(),
    };
  };

  const load = async (cursor?: string) => {
    setLoading(true);
    setError(undefined);
    try {
      const p = await auditLog(period(), cursor);
      setPage(p);
      setEntries((prev) => (cursor ? [...prev, ...p.entries] : p.entries));
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    setDraft(
      Object.fromEntries(FILTERS.map(([k]) => [k, params.get(k) ?? ""])),
    );
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  const set = (changes: Record<string, string | undefined>) => {
    const p = new URLSearchParams(params);
    for (const [k, v] of Object.entries(changes)) {
      if (v) p.set(k, v);
      else p.delete(k);
    }
    // the same filters again: ask again, for what came since
    if (p.toString() === key) load();
    else setParams(p);
  };

  const exportCsv = async () => {
    const rows: AuditEntry[] = [];
    let cursor: string | undefined;
    const f = period();
    do {
      const p = await auditLog(f, cursor, 1000);
      rows.push(...p.entries);
      cursor = p.cursor ?? undefined;
    } while (cursor && rows.length < EXPORT_MAX);
    const lines = [
      [
        "time",
        "person",
        "access key",
        "api",
        "bucket",
        "object",
        "status",
        "source ip",
        "user agent",
        "request id",
        "server",
      ],
      ...rows
        .slice(0, EXPORT_MAX)
        .map((e) => [
          e.time,
          who(e),
          e.accessKey ?? "",
          action(e),
          e.api.bucket ?? "",
          objectOf(e),
          e.api.statusCode ?? "",
          e.remotehost ?? "",
          e.userAgent ?? "",
          e.requestID ?? "",
          e.node,
        ]),
    ];
    const url = URL.createObjectURL(
      new Blob([lines.map((l) => l.map(csvCell).join(",")).join("\n") + "\n"], {
        type: "text/csv",
      }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-${new Date().toISOString().slice(0, 19)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const oldest = page?.coverage
    .filter((c) => c.reachable && c.oldest)
    .map((c) => c.oldest!)
    .reduce((a, b) => Math.max(a, b), 0);
  const dropped = page?.coverage.reduce((a, c) => a + (c.dropped ?? 0), 0) ?? 0;
  const unreachable = page?.coverage.filter((c) => !c.reachable) ?? [];

  return (
    <div>
      <div className="page-head">
        <h1>Audit log</h1>
        <div className="actions">
          {entries.length > 0 && (
            <button
              onClick={() => exportCsv().catch(setError)}
              data-testid="audit-csv"
            >
              Export CSV
            </button>
          )}
        </div>
      </div>
      <p className="muted">
        Every request, by whom, from where and with what result: each server
        keeps the entries of what it served, on its own drive. Forward them to a
        SIEM (Microsoft Sentinel, Splunk) for a record that must last.
      </p>
      <form
        className="inline"
        onSubmit={(e) => {
          e.preventDefault();
          set(draft);
        }}
      >
        <select
          value={range}
          onChange={(e) => set({ range: e.target.value })}
          data-testid="audit-range"
        >
          <option value="1h">Last hour</option>
          <option value="24h">Last day</option>
          <option value="7d">Last week</option>
          <option value="custom">From … to …</option>
        </select>
        {range === "custom" && (
          <>
            <input
              type="datetime-local"
              value={(params.get("from") ?? "").slice(0, 16)}
              onChange={(e) =>
                set({
                  from: e.target.value
                    ? new Date(e.target.value).toISOString()
                    : undefined,
                })
              }
              data-testid="audit-from"
            />
            <input
              type="datetime-local"
              value={(params.get("to") ?? "").slice(0, 16)}
              onChange={(e) =>
                set({
                  to: e.target.value
                    ? new Date(e.target.value).toISOString()
                    : undefined,
                })
              }
              data-testid="audit-to"
            />
          </>
        )}
        <select
          value={params.get("kind") ?? ""}
          onChange={(e) => set({ kind: e.target.value })}
          data-testid="audit-kind"
        >
          <option value="">Any action</option>
          <option value="read">Reads</option>
          <option value="write">Writes</option>
          <option value="delete">Deletes</option>
          <option value="admin">Administration</option>
          <option value="system">Background (healing, lifecycle)</option>
        </select>
        <select
          value={params.get("status") ?? ""}
          onChange={(e) => set({ status: e.target.value })}
          data-testid="audit-status"
        >
          <option value="">Any result</option>
          <option value="ok">Succeeded</option>
          <option value="denied">Denied</option>
          <option value="failed">Failed</option>
        </select>
        {FILTERS.map(([k, label]) => (
          <input
            key={k}
            placeholder={label}
            value={draft[k] ?? ""}
            onChange={(e) => setDraft({ ...draft, [k]: e.target.value })}
            data-testid={`audit-${k}`}
          />
        ))}
        <button type="submit" className="primary" data-testid="audit-apply">
          Apply
        </button>
      </form>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />
      {page && !page.enabled && (
        <p className="banner warn" data-testid="audit-off">
          The servers keep no audit entries (BUCKETS_AUDIT_LOCAL=off): forward
          them to a target instead.
        </p>
      )}
      {page && (
        <p className="muted" data-testid="audit-coverage">
          {oldest
            ? `Entries go back to ${new Date(oldest * 1000).toLocaleString()}.`
            : "No entries kept yet."}
          {dropped > 0 &&
            ` ${dropped.toLocaleString()} entries were dropped while the servers were too busy to keep them.`}
          {unreachable.length > 0 &&
            ` Not answering: ${unreachable.map((c) => c.node).join(", ")}.`}
        </p>
      )}
      {loading && !entries.length && <Spinner />}
      {page && !entries.length && !loading && (
        <p className="muted" data-testid="audit-none">
          Nothing matches in this period.
        </p>
      )}
      {entries.length > 0 && (
        <table data-testid="audit-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Who</th>
              <th>Action</th>
              <th>Bucket / object</th>
              <th>Result</th>
              <th>From</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e, i) => (
              <tr
                key={`${e.requestID}-${i}`}
                className="clickable"
                onClick={() => setOpen(e)}
                data-testid="audit-row"
              >
                <td>{local(e.time)}</td>
                <td>
                  {who(e)}
                  {e.accessKey && e.accessKey !== who(e) && (
                    <div className="muted mono">{e.accessKey}</div>
                  )}
                </td>
                <td className="mono">{action(e)}</td>
                <td>
                  {e.api.bucket ?? ""}
                  {objectOf(e) && (
                    <div className="muted mono">{objectOf(e)}</div>
                  )}
                </td>
                <td>
                  <span className={`pill ${statusClass(e.api.statusCode)}`}>
                    {e.api.statusCode ?? ""}
                  </span>
                </td>
                <td className="mono">{e.remotehost ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {page?.cursor && (
        <div className="form-actions">
          <button
            onClick={() => load(page.cursor!)}
            disabled={loading}
            data-testid="audit-more"
          >
            Older entries
          </button>
        </div>
      )}
      {open && (
        <Modal
          title={`${action(open)} by ${who(open)}`}
          onClose={() => setOpen(null)}
        >
          <p className="muted">
            {local(open.time)} · {open.remotehost} · server {open.node}
            {open.api.rx || open.api.tx
              ? ` · ${formatBytes(open.api.rx ?? 0)} in, ${formatBytes(open.api.tx ?? 0)} out`
              : ""}
          </p>
          <pre className="mono" data-testid="audit-detail">
            {JSON.stringify(open, null, 2)}
          </pre>
        </Modal>
      )}
    </div>
  );
}
