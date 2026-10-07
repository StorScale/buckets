import { Link, useNavigate, useParams } from "react-router-dom";
import {
  Compliance,
  ComplianceBucket,
  ComplianceCount,
  complianceReport,
} from "../api";
import { ErrorBanner, formatBytes, Spinner, useLoad } from "../components";

// Retention and encryption per bucket, for auditors (docs/design/compliance-reports.md): settings read now,
// counts from the scanner's last complete cycle.

const day = (unix: number) => new Date(unix * 1000).toLocaleDateString();
const iso = (unix: number) => (unix ? new Date(unix * 1000).toISOString() : "");
const sum = (...c: (ComplianceCount | undefined)[]) =>
  c.reduce<ComplianceCount>(
    (a, x) => ({
      versions: a.versions + (x?.versions ?? 0),
      bytes: a.bytes + (x?.bytes ?? 0),
    }),
    { versions: 0, bytes: 0 },
  );
const amount = (c?: ComplianceCount) =>
  c && c.versions ? `${c.versions} · ${formatBytes(c.bytes)}` : "—";
const csvCell = (s: string | number) =>
  typeof s === "string" && /[",\n]/.test(s)
    ? `"${s.replace(/"/g, '""')}"`
    : String(s);
const MODE: Record<string, string> = {
  GOVERNANCE: "Governance",
  COMPLIANCE: "Compliance",
};

function defaultRetention(b: ComplianceBucket): string {
  const l = b.objectLock;
  if (!l.enabled) return "—";
  if (!l.mode) return "none";
  const n = l.days
    ? `${l.days} day${l.days === 1 ? "" : "s"}`
    : `${l.years} year${l.years === 1 ? "" : "s"}`;
  return `${MODE[l.mode]}, ${n}`;
}

function download(name: string, lines: (string | number)[][]) {
  const url = URL.createObjectURL(
    new Blob([lines.map((l) => l.map(csvCell).join(",")).join("\n") + "\n"], {
      type: "text/csv",
    }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function retentionCsv(r: Compliance) {
  const at = iso(r.scannedAt);
  const lines: (string | number)[][] = [
    [
      "bucket",
      "object lock",
      "default retention",
      "versioning",
      "governance versions",
      "governance bytes",
      "compliance versions",
      "compliance bytes",
      "legal hold versions",
      "legal hold bytes",
      "latest retain-until",
      "lifecycle expires versions",
      "counted at",
    ],
  ];
  for (const b of r.buckets) {
    const c = b.counts;
    lines.push([
      b.name,
      b.objectLock.enabled ? "on" : "off",
      defaultRetention(b),
      b.versioning,
      c?.governance.versions ?? "",
      c?.governance.bytes ?? "",
      c?.compliance.versions ?? "",
      c?.compliance.bytes ?? "",
      c?.legalHold.versions ?? "",
      c?.legalHold.bytes ?? "",
      c ? iso(c.latestRetainUntil) : "",
      b.lifecycleExpires ? "yes" : "no",
      c ? at : "not yet scanned",
    ]);
  }
  download(`retention-${new Date().toISOString().slice(0, 10)}.csv`, lines);
}

function encryptionCsv(r: Compliance) {
  const at = iso(r.scannedAt);
  const lines: (string | number)[][] = [
    [
      "bucket",
      "default encryption",
      "key",
      "key status",
      "sse-s3 versions",
      "sse-s3 bytes",
      "sse-kms versions",
      "sse-kms bytes",
      "sse-c versions",
      "sse-c bytes",
      "unencrypted versions",
      "unencrypted bytes",
      "counted at",
    ],
  ];
  for (const b of r.buckets) {
    const c = b.counts;
    lines.push([
      b.name,
      b.encryption.algorithm || "none",
      b.encryption.keyId,
      b.encryption.keyStatus,
      c?.sseS3.versions ?? "",
      c?.sseS3.bytes ?? "",
      c?.sseKms.versions ?? "",
      c?.sseKms.bytes ?? "",
      c?.sseC.versions ?? "",
      c?.sseC.bytes ?? "",
      c?.unencrypted.versions ?? "",
      c?.unencrypted.bytes ?? "",
      c ? at : "not yet scanned",
    ]);
  }
  download(`encryption-${new Date().toISOString().slice(0, 10)}.csv`, lines);
}

function Retention({ r }: { r: Compliance }) {
  const locked = r.buckets.filter((b) => b.objectLock.enabled);
  const compliance = sum(...r.buckets.map((b) => b.counts?.compliance));
  const latest = Math.max(
    0,
    ...r.buckets.map((b) => b.counts?.latestRetainUntil ?? 0),
  );
  return (
    <>
      <p data-testid="retention-summary">
        {locked.length} of {r.buckets.length} bucket
        {r.buckets.length === 1 ? "" : "s"} with object lock ·{" "}
        {compliance.versions
          ? `${formatBytes(compliance.bytes)} under Compliance-mode retention, which nobody can shorten`
          : "nothing under Compliance-mode retention"}
        {latest ? ` · retained until ${day(latest)} at the latest` : ""}
      </p>
      <table data-testid="retention-table">
        <thead>
          <tr>
            <th>Bucket</th>
            <th>Object lock</th>
            <th>Default retention</th>
            <th>Versioning</th>
            <th>Governance</th>
            <th>Compliance</th>
            <th>Legal hold</th>
            <th>Retained until</th>
            <th>Lifecycle expires versions</th>
          </tr>
        </thead>
        <tbody>
          {r.buckets.map((b) => (
            <tr key={b.name} data-testid={`retention-${b.name}`}>
              <td>
                <Link to={`/buckets/${encodeURIComponent(b.name)}/settings`}>
                  {b.name}
                </Link>
              </td>
              <td>{b.objectLock.enabled ? "on" : "off"}</td>
              <td>{defaultRetention(b)}</td>
              <td>{b.versioning}</td>
              {b.counts ? (
                <>
                  <td>{amount(b.counts.governance)}</td>
                  <td>{amount(b.counts.compliance)}</td>
                  <td>{amount(b.counts.legalHold)}</td>
                  <td>
                    {b.counts.latestRetainUntil
                      ? day(b.counts.latestRetainUntil)
                      : "—"}
                  </td>
                </>
              ) : (
                <td colSpan={4} className="muted">
                  {r.scannedAt
                    ? "not counted yet: made since the last scan"
                    : "not counted yet: the scanner's first cycle has not finished"}
                </td>
              )}
              <td>
                {b.lifecycleExpires ? (
                  <span className="pill warn">yes</span>
                ) : (
                  "no"
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

const KEY_STATUS: Record<string, string> = {
  ok: "works",
  missing: "missing from the KMS",
  error: "the KMS refused",
  "no-kms": "no KMS configured",
  "": "",
};

function Encryption({ r }: { r: Compliance }) {
  const all = r.buckets.filter((b) => b.counts);
  const enc = sum(
    ...all.flatMap((b) => [b.counts!.sseS3, b.counts!.sseKms, b.counts!.sseC]),
  );
  const plain = sum(...all.map((b) => b.counts!.unencrypted));
  const total = enc.bytes + plain.bytes;
  const noDefault = r.buckets.filter((b) => !b.encryption.algorithm).length;
  const chacha = sum(...all.map((b) => b.counts!.chacha20));
  return (
    <>
      <p data-testid="encryption-summary">
        KMS:{" "}
        {r.kms.configured
          ? r.kms.online
            ? "online"
            : "offline"
          : "not configured"}{" "}
        ·{" "}
        {total
          ? `${Math.floor((enc.bytes / total) * 1000) / 10}% of bytes encrypted`
          : "no data counted yet"}{" "}
        · {noDefault} bucket{noDefault === 1 ? "" : "s"} without default
        encryption
      </p>
      {chacha.versions > 0 && (
        <p data-testid="chacha20-summary">
          <span className="pill warn">ChaCha20</span> {amount(chacha)} encrypted
          with ChaCha20-Poly1305, which{" "}
          {r.fips
            ? "this server, in FIPS mode, cannot read"
            : "FIPS mode cannot read"}
          . <strong>Encrypt existing objects</strong> re-encrypts them with
          AES-256-GCM (outside FIPS mode).
        </p>
      )}
      <table data-testid="encryption-table">
        <thead>
          <tr>
            <th>Bucket</th>
            <th>Default encryption</th>
            <th>Key</th>
            <th>SSE-S3</th>
            <th>SSE-KMS</th>
            <th>SSE-C</th>
            <th>Unencrypted</th>
            {chacha.versions > 0 && <th>ChaCha20</th>}
          </tr>
        </thead>
        <tbody>
          {r.buckets.map((b) => (
            <tr key={b.name} data-testid={`encryption-${b.name}`}>
              <td>
                <Link to={`/buckets/${encodeURIComponent(b.name)}/settings`}>
                  {b.name}
                </Link>
              </td>
              <td>
                {b.encryption.algorithm || (
                  <span className="pill warn">none</span>
                )}
              </td>
              <td>
                {b.encryption.keyId ? (
                  <span className="mono">{b.encryption.keyId}</span>
                ) : (
                  "—"
                )}
                {b.encryption.keyStatus && b.encryption.keyStatus !== "ok" ? (
                  <span className="pill warn">
                    {" "}
                    {KEY_STATUS[b.encryption.keyStatus]}
                  </span>
                ) : null}
              </td>
              {b.counts ? (
                <>
                  <td>{amount(b.counts.sseS3)}</td>
                  <td>{amount(b.counts.sseKms)}</td>
                  <td>{amount(b.counts.sseC)}</td>
                  <td>
                    {amount(b.counts.unencrypted)}
                    {b.counts.unencrypted.versions > 0 &&
                    b.encryption.algorithm ? (
                      <>
                        {" "}
                        <Link
                          to={`/buckets/${encodeURIComponent(b.name)}/settings`}
                          data-testid={`encrypt-existing-${b.name}`}
                        >
                          Encrypt existing objects
                        </Link>
                      </>
                    ) : null}
                  </td>
                  {chacha.versions > 0 && (
                    <td data-testid={`chacha20-${b.name}`}>
                      {amount(b.counts.chacha20)}
                    </td>
                  )}
                </>
              ) : (
                <td colSpan={chacha.versions > 0 ? 5 : 4} className="muted">
                  {r.scannedAt
                    ? "not counted yet: made since the last scan"
                    : "not counted yet: the scanner's first cycle has not finished"}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

export default function CompliancePage() {
  const { tab = "retention" } = useParams();
  const r = useLoad(complianceReport, []);
  const nav = useNavigate();
  const retention = tab !== "encryption";
  return (
    <div>
      <div className="page-head">
        <h1>{retention ? "Retention" : "Encryption coverage"}</h1>
        {r.data && (
          <button
            onClick={() =>
              retention ? retentionCsv(r.data!) : encryptionCsv(r.data!)
            }
            data-testid="compliance-csv"
          >
            Export CSV
          </button>
        )}
      </div>
      <div className="tabs" role="tablist">
        <button
          role="tab"
          aria-selected={retention}
          className={retention ? "active" : ""}
          onClick={() => nav("/reports/retention")}
          data-testid="tab-retention"
        >
          Retention
        </button>
        <button
          role="tab"
          aria-selected={!retention}
          className={retention ? "" : "active"}
          onClick={() => nav("/reports/encryption")}
          data-testid="tab-encryption"
        >
          Encryption coverage
        </button>
      </div>
      <p className="muted">
        {retention
          ? "Which buckets keep their data unchangeable, how, and how much of it is under retention or legal hold."
          : "Which buckets encrypt new objects, with which key, and how much data is stored encrypted or not."}{" "}
        Settings are read now; counts come from the data scanner{" "}
        {r.data?.scannedAt ? (
          <span data-testid="scanned-at">
            as of its cycle finished{" "}
            {new Date(r.data.scannedAt * 1000).toLocaleString()}
          </span>
        ) : (
          <span data-testid="scanned-at">once its first cycle finishes</span>
        )}
        .
      </p>
      <ErrorBanner error={r.error} onClose={() => r.setError(undefined)} />
      {r.loading && !r.data && <Spinner />}
      {r.data &&
        (r.data.buckets.length ? (
          retention ? (
            <Retention r={r.data} />
          ) : (
            <Encryption r={r.data} />
          )
        ) : (
          <p className="muted">No buckets yet.</p>
        ))}
    </div>
  );
}
