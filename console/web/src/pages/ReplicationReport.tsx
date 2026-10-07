import { Link } from "react-router-dom";
import { ReplicationBucket, replicationStatus } from "../api";
import { ErrorBanner, formatBytes, Spinner, useLoad } from "../components";

// Every bucket that replicates, worst first (docs/design/lifecycle-replication-editor.md): where the replication
// alerts send you.

const trouble = (b: ReplicationBucket) =>
  b.targets.filter((t) => !t.online).length * 1e12 + b.targets.reduce((a, t) => a + t.failedLastHour, 0) * 1e6 + b.pending.objects;

export default function ReplicationReportPage() {
  const { data, error, loading } = useLoad(() => replicationStatus(), []);
  if (loading && !data) return <Spinner />;
  const buckets = [...(data?.buckets ?? [])].sort((a, b) => trouble(b) - trouble(a) || a.bucket.localeCompare(b.bucket));
  return (
    <div>
      <div className="page-head">
        <h1>Replication</h1>
      </div>
      <p className="muted">
        Each bucket that replicates, its targets and how they're doing, the worst first. Set replication up in a
        bucket's settings.
      </p>
      <ErrorBanner error={error} />
      {data?.siteReplication && (
        <p className="banner ok">This cluster is in a site replication group: every bucket is replicated to every site.</p>
      )}
      {data && data.serversAnswering < data.servers && (
        <p className="banner warn">
          {data.servers - data.serversAnswering} of {data.servers} servers didn't answer: their counts are missing.
        </p>
      )}
      {data && buckets.length === 0 && <p className="muted">No bucket replicates.</p>}
      {buckets.length > 0 && (
        <table data-testid="replication-report">
          <thead>
            <tr>
              <th>Bucket</th>
              <th>Target</th>
              <th>State</th>
              <th>Replicated</th>
              <th>Failed (last hour)</th>
              <th>Waiting</th>
            </tr>
          </thead>
          <tbody>
            {buckets.flatMap((b) =>
              (b.targets.length ? b.targets : [null]).map((t, i) => (
                <tr key={`${b.bucket}-${t?.arn ?? i}`} data-testid={`replication-row-${b.bucket}`}>
                  <td>{i === 0 && <Link to={`/buckets/${encodeURIComponent(b.bucket)}/settings`}>{b.bucket}</Link>}</td>
                  <td className="mono">{t ? `${t.endpoint}/${t.bucket}` : "no target"}</td>
                  <td>
                    {t ? (
                      <span className={`pill ${!t.online ? "bad" : t.failedLastHour ? "warn" : "ok"}`}>
                        {!t.online ? "offline" : t.failedLastHour ? "failing" : "ok"}
                      </span>
                    ) : (
                      <span className="pill warn">not set up</span>
                    )}
                  </td>
                  <td>{t ? t.replicated.toLocaleString() : ""}</td>
                  <td>{t ? t.failedLastHour.toLocaleString() : ""}</td>
                  <td>{i === 0 ? `${b.pending.objects.toLocaleString()} (${formatBytes(b.pending.bytes)})` : ""}</td>
                </tr>
              )),
            )}
          </tbody>
        </table>
      )}
    </div>
  );
}
