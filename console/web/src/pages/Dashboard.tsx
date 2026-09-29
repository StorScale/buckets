import { dataUsage, serverInfo } from "../api";
import { ErrorBanner, formatBytes, formatDate, Spinner, useLoad } from "../components";

export default function Dashboard() {
  const info = useLoad(serverInfo, []);
  const usage = useLoad(() => dataUsage().catch(() => undefined), []);
  const i = info.data;
  const u = usage.data;
  const drives = i?.servers?.flatMap((s) => s.drives ?? []) ?? [];
  const online = drives.filter((d) => d.state === "ok").length;
  return (
    <div>
      <h1>Dashboard</h1>
      <ErrorBanner error={info.error} />
      {info.loading && <Spinner />}
      {i && (
        <>
          <div className="tiles">
            <Tile label="Buckets" value={String(u?.bucketsCount ?? i.buckets?.count ?? 0)} testId="tile-buckets" />
            <Tile label="Objects" value={String(u?.objectsCount ?? i.objects?.count ?? 0)} />
            <Tile label="Usage" value={formatBytes(u?.objectsTotalSize ?? i.usage?.size ?? 0)} />
            <Tile label="Drives online" value={`${online} / ${drives.length}`} />
            <Tile label="Servers" value={String(i.servers?.length ?? 0)} />
            <Tile label="Mode" value={i.mode} />
          </div>
          <p className="muted">
            Deployment {i.deploymentID}
            {u?.lastUpdate && <> · usage as of {formatDate(u.lastUpdate)}</>}
          </p>
          <h2>Servers</h2>
          <table>
            <thead>
              <tr>
                <th>Endpoint</th>
                <th>State</th>
                <th>Version</th>
                <th>Drives</th>
                <th>Uptime</th>
              </tr>
            </thead>
            <tbody>
              {(i.servers ?? []).map((s) => (
                <tr key={s.endpoint}>
                  <td>{s.endpoint}</td>
                  <td>
                    <span className={`pill ${s.state === "online" ? "ok" : "bad"}`}>{s.state}</span>
                  </td>
                  <td>{s.version}</td>
                  <td>{s.drives?.length ?? 0}</td>
                  <td>{Math.round((s.uptime ?? 0) / 60)} min</td>
                </tr>
              ))}
            </tbody>
          </table>
          {u?.bucketsUsageInfo && Object.keys(u.bucketsUsageInfo).length > 0 && (
            <>
              <h2>Bucket usage</h2>
              <table>
                <thead>
                  <tr>
                    <th>Bucket</th>
                    <th>Objects</th>
                    <th>Size</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(u.bucketsUsageInfo).map(([name, b]) => (
                    <tr key={name}>
                      <td>{name}</td>
                      <td>{b.objectsCount}</td>
                      <td>{formatBytes(b.size)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </>
      )}
    </div>
  );
}

function Tile({ label, value, testId }: { label: string; value: string; testId?: string }) {
  return (
    <div className="tile" data-testid={testId}>
      <div className="tile-value">{value}</div>
      <div className="tile-label">{label}</div>
    </div>
  );
}
