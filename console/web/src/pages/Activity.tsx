import { useState } from "react";
import { Link } from "react-router-dom";
import { Incident, incidentAction, incidents } from "../api";
import { ErrorBanner, Notice, Spinner, useLoad } from "../components";

// Ransomware alerts (docs/design/ransomware-alerts.md): bursts of deletes or overwrites against a bucket's usual
// rate, and changes that weaken a bucket's protection, each with the credential behind it.

const KIND: Record<Incident["kind"], string> = {
  "mass-delete": "Mass delete",
  "mass-overwrite": "Mass overwrite",
  "protection-removed": "Protection removed",
};

const CHANGE: Record<string, string> = {
  "versioning-suspended": "versioning suspended",
  "noncurrent-expiry": "old versions set to expire",
  "retention-bypassed": "retention bypassed",
  "bucket-deleted": "bucket deleted with its data",
  "public-write": "anyone may write or delete",
};

const when = (unix: number) => new Date(unix * 1000).toLocaleString();

function what(x: Incident): string {
  if (x.kind === "protection-removed") {
    const n = x.counts.changes ?? 1;
    return `${CHANGE[x.change ?? ""] ?? x.change}${n > 1 ? ` (${n} times)` : ""}${x.detail ? `: ${x.detail}` : ""}`;
  }
  const n = x.kind === "mass-delete" ? x.counts.deleted : x.counts.overwritten;
  return `${(n ?? 0).toLocaleString()} objects (usually ${x.usual.toLocaleString()})`;
}

function credentialState(x: Incident): string {
  if (!x.action || x.action === "none")
    return x.actionError ? `not turned off: ${x.actionError}` : "";
  if (x.undone) return "turned back on";
  return x.action === "revoked" ? "sessions revoked" : "turned off";
}

export default function ActivityPage() {
  const [all, setAll] = useState(false);
  const r = useLoad(() => incidents(all), [all]);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<unknown>();
  const act = async (
    x: Incident,
    action: "disable" | "undo" | "false-alarm",
  ) => {
    setError(undefined);
    try {
      await incidentAction(x.id, action);
      setNotice(
        action === "disable"
          ? "The credential is turned off."
          : action === "undo"
            ? "The credential is turned back on."
            : "Marked as a false alarm.",
      );
      r.reload();
    } catch (e) {
      setError(e);
    }
  };
  const list = r.data?.incidents ?? [];
  return (
    <div>
      <div className="page-head">
        <h1>Activity</h1>
        <label className="check">
          <input
            type="checkbox"
            checked={all}
            onChange={(e) => setAll(e.target.checked)}
            data-testid="activity-all"
          />
          Show closed incidents (90 days)
        </label>
      </div>
      <p className="muted">
        Bursts of deletes or overwrites, against each bucket&apos;s usual rate,
        and changes that weaken a bucket&apos;s protection, with the credential
        behind each.{" "}
        {r.data && (
          <span data-testid="activity-rule">
            A burst is at least {r.data.rule.floor.toLocaleString()} objects in{" "}
            {r.data.rule.windowMinutes} minutes, and more than{" "}
            {r.data.rule.factor} times the usual rate.{" "}
            {r.data.response === "disable"
              ? "The credential behind a burst is turned off at once."
              : "Credentials are only turned off from here."}
          </span>
        )}
      </p>
      <ErrorBanner
        error={r.error ?? error}
        onClose={() => (r.setError(undefined), setError(undefined))}
      />
      <Notice text={notice} />
      {r.loading && !r.data && <Spinner />}
      {r.data && !list.length && (
        <p className="muted" data-testid="activity-none">
          {all ? "No incidents in the last 90 days." : "No open incidents."}
        </p>
      )}
      {list.length > 0 && (
        <table data-testid="activity-table">
          <thead>
            <tr>
              <th>Opened</th>
              <th>What</th>
              <th>Bucket</th>
              <th>Credential</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {list.map((x) => {
              const c = x.credentials[0];
              const off = x.action === "disabled" && !x.undone;
              const canDisable =
                c &&
                (!x.action || x.action === "none" || x.undone) &&
                ["access-key", "user", "sts"].includes(c.type);
              return (
                <tr key={x.id} data-testid={`incident-${x.id}`}>
                  <td>{when(x.opened)}</td>
                  <td>
                    <span
                      className={`pill ${x.kind === "protection-removed" ? "warn" : "bad"}`}
                    >
                      {KIND[x.kind]}
                    </span>{" "}
                    {what(x)}
                  </td>
                  <td>
                    {x.bucket ? (
                      <Link
                        to={`/buckets/${encodeURIComponent(x.bucket)}/settings`}
                      >
                        {x.bucket}
                      </Link>
                    ) : (
                      <span className="muted">several</span>
                    )}
                  </td>
                  <td>
                    {c ? (
                      <>
                        <span className="mono">
                          {c.accessKey || "anonymous"}
                        </span>
                        {c.user && c.user !== c.accessKey && <> ({c.user})</>}
                        {c.accessKey && (
                          <div>
                            <Link
                              to={`/reports/audit?range=custom&accessKey=${encodeURIComponent(c.accessKey)}&from=${new Date((x.opened - 1800) * 1000).toISOString()}&to=${new Date(((x.closed || x.lastSeen) + 600) * 1000).toISOString()}`}
                              data-testid={`audit-link-${x.id}`}
                            >
                              What it did
                            </Link>
                          </div>
                        )}
                        {x.credentials.length > 1 && (
                          <span className="muted">
                            {" "}
                            and {x.credentials.length - 1} more
                          </span>
                        )}
                        {credentialState(x) && (
                          <div className="muted">{credentialState(x)}</div>
                        )}
                      </>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td>
                    {x.closed ? (
                      `closed ${when(x.closed)}`
                    ) : (
                      <span className="pill bad">open</span>
                    )}
                    {x.falseAlarm && <div className="muted">false alarm</div>}
                  </td>
                  <td className="actions">
                    {canDisable && (
                      <button
                        className="danger"
                        onClick={() => act(x, "disable")}
                        data-testid={`disable-${x.id}`}
                      >
                        Turn off credential
                      </button>
                    )}
                    {off && (
                      <button
                        onClick={() => act(x, "undo")}
                        data-testid={`undo-${x.id}`}
                      >
                        Turn back on
                      </button>
                    )}
                    {!x.falseAlarm && (
                      <button
                        className="link"
                        onClick={() => act(x, "false-alarm")}
                        data-testid={`false-${x.id}`}
                      >
                        False alarm
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
  );
}
