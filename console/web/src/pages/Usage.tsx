import { useState } from "react";
import { Link } from "react-router-dom";
import {
  clearUsageRates,
  setUsageRates,
  UsageBucket,
  UsageRates,
  UsageReport,
  UsageTotals,
  usageReport,
} from "../api";
import {
  ErrorBanner,
  formatBytes,
  Modal,
  Spinner,
  useLoad,
} from "../components";

// Who stores and moves how much, per team and per bucket, and what that costs when rates are set
// (docs/design/usage-reports.md). Days are UTC days, as the servers record them.

type Period = "this" | "last" | "custom";

const isoDay = (d: Date) => d.toISOString().slice(0, 10);
function lastMonth(): [string, string] {
  const now = new Date();
  const first = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1),
  );
  const last = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 0));
  return [isoDay(first), isoDay(last)];
}

const gb = (bytes: number) => bytes / 1e9;
const num = (n: number) => n.toLocaleString();
const gbMonths = (n: number) =>
  n >= 100 ? n.toFixed(0) : n >= 1 ? n.toFixed(2) : n.toPrecision(2);

export function cost(t: UsageTotals, r: UsageRates | null): number | null {
  if (!r) return null;
  return (
    t.storage.gbMonths * (r.storageGbMonth ?? 0) +
    gb(t.dataOut) * (r.outGb ?? 0) +
    gb(t.dataIn) * (r.inGb ?? 0) +
    (t.requests.read / 1e4) * (r.per10kRead ?? 0) +
    (t.requests.write / 1e4) * (r.per10kWrite ?? 0) +
    (t.requests.delete / 1e4) * (r.per10kDelete ?? 0)
  );
}
const money = (n: number | null, r: UsageRates | null) =>
  n === null || !r ? "—" : `${n.toFixed(2)} ${r.currency}`;

const csvCell = (s: string | number) =>
  typeof s === "string" && /[",\n]/.test(s)
    ? `"${s.replace(/"/g, '""')}"`
    : String(s);

const RATE_FIELDS: [keyof UsageRates, string][] = [
  ["storageGbMonth", "per GB-month stored"],
  ["outGb", "per GB out"],
  ["inGb", "per GB in"],
  ["per10kRead", "per 10,000 reads"],
  ["per10kWrite", "per 10,000 writes"],
  ["per10kDelete", "per 10,000 deletes"],
];

function csv(r: UsageReport, byTeam: boolean) {
  const head = [
    byTeam ? "team" : "bucket",
    ...(byTeam ? ["buckets"] : ["team"]),
    "GB-months",
    "peak bytes",
    "bytes in",
    "bytes out",
    "reads",
    "writes",
    "deletes",
    ...(r.rates ? [`cost (${r.rates.currency})`] : []),
  ];
  const lines: (string | number)[][] = [head];
  const rows: (UsageTotals & { label: string; other: string })[] = byTeam
    ? r.teams.map((t) => ({
        ...t,
        label: t.name ?? "No team",
        other: t.buckets.join(" "),
      }))
    : r.buckets.map((b) => ({
        ...b,
        label: b.name,
        other: b.team ?? "No team",
      }));
  for (const x of rows) {
    const c = cost(x, r.rates);
    lines.push([
      x.label,
      x.other,
      x.storage.gbMonths.toFixed(6),
      x.storage.peakBytes,
      x.dataIn,
      x.dataOut,
      x.requests.read,
      x.requests.write,
      x.requests.delete,
      ...(c === null ? [] : [c.toFixed(2)]),
    ]);
  }
  // what the figures rest on: the period and, when costed, the rates
  lines.push([]);
  lines.push(["period", r.from, r.to]);
  if (r.missingDays.length)
    lines.push(["days without records", ...r.missingDays]);
  if (r.rates) {
    lines.push(["currency", r.rates.currency]);
    for (const [k, label] of RATE_FIELDS)
      if (r.rates[k] !== undefined)
        lines.push([`rate ${label}`, r.rates[k] as number]);
  }
  const url = URL.createObjectURL(
    new Blob([lines.map((l) => l.map(csvCell).join(",")).join("\n") + "\n"], {
      type: "text/csv",
    }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = `usage-${byTeam ? "teams" : "buckets"}-${r.from}-${r.to}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// A bucket's daily size, as a small bar chart.
function Daily({ b }: { b: UsageBucket }) {
  const max = Math.max(1, ...b.daily.map((d) => d.bytes));
  const w = Math.max(4, Math.min(24, Math.floor(720 / b.daily.length)));
  const h = 80;
  return (
    <div data-testid={`daily-${b.name}`}>
      <svg
        width={w * b.daily.length}
        height={h}
        role="img"
        aria-label={`${b.name}: daily storage`}
      >
        {b.daily.map((d, i) => {
          const bh = Math.round((d.bytes / max) * (h - 2));
          return (
            <rect
              key={d.day}
              x={i * w}
              y={h - bh}
              width={w - 1}
              height={bh}
              fill="var(--accent)"
            >
              <title>{`${d.day}: ${formatBytes(d.bytes)} stored, ${formatBytes(d.in)} in, ${formatBytes(d.out)} out`}</title>
            </rect>
          );
        })}
      </svg>
      <div className="muted">
        {b.daily[0]?.day} – {b.daily[b.daily.length - 1]?.day}, up to{" "}
        {formatBytes(max)} a day
      </div>
    </div>
  );
}

function Cells({ t, rates }: { t: UsageTotals; rates: UsageRates | null }) {
  return (
    <>
      <td>{gbMonths(t.storage.gbMonths)}</td>
      <td>{formatBytes(t.storage.peakBytes)}</td>
      <td>{formatBytes(t.dataIn)}</td>
      <td>{formatBytes(t.dataOut)}</td>
      <td>{num(t.requests.read)}</td>
      <td>{num(t.requests.write)}</td>
      <td>{num(t.requests.delete)}</td>
      {rates && <td data-testid="cost">{money(cost(t, rates), rates)}</td>}
    </>
  );
}

function Heads({ rates }: { rates: UsageRates | null }) {
  return (
    <>
      <th title="Storage averaged over the period: GB held for a month">
        GB-months
      </th>
      <th>Peak</th>
      <th>Data in</th>
      <th>Data out</th>
      <th>Reads</th>
      <th>Writes</th>
      <th>Deletes</th>
      {rates && <th>Cost</th>}
    </>
  );
}

function Teams({ r }: { r: UsageReport }) {
  return (
    <table data-testid="usage-teams">
      <thead>
        <tr>
          <th>Team</th>
          <th>Buckets</th>
          <Heads rates={r.rates} />
        </tr>
      </thead>
      <tbody>
        {r.teams.map((t) => (
          <tr key={t.name ?? ""} data-testid={`team-${t.name ?? "none"}`}>
            <td>{t.name ?? <span className="muted">No team</span>}</td>
            <td>{t.buckets.length}</td>
            <Cells t={t} rates={r.rates} />
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Buckets({ r }: { r: UsageReport }) {
  const [open, setOpen] = useState<string | null>(null);
  const cols = 9 + (r.rates ? 1 : 0);
  return (
    <table data-testid="usage-buckets">
      <thead>
        <tr>
          <th>Bucket</th>
          <th>Team</th>
          <Heads rates={r.rates} />
        </tr>
      </thead>
      <tbody>
        {r.buckets.flatMap((b) => [
          <tr key={b.name} data-testid={`bucket-${b.name}`}>
            <td>
              <button
                className="link"
                aria-expanded={open === b.name}
                onClick={() => setOpen(open === b.name ? null : b.name)}
              >
                {open === b.name ? "▾" : "▸"} {b.name}
              </button>
            </td>
            <td>
              {b.team ?? <span className="muted">No team</span>}
              {b.namedByTwoTeams && (
                <span
                  className="pill warn"
                  title="More than one team names this bucket; it is charged to the first by name"
                >
                  {" "}
                  named by two teams
                </span>
              )}
            </td>
            <Cells t={b} rates={r.rates} />
          </tr>,
          ...(open === b.name
            ? [
                <tr key={`${b.name}-daily`}>
                  <td colSpan={cols}>
                    <Daily b={b} />
                  </td>
                </tr>,
              ]
            : []),
        ])}
      </tbody>
    </table>
  );
}

function RatesForm({
  rates,
  onClose,
  onSaved,
}: {
  rates: UsageRates | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [currency, setCurrency] = useState(rates?.currency ?? "USD");
  const [vals, setVals] = useState<Record<string, string>>(
    Object.fromEntries(
      RATE_FIELDS.map(([k]) => [
        k,
        rates?.[k] !== undefined ? String(rates[k]) : "",
      ]),
    ),
  );
  const [error, setError] = useState<unknown>();
  const save = async () => {
    const r: UsageRates = { currency: currency.trim() };
    for (const [k] of RATE_FIELDS) {
      const v = vals[k].trim();
      if (v !== "") (r as Record<string, unknown>)[k] = Number(v);
    }
    try {
      await setUsageRates(r);
      onSaved();
    } catch (e) {
      setError(e);
    }
  };
  const clear = async () => {
    try {
      await clearUsageRates();
      onSaved();
    } catch (e) {
      setError(e);
    }
  };
  return (
    <Modal title="Rates" onClose={onClose}>
      <p className="muted">
        Costs are worked out from usage when the report is viewed, so a change
        re-prices past periods too. Leave a price empty for none.
      </p>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />
      <label>
        Currency
        <input
          value={currency}
          maxLength={8}
          onChange={(e) => setCurrency(e.target.value)}
          data-testid="rate-currency"
        />
      </label>
      {RATE_FIELDS.map(([k, label]) => (
        <label key={k}>
          Price {label}
          <input
            type="number"
            min={0}
            step="any"
            value={vals[k]}
            onChange={(e) => setVals({ ...vals, [k]: e.target.value })}
            data-testid={`rate-${k}`}
          />
        </label>
      ))}
      <div className="form-actions">
        {rates && (
          <button className="danger" onClick={clear} data-testid="rates-clear">
            Remove rates
          </button>
        )}
        <button onClick={onClose}>Cancel</button>
        <button className="primary" onClick={save} data-testid="rates-save">
          Save
        </button>
      </div>
    </Modal>
  );
}

export default function UsagePage() {
  const [period, setPeriod] = useState<Period>("this");
  const [custom, setCustom] = useState<[string, string]>(lastMonth());
  const [byTeam, setByTeam] = useState(true);
  const [editRates, setEditRates] = useState(false);
  // "this month so far" is the server's: its days are the ones it records
  const [from, to] =
    period === "this" ? ["", ""] : period === "last" ? lastMonth() : custom;
  const r = useLoad(() => usageReport(from, to), [from, to]);
  return (
    <div>
      <div className="page-head">
        <h1>Usage</h1>
        <div className="actions">
          <button onClick={() => setEditRates(true)} data-testid="rates-edit">
            Rates
          </button>
          {r.data && (
            <button
              onClick={() => csv(r.data!, byTeam)}
              data-testid="usage-csv"
            >
              Export CSV
            </button>
          )}
        </div>
      </div>
      <p className="muted">
        Storage averaged over the period (GB-months) and at its peak, data in
        and out, and requests, per team and per bucket. Teams are the ones on
        the <Link to="/identity/teams">Teams</Link> page today; a bucket is
        charged to the team that names it, else to the team whose prefix matches
        it most closely.
      </p>
      <form className="inline" onSubmit={(e) => e.preventDefault()}>
        <select
          value={period}
          onChange={(e) => setPeriod(e.target.value as Period)}
          data-testid="usage-period"
        >
          <option value="this">This month so far</option>
          <option value="last">Last month</option>
          <option value="custom">Days from … to …</option>
        </select>
        {period === "custom" && (
          <>
            <input
              type="date"
              value={custom[0]}
              onChange={(e) => setCustom([e.target.value, custom[1]])}
              data-testid="usage-from"
            />
            <input
              type="date"
              value={custom[1]}
              onChange={(e) => setCustom([custom[0], e.target.value])}
              data-testid="usage-to"
            />
          </>
        )}
        {r.data && (
          <span className="muted" data-testid="usage-range">
            {r.data.from} to {r.data.to} (UTC), {r.data.days} day
            {r.data.days === 1 ? "" : "s"}
          </span>
        )}
      </form>
      <div className="tabs" role="tablist">
        <button
          role="tab"
          aria-selected={byTeam}
          className={byTeam ? "active" : ""}
          onClick={() => setByTeam(true)}
          data-testid="tab-teams"
        >
          By team
        </button>
        <button
          role="tab"
          aria-selected={!byTeam}
          className={byTeam ? "" : "active"}
          onClick={() => setByTeam(false)}
          data-testid="tab-buckets"
        >
          By bucket
        </button>
      </div>
      <ErrorBanner error={r.error} onClose={() => r.setError(undefined)} />
      {r.loading && !r.data && <Spinner />}
      {r.data && r.data.missingDays.length > 0 && (
        <p className="muted" data-testid="usage-missing">
          No records for {r.data.missingDays.length} day
          {r.data.missingDays.length === 1 ? "" : "s"} of the period (
          {r.data.missingDays[0]}
          {r.data.missingDays.length > 1
            ? ` – ${r.data.missingDays[r.data.missingDays.length - 1]}`
            : ""}
          ): usage is recorded from Buckets 1.12.0 on, and kept for 13 months.
        </p>
      )}
      {r.data &&
        (r.data.buckets.length ? (
          byTeam ? (
            <Teams r={r.data} />
          ) : (
            <Buckets r={r.data} />
          )
        ) : (
          <p className="muted">No usage recorded in this period.</p>
        ))}
      {r.data?.rates && (
        <p className="muted" data-testid="usage-rates">
          Costs at{" "}
          {RATE_FIELDS.filter(([k]) => r.data!.rates![k])
            .map(
              ([k, label]) =>
                `${r.data!.rates![k]} ${r.data!.rates!.currency} ${label}`,
            )
            .join(", ") || "no prices"}
          .
        </p>
      )}
      {editRates && (
        <RatesForm
          rates={r.data?.rates ?? null}
          onClose={() => setEditRates(false)}
          onSaved={() => {
            setEditRates(false);
            r.reload();
          }}
        />
      )}
    </div>
  );
}
