import { useState } from "react";
import { trace, TRACE_TYPES, TraceRecord } from "../api";
import { Modal } from "../components";
import { StreamBar, StreamError, useStream } from "./Stream";

// mc admin trace: the cluster's calls as they happen.
function durationText(ns?: number): string {
  if (ns === undefined) return "";
  if (ns < 1e3) return `${ns}ns`;
  if (ns < 1e6) return `${(ns / 1e3).toFixed(1)}µs`;
  if (ns < 1e9) return `${(ns / 1e6).toFixed(1)}ms`;
  return `${(ns / 1e9).toFixed(2)}s`;
}

export default function Trace() {
  const [types, setTypes] = useState<string[]>(["s3"]);
  const [errorsOnly, setErrorsOnly] = useState(false);
  const [threshold, setThreshold] = useState("");
  const [detail, setDetail] = useState<TraceRecord | null>(null);
  const s = useStream<TraceRecord>((onItem, signal) => trace(types, errorsOnly, threshold, onItem, signal));
  const toggle = (t: string) => setTypes((prev) => (prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t]));
  return (
    <div>
      <div className="page-head">
        <h1>Trace</h1>
      </div>
      <StreamError error={s.error} onClose={() => s.setError(undefined)} />
      <StreamBar running={s.running} count={s.items.length} onStart={s.start} onStop={s.stop} onClear={s.clear}>
        {TRACE_TYPES.map((t) => (
          <label key={t} className="check">
            <input type="checkbox" checked={types.includes(t)} onChange={() => toggle(t)} disabled={s.running} data-testid={`trace-type-${t}`} /> {t}
          </label>
        ))}
        <label className="check">
          <input type="checkbox" checked={errorsOnly} onChange={(e) => setErrorsOnly(e.target.checked)} disabled={s.running} /> errors only
        </label>
        <input
          className="small"
          placeholder="slower than, e.g. 100ms"
          value={threshold}
          onChange={(e) => setThreshold(e.target.value)}
          disabled={s.running}
        />
      </StreamBar>
      <table data-testid="trace-table" className="dense">
        <thead>
          <tr>
            <th>Time</th>
            <th>Node</th>
            <th>Call</th>
            <th>Status</th>
            <th>Duration</th>
            <th>Path</th>
          </tr>
        </thead>
        <tbody>
          {s.items.map((r, i) => (
            <tr key={s.items.length - i} onClick={() => setDetail(r)} className="clickable" data-testid="trace-row">
              <td className="mono">{r.time?.slice(11, 23)}</td>
              <td>{r.nodename}</td>
              <td className="mono">{r.funcname}</td>
              <td>
                {r.error ? (
                  <span className="pill bad">{r.error.slice(0, 40)}</span>
                ) : r.http?.response?.statusCode ? (
                  <span className={`pill ${r.http.response.statusCode < 400 ? "ok" : "bad"}`}>{r.http.response.statusCode}</span>
                ) : (
                  ""
                )}
              </td>
              <td className="mono">{durationText(r.dur)}</td>
              <td className="mono ellipsis">{r.http?.request?.path ?? r.path}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {detail && (
        <Modal title={detail.funcname} onClose={() => setDetail(null)}>
          <pre className="json">{JSON.stringify(detail, null, 2)}</pre>
        </Modal>
      )}
    </div>
  );
}
