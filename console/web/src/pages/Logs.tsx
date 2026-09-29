import { useState } from "react";
import { consoleLogs, LogEntry } from "../api";
import { StreamBar, StreamError, useStream } from "./Stream";

// mc admin logs: the recent server log, then new entries as they come.
export default function Logs() {
  const [node, setNode] = useState("");
  const [logType, setLogType] = useState("ALL");
  const s = useStream<LogEntry>((onItem, signal) => consoleLogs(node, logType, 100, onItem, signal));
  return (
    <div>
      <div className="page-head">
        <h1>Logs</h1>
      </div>
      <StreamError error={s.error} onClose={() => s.setError(undefined)} />
      <StreamBar running={s.running} count={s.items.length} onStart={s.start} onStop={s.stop} onClear={s.clear}>
        <select value={logType} onChange={(e) => setLogType(e.target.value)} disabled={s.running} data-testid="log-type">
          <option value="ALL">All</option>
          <option value="MINIO">Server</option>
          <option value="APPLICATION">Application</option>
        </select>
        <input className="small" placeholder="node (host:port)" value={node} onChange={(e) => setNode(e.target.value)} disabled={s.running} />
      </StreamBar>
      <table data-testid="log-table" className="dense">
        <thead>
          <tr>
            <th>Time</th>
            <th>Level</th>
            <th>Node</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {s.items.map((e, i) => (
            <tr key={s.items.length - i} data-testid="log-row">
              <td className="mono">{e.time && !e.time.startsWith("0001") ? e.time.slice(0, 19).replace("T", " ") : ""}</td>
              <td>{e.level ? <span className={`pill ${e.level === "ERROR" || e.level === "FATAL" ? "bad" : "warn"}`}>{e.level}</span> : ""}</td>
              <td>{e.node}</td>
              <td className="mono wrap">{e.ConsoleMsg ?? e.error?.message ?? e.message ?? ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
