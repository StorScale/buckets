import { useState } from "react";
import { EventRecord, listBuckets, listenEvents } from "../api";
import { formatBytes, useLoad } from "../components";
import { StreamBar, StreamError, useStream } from "./Stream";

// mc event listen: a bucket's (or every bucket's) events as they happen.
const EVENTS = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*", "s3:ObjectAccessed:*"];

export default function Events() {
  const buckets = useLoad(listBuckets, []);
  const [bucket, setBucket] = useState("");
  const [prefix, setPrefix] = useState("");
  const [suffix, setSuffix] = useState("");
  const [events, setEvents] = useState<string[]>(["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]);
  const s = useStream<EventRecord>((onItem, signal) => listenEvents(bucket, prefix, suffix, events, onItem, signal));
  const toggle = (e: string) => setEvents((prev) => (prev.includes(e) ? prev.filter((x) => x !== e) : [...prev, e]));
  return (
    <div>
      <div className="page-head">
        <h1>Events</h1>
      </div>
      <StreamError error={s.error} onClose={() => s.setError(undefined)} />
      <StreamBar running={s.running} count={s.items.length} onStart={s.start} onStop={s.stop} onClear={s.clear}>
        <select value={bucket} onChange={(e) => setBucket(e.target.value)} disabled={s.running} data-testid="events-bucket">
          <option value="">All buckets</option>
          {(buckets.data ?? []).map((b) => (
            <option key={b.name} value={b.name}>
              {b.name}
            </option>
          ))}
        </select>
        <input className="small" placeholder="prefix" value={prefix} onChange={(e) => setPrefix(e.target.value)} disabled={s.running} />
        <input className="small" placeholder="suffix" value={suffix} onChange={(e) => setSuffix(e.target.value)} disabled={s.running} />
        {EVENTS.map((e) => (
          <label key={e} className="check">
            <input type="checkbox" checked={events.includes(e)} onChange={() => toggle(e)} disabled={s.running} /> {e.split(":")[1]}
          </label>
        ))}
      </StreamBar>
      <table data-testid="events-table" className="dense">
        <thead>
          <tr>
            <th>Time</th>
            <th>Event</th>
            <th>Bucket</th>
            <th>Object</th>
            <th>Size</th>
          </tr>
        </thead>
        <tbody>
          {s.items.map((r, i) => (
            <tr key={s.items.length - i} data-testid="event-row">
              <td className="mono">{r.eventTime?.slice(0, 19).replace("T", " ")}</td>
              <td className="mono">{r.eventName.replace(/^s3:/, "")}</td>
              <td>{r.s3.bucket.name}</td>
              <td className="mono ellipsis">{decodeURIComponent(r.s3.object.key.replace(/\+/g, " "))}</td>
              <td>{r.s3.object.size !== undefined ? formatBytes(r.s3.object.size) : ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
