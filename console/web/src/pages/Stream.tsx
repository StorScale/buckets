import { ReactNode, useEffect, useRef, useState } from "react";
import { ErrorBanner } from "../components";

// A live stream's shared chrome: start/stop, a row cap, pause-on-hover.
export const MAX_ROWS = 500;

export function useStream<T>(open: (onItem: (item: T) => void, signal: AbortSignal) => Promise<void>) {
  const [items, setItems] = useState<T[]>([]);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<unknown>();
  const abort = useRef<AbortController | null>(null);
  const stop = () => {
    abort.current?.abort();
    abort.current = null;
    setRunning(false);
  };
  const start = () => {
    stop();
    setError(undefined);
    const ctl = new AbortController();
    abort.current = ctl;
    setRunning(true);
    open((item) => setItems((prev) => [item, ...prev].slice(0, MAX_ROWS)), ctl.signal)
      .catch((e) => !ctl.signal.aborted && setError(e))
      .finally(() => abort.current === ctl && setRunning(false));
  };
  useEffect(() => () => abort.current?.abort(), []);
  return { items, running, error, setError, start, stop, clear: () => setItems([]) };
}

export function StreamBar({
  running,
  count,
  onStart,
  onStop,
  onClear,
  children,
}: {
  running: boolean;
  count: number;
  onStart: () => void;
  onStop: () => void;
  onClear: () => void;
  children?: ReactNode;
}) {
  return (
    <div className="toolbar stream-bar">
      {children}
      {running ? (
        <button onClick={onStop} data-testid="stream-stop">
          Stop
        </button>
      ) : (
        <button className="primary" onClick={onStart} data-testid="stream-start">
          Start
        </button>
      )}
      <button onClick={onClear} disabled={!count}>
        Clear
      </button>
      <span className="muted" data-testid="stream-count">
        {running ? "live · " : ""}
        {count} {count === 1 ? "entry" : "entries"}
        {count >= MAX_ROWS ? ` (newest ${MAX_ROWS})` : ""}
      </span>
    </div>
  );
}

export function StreamError({ error, onClose }: { error: unknown; onClose: () => void }) {
  return <ErrorBanner error={error} onClose={onClose} />;
}
