import { ReactNode, useEffect, useState } from "react";
import { ApiError } from "./api";

export function formatBytes(n: number | undefined): string {
  if (n === undefined || isNaN(n)) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i ? v.toFixed(1) : v} ${units[i]}`;
}

export function formatDate(s: string | undefined): string {
  if (!s) return "—";
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleString();
}

export function errorText(e: unknown): string {
  if (e instanceof ApiError) return e.code && e.message !== e.code ? `${e.message} (${e.code})` : e.message;
  return e instanceof Error ? e.message : String(e);
}

export function ErrorBanner({ error, onClose }: { error: unknown; onClose?: () => void }) {
  if (!error) return null;
  return (
    <div className="banner error" role="alert" data-testid="error">
      <span>{errorText(error)}</span>
      {onClose && (
        <button className="link" onClick={onClose} aria-label="dismiss">
          ×
        </button>
      )}
    </div>
  );
}

export function Notice({ text }: { text: string | null }) {
  if (!text) return null;
  return (
    <div className="banner ok" role="status" data-testid="notice">
      {text}
    </div>
  );
}

export function Spinner() {
  return <div className="spinner" aria-label="loading" />;
}

export function Modal({ title, children, onClose }: { title: string; children: ReactNode; onClose: () => void }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className="modal" role="dialog" aria-label={title} onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h2>{title}</h2>
          <button className="link" onClick={onClose} aria-label="close">
            ×
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

// A button that asks once more before doing something destructive.
export function ConfirmButton({ label, confirm, onConfirm, testId }: { label: string; confirm: string; onConfirm: () => void; testId?: string }) {
  const [asking, setAsking] = useState(false);
  if (!asking)
    return (
      <button className="danger" onClick={() => setAsking(true)} data-testid={testId}>
        {label}
      </button>
    );
  return (
    <span className="confirm">
      <span>{confirm}</span>
      <button
        className="danger"
        data-testid={testId ? `${testId}-yes` : undefined}
        onClick={() => {
          setAsking(false);
          onConfirm();
        }}
      >
        Yes
      </button>
      <button onClick={() => setAsking(false)}>No</button>
    </span>
  );
}

// Runs an async loader and keeps its state.
export function useLoad<T>(load: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | undefined>();
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    setLoading(true);
    setError(undefined);
    load()
      .then((d) => live && setData(d))
      .catch((e) => live && setError(e))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { data, error, loading, reload: () => setTick((t) => t + 1), setError };
}
