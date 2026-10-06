import { useEffect, useState } from "react";
import { configHelp, ConfigHelp, getConfig, setConfig } from "../api";
import { ErrorBanner, Notice, Spinner, useLoad } from "../components";

// "subsys[:target] k=v k2=\"v 2\"" -> {k: v}
function parseKv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  const line = text.split("\n").find((l) => l.trim() && !l.startsWith("#")) ?? "";
  const re = /(\w+)=("(?:[^"\\]|\\.)*"|\S*)/g;
  let m;
  while ((m = re.exec(line))) out[m[1]] = m[2].startsWith('"') ? m[2].slice(1, -1).replace(/\\"/g, '"') : m[2];
  return out;
}

// MinIO's own services (its SUBNET license and call-home): the server keeps them for MinIO's tools, but they
// do nothing for Buckets, so the page leaves them out.
const MINIO_ONLY = ["subnet", "callhome"];

export default function Configuration() {
  const [subsys, setSubsys] = useState("api");
  // The subsystems the server documents (help without one lists them): deprecated ones it keeps
  // only for old settings, such as policy_opa and region, have no help and are not shown.
  const all = useLoad(() => configHelp(), []);
  const subsystems = all.data?.keysHelp.map((k) => k.key).filter((k) => !MINIO_ONLY.includes(k)) ?? [];
  const help = useLoad(() => configHelp(subsys), [subsys]);
  const [values, setValues] = useState<Record<string, string>>({});
  const [original, setOriginal] = useState<Record<string, string>>({});
  const [error, setError] = useState<unknown>();
  const [notice, setNotice] = useState<string | null>(null);
  const [loadedFor, setLoadedFor] = useState<string | null>(null);

  useEffect(() => {
    setNotice(null);
    setLoadedFor(null);
    let live = true;
    getConfig(subsys)
      .then((t) => {
        if (!live) return;
        const kv = parseKv(t);
        setValues(kv);
        setOriginal(kv);
        setLoadedFor(subsys);
      })
      .catch((e) => live && setError(e));
    return () => {
      live = false;
    };
  }, [subsys]);

  const save = async () => {
    const changed = Object.entries(values).filter(([k, v]) => original[k] !== v);
    if (!changed.length) return;
    const q = (v: string) => (/[\s"]/.test(v) || v === "" ? `"${v.replace(/"/g, '\\"')}"` : v);
    try {
      await setConfig(`${subsys} ${changed.map(([k, v]) => `${k}=${q(v)}`).join(" ")}`);
      setOriginal(values);
      setNotice("Saved. Some settings apply after a restart.");
    } catch (e) {
      setError(e);
    }
  };
  // Fields appear once the stored values are in, so edits are never overwritten.
  const keys: ConfigHelp["keysHelp"] = loadedFor === subsys ? help.data?.keysHelp ?? [] : [];
  return (
    <div>
      <h1>Configuration</h1>
      <div className="split">
        <nav className="subnav">
          {subsystems.map((s) => (
            <a
              key={s}
              href="#"
              className={s === subsys ? "active" : ""}
              onClick={(e) => {
                e.preventDefault();
                setSubsys(s);
              }}
              data-testid={`config-${s}`}
            >
              {s}
            </a>
          ))}
        </nav>
        <div className="grow">
          <ErrorBanner error={error ?? help.error ?? all.error} onClose={() => setError(undefined)} />
          <Notice text={notice} />
          {(help.loading || loadedFor !== subsys) && <Spinner />}
          {help.data && <p className="muted">{help.data.description}</p>}
          {keys.map((k) => (
            <label key={k.key}>
              {k.key} <span className="muted">— {k.description}</span>
              <input value={values[k.key] ?? ""} onChange={(e) => setValues({ ...values, [k.key]: e.target.value })} data-testid={`cfg-${k.key}`} />
            </label>
          ))}
          {keys.length > 0 && (
            <div className="form-actions">
              <button className="primary" onClick={save} data-testid="config-save">
                Save
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
