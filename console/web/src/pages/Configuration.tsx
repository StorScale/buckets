import { useEffect, useState } from "react";
import { configHelp, ConfigHelp, getConfig, setConfig } from "../api";
import { ErrorBanner, Notice, Spinner, useLoad } from "../components";

// The subsystems shown (MinIO's `mc admin config` names).
const SUBSYSTEMS = [
  "api", "scanner", "compression", "storage_class", "site", "region", "identity_openid", "identity_ldap", "policy_opa",
  "notify_webhook", "notify_amqp", "notify_kafka", "notify_mqtt", "notify_nats", "notify_nsq", "notify_redis",
  "notify_postgres", "notify_mysql", "notify_elasticsearch", "logger_webhook", "audit_webhook", "audit_kafka",
];

// "subsys[:target] k=v k2=\"v 2\"" -> {k: v}
function parseKv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  const line = text.split("\n").find((l) => l.trim() && !l.startsWith("#")) ?? "";
  const re = /(\w+)=("(?:[^"\\]|\\.)*"|\S*)/g;
  let m;
  while ((m = re.exec(line))) out[m[1]] = m[2].startsWith('"') ? m[2].slice(1, -1).replace(/\\"/g, '"') : m[2];
  return out;
}

export default function Configuration() {
  const [subsys, setSubsys] = useState("api");
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
          {SUBSYSTEMS.map((s) => (
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
          <ErrorBanner error={error ?? help.error} onClose={() => setError(undefined)} />
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
