import { ReactNode, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  AwsSettings,
  AzureSettings,
  GcpSettings,
  KmsBackend,
  KmsConfig,
  kmsConfig,
  kmsConfigApply,
  kmsConfigTest,
  kmsKeyUsage,
  KmsSettings,
  kmsStatus,
  KmsTest,
  VaultSettings,
} from "../api";
import { ErrorBanner, Spinner } from "../components";

// The four key stores KES can keep keys in, as people know them.
const BACKENDS: { id: KmsBackend; title: string; blurb: string; needs: string[] }[] = [
  {
    id: "vault",
    title: "HashiCorp Vault",
    blurb: "Keys in a KV secrets engine, optionally wrapped by Transit.",
    needs: ["Vault's address", "an AppRole, or a role for Kubernetes sign-in"],
  },
  {
    id: "aws",
    title: "AWS Secrets Manager",
    blurb: "Keys as secrets, encrypted with an AWS KMS key.",
    needs: ["a region", "an access key, or an IAM role for the KES pods"],
  },
  {
    id: "azure",
    title: "Azure Key Vault",
    blurb: "Keys as secrets in a Key Vault.",
    needs: ["the vault's URL", "a service principal, or a managed identity"],
  },
  {
    id: "gcp",
    title: "Google Secret Manager",
    blurb: "Keys as secrets in a Google Cloud project.",
    needs: ["a service account's JSON key"],
  },
];

const STEPS = ["Key store", "Connection", "Default key", "Test and apply"];

const AWS_REGIONS = [
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "ca-central-1",
  "eu-west-1",
  "eu-west-2",
  "eu-central-1",
  "eu-north-1",
  "ap-southeast-1",
  "ap-southeast-2",
  "ap-northeast-1",
  "ap-south-1",
  "sa-east-1",
];

function blank(b: KmsBackend, cluster: string): KmsSettings {
  switch (b) {
    case "vault":
      return { backend: b, vault: { endpoint: "", engine: "kv", version: "v2", prefix: `buckets/${cluster}`, auth: "approle", approle: { id: "", secret: "" }, kubernetes: { role: "" } } };
    case "aws":
      return { backend: b, aws: { region: "" } };
    case "azure":
      return { backend: b, azure: { endpoint: "", auth: "secret" } };
    case "gcp":
      return { backend: b, gcp: { credentials: "" } };
  }
}

// What still has to be filled in before the next step, in words.
function missing(s: KmsSettings | null, saved: Set<string>, awsKeys: boolean): string[] {
  if (!s) return ["a key store"];
  const m: string[] = [];
  const secret = (field: string, v: string | undefined) => !!v || saved.has(field);
  if (s.backend === "vault" && s.vault) {
    const v = s.vault;
    if (!v.endpoint) m.push("Vault's address");
    else if (!/^https?:\/\//.test(v.endpoint)) m.push("an address starting with https://");
    if (v.auth === "approle") {
      if (!v.approle?.id) m.push("the role ID");
      if (!secret("vault.approle.secret", v.approle?.secret)) m.push("the secret ID");
    } else if (!v.kubernetes?.role) m.push("the Vault role");
  }
  if (s.backend === "aws" && s.aws) {
    if (!s.aws.region) m.push("the region");
    if (awsKeys) {
      if (!s.aws.accessKey) m.push("the access key ID");
      if (!secret("aws.secretKey", s.aws.secretKey)) m.push("the secret access key");
    }
  }
  if (s.backend === "azure" && s.azure) {
    const a = s.azure;
    if (!a.endpoint) m.push("the Key Vault URL");
    if (a.auth === "secret") {
      if (!a.tenantId) m.push("the tenant ID");
      if (!a.clientId) m.push("the client ID");
      if (!secret("azure.clientSecret", a.clientSecret)) m.push("the client secret");
    } else if (!a.managedIdentityClientId) m.push("the managed identity's client ID");
  }
  if (s.backend === "gcp" && s.gcp) {
    if (!secret("gcp.credentials", s.gcp.credentials)) m.push("the service account key");
  }
  return m;
}

export default function KmsSetup() {
  const navigate = useNavigate();
  const [cfg, setCfg] = useState<KmsConfig | null | undefined>(undefined);
  const [error, setError] = useState<unknown>();
  const [step, setStep] = useState(0);
  const [settings, setSettings] = useState<KmsSettings | null>(null);
  const [awsKeys, setAwsKeys] = useState(true);
  const [keyName, setKeyName] = useState("buckets-default");
  const [createKey, setCreateKey] = useState(true);
  const [required, setRequired] = useState<{ key: string; why: string }[]>([]);
  const [testId, setTestId] = useState<string | null>(null);
  const [test, setTest] = useState<KmsTest | null>(null);
  const [applied, setApplied] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const c = await kmsConfig();
        setCfg(c);
        if (!c?.managed) return;
        if (c.settings) {
          setSettings(c.settings);
          if (c.settings.backend === "aws") setAwsKeys(!!c.settings.aws?.accessKey);
          setStep(1);
        }
        if (c.keyName) setKeyName(c.keyName);
        // keys this cluster uses now: a new key store must have them
        if (c.status?.activated) {
          const st = await kmsStatus().catch(() => null);
          const def = st?.["default-key-id"] ?? c.keyName ?? "";
          const usage = await kmsKeyUsage(def).catch(() => new Map<string, string[]>());
          const req = new Map<string, string>();
          if (def) req.set(def, "the current default key");
          usage.forEach((buckets, k) => req.set(k, `default encryption of ${buckets.join(", ")}`));
          setRequired([...req.entries()].map(([key, why]) => ({ key, why })));
        }
      } catch (e) {
        setError(e);
        setCfg(null);
      }
    })();
  }, []);

  // follow a test, then the change going live
  useEffect(() => {
    if (!testId || (test && test.phase !== "Running" && !applied)) return;
    let live = true;
    const t = setInterval(async () => {
      try {
        const c = await kmsConfig();
        if (!live || !c) return;
        setCfg(c);
        const tt = c.status?.test;
        if (tt && tt.id === testId) setTest(tt);
      } catch (e) {
        if (live) setError(e);
      }
    }, 1500);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [testId, test?.phase, applied]);

  const saved = useMemo(() => new Set(settings?.secretsSet ?? []), [settings]);
  const todo = missing(settings, saved, awsKeys);

  if (cfg === undefined) return <Spinner />;
  if (cfg === null)
    return (
      <div>
        <h1>Set up the KMS</h1>
        <ErrorBanner error={error} />
        {!error && <div className="banner error">Setting up the KMS needs the admin:ConfigUpdate permission.</div>}
      </div>
    );
  if (!cfg.managed)
    return (
      <div>
        <h1>Set up the KMS</h1>
        <div className="card">
          <p>
            This console does not run under buckets-operator, so the KMS is set on the servers instead: KES with <span className="mono">MINIO_KMS_KES_*</span>, or a
            single static key with <span className="mono">MINIO_KMS_SECRET_KEY</span>.
          </p>
          <Link to="/encryption">Back to Encryption</Link>
        </div>
      </div>
    );

  const editing = !!cfg.settings;
  const cluster = cfg.cluster ?? "buckets";
  const update = (s: KmsSettings) => {
    setSettings(s);
    setTestId(null);
    setTest(null);
  };

  const runTest = async () => {
    if (!settings) return;
    setError(undefined);
    setTest({ id: "", phase: "Running", steps: [] });
    try {
      const body: KmsSettings = { ...settings };
      if (body.backend === "aws" && body.aws && !awsKeys) body.aws = { ...body.aws, accessKey: "", secretKey: "", sessionToken: "" };
      const id = await kmsConfigTest({ settings: body, keyName: keyName.trim(), createKey, requiredKeys: required.map((r) => r.key) });
      setTestId(id);
      setTest({ id, phase: "Running", steps: [] });
    } catch (e) {
      setTest(null);
      setError(e);
    }
  };

  const apply = async () => {
    if (!testId) return;
    setError(undefined);
    try {
      await kmsConfigApply(testId);
      setApplied(true);
    } catch (e) {
      setError(e);
    }
  };

  return (
    <div className="kms-setup">
      <div className="page-head">
        <h1>
          <Link to="/encryption">Encryption</Link> / {editing ? "Key store settings" : "Set up the KMS"}
        </h1>
      </div>
      <ol className="steps" data-testid="kms-steps">
        {STEPS.map((name, i) => (
          <li key={name} className={i === step ? "current" : i < step ? "done" : ""}>
            <button className="link" disabled={i > step || applied} onClick={() => setStep(i)}>
              <span className="step-no">{i < step ? "✓" : i + 1}</span> {name}
            </button>
          </li>
        ))}
      </ol>
      <ErrorBanner error={error} onClose={() => setError(undefined)} />

      {step === 0 && (
        <div className="card section">
          <h2>Where should Buckets keep its encryption keys?</h2>
          <p className="muted">
            Buckets runs a KES server next to the cluster. KES keeps the keys in the key store you choose here, and never stores them on the storage servers.
          </p>
          <div className="choices" role="radiogroup">
            {BACKENDS.map((b) => (
              <button
                key={b.id}
                role="radio"
                aria-checked={settings?.backend === b.id}
                className={`choice ${settings?.backend === b.id ? "selected" : ""}`}
                data-testid={`kms-backend-${b.id}`}
                onClick={() => update(settings?.backend === b.id ? settings : cfg.settings?.backend === b.id ? cfg.settings : blank(b.id, cluster))}
              >
                <strong>{b.title}</strong>
                <span>{b.blurb}</span>
                <span className="muted">You need {b.needs.join(" and ")}.</span>
              </button>
            ))}
          </div>
          <div className="form-actions">
            <Link className="button" to="/encryption">
              Cancel
            </Link>
            <button className="primary" disabled={!settings} onClick={() => setStep(1)} data-testid="kms-next">
              Next
            </button>
          </div>
        </div>
      )}

      {step === 1 && settings && (
        <div className="card section">
          <h2>Connect to {BACKENDS.find((b) => b.id === settings.backend)?.title}</h2>
          {settings.backend === "vault" && <VaultForm v={settings.vault!} saved={saved} cfg={cfg} onChange={(vault) => update({ ...settings, vault })} />}
          {settings.backend === "aws" && <AwsForm a={settings.aws!} saved={saved} keys={awsKeys} setKeys={setAwsKeys} onChange={(aws) => update({ ...settings, aws })} />}
          {settings.backend === "azure" && <AzureForm a={settings.azure!} saved={saved} onChange={(azure) => update({ ...settings, azure })} />}
          {settings.backend === "gcp" && <GcpForm g={settings.gcp!} saved={saved} onChange={(gcp) => update({ ...settings, gcp })} />}
          {todo.length > 0 && (
            <p className="hint" data-testid="kms-missing">
              Still needed: {todo.join(", ")}.
            </p>
          )}
          <div className="form-actions">
            <button onClick={() => setStep(0)}>Back</button>
            <button className="primary" disabled={todo.length > 0} onClick={() => setStep(2)} data-testid="kms-next">
              Next
            </button>
          </div>
        </div>
      )}

      {step === 2 && (
        <div className="card section">
          <h2>Default key</h2>
          <p className="muted">
            SSE-S3 encrypts with this key, and so does SSE-KMS when a request or bucket names no key. Buckets can create more keys later, under Encryption.
          </p>
          <label>
            Key name
            <input value={keyName} onChange={(e) => (setKeyName(e.target.value), setTestId(null), setTest(null))} data-testid="kms-key-name" />
          </label>
          <label className="check">
            <input type="checkbox" checked={createKey} onChange={(e) => (setCreateKey(e.target.checked), setTestId(null), setTest(null))} data-testid="kms-create-key" />
            Create it in the key store if it is not there
          </label>
          {required.length > 0 && (
            <div className="subsection" data-testid="kms-required">
              <h3>Keys in use</h3>
              <p className="muted">Objects are encrypted with these keys now. The test checks that the key store has every one of them, so nothing becomes unreadable.</p>
              <ul>
                {required.map((r) => (
                  <li key={r.key}>
                    <span className="mono">{r.key}</span> <span className="muted">— {r.why}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className="form-actions">
            <button onClick={() => setStep(1)}>Back</button>
            <button className="primary" disabled={!/^[A-Za-z0-9_.-]+$/.test(keyName.trim())} onClick={() => setStep(3)} data-testid="kms-next">
              Next
            </button>
          </div>
        </div>
      )}

      {step === 3 && settings && (
        <div className="card section">
          <h2>Test and apply</h2>
          {!applied && (
            <>
              <Review settings={settings} keyName={keyName} createKey={createKey} awsKeys={awsKeys} />
              <p className="muted">
                The test starts a temporary KES server with these settings, signs in to the key store, makes sure the default key is there and encrypts and decrypts
                with it. Nothing changes for the cluster until you apply.
              </p>
              {test && <TestResult test={test} />}
              <div className="form-actions">
                <button onClick={() => setStep(2)} disabled={test?.phase === "Running"}>
                  Back
                </button>
                {test?.phase === "Failed" && (
                  <button onClick={() => setStep(1)} data-testid="kms-fix">
                    Change settings
                  </button>
                )}
                {test?.phase !== "Passed" && (
                  <button className="primary" onClick={runTest} disabled={test?.phase === "Running"} data-testid="kms-test">
                    {test?.phase === "Running" ? "Testing…" : test ? "Test again" : "Test settings"}
                  </button>
                )}
                {test?.phase === "Passed" && (
                  <button className="primary" onClick={apply} data-testid="kms-apply">
                    Apply
                  </button>
                )}
              </div>
              {test?.phase === "Passed" && (
                <p className="muted" data-testid="kms-apply-note">
                  {cfg.status?.activated
                    ? "Applying restarts the KES servers with these settings, one at a time. Storage servers keep running."
                    : "Applying starts the KES servers, then restarts the storage servers one at a time to use them. Buckets stays available throughout."}
                </p>
              )}
            </>
          )}
          {applied && <Rollout cfg={cfg} keyName={keyName} onDone={() => navigate("/encryption")} />}
        </div>
      )}
    </div>
  );
}

// ---- the forms ------------------------------------------------------------------

function Field({ label, help, children }: { label: string; help?: ReactNode; children: ReactNode }) {
  return (
    <label>
      <span className="field-label">{label}</span>
      {children}
      {help && <span className="field-help">{help}</span>}
    </label>
  );
}

function Secret({ value, field, saved, onChange, testId, placeholder }: { value?: string; field: string; saved: Set<string>; onChange: (v: string) => void; testId: string; placeholder?: string }) {
  return (
    <input
      type="password"
      autoComplete="new-password"
      value={value ?? ""}
      placeholder={saved.has(field) ? "•••••••• saved — leave empty to keep" : placeholder}
      onChange={(e) => onChange(e.target.value)}
      data-testid={testId}
    />
  );
}

function Segmented<T extends string>({ value, options, onChange, testId }: { value: T; options: [T, string][]; onChange: (v: T) => void; testId: string }) {
  return (
    <div className="segmented" role="radiogroup" data-testid={testId}>
      {options.map(([v, label]) => (
        <button key={v} role="radio" aria-checked={value === v} className={value === v ? "selected" : ""} onClick={() => onChange(v)} data-testid={`${testId}-${v}`}>
          {label}
        </button>
      ))}
    </div>
  );
}

function FileText({ onText, accept, label }: { onText: (t: string) => void; accept: string; label: string }) {
  return (
    <span className="file-text">
      <span className="muted">or</span>
      <label className="button">
        {label}
        <input
          type="file"
          accept={accept}
          hidden
          onChange={async (e) => {
            const f = e.target.files?.[0];
            if (f) onText(await f.text());
            e.target.value = "";
          }}
        />
      </label>
    </span>
  );
}

function Guide({ title, children }: { title: string; children: ReactNode }) {
  return (
    <details className="guide">
      <summary>{title}</summary>
      {children}
    </details>
  );
}

function Copyable({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="copyable">
      <pre>{text}</pre>
      <button
        className="link"
        onClick={() => {
          navigator.clipboard?.writeText(text).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          });
        }}
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

function VaultForm({ v, saved, cfg, onChange }: { v: VaultSettings; saved: Set<string>; cfg: KmsConfig; onChange: (v: VaultSettings) => void }) {
  const set = (p: Partial<VaultSettings>) => onChange({ ...v, ...p });
  const engine = v.engine || "kv";
  const prefix = (v.prefix || "").replace(/^\/+|\/+$/g, "");
  const sub = prefix ? `${prefix}/*` : "*";
  const policy =
    v.version === "v1"
      ? `path "${engine}/${sub}" {\n  capabilities = ["create", "read", "delete", "list"]\n}`
      : `path "${engine}/data/${sub}" {\n  capabilities = ["create", "read", "delete"]\n}\npath "${engine}/metadata/${sub}" {\n  capabilities = ["list", "delete"]\n}`;
  const transit = v.transit?.key ? `\npath "${v.transit.engine || "transit"}/encrypt/${v.transit.key}" {\n  capabilities = ["update"]\n}\npath "${v.transit.engine || "transit"}/decrypt/${v.transit.key}" {\n  capabilities = ["update"]\n}` : "";
  const authCmds =
    v.auth === "approle"
      ? `vault auth enable ${v.approle?.engine || "approle"}   # once\nvault write auth/${v.approle?.engine || "approle"}/role/buckets-kes token_policies=buckets-kes token_ttl=1h token_max_ttl=24h\nvault read auth/${v.approle?.engine || "approle"}/role/buckets-kes/role-id\nvault write -f auth/${v.approle?.engine || "approle"}/role/buckets-kes/secret-id`
      : `vault auth enable ${v.kubernetes?.engine || "kubernetes"}   # once, then: vault write auth/${v.kubernetes?.engine || "kubernetes"}/config kubernetes_host=https://<this cluster's API server>\nvault write auth/${v.kubernetes?.engine || "kubernetes"}/role/${v.kubernetes?.role || "buckets-kes"} \\\n  bound_service_account_names=${cfg.kesServiceAccount} \\\n  bound_service_account_namespaces=${cfg.namespace} \\\n  token_policies=buckets-kes token_ttl=1h`;
  const script = `vault secrets enable -path=${engine} -version=${v.version === "v1" ? 1 : 2} kv   # once\nvault policy write buckets-kes - <<'EOF'\n${policy}${transit}\nEOF\n${authCmds}`;
  return (
    <>
      <Guide title="Before you start: a policy and a role for KES in Vault">
        <p className="muted">Run these as a Vault administrator. They follow the settings above.</p>
        <Copyable text={script} />
      </Guide>
      <Field label="Vault address" help="The URL KES reaches Vault at, from inside the cluster.">
        <input value={v.endpoint} placeholder="https://vault.example.com:8200" onChange={(e) => set({ endpoint: e.target.value.trim() })} data-testid="vault-endpoint" />
      </Field>
      <Field label="Sign in with">
        <Segmented
          value={v.auth}
          options={[
            ["approle", "AppRole"],
            ["kubernetes", "Kubernetes service account"],
          ]}
          onChange={(auth) => set({ auth })}
          testId="vault-auth"
        />
      </Field>
      {v.auth === "approle" ? (
        <div className="field-row">
          <Field label="Role ID">
            <input value={v.approle?.id ?? ""} onChange={(e) => set({ approle: { ...v.approle!, id: e.target.value.trim() } })} data-testid="vault-role-id" />
          </Field>
          <Field label="Secret ID">
            <Secret value={v.approle?.secret} field="vault.approle.secret" saved={saved} onChange={(secret) => set({ approle: { ...v.approle!, id: v.approle?.id ?? "", secret } })} testId="vault-secret-id" />
          </Field>
        </div>
      ) : (
        <Field
          label="Vault role"
          help={
            <>
              KES signs in as service account <span className="mono">{cfg.namespace}/{cfg.kesServiceAccount}</span>; bind this role of Vault's Kubernetes auth method to it.
            </>
          }
        >
          <input value={v.kubernetes?.role ?? ""} placeholder="buckets-kes" onChange={(e) => set({ kubernetes: { ...v.kubernetes, role: e.target.value.trim() } })} data-testid="vault-k8s-role" />
        </Field>
      )}
      <div className="field-row">
        <Field label="KV engine path">
          <input value={v.engine ?? ""} placeholder="kv" onChange={(e) => set({ engine: e.target.value.trim() })} data-testid="vault-engine" />
        </Field>
        <Field label="KV version">
          <select value={v.version ?? "v2"} onChange={(e) => set({ version: e.target.value as "v1" | "v2" })} data-testid="vault-version">
            <option value="v2">2</option>
            <option value="v1">1</option>
          </select>
        </Field>
        <Field label="Key prefix" help="Keys are kept under engine/prefix/name. Give each cluster its own prefix.">
          <input value={v.prefix ?? ""} onChange={(e) => set({ prefix: e.target.value.trim() })} data-testid="vault-prefix" />
        </Field>
      </div>
      <details className="advanced">
        <summary>Advanced</summary>
        <div className="field-row">
          <Field label="Namespace" help="Vault Enterprise only.">
            <input value={v.namespace ?? ""} onChange={(e) => set({ namespace: e.target.value.trim() })} />
          </Field>
          <Field label={v.auth === "approle" ? "AppRole mount path" : "Kubernetes mount path"}>
            {v.auth === "approle" ? (
              <input value={v.approle?.engine ?? ""} placeholder="approle" onChange={(e) => set({ approle: { ...v.approle!, engine: e.target.value.trim() } })} />
            ) : (
              <input value={v.kubernetes?.engine ?? ""} placeholder="kubernetes" onChange={(e) => set({ kubernetes: { ...v.kubernetes!, engine: e.target.value.trim() } })} />
            )}
          </Field>
        </div>
        <div className="field-row">
          <Field label="Transit key" help="Wraps every stored key with this Transit key as well.">
            <input value={v.transit?.key ?? ""} onChange={(e) => set({ transit: { engine: v.transit?.engine, key: e.target.value.trim() } })} />
          </Field>
          <Field label="Transit mount path">
            <input value={v.transit?.engine ?? ""} placeholder="transit" onChange={(e) => set({ transit: { key: v.transit?.key ?? "", engine: e.target.value.trim() } })} />
          </Field>
        </div>
        <Field label="CA certificate" help="Needed when Vault's certificate is not from a public certificate authority.">
          <textarea rows={4} value={v.caCert ?? ""} placeholder="-----BEGIN CERTIFICATE-----" onChange={(e) => set({ caCert: e.target.value })} data-testid="vault-ca" />
          <FileText accept=".pem,.crt,.cer" label="Upload a PEM file" onText={(caCert) => set({ caCert })} />
        </Field>
      </details>
    </>
  );
}

function AwsForm({ a, saved, keys, setKeys, onChange }: { a: AwsSettings; saved: Set<string>; keys: boolean; setKeys: (k: boolean) => void; onChange: (a: AwsSettings) => void }) {
  const set = (p: Partial<AwsSettings>) => onChange({ ...a, ...p });
  const policy = JSON.stringify(
    {
      Version: "2012-10-17",
      Statement: [
        { Effect: "Allow", Action: ["secretsmanager:CreateSecret", "secretsmanager:DeleteSecret", "secretsmanager:GetSecretValue", "secretsmanager:ListSecrets"], Resource: "*" },
        { Effect: "Allow", Action: ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt"], Resource: a.kmsKey ? a.kmsKey : "*" },
      ],
    },
    null,
    2,
  );
  return (
    <>
      <div className="field-row">
        <Field label="Region">
          <input list="aws-regions" value={a.region} placeholder="us-east-1" onChange={(e) => set({ region: e.target.value.trim() })} data-testid="aws-region" />
          <datalist id="aws-regions">
            {AWS_REGIONS.map((r) => (
              <option key={r} value={r} />
            ))}
          </datalist>
        </Field>
        <Field label="KMS key" help="Encrypts the secrets KES stores. Empty: Secrets Manager's own key, aws/secretsmanager.">
          <input value={a.kmsKey ?? ""} placeholder="alias/buckets-kes" onChange={(e) => set({ kmsKey: e.target.value.trim() })} />
        </Field>
      </div>
      <Field label="Sign in with">
        <Segmented
          value={keys ? "keys" : "role"}
          options={[
            ["keys", "An access key"],
            ["role", "The pods' IAM role"],
          ]}
          onChange={(v) => setKeys(v === "keys")}
          testId="aws-auth"
        />
      </Field>
      {keys ? (
        <div className="field-row">
          <Field label="Access key ID">
            <input value={a.accessKey ?? ""} onChange={(e) => set({ accessKey: e.target.value.trim() })} data-testid="aws-access-key" />
          </Field>
          <Field label="Secret access key">
            <Secret value={a.secretKey} field="aws.secretKey" saved={saved} onChange={(secretKey) => set({ secretKey })} testId="aws-secret-key" />
          </Field>
        </div>
      ) : (
        <p className="muted">KES uses the AWS SDK's own credentials: an IAM role for its service account (IRSA), or the node's instance profile.</p>
      )}
      <details className="advanced">
        <summary>Advanced</summary>
        <div className="field-row">
          <Field label="Endpoint" help={`Default: secretsmanager.${a.region || "<region>"}.amazonaws.com`}>
            <input value={a.endpoint ?? ""} onChange={(e) => set({ endpoint: e.target.value.trim() })} />
          </Field>
          {keys && (
            <Field label="Session token" help="Only for temporary credentials.">
              <Secret value={a.sessionToken} field="aws.sessionToken" saved={saved} onChange={(sessionToken) => set({ sessionToken })} testId="aws-session-token" />
            </Field>
          )}
        </div>
      </details>
      <Guide title="Prepare AWS: what the IAM identity may do">
        <p className="muted">Attach this policy to the user or role KES signs in as.</p>
        <Copyable text={policy} />
      </Guide>
    </>
  );
}

function AzureForm({ a, saved, onChange }: { a: AzureSettings; saved: Set<string>; onChange: (a: AzureSettings) => void }) {
  const set = (p: Partial<AzureSettings>) => onChange({ ...a, ...p });
  return (
    <>
      <Field label="Key Vault URL">
        <input value={a.endpoint} placeholder="https://my-vault.vault.azure.net" onChange={(e) => set({ endpoint: e.target.value.trim() })} data-testid="azure-endpoint" />
      </Field>
      <Field label="Sign in with">
        <Segmented
          value={a.auth}
          options={[
            ["secret", "A client secret"],
            ["managedIdentity", "A managed identity"],
          ]}
          onChange={(auth) => set({ auth })}
          testId="azure-auth"
        />
      </Field>
      {a.auth === "secret" ? (
        <>
          <div className="field-row">
            <Field label="Directory (tenant) ID">
              <input value={a.tenantId ?? ""} onChange={(e) => set({ tenantId: e.target.value.trim() })} data-testid="azure-tenant" />
            </Field>
            <Field label="Application (client) ID">
              <input value={a.clientId ?? ""} onChange={(e) => set({ clientId: e.target.value.trim() })} data-testid="azure-client" />
            </Field>
          </div>
          <Field label="Client secret">
            <Secret value={a.clientSecret} field="azure.clientSecret" saved={saved} onChange={(clientSecret) => set({ clientSecret })} testId="azure-secret" />
          </Field>
        </>
      ) : (
        <Field label="Managed identity client ID" help="The user-assigned identity the KES pods run as.">
          <input value={a.managedIdentityClientId ?? ""} onChange={(e) => set({ managedIdentityClientId: e.target.value.trim() })} data-testid="azure-mi" />
        </Field>
      )}
      <Guide title="Prepare Azure: access to the Key Vault">
        <p className="muted">
          Give the application or identity the <strong>Key Vault Secrets Officer</strong> role on the vault (with Azure RBAC), or an access policy allowing Get, List,
          Set, Delete, Recover and Purge on secrets.
        </p>
      </Guide>
    </>
  );
}

function GcpForm({ g, saved, onChange }: { g: GcpSettings; saved: Set<string>; onChange: (g: GcpSettings) => void }) {
  const set = (p: Partial<GcpSettings>) => onChange({ ...g, ...p });
  let who = "";
  let bad = false;
  if (g.credentials) {
    try {
      const j = JSON.parse(g.credentials);
      who = j.client_email ?? "";
      bad = !j.private_key || !who;
    } catch {
      bad = true;
    }
  }
  const setCreds = (credentials: string) => {
    let projectId = g.projectId;
    try {
      projectId = projectId || JSON.parse(credentials).project_id;
    } catch {
      /* shown below */
    }
    set({ credentials, projectId });
  };
  return (
    <>
      <Field label="Service account key (JSON)" help={saved.has("gcp.credentials") && !g.credentials ? "A key is saved; paste or upload another to replace it." : undefined}>
        <textarea rows={5} value={g.credentials} placeholder='{"type": "service_account", ...}' onChange={(e) => setCreds(e.target.value)} data-testid="gcp-credentials" />
        <FileText accept=".json,application/json" label="Upload the JSON key" onText={setCreds} />
      </Field>
      {who && !bad && (
        <p className="muted" data-testid="gcp-who">
          KES signs in as <span className="mono">{who}</span>.
        </p>
      )}
      {bad && <p className="bad">This is not a service account's JSON key: download one from the Google Cloud console (IAM › Service accounts › Keys › Add key › JSON).</p>}
      <Field label="Project ID" help="Taken from the key; change it to keep keys in another project.">
        <input value={g.projectId ?? ""} onChange={(e) => set({ projectId: e.target.value.trim() })} data-testid="gcp-project" />
      </Field>
      <Guide title="Prepare Google Cloud: what the service account may do">
        <p className="muted">
          Enable the Secret Manager API in the project and give the service account the <strong>Secret Manager Admin</strong> role (
          <span className="mono">roles/secretmanager.admin</span>) there.
        </p>
      </Guide>
    </>
  );
}

// ---- review, test, rollout ------------------------------------------------------------

// What a key store's error most likely means, for the usual mistakes.
export function hintFor(message: string): string | null {
  const m = message.toLowerCase();
  if (m.includes("no such host")) return "Nothing by that host name can be found from the cluster: check the address.";
  if (m.includes("connection refused")) return "Nothing answers at that address and port: check the port, and that the key store is running.";
  if (m.includes("i/o timeout") || m.includes("deadline exceeded")) return "The key store did not answer in time: a firewall or network policy may block the cluster from reaching it.";
  if (m.includes("invalid role or secret id")) return "Vault does not accept this role ID and secret ID: check them, and that the secret ID has not expired or been used up.";
  if (m.includes("permission denied") || m.includes("accessdenied") || m.includes("forbidden") || m.includes("unauthorized"))
    return "The key store refused: the identity KES signs in as may not read and write keys there. See the preparation steps on the Connection page.";
  if (m.includes("x509") || m.includes("certificate")) return "The key store's TLS certificate is not trusted: add its CA certificate on the Connection page.";
  if (m.includes("cannot be pulled")) return "The cluster cannot download the KES image: set the operator's BUCKETS_KES_IMAGE to a registry it can reach.";
  if (m.includes("not in this key store") || m.includes("lacks keys")) return null;
  return null;
}



function Review({ settings, keyName, createKey, awsKeys }: { settings: KmsSettings; keyName: string; createKey: boolean; awsKeys: boolean }) {
  const rows: [string, string][] = [["Key store", BACKENDS.find((b) => b.id === settings.backend)?.title ?? settings.backend]];
  const v = settings.vault,
    a = settings.aws,
    z = settings.azure,
    g = settings.gcp;
  if (settings.backend === "vault" && v) {
    rows.push(["Address", v.endpoint], ["Sign-in", v.auth === "approle" ? `AppRole ${v.approle?.id}` : `Kubernetes role ${v.kubernetes?.role}`]);
    rows.push(["Keys at", `${v.engine || "kv"} (KV ${v.version === "v1" ? 1 : 2}) / ${v.prefix || "(no prefix)"}`]);
    if (v.transit?.key) rows.push(["Transit key", v.transit.key]);
  }
  if (settings.backend === "aws" && a) rows.push(["Region", a.region], ["Sign-in", awsKeys ? `access key ${a.accessKey ?? ""}` : "the pods' IAM role"], ["KMS key", a.kmsKey || "aws/secretsmanager"]);
  if (settings.backend === "azure" && z) rows.push(["Key Vault", z.endpoint], ["Sign-in", z.auth === "secret" ? `client ${z.clientId}` : `managed identity ${z.managedIdentityClientId}`]);
  if (settings.backend === "gcp" && g) rows.push(["Project", g.projectId ?? ""]);
  rows.push(["Default key", `${keyName}${createKey ? " (created if missing)" : ""}`]);
  return (
    <table className="kv" data-testid="kms-review">
      <tbody>
        {rows.map(([k, val]) => (
          <tr key={k}>
            <th>{k}</th>
            <td className={k === "Address" || k === "Key Vault" ? "mono" : undefined}>{val}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function TestResult({ test }: { test: KmsTest }) {
  const steps = test.steps ?? [];
  return (
    <div className={`test-result ${test.phase.toLowerCase()}`} data-testid="kms-test-result">
      <ul className="checks">
        {steps.length === 0 && (
          <li className="running">
            <span className="mark" /> Starting the test…
          </li>
        )}
        {steps.map((s) => (
          <li key={s.name} className={s.status}>
            <span className="mark">{s.status === "ok" ? "✓" : s.status === "failed" ? "✗" : ""}</span>
            <span>
              {s.name}
              {s.message && s.status === "ok" && <span className="muted"> — {s.message}</span>}
              {s.message && s.status === "failed" && <div className="bad step-why">{s.message}</div>}
              {s.message && s.status === "failed" && hintFor(s.message) && (
                <div className="step-hint" data-testid="kms-hint">
                  {hintFor(s.message)}
                </div>
              )}
            </span>
          </li>
        ))}
      </ul>
      {test.phase === "Passed" && <div className="banner ok">The settings work.</div>}
      {test.phase === "Failed" && !steps.some((s) => s.status === "failed") && test.message && <div className="banner error">{test.message}</div>}
    </div>
  );
}

function Rollout({ cfg, keyName, onDone }: { cfg: KmsConfig; keyName: string; onDone: () => void }) {
  const st = cfg.status ?? {};
  const [serving, setServing] = useState(false);
  const ready = st.phase === "Ready" && st.keyName === keyName;
  useEffect(() => {
    if (!ready) return;
    let live = true;
    const t = setInterval(() => {
      kmsStatus()
        .then((s) => live && setServing(s.name.includes("KES") && s["default-key-id"] === keyName))
        .catch(() => undefined);
    }, 2000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [ready, keyName]);
  const done = ready && serving;
  return (
    <div data-testid="kms-rollout">
      <ul className="checks">
        <li className="ok">
          <span className="mark">✓</span> Settings saved
        </li>
        <li className={ready ? "ok" : st.phase === "Error" ? "failed" : "running"}>
          <span className="mark">{ready ? "✓" : st.phase === "Error" ? "✗" : ""}</span>
          <span>
            KES servers {st.readyReplicas ?? 0} of {st.replicas ?? "?"} ready, key {keyName}
            {st.message && !ready && <div className={st.phase === "Error" ? "bad step-why" : "muted"}>{st.message}</div>}
          </span>
        </li>
        <li className={done ? "ok" : ready ? "running" : ""}>
          <span className="mark">{done ? "✓" : ""}</span> Storage servers using KES
        </li>
      </ul>
      {done ? (
        <div className="banner ok" data-testid="kms-done">
          Encryption is ready. Turn on default encryption for buckets in their settings, or encrypt existing objects from there.
        </div>
      ) : (
        <p className="muted">This takes a minute or two. You can leave this page; the change carries on.</p>
      )}
      <div className="form-actions">
        <button className={done ? "primary" : ""} onClick={onDone} data-testid="kms-finish">
          {done ? "Done" : "Back to Encryption"}
        </button>
      </div>
    </div>
  );
}
