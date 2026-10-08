import { ReactNode, useEffect, useState } from "react";
import { bucketDocs, DeclaredBucket, lifecyclePreview, LifecyclePreview, listTiers } from "../api";
import { formatBytes, Modal, Spinner } from "../components";
import {
  emptyRule,
  LcRule,
  lifecycleWarnings,
  lifecycleXml,
  lifecycleYaml,
  nextRuleId,
  parseLifecycle,
  ruleWords,
} from "../lifecycle";

// A bucket's lifecycle rules (docs/design/lifecycle-replication-editor.md): in words, with a form for each rule, a
// preview of what they'd do before saving, warnings, and the XML behind them.

function Field({ label, help, children }: { label: string; help?: ReactNode; children: ReactNode }) {
  return (
    <label>
      <span className="field-label">{label}</span>
      {children}
      {help && <span className="field-help">{help}</span>}
    </label>
  );
}

const ACTION_WORDS: Record<string, string> = {
  expire: "deleted (a delete marker where versions are kept)",
  "delete-version": "old versions deleted",
  transition: "moved to a tier",
  "transition-version": "old versions moved to a tier",
  "delete-all-versions": "deleted with every version",
  "delete-marker-all-versions": "delete markers removed",
};
const WHEN_WORDS = { "next-run": "on the next run", "7d": "within 7 days", "30d": "within 30 days" };

// "" in a number field: unset
const numOrUndef = (s: string) => (s.trim() === "" ? undefined : Number(s));
const str = (n: number | undefined) => (n === undefined ? "" : String(n));

type Props = {
  bucket: string;
  versioned: boolean;
  locked: boolean;
  declared: DeclaredBucket | null;
  onSaved: (text: string) => void;
  onError: (e: unknown) => void;
};

export default function LifecycleSection({ bucket, versioned, locked, declared, onSaved, onError }: Props) {
  const [loaded, setLoaded] = useState(false);
  const [savedXml, setSavedXml] = useState("");
  const [rules, setRules] = useState<LcRule[]>([]);
  const [unknown, setUnknown] = useState<string[]>([]);
  const [xmlMode, setXmlMode] = useState(false);
  const [xml, setXml] = useState("");
  const [dirty, setDirty] = useState(false);
  const [editing, setEditing] = useState<{ rule: LcRule; index: number } | null>(null);
  const [preview, setPreview] = useState<LifecyclePreview | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [tiers, setTiers] = useState<string[]>([]);
  const [yaml, setYaml] = useState<{ yaml: string; left: string[] } | null>(null);
  const readOnly = !!declared?.lifecycle;

  const load = async () => {
    const x = (await bucketDocs.lifecycle.get(bucket)) ?? "";
    const p = parseLifecycle(x);
    setSavedXml(x);
    setRules(p.rules);
    setUnknown(p.unknown);
    setXml(x);
    setXmlMode(p.unknown.length > 0);
    setDirty(false);
    setPreview(null);
  };
  useEffect(() => {
    load()
      .catch(onError)
      .finally(() => setLoaded(true));
    listTiers()
      .then((t) => setTiers(t.map((x) => x.name)))
      .catch(() => setTiers([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bucket]);

  const change = (next: LcRule[]) => {
    setRules(next);
    setDirty(true);
    setPreview(null);
  };
  const draftXml = () => (xmlMode ? xml : rules.length ? lifecycleXml(rules) : "");

  const runPreview = async () => {
    setPreviewing(true);
    try {
      const x = draftXml();
      setPreview(x.trim() ? await lifecyclePreview(bucket, x) : { scanned: 0, complete: true, opensIncident: false, actions: [] });
    } catch (e) {
      onError(e);
    } finally {
      setPreviewing(false);
    }
  };

  const save = async () => {
    try {
      const x = draftXml();
      if (x.trim()) await bucketDocs.lifecycle.put(bucket, x);
      else if (savedXml.trim()) await bucketDocs.lifecycle.del(bucket);
      await load();
      onSaved("Lifecycle saved.");
    } catch (e) {
      onError(e);
    }
  };

  const toForm = () => {
    const p = parseLifecycle(xml);
    if (p.unknown.length) {
      setUnknown(p.unknown);
      return;
    }
    setRules(p.rules);
    setUnknown([]);
    setXmlMode(false);
  };

  if (!loaded) return <Spinner />;
  const warnings = lifecycleWarnings(rules, { versioned, locked });

  return (
    <div data-testid="lifecycle-section">
      {readOnly && (
        <p className="banner warn" data-testid="lifecycle-declared">
          Declared in Kubernetes (Bucket {declared!.resource}): change it there, or the operator will put it back within
          10 minutes.
        </p>
      )}
      {xmlMode ? (
        <>
          {unknown.length > 0 && (
            <p className="muted" data-testid="lifecycle-unknown">
              The form can't show {unknown.join(", ")}, so this configuration is shown as XML.
            </p>
          )}
          <textarea
            rows={10}
            value={xml}
            readOnly={readOnly}
            onChange={(e) => {
              setXml(e.target.value);
              setDirty(true);
              setPreview(null);
            }}
            placeholder="<LifecycleConfiguration>…</LifecycleConfiguration>; empty: no rules"
            data-testid="lifecycle"
          />
          <div className="form-actions">
            <button onClick={toForm} data-testid="lifecycle-form-mode">
              Back to the form
            </button>
          </div>
        </>
      ) : (
        <>
          {rules.length === 0 && <p className="muted">No rules: objects stay until someone deletes them.</p>}
          <ul className="members" data-testid="lifecycle-rules">
            {rules.map((r, i) => (
              <li key={i} className="team-level" data-testid={`lc-rule-${r.id}`}>
                <div>
                  <strong className="mono">{r.id}</strong> {!r.enabled && <span className="pill warn">off</span>}
                </div>
                <div>{ruleWords(r)}</div>
                {!readOnly && (
                  <div className="actions">
                    <button onClick={() => setEditing({ rule: { ...r, tags: [...r.tags] }, index: i })} data-testid={`lc-edit-${r.id}`}>
                      Edit
                    </button>
                    <button onClick={() => change(rules.map((x, j) => (j === i ? { ...x, enabled: !x.enabled } : x)))}>
                      {r.enabled ? "Turn off" : "Turn on"}
                    </button>
                    <button onClick={() => change(rules.filter((_, j) => j !== i))} data-testid={`lc-remove-${r.id}`}>
                      Remove
                    </button>
                  </div>
                )}
              </li>
            ))}
          </ul>
          <div className="form-actions">
            {!readOnly && (
              <button onClick={() => setEditing({ rule: emptyRule(nextRuleId(rules)), index: -1 })} data-testid="lc-add">
                Add rule
              </button>
            )}
            <button
              onClick={() => {
                setXml(rules.length ? lifecycleXml(rules) : "");
                setXmlMode(true);
              }}
              data-testid="lifecycle-xml-mode"
            >
              {readOnly ? "Show XML" : "Edit as XML"}
            </button>
            <button onClick={() => setYaml(lifecycleYaml(rules))} data-testid="lifecycle-yaml">
              Copy as YAML
            </button>
          </div>
        </>
      )}

      {!readOnly && (dirty || xmlMode) && (
        <>
          {!xmlMode &&
            warnings.map((w, i) => (
              <p key={i} className={`banner ${w.level === "danger" ? "error" : w.level === "warn" ? "warn" : "ok"}`} data-testid={`lc-warning-${w.level}`}>
                {w.text}
              </p>
            ))}
          <div className="form-actions">
            <button onClick={runPreview} disabled={previewing} data-testid="lifecycle-preview">
              {previewing ? "Looking…" : "Preview"}
            </button>
            <button className="primary" onClick={save} data-testid="save-lifecycle">
              Save lifecycle
            </button>
            {dirty && (
              <button onClick={() => load().catch(onError)} data-testid="lifecycle-discard">
                Discard changes
              </button>
            )}
          </div>
        </>
      )}

      {preview && (
        <div className="subsection" data-testid="lifecycle-preview-result">
          <h3>What these rules would do</h3>
          {preview.opensIncident && (
            <p className="banner error">Saving opens a ransomware alert: a rule now deletes versions for good.</p>
          )}
          {preview.actions.length === 0 ? (
            <p className="muted">Nothing, among the {preview.scanned.toLocaleString()} versions there are now.</p>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>What</th>
                  <th>When</th>
                  <th>Versions</th>
                  <th>Size</th>
                  <th>For example</th>
                </tr>
              </thead>
              <tbody>
                {preview.actions.map((a, i) => (
                  <tr key={i} data-testid={`lc-preview-${a.rule}-${a.when}`}>
                    <td className="mono">{a.rule}</td>
                    <td>{ACTION_WORDS[a.action] ?? a.action}</td>
                    <td>{WHEN_WORDS[a.when]}</td>
                    <td>
                      {preview.complete ? "" : "at least "}
                      {a.objects.toLocaleString()}
                    </td>
                    <td>{formatBytes(a.bytes)}</td>
                    <td className="mono muted">{a.examples.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="muted">
            {preview.complete
              ? `Every version looked at (${preview.scanned.toLocaleString()}).`
              : `Stopped after ${preview.scanned.toLocaleString()} versions: the counts are at least these.`}{" "}
            Versions under retention or legal hold are kept whatever the rules say.
          </p>
        </div>
      )}

      {editing && (
        <RuleForm
          rule={editing.rule}
          tiers={tiers}
          versioned={versioned}
          taken={rules.filter((_, j) => j !== editing.index).map((r) => r.id)}
          onClose={() => setEditing(null)}
          onDone={(r) => {
            change(editing.index < 0 ? [...rules, r] : rules.map((x, j) => (j === editing.index ? r : x)));
            setEditing(null);
          }}
        />
      )}

      {yaml && (
        <Modal title="As a Bucket resource" onClose={() => setYaml(null)}>
          <p className="muted">The spec's lifecycle block, for a Bucket resource kept in Git.</p>
          <pre className="mono" data-testid="lifecycle-yaml-text">
            {yaml.yaml}
          </pre>
          <button onClick={() => navigator.clipboard?.writeText(yaml.yaml)} data-testid="lifecycle-yaml-copy">
            Copy
          </button>
          {yaml.left.length > 0 && (
            <p className="banner warn" data-testid="lifecycle-yaml-left">
              A Bucket resource can't say: {yaml.left.join("; ")}.
            </p>
          )}
        </Modal>
      )}
    </div>
  );
}

function RuleForm({
  rule,
  tiers,
  versioned,
  taken,
  onClose,
  onDone,
}: {
  rule: LcRule;
  tiers: string[];
  versioned: boolean;
  taken: string[];
  onClose: () => void;
  onDone: (r: LcRule) => void;
}) {
  const [r, setR] = useState<LcRule>(rule);
  const [expireBy, setExpireBy] = useState<"days" | "date">(rule.expireDate ? "date" : "days");
  const [understood, setUnderstood] = useState(!!rule.allVersions);
  const set = (p: Partial<LcRule>) => setR({ ...r, ...p });
  const problems: string[] = [];
  if (!r.id.trim()) problems.push("Give the rule an ID.");
  if (taken.includes(r.id)) problems.push(`Another rule is called ${r.id}.`);
  if (r.allVersions && !understood) problems.push("Confirm that deleting every version can't be undone.");
  if ((r.transitionDays !== undefined || r.transitionDate) && !r.transitionTier) problems.push("Choose the tier to move objects to.");
  if (r.noncurrentTransitionDays !== undefined && !r.noncurrentTier) problems.push("Choose the tier to move old versions to.");
  if (r.abortDays !== undefined && (r.tags.length || r.sizeGt !== undefined || r.sizeLt !== undefined))
    problems.push("Removing incomplete uploads works by prefix only: no tags or sizes.");
  const nothing =
    r.expireDays === undefined &&
    !r.expireDate &&
    r.transitionDays === undefined &&
    !r.transitionDate &&
    r.noncurrentDays === undefined &&
    r.noncurrentTransitionDays === undefined &&
    !r.expiredDeleteMarker &&
    r.delMarkerDays === undefined &&
    r.abortDays === undefined;
  if (nothing) problems.push("Choose at least one thing for the rule to do.");

  return (
    <Modal title={rule.id ? `Rule ${rule.id}` : "New rule"} onClose={onClose}>
      <div className="field-row">
        <Field label="ID">
          <input value={r.id} onChange={(e) => set({ id: e.target.value.trim() })} data-testid="lc-id" />
        </Field>
        <Field label="Object prefix" help="Empty: the whole bucket.">
          <input value={r.prefix} placeholder="logs/" onChange={(e) => set({ prefix: e.target.value })} data-testid="lc-prefix" />
        </Field>
      </div>
      <details className="advanced">
        <summary>Tags and size</summary>
        {r.tags.map((t, i) => (
          <div className="inline-form" key={i}>
            <input value={t.key} placeholder="key" onChange={(e) => set({ tags: r.tags.map((x, j) => (j === i ? { ...x, key: e.target.value } : x)) })} />
            <input value={t.value} placeholder="value" onChange={(e) => set({ tags: r.tags.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)) })} />
            <button onClick={() => set({ tags: r.tags.filter((_, j) => j !== i) })}>Remove</button>
          </div>
        ))}
        <button onClick={() => set({ tags: [...r.tags, { key: "", value: "" }] })}>Add tag</button>
        <div className="field-row">
          <Field label="Larger than (bytes)">
            <input type="number" min={0} value={str(r.sizeGt)} onChange={(e) => set({ sizeGt: numOrUndef(e.target.value) })} />
          </Field>
          <Field label="Smaller than (bytes)">
            <input type="number" min={1} value={str(r.sizeLt)} onChange={(e) => set({ sizeLt: numOrUndef(e.target.value) })} />
          </Field>
        </div>
      </details>

      <h3>Objects</h3>
      <div className="field-row">
        <Field label="Delete them">
          <select value={expireBy} onChange={(e) => setExpireBy(e.target.value as "days" | "date")}>
            <option value="days">days after they're written</option>
            <option value="date">on a date</option>
          </select>
        </Field>
        {expireBy === "days" ? (
          <Field label="Days" help="Empty: never.">
            <input type="number" min={1} value={str(r.expireDays)} onChange={(e) => set({ expireDays: numOrUndef(e.target.value), expireDate: undefined })} data-testid="lc-expire-days" />
          </Field>
        ) : (
          <Field label="Date">
            <input type="date" value={r.expireDate ?? ""} onChange={(e) => set({ expireDate: e.target.value || undefined, expireDays: undefined })} data-testid="lc-expire-date" />
          </Field>
        )}
      </div>
      {tiers.length > 0 ? (
        <div className="field-row">
          <Field label="Move to a tier after (days)">
            <input type="number" min={0} value={str(r.transitionDays)} onChange={(e) => set({ transitionDays: numOrUndef(e.target.value) })} data-testid="lc-transition-days" />
          </Field>
          <Field label="Tier">
            <select value={r.transitionTier ?? ""} onChange={(e) => set({ transitionTier: e.target.value || undefined })} data-testid="lc-transition-tier">
              <option value="">—</option>
              {tiers.map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
          </Field>
        </div>
      ) : (
        <p className="field-help">
          Moving objects to cheaper storage needs a tier, set up with <code>mc ilm tier add</code>.
        </p>
      )}

      <h3>Old versions{!versioned && <span className="muted"> (the bucket doesn't keep versions)</span>}</h3>
      <div className="field-row">
        <Field label="Delete them after (days)" help="Counted from when a newer version replaced them.">
          <input type="number" min={1} value={str(r.noncurrentDays)} onChange={(e) => set({ noncurrentDays: numOrUndef(e.target.value) })} data-testid="lc-noncurrent-days" />
        </Field>
        <Field label="But keep the newest">
          <input type="number" min={0} value={str(r.keepNewer)} onChange={(e) => set({ keepNewer: numOrUndef(e.target.value) })} data-testid="lc-keep-newer" />
        </Field>
      </div>
      {tiers.length > 0 && (
        <div className="field-row">
          <Field label="Move them to a tier after (days)">
            <input type="number" min={0} value={str(r.noncurrentTransitionDays)} onChange={(e) => set({ noncurrentTransitionDays: numOrUndef(e.target.value) })} />
          </Field>
          <Field label="Tier">
            <select value={r.noncurrentTier ?? ""} onChange={(e) => set({ noncurrentTier: e.target.value || undefined })}>
              <option value="">—</option>
              {tiers.map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
          </Field>
        </div>
      )}

      <h3>Clean-up</h3>
      <label className="checklist">
        <input type="checkbox" checked={!!r.expiredDeleteMarker} onChange={(e) => set({ expiredDeleteMarker: e.target.checked || undefined })} data-testid="lc-expired-markers" />
        Remove delete markers left with no versions behind them
      </label>
      <div className="field-row">
        <Field label="Remove delete markers after (days)">
          <input type="number" min={1} value={str(r.delMarkerDays)} onChange={(e) => set({ delMarkerDays: numOrUndef(e.target.value) })} />
        </Field>
        <Field label="Remove incomplete uploads after (days)" help="Uploads are also removed a day after they start (api stale_uploads_expiry).">
          <input type="number" min={1} value={str(r.abortDays)} onChange={(e) => set({ abortDays: numOrUndef(e.target.value) })} data-testid="lc-abort-days" />
        </Field>
      </div>
      {r.expireDays !== undefined && (
        <label className="checklist">
          <input type="checkbox" checked={!!r.allVersions} onChange={(e) => set({ allVersions: e.target.checked || undefined })} data-testid="lc-all-versions" />
          When an object is deleted, delete every version of it too
        </label>
      )}
      {r.allVersions && (
        <div className="banner error">
          <label className="checklist">
            <input type="checkbox" checked={understood} onChange={(e) => setUnderstood(e.target.checked)} data-testid="lc-all-versions-ok" />
            I understand: the objects and all their versions are gone for good, with nothing to restore from.
          </label>
        </div>
      )}

      {problems.length > 0 && (
        <ul className="field-help" data-testid="lc-problems">
          {problems.map((p) => (
            <li key={p}>{p}</li>
          ))}
        </ul>
      )}
      <div className="form-actions">
        <button className="primary" disabled={problems.length > 0} onClick={() => onDone({ ...r, tags: r.tags.filter((t) => t.key) })} data-testid="lc-done">
          Done
        </button>
        <button onClick={onClose}>Cancel</button>
      </div>
      <p className="muted">{ruleWords(r)}</p>
    </Modal>
  );
}
