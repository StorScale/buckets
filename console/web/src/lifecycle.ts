// A bucket's lifecycle rules as the editor shows them (docs/design/lifecycle-replication-editor.md): S3's and
// MinIO's lifecycle XML to rules and back, each rule in words, the warnings before saving, and the rules as a
// Bucket resource's lifecycle block. A configuration with anything the form doesn't know stays in XML, so saving
// the form never drops it.

export type LcTag = { key: string; value: string };

export type LcRule = {
  id: string;
  enabled: boolean;
  // which objects
  prefix: string;
  tags: LcTag[];
  sizeGt?: number;
  sizeLt?: number;
  // the current version
  expireDays?: number;
  expireDate?: string; // YYYY-MM-DD
  transitionDays?: number;
  transitionDate?: string;
  transitionTier?: string;
  // old versions
  noncurrentDays?: number;
  keepNewer?: number;
  noncurrentTransitionDays?: number;
  noncurrentTier?: string;
  // clean-up
  expiredDeleteMarker?: boolean;
  delMarkerDays?: number;
  abortDays?: number;
  allVersions?: boolean; // ExpiredObjectAllVersions: with the expiry, every version goes
};

export type LcParsed = { rules: LcRule[]; unknown: string[] };

const KNOWN_RULE = new Set([
  "ID",
  "Status",
  "Filter",
  "Prefix",
  "Expiration",
  "Transition",
  "NoncurrentVersionExpiration",
  "NoncurrentVersionTransition",
  "DelMarkerExpiration",
  "AbortIncompleteMultipartUpload",
]);

// what the form keeps inside each element it knows; anything else stays in XML
const KNOWN_IN: Record<string, Set<string>> = {
  Filter: new Set(["Prefix", "And", "Tag", "ObjectSizeGreaterThan", "ObjectSizeLessThan"]),
  And: new Set(["Prefix", "Tag", "ObjectSizeGreaterThan", "ObjectSizeLessThan"]),
  Tag: new Set(["Key", "Value"]),
  Expiration: new Set(["Days", "Date", "ExpiredObjectDeleteMarker", "ExpiredObjectAllVersions"]),
  Transition: new Set(["Days", "Date", "StorageClass"]),
  NoncurrentVersionExpiration: new Set(["NoncurrentDays", "NewerNoncurrentVersions"]),
  NoncurrentVersionTransition: new Set(["NoncurrentDays", "StorageClass"]),
  DelMarkerExpiration: new Set(["Days"]),
  AbortIncompleteMultipartUpload: new Set(["DaysAfterInitiation"]),
};

const kids = (e: Element, name?: string) => Array.from(e.children).filter((c) => !name || c.localName === name);
const kid = (e: Element | undefined, name: string) => (e ? kids(e, name)[0] : undefined);
const text = (e: Element | undefined, name: string) => kid(e, name)?.textContent?.trim() ?? "";
const num = (e: Element | undefined, name: string) => {
  const t = text(e, name);
  return t ? Number(t) : undefined;
};

export function emptyRule(id = ""): LcRule {
  return { id, enabled: true, prefix: "", tags: [] };
}

export function parseLifecycle(xml: string | null): LcParsed {
  if (!xml || !xml.trim()) return { rules: [], unknown: [] };
  const doc = new DOMParser().parseFromString(xml, "application/xml");
  const root = doc.documentElement;
  if (!root || root.localName !== "LifecycleConfiguration") return { rules: [], unknown: ["the configuration"] };
  const unknown: string[] = [];
  const rules: LcRule[] = [];
  for (const c of kids(root)) {
    if (c.localName === "ExpiryUpdatedAt") continue;
    if (c.localName !== "Rule") {
      unknown.push(c.localName);
      continue;
    }
    const r = emptyRule(text(c, "ID"));
    r.enabled = text(c, "Status") === "Enabled";
    const check = (e: Element, path: string) => {
      const known = KNOWN_IN[e.localName];
      if (!known) return;
      for (const k of kids(e)) {
        if (!known.has(k.localName)) unknown.push(`${path}/${k.localName} (rule ${r.id})`);
        else check(k, `${path}/${k.localName}`);
      }
    };
    for (const k of kids(c)) {
      if (!KNOWN_RULE.has(k.localName)) unknown.push(`${k.localName} (rule ${r.id})`);
      else check(k, k.localName);
    }
    r.prefix = text(c, "Prefix");
    const f = kid(c, "Filter");
    if (f) {
      const and = kid(f, "And");
      const src = and ?? f;
      if (text(src, "Prefix")) r.prefix = text(src, "Prefix");
      r.sizeGt = num(src, "ObjectSizeGreaterThan");
      r.sizeLt = num(src, "ObjectSizeLessThan");
      r.tags = kids(src, "Tag").map((t) => ({ key: text(t, "Key"), value: text(t, "Value") }));
    }
    const ex = kid(c, "Expiration");
    if (ex) {
      r.expireDays = num(ex, "Days");
      r.expireDate = text(ex, "Date").slice(0, 10) || undefined;
      r.expiredDeleteMarker = text(ex, "ExpiredObjectDeleteMarker") === "true" || undefined;
      r.allVersions = text(ex, "ExpiredObjectAllVersions") === "true" || undefined;
    }
    const tr = kid(c, "Transition");
    if (tr) {
      r.transitionDays = num(tr, "Days") ?? (text(tr, "Date") ? undefined : 0);
      r.transitionDate = text(tr, "Date").slice(0, 10) || undefined;
      r.transitionTier = text(tr, "StorageClass");
    }
    const nve = kid(c, "NoncurrentVersionExpiration");
    if (nve) {
      r.noncurrentDays = num(nve, "NoncurrentDays");
      r.keepNewer = num(nve, "NewerNoncurrentVersions");
    }
    const nvt = kid(c, "NoncurrentVersionTransition");
    if (nvt) {
      r.noncurrentTransitionDays = num(nvt, "NoncurrentDays") ?? 0;
      r.noncurrentTier = text(nvt, "StorageClass");
    }
    r.delMarkerDays = num(kid(c, "DelMarkerExpiration"), "Days");
    r.abortDays = num(kid(c, "AbortIncompleteMultipartUpload"), "DaysAfterInitiation");
    rules.push(r);
  }
  return { rules, unknown };
}

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const el = (name: string, inner: string) => `<${name}>${inner}</${name}>`;
const has = (n: number | undefined) => n !== undefined && !Number.isNaN(n);

export function lifecycleXml(rules: LcRule[]): string {
  const out = rules.map((r) => {
    let x = el("ID", esc(r.id)) + el("Status", r.enabled ? "Enabled" : "Disabled");
    const parts: string[] = [];
    if (r.prefix) parts.push(el("Prefix", esc(r.prefix)));
    if (has(r.sizeGt)) parts.push(el("ObjectSizeGreaterThan", String(r.sizeGt)));
    if (has(r.sizeLt)) parts.push(el("ObjectSizeLessThan", String(r.sizeLt)));
    for (const t of r.tags) parts.push(el("Tag", el("Key", esc(t.key)) + el("Value", esc(t.value))));
    x += el("Filter", parts.length > 1 ? el("And", parts.join("")) : parts.join(""));
    if (has(r.expireDays) || r.expireDate || r.expiredDeleteMarker) {
      let e = "";
      if (has(r.expireDays)) e += el("Days", String(r.expireDays));
      else if (r.expireDate) e += el("Date", `${r.expireDate}T00:00:00Z`);
      if (r.expiredDeleteMarker && !has(r.expireDays) && !r.expireDate) e += el("ExpiredObjectDeleteMarker", "true");
      if (r.allVersions && has(r.expireDays)) e += el("ExpiredObjectAllVersions", "true"); // with Days only
      x += el("Expiration", e);
    }
    if (r.transitionTier && (has(r.transitionDays) || r.transitionDate))
      x += el(
        "Transition",
        (r.transitionDate ? el("Date", `${r.transitionDate}T00:00:00Z`) : el("Days", String(r.transitionDays))) +
          el("StorageClass", esc(r.transitionTier)),
      );
    if (has(r.delMarkerDays)) x += el("DelMarkerExpiration", el("Days", String(r.delMarkerDays)));
    if (has(r.noncurrentDays))
      x += el(
        "NoncurrentVersionExpiration",
        el("NoncurrentDays", String(r.noncurrentDays)) + (r.keepNewer ? el("NewerNoncurrentVersions", String(r.keepNewer)) : ""),
      );
    if (r.noncurrentTier && has(r.noncurrentTransitionDays))
      x += el(
        "NoncurrentVersionTransition",
        el("NoncurrentDays", String(r.noncurrentTransitionDays)) + el("StorageClass", esc(r.noncurrentTier)),
      );
    if (has(r.abortDays)) x += el("AbortIncompleteMultipartUpload", el("DaysAfterInitiation", String(r.abortDays)));
    return el("Rule", x);
  });
  return el("LifecycleConfiguration", out.join(""));
}

const days = (n: number) => (n === 1 ? "1 day" : `${n} days`);
const sizeWords = (n: number) => {
  for (const [u, f] of [
    ["GiB", 2 ** 30],
    ["MiB", 2 ** 20],
    ["KiB", 2 ** 10],
  ] as const)
    if (n >= f && n % f === 0) return `${n / f} ${u}`;
  return `${n} bytes`;
};

/** Which objects, in words: "Objects under logs/ tagged env=dev, larger than 1 MiB". */
export function scopeWords(r: LcRule): string {
  const bits = [r.prefix ? `Objects under ${r.prefix}` : "All objects"];
  if (r.tags.length) bits.push(`tagged ${r.tags.map((t) => `${t.key}=${t.value}`).join(", ")}`);
  if (has(r.sizeGt)) bits.push(`larger than ${sizeWords(r.sizeGt!)}`);
  if (has(r.sizeLt)) bits.push(`smaller than ${sizeWords(r.sizeLt!)}`);
  return bits.join(", ");
}

/** What the rule does, in words, one phrase per action. */
export function actionWords(r: LcRule): string[] {
  const a: string[] = [];
  if (has(r.expireDays) || r.expireDate) {
    const when = r.expireDate ? `on ${r.expireDate}` : `${days(r.expireDays!)} after they're written`;
    a.push(r.allVersions ? `deleted with all their versions ${when}` : `deleted ${when}`);
  }
  if (r.transitionTier && (has(r.transitionDays) || r.transitionDate))
    a.push(`moved to ${r.transitionTier} ${r.transitionDate ? `on ${r.transitionDate}` : `${days(r.transitionDays!)} after they're written`}`);
  if (has(r.noncurrentDays))
    a.push(`old versions deleted ${days(r.noncurrentDays!)} after they're replaced${r.keepNewer ? `, keeping the newest ${r.keepNewer}` : ""}`);
  if (r.noncurrentTier && has(r.noncurrentTransitionDays))
    a.push(`old versions moved to ${r.noncurrentTier} ${days(r.noncurrentTransitionDays!)} after they're replaced`);
  if (r.expiredDeleteMarker) a.push("delete markers with no versions left removed");
  if (has(r.delMarkerDays)) a.push(`delete markers removed after ${days(r.delMarkerDays!)}`);
  if (has(r.abortDays)) a.push(`incomplete uploads removed after ${days(r.abortDays!)}`);
  return a;
}

export function ruleWords(r: LcRule): string {
  const a = actionWords(r);
  return `${scopeWords(r)}: ${a.length ? a.join("; ") : "nothing"}.`;
}

export type LcWarning = { level: "danger" | "warn" | "info"; text: string };

/** Warnings before saving, for the bucket as it is. */
export function lifecycleWarnings(rules: LcRule[], b: { versioned: boolean; locked: boolean }): LcWarning[] {
  const w: LcWarning[] = [];
  const on = rules.filter((r) => r.enabled);
  if (on.some((r) => has(r.noncurrentDays) || r.allVersions))
    w.push({
      level: "danger",
      text: "This removes the copies that let you recover from an overwrite or ransomware. Saving it opens a ransomware alert (protection removed).",
    });
  if (b.locked) w.push({ level: "info", text: "Versions under retention are kept until their date, whatever these rules say." });
  if (!b.versioned && on.some((r) => has(r.noncurrentDays) || has(r.noncurrentTransitionDays) || r.expiredDeleteMarker || has(r.delMarkerDays)))
    w.push({ level: "warn", text: "Rules for old versions and delete markers do nothing: the bucket doesn't keep versions." });
  if (b.versioned && on.some((r) => (has(r.expireDays) || r.expireDate) && !r.allVersions) && !on.some((r) => has(r.noncurrentDays)))
    w.push({
      level: "info",
      text: "The bucket keeps versions: an expired object gets a delete marker, and its versions stay (and take space) until a rule deletes old versions.",
    });
  for (let i = 0; i < on.length; i++)
    for (let j = i + 1; j < on.length; j++) {
      const a = on[i],
        c = on[j];
      const overlap = a.prefix.startsWith(c.prefix) || c.prefix.startsWith(a.prefix);
      if (overlap && has(a.expireDays) && has(c.expireDays) && a.expireDays !== c.expireDays)
        w.push({ level: "info", text: `Rules ${a.id} and ${c.id} both expire some objects: the shorter time wins.` });
    }
  const ids = new Set<string>();
  for (const r of rules) {
    if (ids.has(r.id)) w.push({ level: "warn", text: `Two rules are called ${r.id}: give each its own ID.` });
    ids.add(r.id);
  }
  return w;
}

/** The rules as a Bucket resource's lifecycle block, and what it can't say. */
export function lifecycleYaml(rules: LcRule[]): { yaml: string; left: string[] } {
  const left: string[] = [];
  const lines = ["lifecycle:"];
  if (!rules.length) lines[0] = "lifecycle: []";
  for (const r of rules) {
    const miss: string[] = [];
    if (!r.enabled) miss.push("turned off");
    if (r.tags.length) miss.push("tags");
    if (has(r.sizeGt) || has(r.sizeLt)) miss.push("object size");
    if (r.expireDate) miss.push("an expiry date");
    if (r.transitionTier || r.noncurrentTier) miss.push("moving to a tier");
    if (r.keepNewer) miss.push("keeping the newest versions");
    if (has(r.delMarkerDays)) miss.push("removing delete markers after days");
    if (r.allVersions) miss.push("deleting all versions");
    if (miss.length) left.push(`${r.id}: ${miss.join(", ")}`);
    lines.push(`  - id: ${JSON.stringify(r.id)}`);
    if (r.prefix) lines.push(`    prefix: ${JSON.stringify(r.prefix)}`);
    if (has(r.expireDays)) lines.push(`    expireDays: ${r.expireDays}`);
    if (has(r.noncurrentDays)) lines.push(`    noncurrentExpireDays: ${r.noncurrentDays}`);
    if (has(r.abortDays)) lines.push(`    abortIncompleteUploadDays: ${r.abortDays}`);
    if (r.expiredDeleteMarker) lines.push(`    expireDeleteMarkers: true`);
  }
  return { yaml: lines.join("\n") + "\n", left };
}

/** A new rule's ID: "rule-1", "rule-2", ... not yet taken. */
export function nextRuleId(rules: LcRule[]): string {
  for (let i = 1; ; i++) if (!rules.some((r) => r.id === `rule-${i}`)) return `rule-${i}`;
}
