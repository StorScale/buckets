// The console's calls to consoled: S3 (XML) and admin (JSON) through the
// BFF's signing proxy, plus login/session.

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message || code || `HTTP ${status}`);
    this.status = status;
    this.code = code;
  }
}

type CallOpts = {
  query?: Record<string, string | undefined>;
  body?: BodyInit | null;
  headers?: Record<string, string>;
  encrypt?: boolean; // madmin-encrypt the body (admin)
  decrypt?: boolean; // decrypt an encrypted admin reply
  signal?: AbortSignal;
};

export const SESSION_EXPIRED = "buckets-session-expired";

function qs(query?: Record<string, string | undefined>): string {
  if (!query) return "";
  const parts: string[] = [];
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined) continue;
    parts.push(v === "" ? encodeURIComponent(k) : `${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
  }
  return parts.length ? `?${parts.join("&")}` : "";
}

async function errorFrom(res: Response): Promise<ApiError> {
  const text = await res.text().catch(() => "");
  let code = "", message = "";
  if (text.startsWith("<") || text.startsWith("<?xml")) {
    const doc = new DOMParser().parseFromString(text, "application/xml");
    code = doc.querySelector("Code")?.textContent ?? "";
    message = doc.querySelector("Message")?.textContent ?? "";
  } else if (text) {
    try {
      const j = JSON.parse(text);
      code = j.Code ?? j.code ?? "";
      message = j.Message ?? j.message ?? "";
    } catch {
      message = text;
    }
  }
  return new ApiError(res.status, code, message);
}

export async function call(method: string, path: string, opts: CallOpts = {}): Promise<Response> {
  const headers: Record<string, string> = { "X-Console-Request": "1", ...(opts.headers ?? {}) };
  if (opts.encrypt) headers["X-Console-Encrypt"] = "1";
  if (opts.decrypt) headers["X-Console-Decrypt"] = "1";
  const res = await fetch(path + qs(opts.query), {
    method,
    headers,
    body: opts.body ?? undefined,
    credentials: "same-origin",
    signal: opts.signal,
  });
  if (!res.ok) {
    const err = await errorFrom(res);
    if (res.status === 401 && err.code === "Unauthorized") window.dispatchEvent(new Event(SESSION_EXPIRED));
    throw err;
  }
  return res;
}

// ---- session ----

export type Session = { accessKey: string; expiresAt: number };

export type LoginMethods = { ldap: boolean; share: boolean; oidc: boolean; oidcName?: string; localUsers: boolean };
export async function loginMethods(): Promise<LoginMethods> {
  return (await call("GET", "/api/v1/login-methods")).json();
}
export async function login(accessKey: string, secretKey: string, method?: "ldap"): Promise<void> {
  await call("POST", "/api/v1/login", {
    body: JSON.stringify({ accessKey, secretKey, method }),
    headers: { "Content-Type": "application/json" },
  });
}
export async function logout(): Promise<void> {
  await call("POST", "/api/v1/logout");
}
export async function session(): Promise<Session> {
  return (await call("GET", "/api/v1/session")).json();
}

// ---- S3 ----

export function encodeKey(key: string): string {
  return key.split("/").map(encodeURIComponent).join("/");
}
export function s3Path(bucket?: string, key?: string): string {
  let p = "/api/v1/s3/";
  if (bucket) p += encodeURIComponent(bucket);
  if (key) p += "/" + encodeKey(key);
  return p;
}

async function xml(res: Response): Promise<Document> {
  return new DOMParser().parseFromString(await res.text(), "application/xml");
}
const txt = (el: Element | Document, sel: string) => el.querySelector(sel)?.textContent ?? "";
const kids = (el: Element | Document, tag: string) => Array.from(el.getElementsByTagName(tag));

export type BucketInfo = { name: string; created: string };
export async function listBuckets(): Promise<BucketInfo[]> {
  const d = await xml(await call("GET", s3Path()));
  return kids(d, "Bucket").map((b) => ({ name: txt(b, "Name"), created: txt(b, "CreationDate") }));
}
export async function makeBucket(name: string, locking: boolean): Promise<void> {
  await call("PUT", s3Path(name), { headers: locking ? { "X-Amz-Bucket-Object-Lock-Enabled": "true" } : {} });
}
export async function deleteBucket(name: string): Promise<void> {
  await call("DELETE", s3Path(name));
}

export type ObjectInfo = { key: string; size: number; lastModified: string; etag: string };
export type Listing = { prefixes: string[]; objects: ObjectInfo[]; next?: string };
export async function listObjects(bucket: string, prefix: string, token?: string): Promise<Listing> {
  const d = await xml(
    await call("GET", s3Path(bucket), {
      query: { "list-type": "2", prefix, delimiter: "/", "max-keys": "1000", "continuation-token": token },
    }),
  );
  return {
    prefixes: kids(d, "CommonPrefixes").map((p) => txt(p, "Prefix")),
    objects: kids(d, "Contents").map((c) => ({
      key: txt(c, "Key"),
      size: Number(txt(c, "Size")),
      lastModified: txt(c, "LastModified"),
      etag: txt(c, "ETag").replace(/"/g, ""),
    })),
    next: txt(d, "IsTruncated") === "true" ? txt(d, "NextContinuationToken") : undefined,
  };
}

export type VersionInfo = ObjectInfo & { versionId: string; isLatest: boolean; deleteMarker: boolean };
export async function listVersions(bucket: string, prefix: string): Promise<VersionInfo[]> {
  const d = await xml(await call("GET", s3Path(bucket), { query: { versions: "", prefix, "max-keys": "1000" } }));
  const out: VersionInfo[] = [];
  for (const el of Array.from(d.documentElement.children)) {
    if (el.tagName !== "Version" && el.tagName !== "DeleteMarker") continue;
    out.push({
      key: txt(el, "Key"),
      versionId: txt(el, "VersionId"),
      isLatest: txt(el, "IsLatest") === "true",
      deleteMarker: el.tagName === "DeleteMarker",
      size: Number(txt(el, "Size") || 0),
      lastModified: txt(el, "LastModified"),
      etag: txt(el, "ETag").replace(/"/g, ""),
    });
  }
  return out;
}

// XMLHttpRequest, for upload progress.
export function putObject(bucket: string, key: string, file: Blob, onProgress?: (done: number, total: number) => void): Promise<void> {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open("PUT", s3Path(bucket, key));
    x.setRequestHeader("X-Console-Request", "1");
    x.setRequestHeader("Content-Type", (file as File).type || "application/octet-stream");
    x.upload.onprogress = (e) => onProgress?.(e.loaded, e.total);
    x.onload = async () => {
      if (x.status >= 200 && x.status < 300) resolve();
      else reject(await errorFrom(new Response(x.responseText, { status: x.status })));
    };
    x.onerror = () => reject(new ApiError(0, "NetworkError", "upload failed"));
    x.send(file);
  });
}

export async function deleteObject(bucket: string, key: string, versionId?: string): Promise<void> {
  await call("DELETE", s3Path(bucket, key), { query: { versionId } });
}

// CRC32 (IEEE) for x-amz-checksum-crc32: DeleteObjects needs a checksum.
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
export function crc32Base64(data: Uint8Array): string {
  let c = 0xffffffff;
  for (const b of data) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  c = (c ^ 0xffffffff) >>> 0;
  return btoa(String.fromCharCode((c >>> 24) & 0xff, (c >>> 16) & 0xff, (c >>> 8) & 0xff, c & 0xff));
}
const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export async function deleteObjects(bucket: string, items: { key: string; versionId?: string }[]): Promise<string[]> {
  const failed: string[] = [];
  for (let i = 0; i < items.length; i += 1000) {
    const batch = items.slice(i, i + 1000);
    const body =
      "<Delete><Quiet>true</Quiet>" +
      batch.map((o) => `<Object><Key>${esc(o.key)}</Key>${o.versionId ? `<VersionId>${esc(o.versionId)}</VersionId>` : ""}</Object>`).join("") +
      "</Delete>";
    const bytes = new TextEncoder().encode(body);
    const d = await xml(
      await call("POST", s3Path(bucket), {
        query: { delete: "" },
        body: bytes,
        headers: { "Content-Type": "application/xml", "x-amz-checksum-crc32": crc32Base64(bytes) },
      }),
    );
    for (const e of kids(d, "Error")) failed.push(`${txt(e, "Key")}: ${txt(e, "Message")}`);
  }
  return failed;
}

export function downloadUrl(bucket: string, key: string, versionId?: string): string {
  const name = key.split("/").pop() ?? key;
  const q: Record<string, string> = { "response-content-disposition": `attachment; filename="${name.replace(/"/g, "")}"` };
  if (versionId) q.versionId = versionId;
  return s3Path(bucket, key) + qs(q);
}

export async function headObject(bucket: string, key: string, versionId?: string): Promise<Headers> {
  return (await call("HEAD", s3Path(bucket, key), { query: { versionId } })).headers;
}

// Bucket sub-resources, as XML documents (NoSuch... errors mean "none").
async function getSub(bucket: string, sub: string, missing: string[]): Promise<string | null> {
  try {
    return await (await call("GET", s3Path(bucket), { query: { [sub]: "" } })).text();
  } catch (e) {
    if (e instanceof ApiError && missing.includes(e.code)) return null;
    throw e;
  }
}
async function putSub(bucket: string, sub: string, body: string, contentType = "application/xml"): Promise<void> {
  const bytes = new TextEncoder().encode(body);
  await call("PUT", s3Path(bucket), {
    query: { [sub]: "" },
    body: bytes,
    headers: { "Content-Type": contentType, "x-amz-checksum-crc32": crc32Base64(bytes) },
  });
}
async function delSub(bucket: string, sub: string): Promise<void> {
  await call("DELETE", s3Path(bucket), { query: { [sub]: "" } });
}

export async function getVersioning(bucket: string): Promise<string> {
  const x = await getSub(bucket, "versioning", []);
  return x ? txt(new DOMParser().parseFromString(x, "application/xml"), "Status") : "";
}
export async function setVersioning(bucket: string, status: "Enabled" | "Suspended"): Promise<void> {
  await putSub(bucket, "versioning", `<VersioningConfiguration><Status>${status}</Status></VersioningConfiguration>`);
}

export const bucketDocs = {
  policy: { get: (b: string) => getSub(b, "policy", ["NoSuchBucketPolicy"]), put: (b: string, v: string) => putSub(b, "policy", v, "application/json"), del: (b: string) => delSub(b, "policy") },
  lifecycle: { get: (b: string) => getSub(b, "lifecycle", ["NoSuchLifecycleConfiguration"]), put: (b: string, v: string) => putSub(b, "lifecycle", v), del: (b: string) => delSub(b, "lifecycle") },
  encryption: { get: (b: string) => getSub(b, "encryption", ["ServerSideEncryptionConfigurationNotFoundError"]), put: (b: string, v: string) => putSub(b, "encryption", v), del: (b: string) => delSub(b, "encryption") },
  tagging: { get: (b: string) => getSub(b, "tagging", ["NoSuchTagSet"]), put: (b: string, v: string) => putSub(b, "tagging", v), del: (b: string) => delSub(b, "tagging") },
  objectLock: { get: (b: string) => getSub(b, "object-lock", ["ObjectLockConfigurationNotFoundError"]), put: (b: string, v: string) => putSub(b, "object-lock", v) },
};

export type Tag = { key: string; value: string };
export function parseTags(x: string | null): Tag[] {
  if (!x) return [];
  const d = new DOMParser().parseFromString(x, "application/xml");
  return kids(d, "Tag").map((t) => ({ key: txt(t, "Key"), value: txt(t, "Value") }));
}
export function tagsXml(tags: Tag[]): string {
  return `<Tagging><TagSet>${tags.map((t) => `<Tag><Key>${esc(t.key)}</Key><Value>${esc(t.value)}</Value></Tag>`).join("")}</TagSet></Tagging>`;
}
export async function getObjectTags(bucket: string, key: string, versionId?: string): Promise<Tag[]> {
  return parseTags(await (await call("GET", s3Path(bucket, key), { query: { tagging: "", versionId } })).text());
}
export async function setObjectTags(bucket: string, key: string, tags: Tag[], versionId?: string): Promise<void> {
  const bytes = new TextEncoder().encode(tagsXml(tags));
  await call("PUT", s3Path(bucket, key), {
    query: { tagging: "", versionId },
    body: bytes,
    headers: { "Content-Type": "application/xml", "x-amz-checksum-crc32": crc32Base64(bytes) },
  });
}

// ---- admin ----

const admin = (api: string) => `/api/v1/admin/${api}`;
async function adminJson<T>(method: string, api: string, opts: CallOpts = {}): Promise<T> {
  const res = await call(method, admin(api), { decrypt: true, ...opts });
  const t = await res.text();
  return (t ? JSON.parse(t) : {}) as T;
}

export type ServerInfo = {
  mode: string;
  deploymentID: string;
  buckets?: { count: number };
  objects?: { count: number };
  usage?: { size: number };
  servers?: { endpoint: string; state: string; version: string; uptime: number; drives?: { state: string; totalspace?: number; usedspace?: number }[] }[];
  backend?: { backendType: string; onlineDisks: number; offlineDisks: number; standardSCParity?: number };
};
export const serverInfo = () => adminJson<ServerInfo>("GET", "info");
export type DataUsage = {
  lastUpdate: string;
  objectsCount: number;
  objectsTotalSize: number;
  bucketsCount: number;
  bucketsUsageInfo?: Record<string, { size: number; objectsCount: number; versionsCount?: number }>;
};
export const dataUsage = () => adminJson<DataUsage>("GET", "datausageinfo");
export type AccountInfo = { AccountName: string; Policy: unknown; Buckets: { name: string; access: { read: boolean; write: boolean } }[] };
export const accountInfo = () => adminJson<AccountInfo>("GET", "accountinfo");

export type UserInfo = { status: string; policyName?: string; memberOf?: string[] };
export const listUsers = () => adminJson<Record<string, UserInfo>>("GET", "list-users");

// ---- KMS: the keys objects are encrypted with ----

const kms = (api: string) => `/api/v1/kms/${api}`;
export type KMSStatus = { name: string; "default-key-id": string; endpoints: Record<string, string> };
export type KMSKeyCheck = { "key-id": string; "encryption-error"?: string; "decryption-error"?: string };
export const kmsStatus = async (): Promise<KMSStatus> => (await call("GET", kms("status"))).json();
export const kmsListKeys = async (): Promise<string[]> =>
  ((await (await call("GET", kms("key/list"), { query: { pattern: "*" } })).json()) as { name: string }[]).map((k) => k.name).sort();
// Encrypts and decrypts a data key with it: errors say what failed.
export const kmsCheckKey = async (key: string): Promise<KMSKeyCheck> =>
  (await call("GET", kms("key/status"), { query: { "key-id": key } })).json();
export const kmsCreateKey = (key: string) => call("POST", kms("key/create"), { query: { "key-id": key } });
// Gone for good, with every object encrypted under it: the server refuses the
// default key and keys a bucket encrypts with by default (KMSKeyInUse).
export const kmsDeleteKey = (key: string) => call("POST", kms("key/delete"), { query: { "key-id": key } });

// ---- KMS settings (where the operator runs KES for the cluster) ----

export type KmsBackend = "vault" | "aws" | "azure" | "gcp";
export type VaultSettings = {
  endpoint: string;
  engine?: string;
  version?: "v1" | "v2";
  namespace?: string;
  prefix?: string;
  auth: "approle" | "kubernetes";
  approle?: { engine?: string; id: string; secret: string };
  kubernetes?: { engine?: string; role: string };
  transit?: { engine?: string; key: string };
  caCert?: string;
};
export type AwsSettings = { region: string; endpoint?: string; kmsKey?: string; accessKey?: string; secretKey?: string; sessionToken?: string };
export type AzureSettings = {
  endpoint: string;
  auth: "secret" | "managedIdentity";
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;
  managedIdentityClientId?: string;
};
export type GcpSettings = { projectId?: string; endpoint?: string; credentials: string };
export type KmsSettings = {
  backend: KmsBackend;
  vault?: VaultSettings;
  aws?: AwsSettings;
  azure?: AzureSettings;
  gcp?: GcpSettings;
  secretsSet?: string[]; // saved secrets, left out: "vault.approle.secret", ...
};
export type KmsTestStep = { name: string; status: "ok" | "failed" | "running"; message?: string };
export type KmsTest = { id: string; phase: "Running" | "Passed" | "Failed"; message?: string; steps?: KmsTestStep[] };
export type KmsConfigStatus = {
  phase?: "Off" | "NotConfigured" | "Starting" | "Ready" | "Degraded" | "Error";
  message?: string;
  backend?: string;
  keyName?: string;
  replicas?: number;
  readyReplicas?: number;
  activated?: boolean;
  test?: KmsTest;
};
export type KmsConfig = {
  managed: boolean;
  cluster?: string;
  namespace?: string;
  kesServiceAccount?: string;
  enabled?: boolean;
  keyName?: string;
  settings?: KmsSettings | null;
  description?: string;
  status?: KmsConfigStatus;
};
// null: this session may not set up the KMS (it needs admin:ConfigUpdate)
export async function kmsConfig(): Promise<KmsConfig | null> {
  try {
    return await (await call("GET", "/api/v1/kms-config")).json();
  } catch (e) {
    if (e instanceof ApiError && e.status === 403) return null;
    throw e;
  }
}
export async function kmsConfigTest(req: { settings: KmsSettings; keyName: string; createKey: boolean; requiredKeys: string[] }): Promise<string> {
  const res = await call("POST", "/api/v1/kms-config/test", { body: JSON.stringify(req), headers: { "Content-Type": "application/json" } });
  return ((await res.json()) as { testId: string }).testId;
}
export const kmsConfigApply = (testId: string) =>
  call("POST", "/api/v1/kms-config/apply", { body: JSON.stringify({ testId }), headers: { "Content-Type": "application/json" } });

// ---- sign-in settings (the Identity page; see src/console/idpconfig.h) ----------------------
export type OidcProvider = "entra" | "okta" | "keycloak" | "generic";
export type OidcSettings = {
  provider: OidcProvider;
  displayName?: string;
  tenantId?: string;
  domain?: string;
  authServer?: string;
  url?: string;
  realm?: string;
  configUrl?: string;
  clientId: string;
  clientSecret?: string;
  claimName?: string;
  scopes?: string;
  redirectUri?: string;
  rolePolicy?: string;
  claimUserinfo?: boolean;
  // people who leave lose their access (Entra ID for now; docs/design/identity-sync.md)
  removal?: { enabled: boolean; deleteAfterDays?: number; maxPerSync?: number };
};
export type LdapSettings = {
  preset: "ad" | "openldap" | "custom";
  serverAddr: string;
  tls?: "ldaps" | "starttls" | "plain";
  skipVerify?: boolean;
  lookupBindDn: string;
  lookupBindPassword?: string;
  userSearchBase: string;
  userSearchFilter?: string;
  groupSearchBase?: string;
  groupSearchFilter?: string;
};
export type IdentitySettings = { openid?: OidcSettings | null; ldap?: LdapSettings | null; secretsSet?: string[] };
export type OidcTest = { passed: boolean; error?: string; user?: string; claimName?: string; roles?: string[]; policies?: string[]; unmatched?: string[]; at?: number };
export type LdapTest = { passed: boolean; error?: string; note?: string; dn?: string; groups?: string[]; policies?: string[]; at?: number };
export type RemovalTest = { passed: boolean; error?: string; user?: string; state?: "active" | "disabled"; id?: string; displayName?: string; userPrincipalName?: string; at?: number };
export type IdentityConfig = {
  managed: boolean;
  cluster?: string;
  namespace?: string;
  redirectUri?: string;
  settings?: IdentitySettings | null;
  description?: string;
  candidate?: IdentitySettings | null;
  candidateHash?: string;
  test?: { hash?: string; openid?: OidcTest; ldap?: LdapTest; removal?: RemovalTest };
  status?: { phase?: string; message?: string; description?: string };
};
const jsonBody = (v: unknown) => ({ body: JSON.stringify(v), headers: { "Content-Type": "application/json" } });
// null: this session may not set up sign-in (it needs admin:ConfigUpdate)
export async function identityConfig(): Promise<IdentityConfig | null> {
  try {
    return await (await call("GET", "/api/v1/identity-config")).json();
  } catch (e) {
    if (e instanceof ApiError && e.status === 403) return null;
    throw e;
  }
}
export async function identitySaveCandidate(settings: IdentitySettings): Promise<{ candidate: IdentitySettings; candidateHash: string }> {
  return (await call("PUT", "/api/v1/identity-config/candidate", jsonBody({ settings }))).json();
}
export async function identityLdapTest(username: string, password?: string): Promise<LdapTest> {
  return (await call("POST", "/api/v1/identity-config/ldap-test", jsonBody({ username, password }))).json();
}
export async function identityRemovalTest(user: string): Promise<RemovalTest> {
  return (await call("POST", "/api/v1/identity-config/removal-test", jsonBody({ user }))).json();
}
export const identityApply = (candidateHash: string) => call("POST", "/api/v1/identity-config/apply", jsonBody({ candidateHash }));
// The OpenID test: a sign-in with the candidate in a popup, which tells this window when it ends.
export function identityTestSignIn(): Promise<boolean> {
  return new Promise((resolve) => {
    const w = window.open("/api/v1/login/oidc?test=1", "buckets-identity-test", "width=520,height=680");
    let done = false;
    const finish = (passed: boolean) => {
      if (done) return;
      done = true;
      window.removeEventListener("message", onMsg);
      clearInterval(t);
      resolve(passed);
    };
    const onMsg = (e: MessageEvent) => {
      if (e.origin === window.location.origin && e.data?.type === "buckets-identity-test") finish(!!e.data.passed);
    };
    window.addEventListener("message", onMsg);
    const t = setInterval(() => {
      if (!w || w.closed) finish(false);
    }, 500);
  });
}

// Buckets whose default encryption is SSE-KMS, by key (the KMS's default key
// when the bucket names none).
export async function kmsKeyUsage(defaultKey: string): Promise<Map<string, string[]>> {
  const usage = new Map<string, string[]>();
  const buckets = await listBuckets();
  await Promise.all(
    buckets.map(async (b) => {
      const x = await bucketDocs.encryption.get(b.name).catch(() => null);
      if (!x) return;
      const d = new DOMParser().parseFromString(x, "application/xml");
      if (d.querySelector("SSEAlgorithm")?.textContent !== "aws:kms") return;
      const key = (d.querySelector("KMSMasterKeyID")?.textContent || defaultKey).replace(/^arn:aws:kms:/, "");
      usage.set(key, [...(usage.get(key) ?? []), b.name].sort());
    }),
  );
  return usage;
}

// Encrypting a bucket's unencrypted objects in place: a KeyRotate batch job
// with Buckets' onlyUnencrypted (every version; encrypted ones are left alone).
export async function encryptExisting(bucket: string, alg: "AES256" | "aws:kms", key?: string): Promise<string> {
  const enc = alg === "aws:kms" ? `    type: sse-kms\n    key: ${JSON.stringify(key ?? "")}\n` : "    type: sse-s3\n";
  const yaml = `keyrotate:\n  apiVersion: v1\n  bucket: ${JSON.stringify(bucket)}\n  encryption:\n${enc}    onlyUnencrypted: true\n`;
  const res = await call("POST", admin("start-job"), { body: yaml, headers: { "Content-Type": "application/yaml" } });
  return ((await res.json()) as { id: string }).id;
}
export type JobProgress = { complete: boolean; failed: boolean; objects: number; objectsFailed: number };
export async function jobProgress(id: string): Promise<JobProgress> {
  const st = (await (await call("GET", admin("status-job"), { query: { jobId: id } })).json()) as {
    LastMetric: { complete: boolean; failed: boolean; rotation?: { objects?: number; objectsFailed?: number } };
  };
  const m = st.LastMetric;
  return { complete: m.complete, failed: m.failed, objects: m.rotation?.objects ?? 0, objectsFailed: m.rotation?.objectsFailed ?? 0 };
}

// People from the OpenID provider that Buckets knows of: signed in now, or holding access keys.
type KeyInfo = { accessKey: string; expiration?: string };
export type OpenIDUser = {
  minioAccessKey: string;
  ID: string;
  readableName: string;
  displayName: string;
  email: string;
  policies: string[];
  serviceAccounts: KeyInfo[] | null;
  stsKeys: KeyInfo[] | null;
};
export const listOpenIDUsers = async (): Promise<OpenIDUser[]> =>
  (
    await adminJson<{ configName: string; users: OpenIDUser[] | null }[]>("GET", "idp/openid/list-access-keys-bulk", {
      query: { all: "true", listType: "all" },
    })
  ).flatMap((c) => c.users ?? []);
export const addUser = (accessKey: string, secretKey: string) =>
  call("PUT", admin("add-user"), { query: { accessKey }, body: JSON.stringify({ secretKey, status: "enabled" }), encrypt: true });
export const removeUser = (accessKey: string) => call("DELETE", admin("remove-user"), { query: { accessKey } });
export const setUserStatus = (accessKey: string, status: "enabled" | "disabled") =>
  call("PUT", admin("set-user-status"), { query: { accessKey, status } });
export const userInfo = (accessKey: string) => adminJson<UserInfo>("GET", "user-info", { query: { accessKey } });

export const listPolicies = () => adminJson<Record<string, unknown>>("GET", "list-canned-policies");
export const getPolicy = (name: string) => adminJson<{ PolicyName: string; Policy: unknown }>("GET", "info-canned-policy", { query: { name, v: "2" } });
export const putPolicy = (name: string, doc: string) =>
  call("PUT", admin("add-canned-policy"), { query: { name }, body: doc, headers: { "Content-Type": "application/json" } });
export const removePolicy = (name: string) => call("DELETE", admin("remove-canned-policy"), { query: { name } });
export const attachPolicies = (policies: string[], target: { user?: string; group?: string }, detach = false) =>
  call("POST", admin(detach ? "idp/builtin/policy/detach" : "idp/builtin/policy/attach"), {
    body: JSON.stringify({ policies, ...target }),
    encrypt: true,
  });

export type GroupInfo = { name: string; status: string; members: string[] | null; policy: string };
export const listGroups = () => adminJson<string[] | null>("GET", "groups");
export const groupInfo = (group: string) => adminJson<GroupInfo>("GET", "group", { query: { group } });
export const updateGroupMembers = (group: string, members: string[], isRemove: boolean) =>
  call("PUT", admin("update-group-members"), { body: JSON.stringify({ group, members, isRemove }) });
export const setGroupStatus = (group: string, status: "enabled" | "disabled") =>
  call("PUT", admin("set-group-status"), { query: { group, status } });

export type ServiceAccount = { accessKey: string; parentUser?: string; accountStatus?: string; name?: string; description?: string; expiration?: string };
export const listServiceAccounts = (user?: string) =>
  adminJson<{ accounts: ServiceAccount[] | null }>("GET", "list-service-accounts", { query: user ? { user } : {} });
export const addServiceAccount = (req: { name?: string; description?: string; policy?: string; targetUser?: string }) =>
  adminJson<{ credentials: { accessKey: string; secretKey: string } }>("PUT", "add-service-account", {
    body: JSON.stringify(req),
    encrypt: true,
  });
export const deleteServiceAccount = (accessKey: string) => call("DELETE", admin("delete-service-account"), { query: { accessKey } });

export type Quota = { quota: number; quotatype?: string; size?: number };
export const getQuota = (bucket: string) => adminJson<Quota>("GET", "get-bucket-quota", { query: { bucket } });
export const setQuota = (bucket: string, quota: number) =>
  call("PUT", admin("set-bucket-quota"), { query: { bucket }, body: JSON.stringify({ quota, quotatype: "hard" }) });

export async function getConfig(subsys: string): Promise<string> {
  return (await call("GET", admin("get-config-kv"), { query: { key: subsys }, decrypt: true })).text();
}
export async function setConfig(kv: string): Promise<void> {
  await call("PUT", admin("set-config-kv"), { body: kv, encrypt: true });
}
export type ConfigHelp = { subSys: string; description: string; multipleTargets: boolean; keysHelp: { key: string; description: string; optional: boolean; type: string }[] };
export const configHelp = (subSys?: string) => adminJson<ConfigHelp>("GET", "help-config-kv", { query: subSys ? { subSys } : {} });

// ---- sharing, retention and legal hold ----

export async function shareLink(bucket: string, key: string, expires: number, versionId?: string): Promise<{ url: string; expiresAt: number }> {
  return (await call("GET", "/api/v1/share", { query: { bucket, key, versionId, expires: String(expires) } })).json();
}

export function inlineUrl(bucket: string, key: string): string {
  return s3Path(bucket, key) + "?response-content-disposition=inline";
}

async function putObjectSub(bucket: string, key: string, sub: string, body: string, extra: Record<string, string> = {}): Promise<void> {
  const bytes = new TextEncoder().encode(body);
  await call("PUT", s3Path(bucket, key), {
    query: { [sub]: "" },
    body: bytes,
    headers: { "Content-Type": "application/xml", "x-amz-checksum-crc32": crc32Base64(bytes), ...extra },
  });
}

export type Retention = { mode: string; until: string };
export async function getRetention(bucket: string, key: string): Promise<Retention | null> {
  try {
    const d = await xml(await call("GET", s3Path(bucket, key), { query: { retention: "" } }));
    return { mode: txt(d, "Mode"), until: txt(d, "RetainUntilDate") };
  } catch (e) {
    if (e instanceof ApiError && ["NoSuchObjectLockConfiguration", "InvalidRequest", "InvalidBucketState"].includes(e.code)) return null;
    throw e;
  }
}
export async function setRetention(bucket: string, key: string, mode: string, until: string, bypass = false): Promise<void> {
  await putObjectSub(
    bucket,
    key,
    "retention",
    `<Retention><Mode>${mode}</Mode><RetainUntilDate>${new Date(until).toISOString()}</RetainUntilDate></Retention>`,
    bypass ? { "X-Amz-Bypass-Governance-Retention": "true" } : {},
  );
}
export async function getLegalHold(bucket: string, key: string): Promise<boolean | null> {
  try {
    return txt(await xml(await call("GET", s3Path(bucket, key), { query: { "legal-hold": "" } })), "Status") === "ON";
  } catch (e) {
    if (e instanceof ApiError && ["NoSuchObjectLockConfiguration", "InvalidRequest", "InvalidBucketState"].includes(e.code)) return null;
    throw e;
  }
}
export async function setLegalHold(bucket: string, key: string, on: boolean): Promise<void> {
  await putObjectSub(bucket, key, "legal-hold", `<LegalHold><Status>${on ? "ON" : "OFF"}</Status></LegalHold>`);
}

// ---- streams (mc admin trace, mc admin logs, mc event listen) ----

// Reads a never-ending JSON-lines stream until signal aborts: one object per
// line, keep-alive spaces and empty {"Records":null} pings skipped.
export async function readStream(
  path: string,
  query: Record<string, string | undefined>,
  onItem: (item: any) => void,
  signal: AbortSignal,
): Promise<void> {
  const res = await call("GET", path, { query, signal });
  const reader = res.body!.getReader();
  const dec = new TextDecoder();
  let buf = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      buf += dec.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let item;
        try {
          item = JSON.parse(line);
        } catch {
          continue;
        }
        if (item && item.Records === null) continue;
        onItem(item);
      }
      buf = buf.replace(/^\s+/, "");
    }
  } catch (e) {
    if ((e as Error).name !== "AbortError") throw e;
  }
}

export type TraceRecord = {
  type: number;
  nodename: string;
  funcname: string;
  time: string;
  path?: string;
  dur?: number;
  error?: string;
  http?: { request?: { method?: string; path?: string; rawquery?: string; client?: string }; response?: { statusCode?: number } };
  custom?: Record<string, string>;
};
export const TRACE_TYPES = ["s3", "internal", "storage", "os", "scanner", "healing", "ilm"] as const;
export function trace(types: string[], errorsOnly: boolean, threshold: string, onItem: (r: TraceRecord) => void, signal: AbortSignal) {
  const q: Record<string, string | undefined> = { err: String(errorsOnly), threshold: threshold || "0s" };
  for (const t of TRACE_TYPES) q[t] = String(types.includes(t));
  return readStream("/api/v1/admin/trace", q, onItem, signal);
}

export type LogEntry = {
  level?: string;
  time?: string;
  node?: string;
  message?: string;
  ConsoleMsg?: string;
  error?: { message?: string; source?: string[] };
  api?: { name?: string };
};
export function consoleLogs(node: string, logType: string, limit: number, onItem: (e: LogEntry) => void, signal: AbortSignal) {
  return readStream("/api/v1/admin/log", { node: node || undefined, logType, limit: String(limit) }, onItem, signal);
}

export type EventRecord = {
  eventName: string;
  eventTime: string;
  s3: { bucket: { name: string }; object: { key: string; size?: number; versionId?: string } };
  source?: { host?: string; userAgent?: string };
};
export function listenEvents(
  bucket: string,
  prefix: string,
  suffix: string,
  events: string[],
  onItem: (r: EventRecord) => void,
  signal: AbortSignal,
) {
  const parts = [`events`, `prefix=${encodeURIComponent(prefix)}`, `suffix=${encodeURIComponent(suffix)}`, `ping=10`];
  const q = parts.slice(1).concat(events.map((e) => `events=${encodeURIComponent(e)}`)).join("&");
  const path = (bucket ? `/api/v1/s3/${encodeURIComponent(bucket)}` : "/api/v1/s3/") + `?${q}`;
  return readStream(path, {}, (item) => {
    for (const r of item.Records ?? []) onItem(r as EventRecord);
  }, signal);
}

// ---- teams (consoled's /api/v1/teams: a team is its team-<name>-<level> policies) ----

export type TeamLevel = "ro" | "rw" | "admin";
export const TEAM_LEVELS: TeamLevel[] = ["ro", "rw", "admin"];
export type Team = { name: string; buckets: string[]; prefixes: string[]; levels: TeamLevel[] };
export type TeamMembers = Partial<Record<TeamLevel, { users: string[]; groups: string[] }>>;
export type TeamInfo = Team & { edited: TeamLevel[]; members: TeamMembers };
export const teamPolicy = (team: string, level: TeamLevel) => `team-${team}-${level}`;
export async function listTeams(): Promise<{ teams: TeamInfo[]; ldap: boolean }> {
  return (await call("GET", "/api/v1/teams")).json();
}
export async function saveTeam(team: Team, overwrite = false): Promise<Team> {
  return (await call("PUT", `/api/v1/teams/${encodeURIComponent(team.name)}`, jsonBody({ team, overwrite }))).json();
}
export const deleteTeam = (name: string) => call("DELETE", `/api/v1/teams/${encodeURIComponent(name)}`);
export const teamMember = (team: string, level: TeamLevel, who: { user?: string; group?: string }, remove = false) =>
  call("POST", `/api/v1/teams/${encodeURIComponent(team)}/members`, jsonBody({ level, ...who, remove }));

// ---- access review (consoled's /api/v1/access) ----

export type AccessLevel = "read" | "write" | "delete" | "manage" | "any";
export const ACCESS_LEVELS: AccessLevel[] = ["read", "write", "delete", "manage", "any"];
export type AccessBy = { policy?: string; bucketPolicy?: boolean; statement: number; sid?: string; effect: "Allow" | "Deny"; conditions?: string[] };
export type AccessRow = {
  kind: string;
  name: string;
  status?: string;
  members?: string[];
  seen?: string[];
  owner?: string;
  groups?: string[];
  access: "full" | "limited" | "conditional";
  actions: { action: string; decision: "allowed" | "limited" | "conditional"; limits?: string[]; by: AccessBy[] }[];
};
export type AccessReview = { bucket: string; level: AccessLevel; actions: string[]; rows: AccessRow[]; missing: string[]; at: number };
export async function accessReview(bucket: string, level: AccessLevel): Promise<AccessReview> {
  return (await call("GET", `/api/v1/access/bucket/${encodeURIComponent(bucket)}`, { query: { level } })).json();
}
export type AccessWho = { kind: string; name?: string; roles?: string[] };
export type AccessDecision = { decision: "allowed" | "denied" | "conditional"; reason: string; by: AccessBy[]; missing: string[] };
export async function accessCheck(who: AccessWho, action: string, bucket: string, object: string, conds?: Record<string, string>): Promise<AccessDecision> {
  return (await call("POST", "/api/v1/access/check", jsonBody({ who, action, bucket, object, conds }))).json();
}
export type AccessPrincipal = { kind: string; name: string; owner?: string; status?: string };
export async function accessPrincipals(): Promise<{ principals: AccessPrincipal[]; openid: boolean; ldap: boolean; missing: string[] }> {
  return (await call("GET", "/api/v1/access/principals")).json();
}
export type LocalUsersReport = { provider: string | null; users: { name: string; status: string; policies: string[]; groups: string[]; keys: number }[]; missing: string[] };
export async function accessLocalUsers(): Promise<LocalUsersReport> {
  return (await call("GET", "/api/v1/access/local-users")).json();
}
