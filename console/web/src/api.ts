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
  const res = await fetch(path + qs(opts.query), { method, headers, body: opts.body ?? undefined, credentials: "same-origin" });
  if (!res.ok) {
    const err = await errorFrom(res);
    if (res.status === 401 && err.code === "Unauthorized") window.dispatchEvent(new Event(SESSION_EXPIRED));
    throw err;
  }
  return res;
}

// ---- session ----

export type Session = { accessKey: string; expiresAt: number };

export type LoginMethods = { ldap: boolean; share: boolean; oidc: boolean; oidcName?: string };
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
