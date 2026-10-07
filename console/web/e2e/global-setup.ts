import { spawn, ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../..");
export const ROOT_USER = "e2eadmin";
export const ROOT_PASSWORD = "e2esecret123";

async function waitFor(url: string, ms = 15000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try {
      const r = await fetch(url);
      if (r.status < 500) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`${url} did not come up`);
}

export default async function globalSetup() {
  if (process.env.CONSOLE_URL) return; // an existing deployment
  const dir = mkdtempSync(join(tmpdir(), "buckets-e2e-"));
  for (let i = 1; i <= 4; i++) mkdirSync(join(dir, `d${i}`));
  const procs: ChildProcess[] = [];
  // a mock OpenID provider (tests/integration/oidcmock.py)
  const idp = spawn(
    "python3",
    [join(root, "tests/integration/oidcmock.py"), "19891", dir, "console", "s3cr3t", JSON.stringify({ sub: "u-7", preferred_username: "oidcuser", policy: "readwrite" })],
    { stdio: ["ignore", "ignore", "inherit"] },
  );
  procs.push(idp);
  await waitFor("http://127.0.0.1:19891/jwks");
  // a mock Kubernetes API with buckets-operator's KMS answers (tests/integration/kubemock.py)
  const kube = spawn("python3", [join(root, "tests/integration/kubemock.py"), "19892", dir, "e2e", "store"], { stdio: ["ignore", "ignore", "inherit"] });
  procs.push(kube);
  for (let i = 0; i < 100 && !existsSync(join(dir, "kube-ca.pem")); i++) await new Promise((r) => setTimeout(r, 100));
  await new Promise((r) => setTimeout(r, 300));
  const bucketsd = spawn(process.env.BUCKETSD_BIN ?? join(root, "build/src/bucketsd"), ["server", "--address", "127.0.0.1:19889", `${dir}/d{1...4}`], {
    env: { ...process.env, MINIO_ROOT_USER: ROOT_USER, MINIO_ROOT_PASSWORD: ROOT_PASSWORD, MINIO_KMS_SECRET_KEY: "e2e-key:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
      MINIO_IDENTITY_OPENID_CONFIG_URL: "http://127.0.0.1:19891/.well-known/openid-configuration",
      MINIO_IDENTITY_OPENID_CLIENT_ID: "console",
      MINIO_IDENTITY_OPENID_CLAIM_NAME: "policy",
      BUCKETS_USAGE_FLUSH_INTERVAL: "1", // the usage report's traffic, within the test's wait
      BUCKETS_RANSOMWARE_INTERVAL: "1", // the leader's ransomware alerts checks, within the test's wait
    },
    stdio: ["ignore", "ignore", "inherit"],
  });
  procs.push(bucketsd);
  await waitFor("http://127.0.0.1:19889/minio/health/live");
  const consoled = spawn(
    process.env.CONSOLED_BIN ?? join(root, "build/src/consoled"),
    ["--address", "127.0.0.1:19890", "--web-dir", resolve(here, "../dist")],
    {
      env: { ...process.env, CONSOLE_MINIO_SERVER: "http://127.0.0.1:19889", CONSOLE_PBKDF_PASSPHRASE: "e2e", CONSOLE_PBKDF_SALT: "e2e", BUCKETS_CONSOLE_S3_URL: "http://127.0.0.1:19889",
        // OpenID sign-in hides Create user unless asked for; the user tests need it
        BUCKETS_CONSOLE_LOCAL_USERS: "on",
        BUCKETS_CONSOLE_OIDC_CONFIG_URL: "http://127.0.0.1:19891/.well-known/openid-configuration",
        BUCKETS_CONSOLE_OIDC_CLIENT_ID: "console",
        BUCKETS_CONSOLE_OIDC_CLIENT_SECRET: "s3cr3t",
        BUCKETS_CONSOLE_OIDC_DISPLAY_NAME: "Mock IdP",
        // KMS settings through the operator, as in a cluster
        BUCKETS_CONSOLE_CLUSTER: "store",
        BUCKETS_CONSOLE_NAMESPACE: "e2e",
        BUCKETS_KUBE_API: "https://127.0.0.1:19892",
        BUCKETS_KUBE_TOKEN: "kubemock-token",
        BUCKETS_KUBE_CA: join(dir, "kube-ca.pem"),
      },
      stdio: ["ignore", "ignore", "inherit"],
    },
  );
  procs.push(consoled);
  await waitFor("http://127.0.0.1:19890/healthz");
  return async () => {
    for (const p of procs) p.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 300));
    rmSync(dir, { recursive: true, force: true });
  };
}
