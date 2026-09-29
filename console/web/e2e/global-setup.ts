import { spawn, ChildProcess } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
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
  const bucketsd = spawn(process.env.BUCKETSD_BIN ?? join(root, "build/src/bucketsd"), ["server", "--address", "127.0.0.1:19889", `${dir}/d{1...4}`], {
    env: { ...process.env, MINIO_ROOT_USER: ROOT_USER, MINIO_ROOT_PASSWORD: ROOT_PASSWORD, MINIO_KMS_SECRET_KEY: "e2e-key:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" },
    stdio: ["ignore", "ignore", "inherit"],
  });
  procs.push(bucketsd);
  await waitFor("http://127.0.0.1:19889/minio/health/live");
  const consoled = spawn(
    process.env.CONSOLED_BIN ?? join(root, "build/src/consoled"),
    ["--address", "127.0.0.1:19890", "--web-dir", resolve(here, "../dist")],
    {
      env: { ...process.env, CONSOLE_MINIO_SERVER: "http://127.0.0.1:19889", CONSOLE_PBKDF_PASSPHRASE: "e2e", CONSOLE_PBKDF_SALT: "e2e", BUCKETS_CONSOLE_S3_URL: "http://127.0.0.1:19889" },
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
