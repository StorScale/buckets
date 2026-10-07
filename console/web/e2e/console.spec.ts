import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";
import { login, ROOT_USER, unique } from "./helpers";

test.describe("session", () => {
  test("rejects bad keys, signs in, and signs out", async ({ page }) => {
    await page.goto("/buckets");
    await expect(page).toHaveURL(/\/login$/);
    await page.getByTestId("access-key").fill(ROOT_USER);
    await page.getByTestId("secret-key").fill("wrong-secret");
    await page.getByTestId("login").click();
    await expect(page.getByTestId("error")).toBeVisible();

    await login(page);
    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
    await expect(page.getByText("Drives online")).toBeVisible();

    await page.getByTestId("logout").click();
    await expect(page).toHaveURL(/\/login$/);
    const res = await page.request.get("/api/v1/session");
    expect(res.status()).toBe(401);
  });

  test("signs in through an OpenID provider", async ({ page }) => {
    test.skip(!!process.env.CONSOLE_URL, "needs the mock provider of the local setup");
    await page.goto("/login");
    await page.getByTestId("oidc-login").click();
    await expect(page.getByTestId("whoami")).toHaveText("oidcuser");
    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
    // a forged callback lands back on the login page with the reason
    await page.getByTestId("logout").click();
    await page.goto("/oauth_callback?code=x&state=y");
    await expect(page).toHaveURL(/\/login\?error=/);
    await expect(page.getByTestId("error")).toContainText("did not start here");
  });

  test("the API refuses unsafe requests without the CSRF header", async ({ page }) => {
    await login(page);
    const res = await page.request.put("/api/v1/s3/csrf-bucket");
    expect(res.status()).toBe(403);
  });
});

test.describe("buckets and objects", () => {
  test("create a bucket, upload, browse, tag, download and delete", async ({ page }) => {
    const bucket = unique("e2e");
    await login(page);
    await page.getByRole("link", { name: "Buckets" }).click();
    await page.getByTestId("create-bucket").click();
    await page.getByTestId("bucket-name").fill(bucket);
    await page.getByTestId("bucket-create-submit").click();
    await expect(page.getByTestId(`bucket-${bucket}`)).toBeVisible();

    await page.getByRole("link", { name: bucket }).click();
    await expect(page.getByText("This folder is empty.")).toBeVisible();

    // into a folder, then upload two files there
    await page.getByTestId("new-folder").click();
    await page.getByTestId("folder-name").fill("docs");
    await page.getByTestId("folder-create").click();
    await page.getByTestId("file-input").setInputFiles([
      { name: "hello.txt", mimeType: "text/plain", buffer: Buffer.from("hello from the console") },
      { name: "data.bin", mimeType: "application/octet-stream", buffer: Buffer.alloc(3 * 1024 * 1024, 7) },
    ]);
    await expect(page.getByTestId("notice")).toHaveText("Uploaded 2 files.");
    await expect(page.getByTestId("row-docs/hello.txt")).toBeVisible();
    await expect(page.getByTestId("row-docs/data.bin")).toContainText("3.0 MiB");

    // the download link serves the bytes
    const href = await page.getByTestId("download-docs/hello.txt").getAttribute("href");
    const dl = await page.request.get(href!);
    expect(await dl.text()).toBe("hello from the console");
    expect(dl.headers()["content-disposition"]).toContain("hello.txt");

    // object details: metadata and tags
    await page.getByRole("link", { name: "hello.txt" }).click();
    await expect(page.getByRole("dialog")).toContainText("text/plain");
    await page.getByTestId("add-tag").click();
    const tagRow = page.getByTestId("tag-editor").locator(".tag-row").first();
    await tagRow.locator("input").nth(0).fill("team");
    await tagRow.locator("input").nth(1).fill("storage");
    await page.getByTestId("save-tags").click();
    await expect(page.getByTestId("notice").last()).toHaveText("Tags saved.");
    await page.keyboard.press("Escape");
    const tags = await page.request.get(`/api/v1/s3/${bucket}/docs/hello.txt?tagging`);
    expect(await tags.text()).toContain("<Key>team</Key><Value>storage</Value>");

    // breadcrumbs back to the root show the folder
    await page.getByRole("heading").getByText(bucket).click();
    await expect(page.getByTestId("row-docs/")).toBeVisible();

    // delete the folder (recursively), then the bucket
    await page.getByTestId("row-docs/").locator("input[type=checkbox]").check();
    await page.getByTestId("delete-selected").click();
    await page.getByTestId("delete-selected-yes").click();
    await expect(page.getByText("This folder is empty.")).toBeVisible();

    await page.getByRole("link", { name: "Buckets" }).first().click();
    await page.getByTestId(`delete-${bucket}`).click();
    await page.getByTestId(`delete-${bucket}-yes`).click();
    await expect(page.getByTestId(`bucket-${bucket}`)).toHaveCount(0);
  });

  test("versioning keeps every version", async ({ page }) => {
    const bucket = unique("ver");
    await login(page);
    await page.request.put(`/api/v1/s3/${bucket}`, { headers: { "X-Console-Request": "1" } });
    await page.goto(`/buckets/${bucket}/settings`);
    await expect(page.getByTestId("versioning-status")).toHaveText("Unversioned");
    await page.getByTestId("enable-versioning").click();
    await expect(page.getByTestId("versioning-status")).toHaveText("Enabled");

    await page.goto(`/buckets/${bucket}/browse/`);
    for (const body of ["one", "two"]) {
      await page.getByTestId("file-input").setInputFiles({ name: "v.txt", mimeType: "text/plain", buffer: Buffer.from(body) });
      await expect(page.getByTestId("notice")).toHaveText("Uploaded 1 file.");
    }
    await page.getByTestId("show-versions").check();
    await expect(page.getByTestId("version-table").locator("tbody tr")).toHaveCount(2);
    await expect(page.getByTestId("version-table")).toContainText("latest");
  });

  test("bucket settings: quota, policy, tags, encryption, lifecycle", async ({ page }) => {
    const bucket = unique("cfg");
    await login(page);
    await page.request.put(`/api/v1/s3/${bucket}`, { headers: { "X-Console-Request": "1" } });
    await page.goto(`/buckets/${bucket}/settings`);

    await page.getByTestId("quota").fill("2");
    await page.getByTestId("save-quota").click();
    await expect(page.getByTestId("notice")).toHaveText("Quota set to 2.0 GiB.");

    await page.getByTestId("policy-public-read").click();
    await page.getByTestId("save-policy").click();
    await expect(page.getByTestId("notice")).toHaveText("Policy saved.");
    // anonymous reads now work at bucketsd; the console shows the stored policy
    const pol = await page.request.get(`/api/v1/s3/${bucket}?policy`);
    expect(await pol.text()).toContain("s3:GetObject");

    await page.getByTestId("sse-alg").selectOption("AES256");
    await page.getByTestId("save-sse").click();
    await expect(page.getByTestId("notice")).toHaveText("Encryption saved.");

    await page
      .getByTestId("lifecycle")
      .fill("<LifecycleConfiguration><Rule><ID>tmp</ID><Status>Enabled</Status><Filter><Prefix>tmp/</Prefix></Filter><Expiration><Days>7</Days></Expiration></Rule></LifecycleConfiguration>");
    await page.getByTestId("save-lifecycle").click();
    await expect(page.getByTestId("notice")).toHaveText("Lifecycle saved.");

    await page.getByTestId("lifecycle").fill("<LifecycleConfiguration><Rule></LifecycleConfiguration>");
    await page.getByTestId("save-lifecycle").click();
    await expect(page.getByTestId("error")).toBeVisible();

    // a reload shows what was stored
    await page.reload();
    await expect(page.getByTestId("quota")).toHaveValue("2");
    await expect(page.getByTestId("sse-alg")).toHaveValue("AES256");
    await expect(page.getByTestId("lifecycle")).toHaveValue(/<ID>tmp<\/ID>/);
  });
});

test.describe("object details", () => {
  test("preview, share link, retention and legal hold", async ({ page }) => {
    const bucket = unique("lock");
    await login(page);
    await page.goto("/buckets");
    await page.getByTestId("create-bucket").click();
    await page.getByTestId("bucket-name").fill(bucket);
    await page.getByRole("dialog").getByText("Object locking").click();
    await page.getByTestId("bucket-create-submit").click();
    await page.getByRole("link", { name: bucket }).click();
    await page.getByTestId("file-input").setInputFiles({ name: "note.txt", mimeType: "text/plain", buffer: Buffer.from("keep this safe") });
    await expect(page.getByTestId("notice")).toHaveText("Uploaded 1 file.");
    await page.getByRole("link", { name: "note.txt" }).click();

    await expect(page.getByTestId("preview")).toHaveText("keep this safe");

    // a share link works without the console session (when set up to be reachable)
    await page.getByTestId("share").click();
    const url = await page.getByTestId("share-url").inputValue();
    expect(url).toContain("X-Amz-Signature=");
    const anon = await fetch(url);
    expect(await anon.text()).toBe("keep this safe");

    // retention and legal hold
    await expect(page.getByTestId("retention")).toHaveText("No retention.");
    const until = new Date(Date.now() + 3 * 86400_000).toISOString().slice(0, 10);
    await page.getByTestId("retain-until").fill(until);
    await page.getByTestId("save-retention").click();
    await expect(page.getByTestId("retention")).toContainText("GOVERNANCE until");
    await page.getByTestId("legal-hold").check();
    await expect(page.getByRole("dialog").getByTestId("notice")).toHaveText("Legal hold on.");

    // a locked version cannot be deleted (MinIO's ErrObjectLocked: 400, "WORM protected")
    const vid = (await page.request.head(`/api/v1/s3/${bucket}/note.txt`)).headers()["x-amz-version-id"];
    const del = await page.request.delete(`/api/v1/s3/${bucket}/note.txt?versionId=${vid}`, { headers: { "X-Console-Request": "1" } });
    expect(del.status()).toBe(400);
    expect(await del.text()).toContain("WORM protected");
    await page.getByTestId("legal-hold").uncheck();
    await expect(page.getByRole("dialog").getByTestId("notice")).toHaveText("Legal hold off.");
  });
});

test.describe("compliance", () => {
  test("retention and encryption coverage: settings per bucket, and CSV", async ({ page }) => {
    const bucket = unique("locked");
    await login(page);
    // a bucket with object lock, made as people do
    await page.goto("/buckets");
    await page.getByTestId("create-bucket").click();
    await page.getByTestId("bucket-name").fill(bucket);
    await page.getByRole("dialog").getByText("Object locking").click();
    await page.getByTestId("bucket-create-submit").click();
    await page.getByRole("link", { name: "Retention" }).click();
    await expect(page).toHaveURL(/\/compliance\/retention$/);
    await expect(page.getByTestId("retention-summary")).toContainText("with object lock");
    await expect(page.getByTestId(`retention-${bucket}`)).toContainText("on");
    await expect(page.getByTestId(`retention-${bucket}`)).toContainText("Enabled"); // object lock versions the bucket
    await expect(page.getByTestId("scanned-at")).toBeVisible();
    const csv = page.waitForEvent("download");
    await page.getByTestId("compliance-csv").click();
    const file = await (await csv).path();
    const text = readFileSync(file, "utf8");
    expect(text.split("\n")[0]).toContain("default retention");
    expect(text).toContain(bucket + ",on,none,Enabled");
    // encryption: the KMS of the local setup, and the bucket without default encryption
    await page.getByTestId("tab-encryption").click();
    await expect(page).toHaveURL(/\/compliance\/encryption$/);
    if (!process.env.CONSOLE_URL) await expect(page.getByTestId("encryption-summary")).toContainText("KMS: online");
    await expect(page.getByTestId(`encryption-${bucket}`)).toContainText("none");
  });
});

test.describe("identity", () => {
  test("users: create with a policy, sign in as them, disable, delete", async ({ page, browser }) => {
    const user = unique("alice");
    await login(page);
    await page.getByRole("link", { name: "Users" }).click();
    if (!process.env.CONSOLE_URL) {
      // the OpenID user signed in earlier is listed read-only, with their role
      await expect(page.getByTestId("oidc-users")).toContainText("Mock IdP users");
      await expect(page.getByTestId("oidc-user-oidcuser")).toContainText("readwrite");
    }
    await page.getByTestId("create-user").click();
    await page.getByTestId("new-access-key").fill(user);
    await page.getByTestId("new-secret-key").fill("alicesecret1");
    await page.getByTestId("user-create-submit").click();
    await expect(page.getByTestId(`user-${user}`)).toContainText("readwrite");

    // the new user can sign in on their own
    const other = await browser.newPage();
    await login(other, user, "alicesecret1");
    await other.close();

    await page.getByTestId(`user-${user}`).getByRole("button", { name: "Disable" }).click();
    await expect(page.getByTestId(`user-${user}`)).toContainText("disabled");
    await page.getByTestId(`delete-user-${user}`).click();
    await page.getByTestId(`delete-user-${user}-yes`).click();
    await expect(page.getByTestId(`user-${user}`)).toHaveCount(0);
  });

  test("groups and policies", async ({ page }) => {
    const policy = unique("pol");
    const group = unique("grp");
    await login(page);
    await page.getByRole("link", { name: "Policies" }).click();
    await expect(page.getByTestId("policy-readwrite")).toBeVisible();
    await page.getByTestId("create-policy").click();
    await page.getByTestId("policy-name").fill(policy);
    await page.getByTestId("policy-save").click();
    await expect(page.getByTestId(`policy-${policy}`)).toBeVisible();

    await page.request.put(`/api/v1/admin/add-user?accessKey=gm-${group}`, {
      headers: { "X-Console-Request": "1", "X-Console-Encrypt": "1" },
      data: JSON.stringify({ secretKey: "membersecret", status: "enabled" }),
    });
    await page.getByRole("link", { name: "Groups" }).click();
    await page.getByTestId("create-group").click();
    await page.getByTestId("group-name").fill(group);
    await page.getByRole("dialog").getByText(`gm-${group}`).click();
    await page.getByTestId("group-create-submit").click();
    await expect(page.getByTestId(`group-${group}`)).toContainText(`gm-${group}`);

    await page.getByRole("link", { name: "Policies" }).click();
    await page.getByTestId(`delete-policy-${policy}`).click();
    await page.getByTestId(`delete-policy-${policy}-yes`).click();
    await expect(page.getByTestId(`policy-${policy}`)).toHaveCount(0);
  });

  test("teams: create, give access, edit, delete", async ({ page }) => {
    const team = unique("pt");
    const member = `tm-${team}`;
    await login(page);
    const h = { "X-Console-Request": "1" };
    await page.request.put(`/api/v1/admin/add-user?accessKey=${member}`, {
      headers: { ...h, "X-Console-Encrypt": "1" },
      data: JSON.stringify({ secretKey: "membersecret", status: "enabled" }),
    });
    expect((await page.request.put(`/api/v1/s3/${team}-data`, { headers: h })).status()).toBe(200);
    await page.getByRole("link", { name: "Teams" }).click();
    await page.getByTestId("create-team").click();
    await page.getByTestId("team-name").fill(team);
    await page.getByTestId(`team-bucket-${team}-data`).check();
    await page.getByTestId("team-prefixes").fill(`${team}-q`);
    await page.getByTestId("team-level-admin").check();
    await page.getByTestId("team-save").click();

    // saved: the access dialog says what to set up for each level, and takes members
    const access = page.getByRole("dialog", { name: `Access to ${team}` });
    await expect(access.getByTestId("team-access-rw")).toContainText(`team-${team}-rw`);
    if (!process.env.CONSOLE_URL) await expect(access.getByTestId("team-access-rw")).toContainText("claim");
    await access.getByTestId("team-member-level").selectOption("rw");
    await access.getByTestId("team-member-kind").selectOption("user");
    await access.getByTestId("team-member-name").fill(member);
    await access.getByTestId("team-member-add").click();
    await expect(access.getByTestId("team-access-rw")).toContainText(member);
    await page.keyboard.press("Escape");
    await expect(access).toHaveCount(0);
    const row = page.getByTestId(`team-${team}`);
    await expect(row).toContainText(`${team}-data, ${team}-q*`);
    await expect(row).toContainText("1");

    // a level dropped is warned about, then gone
    await page.getByTestId(`team-edit-${team}`).click();
    await page.getByTestId("team-level-ro").uncheck();
    await expect(page.getByRole("dialog")).toContainText("Removing ro deletes that policy");
    await page.getByTestId("team-save").click();
    await expect(access).toBeVisible(); // saving opens the access dialog again
    await page.keyboard.press("Escape");
    await expect(access).toHaveCount(0);
    await expect(row).not.toContainText("ro");
    await expect(row).toContainText("admin");

    await page.getByTestId(`team-delete-${team}`).click();
    await page.getByTestId(`team-delete-${team}-yes`).click();
    await expect(row).toHaveCount(0);
  });

  test("access review: who reaches a bucket, the CSV, and a check", async ({ page }) => {
    const t = unique("ar");
    const user = `u-${t}`;
    await login(page);
    const h = { "X-Console-Request": "1" };
    expect((await page.request.put(`/api/v1/s3/${t}-data`, { headers: h })).status()).toBe(200);
    expect((await page.request.put(`/api/v1/s3/${t}-other`, { headers: h })).status()).toBe(200);
    await page.request.put(`/api/v1/admin/add-user?accessKey=${user}`, {
      headers: { ...h, "X-Console-Encrypt": "1" },
      data: JSON.stringify({ secretKey: "membersecret", status: "enabled" }),
    });
    const team = { name: t, buckets: [`${t}-data`], prefixes: [], levels: ["rw"] };
    expect((await page.request.put(`/api/v1/teams/${t}`, { headers: { ...h, "Content-Type": "application/json" }, data: { team } })).status()).toBe(200);
    expect((await page.request.post(`/api/v1/teams/${t}/members`, { headers: { ...h, "Content-Type": "application/json" }, data: { level: "rw", user } })).status()).toBe(204);

    // from the bucket list straight to its review
    await page.getByRole("link", { name: "Buckets", exact: true }).click();
    await page.getByTestId(`access-${t}-data`).click();
    await expect(page.getByTestId("review-bucket")).toHaveValue(`${t}-data`);
    const row = page.getByTestId(`review-row-${user}`);
    await expect(row).toContainText("local user");
    await expect(row).toContainText(`team-${t}-rw`);
    await expect(page.getByTestId(`review-row-${ROOT_USER}`)).toContainText("root user");
    // the CSV an auditor files
    const [dl] = await Promise.all([page.waitForEvent("download"), page.getByTestId("review-csv").click()]);
    const csv = await (await dl.createReadStream()).toArray().then((c) => Buffer.concat(c).toString());
    expect(csv.split("\n")[0]).toBe("bucket,level,principal,kind,status,action,decision,limits,granted by,reviewed at");
    expect(csv).toContain(`${t}-data,read,${user},local user,enabled,s3:GetObject,allowed,,team-${t}-rw`);

    // would this be allowed?
    await page.getByTestId("check-kind").selectOption("user");
    await page.getByTestId("check-name").selectOption(user);
    await page.getByTestId("check-action").fill("s3:PutObject");
    await page.getByTestId("check-bucket").selectOption(`${t}-data`);
    await page.getByTestId("check-object").fill("a.txt");
    await page.getByTestId("check-submit").click();
    await expect(page.getByTestId("check-result")).toContainText("Allowed");
    await expect(page.getByTestId("check-result")).toContainText(`team-${t}-rw`);
    await page.getByTestId("check-bucket").selectOption(`${t}-other`);
    await page.getByTestId("check-submit").click();
    await expect(page.getByTestId("check-result")).toContainText("Denied");
    await expect(page.getByTestId("check-result")).toContainText("No statement allows it");

    await page.request.delete(`/api/v1/teams/${t}`, { headers: h });
  });

  test("access keys show their secret once", async ({ page }) => {
    await login(page);
    await page.getByRole("link", { name: "Access Keys" }).click();
    await page.getByTestId("create-key").click();
    await page.getByTestId("key-name").fill("ci");
    await page.getByTestId("key-create-submit").click();
    const ak = (await page.getByTestId("created-access-key").textContent())!.trim();
    const sk = (await page.getByTestId("created-secret-key").textContent())!.trim();
    expect(ak.length).toBeGreaterThanOrEqual(16);
    expect(sk.length).toBeGreaterThanOrEqual(32);
    await page.getByRole("button", { name: "Done" }).click();
    await expect(page.getByTestId(`key-${ak}`)).toContainText("ci");
  });
});

test("configuration: read and change a setting", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Configuration" }).click();
  await page.getByTestId("config-scanner").click();
  await expect(page.getByTestId("cfg-speed")).toBeVisible();
  await page.getByTestId("cfg-speed").fill("slow");
  await page.getByTestId("config-save").click();
  await expect(page.getByTestId("notice")).toContainText("Saved");
  await page.getByTestId("config-api").click();
  await page.getByTestId("config-scanner").click();
  await expect(page.getByTestId("cfg-speed")).toHaveValue("slow");
});

test("configuration: every subsystem listed opens without an error", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Configuration" }).click();
  await expect(page.getByTestId("config-identity_openid")).toBeVisible();
  await expect(page.getByTestId("config-policy_opa")).toHaveCount(0);
  await expect(page.getByTestId("config-region")).toHaveCount(0);
  await expect(page.getByTestId("config-subnet")).toHaveCount(0); // MinIO's own services
  await expect(page.getByTestId("config-callhome")).toHaveCount(0);
  const ids = await page.locator('[data-testid^="config-"]:not([data-testid="config-save"])').evaluateAll((els) => els.map((e) => e.getAttribute("data-testid")!));
  expect(ids.length).toBeGreaterThan(20);
  for (const id of ids) {
    await page.getByTestId(id).click();
    await expect(page.locator(".muted").first()).toBeVisible();
    await expect(page.getByText("XMinioConfigError")).toHaveCount(0);
  }
});

test.describe("encryption", () => {
  test("the KMS and its keys, a bucket encrypted with one, and its existing objects", async ({ page }) => {
    test.skip(!!process.env.CONSOLE_URL, "needs the static KMS key of the local setup");
    await login(page);
    await page.getByRole("link", { name: "Encryption", exact: true }).click();
    await expect(page.getByTestId("kms-status")).toContainText("Built-in static key");
    await expect(page.getByTestId("kms-status")).toContainText("e2e-key");
    await expect(page.getByTestId("kms-key-e2e-key")).toContainText("works");
    // one fixed key: nothing to create or delete
    await expect(page.getByTestId("create-kms-key")).toHaveCount(0);
    await expect(page.getByTestId("delete-kms-key-e2e-key")).toHaveCount(0);

    const bucket = unique("sealed");
    await page.getByRole("link", { name: "Buckets" }).click();
    await page.getByTestId("create-bucket").click();
    await page.getByTestId("bucket-name").fill(bucket);
    await page.getByTestId("bucket-create-submit").click();
    // an object from before the bucket was encrypted
    await page.getByRole("link", { name: bucket }).click();
    await page.getByTestId("file-input").setInputFiles([{ name: "old.txt", mimeType: "text/plain", buffer: Buffer.from("written in the clear") }]);
    await expect(page.getByTestId("notice")).toHaveText("Uploaded 1 file.");
    await page.goto(`/buckets/${bucket}/settings`);
    await expect(page.getByTestId("encrypt-existing")).toHaveCount(0); // nothing to encrypt with yet
    await page.getByTestId("sse-alg").selectOption("aws:kms");
    await expect(page.getByTestId("sse-key").locator("option").first()).toHaveText("e2e-key (KMS default key)");
    await page.getByTestId("save-sse").click();
    await expect(page.getByTestId("notice")).toHaveText("Encryption saved.");
    await expect(page.getByTestId("encrypt-existing")).toContainText("e2e-key");
    await page.getByTestId("encrypt-existing-start").click();
    await expect(page.getByTestId("notice")).toHaveText("Encrypted 1 existing object version(s).", { timeout: 20000 });
    const head = await page.request.head(`/api/v1/s3/${bucket}/old.txt`);
    expect(head.headers()["x-amz-server-side-encryption"]).toBe("aws:kms");
    // the key page now names the bucket it encrypts
    await page.getByRole("link", { name: "Encryption", exact: true }).click();
    await expect(page.getByTestId("kms-key-e2e-key")).toContainText(bucket);
  });
});

test.describe("KMS and sign-in setup", () => {
  // the mock Kubernetes API (kubemock.py) stands in for the API server and buckets-operator
  const kubeState = async (page: import("@playwright/test").Page) =>
    (await (await page.request.get("https://127.0.0.1:19892/_state", { ignoreHTTPSErrors: true })).json()) as {
      cluster: { spec: { kms?: { kes?: { keyName?: string } } } };
      secrets: Record<
        string,
        Record<string, { settings?: { vault?: { approle?: { secret?: string; id?: string } } }; vault?: { approle?: { secret?: string; id?: string } }; openid?: { clientSecret?: string; removal?: { enabled: boolean; deleteAfterDays?: number; maxPerSync?: number; intervalMinutes?: number; apiToken?: string } } }>
      >;
    };

  test("Vault: a failed test says why, a passed one applies, and saved secrets are kept", async ({ page }) => {
    test.skip(!!process.env.CONSOLE_URL, "needs the mock Kubernetes API of the local setup");
    await login(page);
    await page.goto("/encryption");
    await page.getByTestId("kms-change").click();
    await expect(page.getByTestId("kms-steps")).toContainText("Key store");

    // 1: where keys are kept
    await expect(page.getByTestId("kms-next")).toBeDisabled();
    await page.getByTestId("kms-backend-vault").click();
    await page.getByTestId("kms-next").click();

    // 2: the connection; Next waits for what is missing, and says what that is
    await expect(page.getByTestId("kms-missing")).toContainText("Vault's address");
    await expect(page.getByTestId("kms-next")).toBeDisabled();
    await page.getByTestId("vault-endpoint").fill("https://unreachable:8200");
    await page.getByTestId("vault-role-id").fill("role-1");
    await page.getByTestId("vault-secret-id").fill("secret-1");
    await expect(page.getByTestId("vault-prefix")).toHaveValue("buckets/store");
    await page.getByText("Before you start: a policy and a role for KES in Vault").click();
    await expect(page.locator(".copyable pre")).toContainText('path "kv/data/buckets/store/*"');
    // Kubernetes sign-in names the service account KES runs as
    await page.getByTestId("vault-auth-kubernetes").click();
    await expect(page.getByText("store-kes", { exact: false }).first()).toBeVisible();
    await page.getByTestId("vault-auth-approle").click();
    await page.getByTestId("kms-next").click();

    // 3: the default key
    await expect(page.getByTestId("kms-key-name")).toHaveValue("buckets-default");
    await page.getByTestId("kms-next").click();

    // 4: a test that fails says why, and leads back to the settings
    await expect(page.getByTestId("kms-review")).toContainText("https://unreachable:8200");
    await page.getByTestId("kms-test").click();
    await expect(page.getByTestId("kms-test-result")).toContainText("no such host", { timeout: 15000 });
    await expect(page.getByTestId("kms-hint")).toContainText("check the address");
    await expect(page.getByTestId("kms-apply")).toHaveCount(0);
    await page.getByTestId("kms-fix").click();
    await page.getByTestId("vault-endpoint").fill("https://vault.example.com:8200");
    await page.getByTestId("kms-next").click();
    await page.getByTestId("kms-next").click();
    await page.getByTestId("kms-test").click();
    await expect(page.getByTestId("kms-test-result")).toContainText("The settings work.", { timeout: 15000 });
    await expect(page.getByTestId("kms-test-result")).toContainText("Default key buckets-default");
    await expect(page.getByTestId("kms-apply-note")).toContainText("restarts the storage servers one at a time");
    await page.getByTestId("kms-apply").click();
    await expect(page.getByTestId("kms-rollout")).toContainText("KES servers 2 of 2 ready", { timeout: 15000 });

    let st = await kubeState(page);
    expect(st.cluster.spec.kms?.kes?.keyName).toBe("buckets-default");
    expect(st.secrets["store-kms"]["settings.json"].vault?.approle?.secret).toBe("secret-1");

    // editing: the secret is not shown again, and stays unless retyped
    await page.goto("/encryption");
    await expect(page.getByTestId("kms-keystore")).toContainText("HashiCorp Vault at https://vault.example.com:8200");
    await page.getByTestId("kms-change").click();
    await expect(page.getByTestId("vault-secret-id")).toHaveValue("");
    await expect(page.getByTestId("vault-secret-id")).toHaveAttribute("placeholder", /saved/);
    await page.getByTestId("vault-role-id").fill("role-2");
    await page.getByTestId("kms-next").click();
    await page.getByTestId("kms-next").click();
    await page.getByTestId("kms-test").click();
    await expect(page.getByTestId("kms-test-result")).toContainText("The settings work.", { timeout: 15000 });
    await page.getByTestId("kms-apply").click();
    await expect(page.getByTestId("kms-rollout")).toBeVisible();
    st = await kubeState(page);
    expect(st.secrets["store-kms"]["settings.json"].vault?.approle).toEqual({ id: "role-2", secret: "secret-1" });
  });

  test("sign-in: steps for the provider, a test sign-in in a popup, then apply", async ({ page }) => {
    test.skip(!!process.env.CONSOLE_URL, "needs the mock Kubernetes API and provider of the local setup");
    await login(page);
    await page.goto("/identity/sign-in");
    await expect(page.getByTestId("signin-status")).toContainText("Not set up here yet");
    await page.getByTestId("oidc-on").getByRole("radio", { name: "On" }).click();
    // the provider's own steps, with this console's redirect URI to register
    await expect(page.getByTestId("provider-steps")).toContainText("App registrations");
    await expect(page.getByTestId("provider-steps")).toContainText("/oauth_callback");
    await page.getByTestId("oidc-provider-generic").click();
    await expect(page.getByTestId("signin-missing")).toContainText("the discovery URL");
    await expect(page.getByTestId("signin-save")).toBeDisabled();
    await page.getByTestId("oidc-config-url").fill("http://127.0.0.1:19891/.well-known/openid-configuration");
    await page.getByTestId("oidc-client-id").fill("console");
    await page.getByTestId("oidc-client-secret").fill("s3cr3t");
    await expect(page.getByTestId("signin-apply")).toBeDisabled();
    await page.getByTestId("signin-save").click();
    await expect(page.getByTestId("signin-save")).toHaveText("Saved");
    await expect(page.getByTestId("oidc-client-secret")).toHaveAttribute("placeholder", /saved/);
    // the test: a real sign-in at the provider, in a popup that reports back
    const popup = page.waitForEvent("popup");
    await page.getByTestId("signin-test").click();
    await expect((await popup).locator("body")).toContainText("Signed in as oidcuser", { timeout: 15000 });
    await expect(page.getByTestId("oidc-result")).toContainText("Signed in as oidcuser", { timeout: 15000 });
    await expect(page.getByTestId("oidc-result")).toContainText("readwrite");
    // still the admin: the test made no session
    expect((await (await page.request.get("/api/v1/session")).json()).accessKey).toBe(ROOT_USER);
    await page.getByTestId("signin-apply").click();
    await expect(page.getByTestId("signin-apply")).toHaveText("Applied");
    await expect(page.getByTestId("signin-status")).toContainText("People sign in with", { timeout: 15000 });
    const st = await kubeState(page);
    expect(st.secrets["store-identity"]["settings.json"].openid?.clientSecret).toBe("s3cr3t");
    // an edit is a new candidate: tested again before it applies
    await page.getByTestId("oidc-client-id").fill("other");
    await expect(page.getByTestId("signin-apply")).toBeDisabled();
  });

  test("sign-in: people who leave, for Entra ID, Okta and Keycloak, with a lookup required before apply", async ({ page }) => {
    test.skip(!!process.env.CONSOLE_URL, "needs the mock Kubernetes API of the local setup");
    await login(page);
    await page.goto("/identity/sign-in");
    await page.getByTestId("oidc-on").getByRole("radio", { name: "On" }).click();
    await page.getByTestId("oidc-provider-entra").click();
    await expect(page.getByTestId("removal")).toContainText("People who leave");
    await page.getByTestId("removal-on").check();
    // what the app needs in Entra ID
    await expect(page.getByTestId("removal")).toContainText("User.Read.All");
    await expect(page.getByTestId("removal")).toContainText("Grant admin consent");
    await page.getByTestId("removal-days").fill("14");
    await page.getByTestId("oidc-tenant").fill("11111111-2222-3333-4444-555555555555");
    await page.getByTestId("oidc-client-id").fill("app-1");
    await page.getByTestId("oidc-client-secret").fill("s3cr3t");
    await expect(page.getByTestId("removal-test")).toBeDisabled(); // saved first
    await page.getByTestId("signin-save").click();
    await expect(page.getByTestId("signin-save")).toHaveText("Saved");
    await expect(page.getByTestId("apply-card")).toContainText("Look up a person (People who leave");
    await expect(page.getByTestId("signin-apply")).toBeDisabled();
    await page.getByTestId("removal-test-user").fill("alice@example.com");
    await expect(page.getByTestId("removal-test")).toBeEnabled();
    const st = await kubeState(page);
    expect(st.secrets["store-identity-candidate"]["settings.json"].openid?.removal).toEqual({ enabled: true, deleteAfterDays: 14 });
    // Okta: the section asks for an API token, and Save waits for one
    await page.getByTestId("oidc-provider-okta").click();
    await page.getByTestId("removal-on").check();
    await expect(page.getByTestId("removal")).toContainText("Security → API → Tokens");
    await page.getByTestId("oidc-domain").fill("example.okta.com");
    await page.getByTestId("oidc-client-id").fill("app-2");
    await page.getByTestId("oidc-client-secret").fill("s3cr3t");
    await expect(page.getByTestId("signin-missing")).toContainText("an Okta API token");
    await page.getByTestId("removal-api-token").fill("00token");
    await expect(page.getByTestId("signin-missing")).toHaveCount(0);
    // Keycloak: the service account's role; another OpenID provider has no such section
    await page.getByTestId("oidc-provider-keycloak").click();
    await page.getByTestId("removal-on").check();
    await expect(page.getByTestId("removal")).toContainText("realm-management: view-users");
    await page.getByTestId("oidc-provider-generic").click();
    await expect(page.getByTestId("removal")).toHaveCount(0);
  });

  test("settings the server refuses are explained before any test", async ({ page }) => {
    test.skip(!!process.env.CONSOLE_URL, "needs the mock Kubernetes API of the local setup");
    await login(page);
    await page.goto("/encryption/setup");
    // saved settings open at the connection: the key store is a step back
    await page.getByTestId("kms-steps").getByRole("button", { name: "Key store" }).click();
    await page.getByTestId("kms-backend-gcp").click();
    await page.getByTestId("kms-next").click();
    await page.getByTestId("gcp-credentials").fill("not json");
    await expect(page.getByText("This is not a service account's JSON key")).toBeVisible();
    await page.getByTestId("gcp-credentials").fill(JSON.stringify({ type: "service_account", project_id: "proj-9", client_email: "kes@proj-9.iam.gserviceaccount.com", private_key: "k" }));
    await expect(page.getByTestId("gcp-who")).toContainText("kes@proj-9.iam.gserviceaccount.com");
    await expect(page.getByTestId("gcp-project")).toHaveValue("proj-9");
    // a key name the server would refuse cannot go on
    await page.getByTestId("kms-next").click();
    await page.getByTestId("kms-key-name").fill("bad name");
    await expect(page.getByTestId("kms-next")).toBeDisabled();
  });
});

test.describe("monitoring", () => {
  test("trace shows calls as they happen", async ({ page }) => {
    await login(page);
    const bucket = unique("trace");
    await page.getByRole("link", { name: "Trace" }).click();
    await expect(page.getByRole("heading", { name: "Trace" })).toBeVisible();
    await page.getByTestId("stream-start").click();
    await expect(page.getByTestId("stream-stop")).toBeVisible();
    await page.waitForTimeout(500);
    await page.request.put(`/api/v1/s3/${bucket}`, { headers: { "X-Console-Request": "1" } });
    await expect(page.getByTestId("trace-row").filter({ hasText: "s3.PutBucket" }).first()).toBeVisible();
    await page.getByTestId("trace-row").filter({ hasText: "s3.PutBucket" }).first().click();
    await expect(page.locator("pre.json")).toContainText(bucket);
    await page.keyboard.press("Escape");
    await page.getByTestId("stream-stop").click({ force: true });
    await expect(page.getByTestId("stream-start")).toBeVisible();
  });

  test("logs stream the server log", async ({ page }) => {
    await login(page);
    await page.getByRole("link", { name: "Logs" }).click();
    await page.getByTestId("stream-start").click();
    await expect(page.getByTestId("log-row").first()).toBeVisible();
    await page.getByTestId("stream-stop").click();
  });

  test("events show a bucket's changes", async ({ page }) => {
    await login(page);
    const bucket = unique("events");
    await page.request.put(`/api/v1/s3/${bucket}`, { headers: { "X-Console-Request": "1" } });
    await page.getByRole("link", { name: "Events" }).click();
    await page.getByTestId("events-bucket").selectOption(bucket);
    await page.getByTestId("stream-start").click();
    await page.waitForTimeout(500);
    await page.request.put(`/api/v1/s3/${bucket}/hello.txt`, { headers: { "X-Console-Request": "1" }, data: "hi" });
    await expect(page.getByTestId("event-row").filter({ hasText: "hello.txt" })).toBeVisible();
    await expect(page.getByTestId("event-row").first()).toContainText("ObjectCreated:Put");
    await page.getByTestId("stream-stop").click();
  });
});
