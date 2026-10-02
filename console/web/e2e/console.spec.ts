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
