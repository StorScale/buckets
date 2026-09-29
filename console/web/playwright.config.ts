import { defineConfig } from "@playwright/test";

// e2e against a real bucketsd + consoled. By default the global setup starts
// both (BUCKETSD_BIN / CONSOLED_BIN, defaulting to the CMake build) on fresh
// drives; CONSOLE_URL points the tests at an existing console instead
// (a kind cluster, for instance).
export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  globalSetup: "./e2e/global-setup.ts",
  use: {
    baseURL: process.env.CONSOLE_URL ?? "http://127.0.0.1:19890",
    trace: "retain-on-failure",
  },
});
