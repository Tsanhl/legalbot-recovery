import { defineConfig } from "@playwright/test";

const runId = process.env.LEGALBOT_BROWSER_RUN_ID || `manual-${Date.now()}`;

export default defineConfig({
  testDir: "./tests/browser",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 30_000,
  outputDir: `../Log/legalbot-controller/LegalBot-GE-2026-09-08-pre-browser-r1/browser/${runId}/artifacts`,
  reporter: [["line"]],
  use: {
    baseURL: "http://127.0.0.1:8777",
    browserName: "chromium",
    channel: "chrome",
    headless: true,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure",
  },
  webServer: {
    command: "npm run start",
    url: "http://127.0.0.1:8777",
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
